"""
Traced Anthropic client.

Every LLM call in this project goes through `call()`. There is no second path.
That is the point: observability you can opt out of is observability you do not
have. The trace row is written whether the call succeeds, fails, or is refused.

Model choice is per-task, not global:
    classification  Haiku 4.5   -- high volume, crisp right/wrong answer
    judgement       Opus 5      -- low volume, on demand, quality matters

Prompts live in prompts/<name>/v<N>.md and are addressed by version, so v1 and
v2 can be compared on the same eval set.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROMPT_DIR = ROOT / "prompts"
TRACE_DB = ROOT / "data" / "out" / "traces.sqlite"

# USD per million tokens. Source: Anthropic pricing, cached 2026-06-24.
PRICING = {
    "claude-haiku-4-5": {"in": 1.00, "out": 5.00},
    "claude-sonnet-5":  {"in": 2.00, "out": 10.00},
    "claude-opus-5":    {"in": 5.00, "out": 25.00},
}

TRACE_SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_calls (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    feature         TEXT NOT NULL,   -- classify-industry | account-brief | ...
    prompt_name     TEXT NOT NULL,
    prompt_version  TEXT NOT NULL,   -- v1, v2 ... comparable across runs
    model           TEXT NOT NULL,
    subject_id      TEXT,            -- company_id this call was about
    input_tokens        INTEGER,
    output_tokens       INTEGER,
    cache_read_tokens   INTEGER,
    latency_ms      INTEGER,
    cost_usd        REAL,
    stop_reason     TEXT,
    decision        TEXT,            -- parsed structured result
    ok              INTEGER NOT NULL,
    error           TEXT,
    request         TEXT,
    response        TEXT,
    eval_run_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_calls_feature ON llm_calls(feature, prompt_version);
CREATE INDEX IF NOT EXISTS idx_calls_ts      ON llm_calls(ts);
"""


def _db() -> sqlite3.Connection:
    TRACE_DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(TRACE_DB)
    con.executescript(TRACE_SCHEMA)
    return con


def load_prompt(name: str, version: str) -> str:
    p = PROMPT_DIR / name / f"{version}.md"
    if not p.exists():
        raise FileNotFoundError(f"no prompt at {p}")
    return p.read_text()


def cost_usd(model: str, in_tok: int, out_tok: int) -> float:
    p = PRICING.get(model)
    if not p:
        return 0.0
    return in_tok / 1e6 * p["in"] + out_tok / 1e6 * p["out"]


def extract_json(text: str) -> dict | None:
    """Models sometimes wrap JSON in prose or a fence. Recover it, or fail loudly."""
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    candidate = fence.group(1) if fence else text
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(candidate[start:end + 1])
    except json.JSONDecodeError:
        return None


def call(
    *,
    feature: str,
    prompt_name: str,
    prompt_version: str,
    model: str,
    user_content: str,
    max_tokens: int = 512,
    subject_id: str | None = None,
    eval_run_id: str | None = None,
    dry_run: bool = False,
) -> dict:
    """
    Make one traced call. Returns {ok, decision, cost_usd, latency_ms, error}.

    dry_run renders the prompt, writes a trace row and returns without calling
    the API -- so the pipeline, the cost model and the trace schema can all be
    exercised without a key or a bill.
    """
    system = load_prompt(prompt_name, prompt_version)
    call_id = str(uuid.uuid4())
    started = time.time()
    row = {
        "id": call_id, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "feature": feature, "prompt_name": prompt_name,
        "prompt_version": prompt_version, "model": model,
        "subject_id": subject_id, "eval_run_id": eval_run_id,
        "input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0,
        "latency_ms": 0, "cost_usd": 0.0, "stop_reason": None,
        "decision": None, "ok": 0, "error": None,
        "request": user_content[:4000], "response": None,
    }

    if dry_run:
        row.update(ok=1, decision=json.dumps({"dry_run": True}),
                   latency_ms=int((time.time() - started) * 1000),
                   error="dry_run: no API call made")
        _write(row)
        return {"ok": True, "decision": None, "cost_usd": 0.0,
                "latency_ms": row["latency_ms"], "error": None, "dry_run": True}

    try:
        import anthropic
    except ImportError:
        row["error"] = "anthropic SDK not installed (pip install anthropic)"
        _write(row)
        return {"ok": False, "decision": None, "cost_usd": 0.0,
                "latency_ms": 0, "error": row["error"]}

    if not (os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        row["error"] = "no credentials (set ANTHROPIC_API_KEY or run `ant auth login`)"
        _write(row)
        return {"ok": False, "decision": None, "cost_usd": 0.0,
                "latency_ms": 0, "error": row["error"]}

    try:
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            # The rubric is identical on every call, so cache it: cache reads
            # bill at ~0.1x. At 10k classifications that is most of the spend.
            system=[{"type": "text", "text": system,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        u = resp.usage
        row.update(
            input_tokens=u.input_tokens, output_tokens=u.output_tokens,
            cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
            latency_ms=int((time.time() - started) * 1000),
            cost_usd=cost_usd(model, u.input_tokens, u.output_tokens),
            stop_reason=resp.stop_reason, response=text[:4000],
        )
        if resp.stop_reason == "refusal":
            row["error"] = "refusal"
            _write(row)
            return {"ok": False, "decision": None, "cost_usd": row["cost_usd"],
                    "latency_ms": row["latency_ms"], "error": "refusal"}

        decision = extract_json(text)
        row.update(decision=json.dumps(decision) if decision else None,
                   ok=1 if decision else 0,
                   error=None if decision else "unparseable response")
        _write(row)
        return {"ok": bool(decision), "decision": decision,
                "cost_usd": row["cost_usd"], "latency_ms": row["latency_ms"],
                "error": row["error"]}

    except Exception as exc:  # noqa: BLE001 - trace everything, re-raise nothing
        row.update(error=f"{type(exc).__name__}: {exc}",
                   latency_ms=int((time.time() - started) * 1000))
        _write(row)
        return {"ok": False, "decision": None, "cost_usd": 0.0,
                "latency_ms": row["latency_ms"], "error": row["error"]}


def _write(row: dict) -> None:
    con = _db()
    con.execute(
        f"INSERT OR REPLACE INTO llm_calls ({','.join(row)}) "
        f"VALUES ({','.join('?' * len(row))})",
        list(row.values()),
    )
    con.commit()
    con.close()


def summary() -> list[tuple]:
    con = _db()
    rows = con.execute("""
        SELECT feature, prompt_version, model, count(*),
               round(sum(cost_usd), 4), round(avg(latency_ms)),
               sum(ok), sum(1 - ok)
        FROM llm_calls GROUP BY feature, prompt_version, model
    """).fetchall()
    con.close()
    return rows
