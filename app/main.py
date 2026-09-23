"""
Perimeter -- sales intelligence from attack surface.

FastAPI + HTMX + Jinja2. No build step on purpose: a reviewer can open a
template and understand the page. For a product judged on clarity, a bundler
is cost with no benefit.

    uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app import queries as q
from core.llm import call

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="Perimeter")
tpl = Jinja2Templates(directory=str(ROOT / "app" / "templates"))

# One switch degrades the whole product to rules-only. The queue still ranks
# correctly without any model -- only the prose disappears.
LLM_DISABLED = os.environ.get("PERIMETER_LLM_DISABLED") == "1"


def _filters(request: Request) -> dict:
    p = request.query_params
    return {k: p.get(k) for k in
            ("country", "industry", "tier", "min_exposure", "finding_type",
             "product", "q")
            if p.get(k)}


@app.get("/", response_class=HTMLResponse)
def queue(request: Request):
    f = _filters(request)
    with q.connect() as con:
        ctx = {"request": request, "rows": q.queue(con, f), "filters": f,
               "facets": q.facets(con), "stats": q.corpus_stats(con)}
    return tpl.TemplateResponse(request, "queue.html", ctx)


@app.get("/rows", response_class=HTMLResponse)
def queue_rows(request: Request):
    """HTMX partial -- filter changes swap just the list."""
    f = _filters(request)
    with q.connect() as con:
        ctx = {"request": request, "rows": q.queue(con, f), "filters": f}
    return tpl.TemplateResponse(request, "_rows.html", ctx)


@app.get("/a/{company_id:path}", response_class=HTMLResponse)
def account(request: Request, company_id: str):
    with q.connect() as con:
        c = q.company(con, company_id)
        if not c:
            return HTMLResponse("<h1>Not found</h1>", status_code=404)
        ctx = {"request": request, "c": c,
               "findings": q.findings(con, company_id),
               "hosts": q.hosts(con, company_id),
               "llm_disabled": LLM_DISABLED}
    return tpl.TemplateResponse(request, "account.html", ctx)


@app.post("/a/{company_id:path}/outreach", response_class=HTMLResponse)
def outreach(request: Request, company_id: str):
    """
    Draft an email -- then verify every cited finding exists.

    The check below is the product's most important line. A rep emailing a
    prospect about a fabricated CVE is unrecoverable, so a draft citing an
    unknown finding is discarded in code rather than trusted to the prompt.
    """
    with q.connect() as con:
        c = q.company(con, company_id)
        fnd = q.findings(con, company_id)

    if LLM_DISABLED or not fnd:
        return tpl.TemplateResponse(request, "_outreach.html", {
            "request": request, "draft": None, "findings": fnd,
            "error": "LLM disabled -- rules-only mode" if LLM_DISABLED
                     else "No findings to write about."})

    payload = json.dumps({
        "company": {k: c.get(k) for k in
                    ("primary_domain", "legal_name", "country", "industry",
                     "identity")},
        "scan_date": str(c.get("last_seen"))[:10],
        "findings": [{"id": str(f["id"]), "type": f["type"],
                      "severity": f["severity"], "title": f["title"],
                      "evidence": f["evidence"], "port": f["port"],
                      "cve": f["cve"], "cvss": f["cvss"]} for f in fnd[:12]],
    }, indent=2, default=str)

    res = call(feature="outreach-draft", prompt_name="outreach-draft",
               prompt_version="v1", model="claude-opus-5",
               user_content=payload, max_tokens=900, subject_id=company_id)

    draft, error = res.get("decision"), res.get("error")
    if draft:
        valid = {str(f["id"]) for f in fnd}
        cited = {str(i) for i in draft.get("cited_finding_ids", [])}
        if not cited <= valid:
            # Hallucinated evidence. Discard the whole draft.
            error = (f"Draft cited findings that do not exist "
                     f"({', '.join(sorted(cited - valid))}) -- discarded.")
            draft = None

    return tpl.TemplateResponse(request, "_outreach.html", {
        "request": request, "draft": draft, "findings": fnd,
        "error": error, "cost": res.get("cost_usd"),
        "latency": res.get("latency_ms")})


@app.get("/segments", response_class=HTMLResponse)
def segments(request: Request):
    f = _filters(request)
    with q.connect() as con:
        ctx = {"request": request, "filters": f, "facets": q.facets(con),
               "seg": q.segment_stats(con, f), "stats": q.corpus_stats(con)}
    return tpl.TemplateResponse(request, "segments.html", ctx)


@app.get("/segments/stats", response_class=HTMLResponse)
def segments_stats(request: Request):
    f = _filters(request)
    with q.connect() as con:
        ctx = {"request": request, "seg": q.segment_stats(con, f), "filters": f}
    return tpl.TemplateResponse(request, "_segstats.html", ctx)


@app.get("/ops", response_class=HTMLResponse)
def ops(request: Request):
    with q.connect() as con:
        stats = q.corpus_stats(con)
        rarity = q.facets(con)["finding_types"]
    evals = []
    for p in sorted((ROOT / "evals" / "results").glob("*.json")):
        try:
            evals.append(json.loads(p.read_text()))
        except json.JSONDecodeError:
            pass
    return tpl.TemplateResponse(request, "ops.html", {
        "request": request, "stats": stats, "rarity": rarity,
        "llm": q.llm_stats(), "evals": evals, "llm_disabled": LLM_DISABLED})
