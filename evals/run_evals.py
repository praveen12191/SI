#!/usr/bin/env python3
"""
One command. Re-runs the labelled set against a prompt version and reports
against the previous one.

    python3 evals/run_evals.py --version v1
    python3 evals/run_evals.py --version v2          # compares to v1
    python3 evals/run_evals.py --version v1 --dry-run

Why these metrics and not "accuracy":

This classifier is allowed to answer `unknown`. Accuracy punishes a correct
abstention exactly as hard as a confident lie, which is backwards -- for a
sales tool, a blank industry is a small cost and a wrong one destroys the
rep's trust in the whole list. So we report:

    coverage    how often it committed to an answer
    precision   of the answers it gave, how many were right
    recall      of all examples, how many it got right
    near-miss   wrong but defensible (edtech labelled `technology`)
    HARMFUL     wrong and damaging -- above all, anti-ICP confusion

ANTI-ICP CONFUSION is the metric that would block a release. Labelling a
hosting provider or a telco as `healthcare` puts a landlord at the top of a
rep's queue, and they will never trust the tool again.
"""
import argparse
import json
import statistics
import sys
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.llm import call  # noqa: E402

LABELLED = ROOT / "evals" / "labelled" / "industry.jsonl"
RESULTS = ROOT / "evals" / "results"
MODEL = "claude-haiku-4-5"

# Companies we must never present as prospects: they are infrastructure or
# competitors. Getting these wrong is qualitatively worse than other errors.
ANTI_ICP = {"hosting", "telecom", "cybersecurity"}

# Pairs where a wrong answer is defensible rather than damaging.
NEAR_MISS = {
    frozenset({"education", "technology"}),
    frozenset({"media", "technology"}),
    frozenset({"retail", "logistics"}),
    frozenset({"government", "education"}),
    frozenset({"nonprofit", "education"}),
    frozenset({"finance", "professional_services"}),
    frozenset({"hosting", "telecom"}),          # both anti-ICP: still suppressed
    frozenset({"technology", "professional_services"}),
}


def render(ev: dict) -> str:
    order = ["domain", "legal_name", "page_title", "products",
             "country", "city", "open_ports"]
    out = []
    for k in order:
        if ev.get(k) is not None:
            v = ev[k]
            out.append(f"{k}: {', '.join(map(str, v)) if isinstance(v, list) else v}")
    return "\n".join(out)


def classify(kind: str, truth: str, pred: str) -> str:
    if pred == truth:
        return "correct"
    if pred == "unknown":
        return "abstained"
    if truth in ANTI_ICP and pred not in ANTI_ICP:
        return "anti_icp_confusion"      # the one that blocks a release
    if frozenset({truth, pred}) in NEAR_MISS:
        return "near_miss"
    return "wrong"


def run(version: str, dry_run: bool) -> dict:
    cases = [json.loads(l) for l in LABELLED.read_text().splitlines() if l.strip()]
    run_id = str(uuid.uuid4())[:8]
    print(f"eval run {run_id}  prompt=classify-industry/{version}  "
          f"model={MODEL}  n={len(cases)}"
          f"{'  [DRY RUN]' if dry_run else ''}\n")

    outcomes, rows, spend, lat = Counter(), [], 0.0, []
    confusion = defaultdict(Counter)

    for c in cases:
        res = call(feature="eval:classify-industry", prompt_name="classify-industry",
                   prompt_version=version, model=MODEL,
                   user_content=render(c["evidence"]), max_tokens=256,
                   subject_id=c["id"], eval_run_id=run_id, dry_run=dry_run)
        spend += res.get("cost_usd") or 0.0
        if res.get("latency_ms"):
            lat.append(res["latency_ms"])

        d = res.get("decision") or {}
        pred = d.get("industry") or ("unknown" if dry_run else "ERROR")
        conf = float(d.get("confidence") or 0.0)
        outcome = classify(c["difficulty"], c["label"], pred)
        outcomes[outcome] += 1
        confusion[c["label"]][pred] += 1
        rows.append({"id": c["id"], "truth": c["label"], "pred": pred,
                     "confidence": conf, "outcome": outcome,
                     "difficulty": c["difficulty"],
                     "domain": c["evidence"].get("domain")})

    n = len(cases)
    answered = n - outcomes["abstained"] - (
        sum(1 for r in rows if r["pred"] == "unknown" and r["truth"] == "unknown")
    )
    correct = outcomes["correct"]
    # Committing to an answer means predicting something other than `unknown`.
    committed = sum(1 for r in rows if r["pred"] not in ("unknown", "ERROR"))
    correct_committed = sum(
        1 for r in rows if r["outcome"] == "correct" and r["pred"] != "unknown")

    metrics = {
        "run_id": run_id, "version": version, "model": MODEL, "n": n,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dry_run": dry_run,
        "coverage": round(committed / n, 3),
        "precision": round(correct_committed / committed, 3) if committed else 0.0,
        "recall": round(correct / n, 3),
        "near_miss_rate": round(outcomes["near_miss"] / n, 3),
        "wrong_rate": round(outcomes["wrong"] / n, 3),
        "anti_icp_confusion": outcomes["anti_icp_confusion"],
        "abstain_rate": round(
            sum(1 for r in rows if r["pred"] == "unknown") / n, 3),
        "cost_usd": round(spend, 5),
        "latency_p50_ms": int(statistics.median(lat)) if lat else 0,
        "by_difficulty": {
            d: round(
                sum(1 for r in rows if r["difficulty"] == d and r["outcome"] == "correct")
                / max(1, sum(1 for r in rows if r["difficulty"] == d)), 3)
            for d in ("easy", "medium", "hard")
        },
        "rows": rows,
    }
    return metrics


def report(m: dict, prev: dict | None) -> None:
    def delta(key: str, higher_better: bool = True) -> str:
        if not prev or key not in prev:
            return ""
        d = m[key] - prev[key]
        if abs(d) < 1e-9:
            return "   ="
        good = (d > 0) == higher_better
        return f"  {'^' if d > 0 else 'v'}{abs(d):+.3f}"[:9] + ("" if good else " !")

    w = 62
    print("=" * w)
    print(f"  classify-industry  {m['version']}"
          + (f"  vs  {prev['version']}" if prev else "  (no baseline)"))
    print("=" * w)
    print(f"  coverage            {m['coverage']:.3f}{delta('coverage')}")
    print(f"  precision           {m['precision']:.3f}{delta('precision')}")
    print(f"  recall              {m['recall']:.3f}{delta('recall')}")
    print(f"  abstain rate        {m['abstain_rate']:.3f}"
          f"{delta('abstain_rate', False)}")
    print(f"  near-miss rate      {m['near_miss_rate']:.3f}"
          f"{delta('near_miss_rate', False)}")
    print(f"  wrong rate          {m['wrong_rate']:.3f}"
          f"{delta('wrong_rate', False)}")
    print("-" * w)
    flag = "  <-- BLOCKS RELEASE" if m["anti_icp_confusion"] else "  OK"
    print(f"  ANTI-ICP CONFUSION  {m['anti_icp_confusion']}{flag}")
    print("-" * w)
    d = m["by_difficulty"]
    print(f"  by difficulty       easy {d['easy']:.2f}   "
          f"medium {d['medium']:.2f}   hard {d['hard']:.2f}")
    print(f"  cost                ${m['cost_usd']:.5f} "
          f"(${m['cost_usd'] / max(m['n'], 1) * 100:.3f} per 100)")
    print(f"  latency p50         {m['latency_p50_ms']} ms")
    print("=" * w)

    bad = [r for r in m["rows"] if r["outcome"] in
           ("wrong", "anti_icp_confusion", "near_miss")]
    if bad:
        print("\n  FAILURES")
        for r in sorted(bad, key=lambda r: r["outcome"]):
            tag = {"anti_icp_confusion": "ANTI-ICP", "wrong": "WRONG",
                   "near_miss": "near-miss"}[r["outcome"]]
            print(f"   [{tag:<9}] {r['id']} {str(r['domain'])[:28]:<28} "
                  f"{r['truth']} -> {r['pred']} (conf {r['confidence']})")

    if prev:
        pm = {r["id"]: r for r in prev["rows"]}
        regressions = [r for r in m["rows"]
                       if r["outcome"] != "correct"
                       and pm.get(r["id"], {}).get("outcome") == "correct"]
        if regressions:
            print(f"\n  REGRESSIONS vs {prev['version']}")
            for r in regressions:
                print(f"   {r['id']} {r['domain']}: "
                      f"{r['truth']} -> {r['pred']}")
        else:
            print(f"\n  no regressions vs {prev['version']}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--compare-to", default=None,
                    help="version to diff against (default: previous by mtime)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    m = run(args.version, args.dry_run)

    prev = None
    target = args.compare_to
    if not target:
        others = sorted(
            (p for p in RESULTS.glob("classify-industry_*.json")
             if args.version not in p.stem),
            key=lambda p: p.stat().st_mtime, reverse=True)
        if others:
            prev = json.loads(others[0].read_text())
    else:
        p = RESULTS / f"classify-industry_{target}.json"
        if p.exists():
            prev = json.loads(p.read_text())

    report(m, prev)

    if not args.dry_run:
        out = RESULTS / f"classify-industry_{args.version}.json"
        out.write_text(json.dumps(m, indent=2))
        print(f"\n  saved {out.relative_to(ROOT)}")

    # Non-zero exit on the release-blocking metric, so CI can gate on it.
    raise SystemExit(1 if m["anti_icp_confusion"] else 0)


if __name__ == "__main__":
    main()
