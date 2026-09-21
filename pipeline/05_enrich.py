#!/usr/bin/env python3
"""
Industry classification -- the one job in this pipeline that rules cannot do.

Everything else here is deterministic. Deciding that `northwind-ortho.com`
with a page titled "Patient Portal" is healthcare is judgement from weak,
noisy text, which is exactly what a language model is for and exactly what a
regex is not.

Cost discipline:
  * only companies that already pass a rules-based gate are sent
  * cheapest capable model (Haiku 4.5), because this is classification with a
    crisp right answer, not judgement
  * the rubric is cached, so repeat calls bill the system prompt at ~0.1x
  * --limit and --dry-run make the spend knowable before it is spent

Usage:
    python3 pipeline/05_enrich.py data/out/perimeter.duckdb --dry-run
    python3 pipeline/05_enrich.py data/out/perimeter.duckdb --limit 200
"""
import argparse
import json
import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.llm import call, cost_usd  # noqa: E402

MODEL = "claude-haiku-4-5"
PROMPT, VERSION = "classify-industry", "v1"

VALID = {
    "healthcare", "manufacturing", "finance", "education", "government",
    "legal", "professional_services", "retail", "logistics", "energy",
    "utilities", "real_estate", "media", "nonprofit", "technology",
    "cybersecurity", "hosting", "telecom", "unknown",
}


def evidence(row: dict) -> str:
    """Only real observations. Nothing invented, nothing padded."""
    lines = [f"domain: {row['primary_domain']}"]
    if row.get("legal_name"):
        lines.append(f"legal_name: {row['legal_name']}")
    if row.get("page_title"):
        lines.append(f"page_title: {row['page_title']}")
    if row.get("products"):
        lines.append(f"products: {', '.join(row['products'][:6])}")
    if row.get("country"):
        lines.append(f"country: {row['country']}"
                     + (f", city: {row['city']}" if row.get("city") else ""))
    if row.get("open_ports"):
        lines.append(f"open_ports: {sorted(row['open_ports'])[:12]}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("db", nargs="?", default="data/out/perimeter.duckdb")
    ap.add_argument("--limit", type=int, default=0, help="0 = all eligible")
    ap.add_argument("--dry-run", action="store_true",
                    help="render prompts, trace, and cost -- no API calls")
    args = ap.parse_args()

    con = duckdb.connect(args.db)

    # --- the gate: only spend on companies that could matter ---------------
    # Classifying all 60k would cost real money to label companies nobody will
    # ever open. A company with no findings is Tier D whatever its industry.
    con.execute("""
        CREATE OR REPLACE TEMP VIEW eligible AS
        SELECT c.company_id, c.primary_domain, c.legal_name, c.country, c.city,
               c.products, c.page_title, c.open_ports, c.n_ips, c.n_ports,
               (SELECT count(*) FROM findings f
                 WHERE f.company_id = c.company_id) AS n_findings
        FROM companies c
        WHERE c.n_ips >= 2
    """)
    rows = con.execute("""
        SELECT * FROM eligible WHERE n_findings > 0
        ORDER BY n_findings DESC
    """).fetchall()
    cols = [d[0] for d in con.description]
    if args.limit:
        rows = rows[: args.limit]

    total_co = con.sql("SELECT count(*) FROM companies").fetchone()[0]
    print(f"companies total      : {total_co:,}")
    print(f"eligible for LLM     : {len(rows):,} "
          f"({len(rows) / max(total_co, 1) * 100:.1f}%)  <- rules gate")

    # Cost forecast before spending anything.
    est_in, est_out = 620, 70
    fc = len(rows) * cost_usd(MODEL, est_in, est_out)
    print(f"forecast             : ~{est_in} in / {est_out} out tokens each")
    print(f"                       ~${fc:.2f} at list price "
          f"(~${fc / 2:.2f} via Batch API)")
    if args.dry_run:
        print("\n--dry-run: no API calls will be made\n")

    results, spend, failures = [], 0.0, 0
    for i, r in enumerate(rows, 1):
        row = dict(zip(cols, r))
        res = call(
            feature="classify-industry", prompt_name=PROMPT,
            prompt_version=VERSION, model=MODEL,
            user_content=evidence(row), max_tokens=256,
            subject_id=row["company_id"], dry_run=args.dry_run,
        )
        spend += res.get("cost_usd") or 0.0

        d = res.get("decision") or {}
        industry = d.get("industry")
        if industry not in VALID:
            # A label outside the taxonomy is a failure, not a new category.
            if not args.dry_run:
                failures += 1
            industry, conf = "unknown", 0.0
        else:
            conf = float(d.get("confidence") or 0.0)

        results.append((row["company_id"], industry, conf,
                        d.get("segment"), d.get("reasoning")))

        if i % 100 == 0:
            print(f"  {i:,}/{len(rows):,}  spend ${spend:.3f}  failures {failures}")

    con.execute("DROP TABLE IF EXISTS company_industry")
    con.execute("""
        CREATE TABLE company_industry (
            company_id VARCHAR, industry VARCHAR, confidence DOUBLE,
            segment VARCHAR, reasoning VARCHAR
        )
    """)
    con.executemany("INSERT INTO company_industry VALUES (?,?,?,?,?)", results)

    # Fold the label onto companies so 06_score.py picks it up automatically.
    con.execute("ALTER TABLE companies ADD COLUMN IF NOT EXISTS industry VARCHAR")
    con.execute("""
        UPDATE companies SET industry = ci.industry
        FROM company_industry ci WHERE ci.company_id = companies.company_id
    """)

    print(f"\nclassified {len(results):,}   spend ${spend:.4f}   failures {failures}")
    if not args.dry_run:
        print("\nlabel distribution:")
        for ind, n, ac in con.sql("""
            SELECT industry, count(*), round(avg(confidence), 2)
            FROM company_industry GROUP BY 1 ORDER BY 2 DESC
        """).fetchall():
            print(f"  {ind:<22} {n:>6,}  avg confidence {ac}")
    con.close()


if __name__ == "__main__":
    main()
