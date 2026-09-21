#!/usr/bin/env python3
"""
Score every company on fit and exposure, assign a tier, write `scores`.

Usage:
    python3 pipeline/06_score.py data/out/perimeter.duckdb
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.scoring import exposure_score, fit_score, tier  # noqa: E402


def build(db_path: str) -> None:
    con = duckdb.connect(db_path)

    prevalence = dict(con.execute(
        "SELECT type, prevalence FROM finding_rarity").fetchall())
    print(f"loaded rarity for {len(prevalence)} finding types")

    by_co = defaultdict(list)
    for cid, t, pts, sev, title in con.execute(
            "SELECT company_id, type, points, severity, title FROM findings"
    ).fetchall():
        by_co[cid].append({"type": t, "points": pts,
                           "severity": sev, "title": title})

    cols = ["company_id", "primary_domain", "legal_name", "country",
            "n_ips", "n_ports", "n_asns", "identity"]
    has_industry = "industry" in [
        r[1] for r in con.execute("PRAGMA table_info('companies')").fetchall()]
    if has_industry:
        cols.append("industry")

    rows = con.execute(f"SELECT {', '.join(cols)} FROM companies").fetchall()
    print(f"scoring {len(rows):,} companies "
          f"({'with' if has_industry else 'without'} industry labels)")

    out = []
    for r in rows:
        c = dict(zip(cols, r))
        fnd = by_co.get(c["company_id"], [])
        exp = exposure_score(fnd, prevalence)
        fit = fit_score(c)
        t, rationale = tier(fit["score"], exp["score"])
        out.append((
            c["company_id"], fit["score"], exp["score"], t, rationale,
            fit["size_band"], len(fnd),
            json.dumps({"fit": fit, "exposure": exp}),
        ))

    con.execute("DROP TABLE IF EXISTS scores")
    con.execute("""
        CREATE TABLE scores (
            company_id VARCHAR, fit_score DOUBLE, exposure_score DOUBLE,
            tier VARCHAR, rationale VARCHAR, size_band VARCHAR,
            n_findings INTEGER, breakdown JSON
        )
    """)
    con.executemany("INSERT INTO scores VALUES (?,?,?,?,?,?,?,?)", out)

    # --- the sanity check that matters -------------------------------------
    # If everything clusters at the top, the score is decorative and we have
    # built nothing. A real distribution is the pass condition.
    print("\nEXPOSURE DISTRIBUTION")
    for lo, cnt in con.sql("""
        SELECT CAST(exposure_score / 10 AS INTEGER) * 10 AS lo, count(*)
        FROM scores GROUP BY 1 ORDER BY 1
    """).fetchall():
        print(f"  {lo:>3}-{lo + 9:<3} {cnt:>7,}  "
              f"{'#' * min(60, cnt * 60 // max(1, len(out)))}")

    print("\nTIER SPLIT")
    for t, cnt, af, ae in con.sql("""
        SELECT tier, count(*), round(avg(fit_score), 1), round(avg(exposure_score), 1)
        FROM scores GROUP BY tier ORDER BY tier
    """).fetchall():
        print(f"  {t}  {cnt:>7,}   avg fit {af:>5}   avg exposure {ae:>5}")

    print("\nTOP 12 — what a rep would see on Monday")
    for d, ln, co, f, e, t, nf in con.sql("""
        SELECT c.primary_domain, c.legal_name, c.country,
               s.fit_score, s.exposure_score, s.tier, s.n_findings
        FROM scores s JOIN companies c USING (company_id)
        WHERE s.tier = 'A'
        ORDER BY s.exposure_score DESC, s.fit_score DESC,
                 c.company_id ASC   -- stable tiebreaker
        LIMIT 12
    """).fetchall():
        name = (ln or d or "")[:32]
        print(f"  {name:<32} {str(co):<3} fit={f:>3.0f} exp={e:>5.1f} "
              f"tier={t} findings={nf}")

    con.close()


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "data/out/perimeter.duckdb")
