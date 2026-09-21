#!/usr/bin/env python3
"""
Build a slim database for deployment.

The working database is ~1 GB, most of it intermediate tables the app never
reads (`observations`, `dom_map`, `domain_shape`, `row_dom`, `entity_shape`)
plus `obs_keyed`, which is 2.8M rows of arrays used for exactly one thing:
the host list on an account page.

Those tables exist to make entity resolution debuggable. They have no business
in a container. This script keeps what the app queries, pre-aggregates the
host list, and leaves the working DB untouched.

    python3 pipeline/07_prepare_deploy.py
    -> data/out/perimeter-deploy.duckdb
"""
import sys
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]


# Tier B exists to demonstrate restraint -- "right profile, nothing wrong, do
# not call". 27,797 rows prove that no better than 3,000 do, and the deploy
# artifact has to stay well under GitHub's 100 MiB hard limit (a push over it
# is rejected outright, not warned about).
TIER_B_SAMPLE = 3_000


def build(src: str, dst: str) -> None:
    out = Path(dst)
    out.unlink(missing_ok=True)

    con = duckdb.connect(dst)
    con.execute(f"ATTACH '{src}' AS s (READ_ONLY)")

    # Tier D is suppressed by the product -- the queue sorts A,C,B,D and the
    # UI calls it "never surface". Shipping 256k companies nobody can see is
    # paying to host invisible data.
    print("copying tables the app reads (Tier D dropped) ...")
    con.execute(f"""
        CREATE TABLE scores AS
        SELECT * FROM s.scores WHERE tier IN ('A', 'C')
        UNION ALL
        SELECT * FROM (
            SELECT * FROM s.scores WHERE tier = 'B'
            ORDER BY exposure_score DESC, company_id
            LIMIT {TIER_B_SAMPLE}
        )
    """)
    con.execute("""
        CREATE TABLE companies AS
        SELECT c.* FROM s.companies c
        JOIN scores sc ON sc.company_id = c.company_id
    """)
    con.execute("CREATE TABLE finding_rarity AS SELECT * FROM s.finding_rarity")
    for t in ("companies", "scores", "finding_rarity"):
        n = con.sql(f"SELECT count(*) FROM {t}").fetchone()[0]
        print(f"  {t:<16} {n:>10,}")

    # Findings drive every score and every outreach line, so they must ship in
    # full -- but only for companies that can actually surface. Tier D is
    # suppressed and never rendered, and it is 89% of the corpus.
    con.execute("""
        CREATE TABLE findings AS
        SELECT f.* FROM s.findings f
        JOIN scores sc ON sc.company_id = f.company_id
    """)
    kept, total = con.sql(
        "SELECT (SELECT count(*) FROM findings), (SELECT count(*) FROM s.findings)"
    ).fetchone()
    print(f"  {'findings':<16} {kept:>10,}  (of {total:,})")

    # Replace obs_keyed with just the host rollup the account page renders.
    print("pre-aggregating host list (replaces obs_keyed) ...")
    con.execute("""
        CREATE TABLE company_hosts AS
        SELECT o.entity_key AS company_id, o.ip,
               count(DISTINCT o.port)                          AS n_ports,
               string_agg(DISTINCT CAST(o.port AS VARCHAR), ', ') AS ports,
               any_value(o.org)     AS org,
               any_value(o.asn)     AS asn,
               string_agg(DISTINCT o.product, ', ')            AS products
        FROM s.obs_keyed o
        JOIN scores sc ON sc.company_id = o.entity_key
        GROUP BY o.entity_key, o.ip
    """)
    n = con.sql("SELECT count(*) FROM company_hosts").fetchone()[0]
    print(f"  {'company_hosts':<16} {n:>10,}")

    # Precompute what the queue page recomputed per row.
    #
    # The queue ran two correlated subqueries against `findings` for every row
    # returned. On a laptop that is a few hundred ms; on a 512 MB shared-CPU
    # instance it took 8-14s and got the worker OOM-killed mid-response --
    # Render returned 502 while the HTML was already correct.
    print("precomputing queue columns ...")
    con.execute("""
        CREATE TABLE queue_cache AS
        SELECT company_id,
               string_agg(t, '|' ORDER BY sv, pv) AS top_findings,
               bool_or(sev = 'critical')          AS has_critical
        FROM (
            SELECT f.company_id, f.title AS t,
                   min(CASE f.severity WHEN 'critical' THEN 0
                                       WHEN 'high' THEN 1
                                       WHEN 'medium' THEN 2 ELSE 3 END) AS sv,
                   min(coalesce(r.prevalence, 1)) AS pv,
                   min(f.severity)                AS sev,
                   row_number() OVER (
                       PARTITION BY f.company_id
                       ORDER BY min(CASE f.severity WHEN 'critical' THEN 0
                                                    WHEN 'high' THEN 1
                                                    WHEN 'medium' THEN 2 ELSE 3 END),
                                min(coalesce(r.prevalence, 1))) AS rk
            FROM findings f
            LEFT JOIN finding_rarity r ON r.type = f.type
            GROUP BY f.company_id, f.title
        ) WHERE rk <= 3
        GROUP BY company_id
    """)
    con.execute("""
        CREATE OR REPLACE TABLE queue_cache AS
        SELECT q.company_id, q.top_findings,
               EXISTS (SELECT 1 FROM findings f
                       WHERE f.company_id = q.company_id
                         AND f.severity = 'critical') AS has_critical
        FROM queue_cache q
    """)
    n = con.sql("SELECT count(*) FROM queue_cache").fetchone()[0]
    print(f"  {'queue_cache':<16} {n:>10,}")

    con.execute("DETACH s")
    con.close()

    # DuckDB does not shrink in place, so copy into a fresh file.
    print("compacting + indexing ...")
    tmp = out.with_suffix(".compact")
    tmp.unlink(missing_ok=True)
    c2 = duckdb.connect(str(tmp))
    c2.execute(f"ATTACH '{dst}' AS old (READ_ONLY)")
    for t in ("companies", "scores", "finding_rarity", "findings",
              "company_hosts", "queue_cache"):
        c2.execute(f"CREATE TABLE {t} AS SELECT * FROM old.{t}")
    for tbl in ("findings", "scores", "companies", "company_hosts", "queue_cache"):
        c2.execute(f"CREATE INDEX idx_{tbl}_cid ON {tbl}(company_id)")
    c2.execute("DETACH old")
    c2.close()
    tmp.replace(out)

    src_mb = Path(src).stat().st_size / 1e6
    dst_mb = out.stat().st_size / 1e6
    print(f"\n  {src:<38} {src_mb:>8.0f} MB")
    print(f"  {dst:<38} {dst_mb:>8.0f} MB   ({src_mb / dst_mb:.1f}x smaller)")


if __name__ == "__main__":
    build(
        sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "data/out/perimeter.duckdb"),
        sys.argv[2] if len(sys.argv) > 2 else str(ROOT / "data/out/perimeter-deploy.duckdb"),
    )
