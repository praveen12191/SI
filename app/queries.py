"""
All SQL lives here.

Keeping it in one module rather than scattered through route handlers means
the data contract is readable in one sitting, and the routes stay about HTTP.
DuckDB is opened read-only so the app can never mutate the pipeline's output.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
# Deployment ships a slim DB (Tier D dropped, intermediates removed, host list
# pre-aggregated). PERIMETER_DB lets the container point at it without a code
# change; locally it defaults to the full working database.
DB = Path(os.environ.get("PERIMETER_DB")
          or ROOT / "data" / "out" / "perimeter.duckdb")
TRACES = ROOT / "data" / "out" / "traces.sqlite"

SEVERITY_RANK = """
    CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
"""


# Free-tier containers have 512 MB and shared CPU. Left unbounded, DuckDB
# sizes its buffer pool from the HOST's memory, not the container's cgroup
# limit, and gets OOM-killed mid-response -- the client sees a 502 even though
# the HTML was already correct.
MEM_LIMIT = os.environ.get("PERIMETER_DB_MEMORY", "192MB")
THREADS = int(os.environ.get("PERIMETER_DB_THREADS", "2"))


def connect() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(str(DB), read_only=True)
    con.execute(f"SET memory_limit='{MEM_LIMIT}'")
    con.execute(f"SET threads={THREADS}")
    return con


def _rows(con, sql: str, params: list | None = None) -> list[dict]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


# --- filters ---------------------------------------------------------------
def _where(f: dict) -> tuple[str, list]:
    clauses, params = [], []
    if f.get("country"):
        clauses.append("c.country = ?")
        params.append(f["country"])
    if f.get("industry"):
        clauses.append("c.industry = ?")
        params.append(f["industry"])
    if f.get("tier"):
        clauses.append("s.tier = ?")
        params.append(f["tier"])
    if f.get("product"):
        # `products` is a LIST column -- a company runs several -- so this is
        # membership, not equality. It answers the question a rep has the
        # morning a CVE drops: "who do we know runs this?"
        clauses.append("list_contains(c.products, ?)")
        params.append(f["product"])
    if f.get("min_exposure"):
        clauses.append("s.exposure_score >= ?")
        params.append(float(f["min_exposure"]))
    if f.get("finding_type"):
        clauses.append("""EXISTS (SELECT 1 FROM findings ff
                          WHERE ff.company_id = c.company_id AND ff.type = ?)""")
        params.append(f["finding_type"])
    if f.get("q"):
        clauses.append("(c.primary_domain ILIKE ? OR c.legal_name ILIKE ?)")
        params += [f"%{f['q']}%"] * 2
    return (" AND ".join(clauses) or "TRUE"), params


def queue(con, f: dict, limit: int = 60) -> list[dict]:
    """The Monday-morning list: highest exposure inside the ICP, ranked."""
    where, params = _where(f)
    return _rows(con, f"""
        SELECT c.company_id, c.primary_domain, c.legal_name, c.country, c.city,
               c.industry, c.n_ips, c.n_ports, c.identity, c.page_title,
               s.fit_score, s.exposure_score, s.tier, s.rationale,
               s.size_band, s.n_findings,
               -- Precomputed by 07_prepare_deploy. These were two correlated
               -- subqueries over ~1M findings per row, which cost 8-14s and an
               -- OOM kill on a 512 MB instance. Now a join.
               qc.top_findings,
               qc.has_critical
        FROM scores s JOIN companies c USING (company_id)
        LEFT JOIN queue_cache qc ON qc.company_id = c.company_id
        WHERE {where}
        ORDER BY CASE s.tier WHEN 'A' THEN 0 WHEN 'C' THEN 1
                             WHEN 'B' THEN 2 ELSE 3 END,
                 s.exposure_score DESC, s.fit_score DESC,
                 c.company_id ASC   -- total order: ties must not reshuffle
        LIMIT {int(limit)}
    """, params)


def company(con, cid: str) -> dict | None:
    r = _rows(con, """
        SELECT c.*, s.fit_score, s.exposure_score, s.tier, s.rationale,
               s.size_band, s.n_findings, s.breakdown
        FROM companies c LEFT JOIN scores s USING (company_id)
        WHERE c.company_id = ?
    """, [cid])
    if not r:
        return None
    c = r[0]
    if isinstance(c.get("breakdown"), str):
        try:
            c["breakdown"] = json.loads(c["breakdown"])
        except json.JSONDecodeError:
            c["breakdown"] = {}
    return c


def findings(con, cid: str) -> list[dict]:
    return _rows(con, f"""
        SELECT rowid AS id, ip, port, type, severity, points, title,
               evidence, cve, cvss, scope
        FROM findings f
        WHERE company_id = ?
        ORDER BY {SEVERITY_RANK}, points DESC
    """, [cid])


def hosts(con, cid: str) -> list[dict]:
    """
    Host rollup for the account page.

    The deploy DB ships `company_hosts` pre-aggregated, because the source
    (`obs_keyed`, 2.8M rows of array columns) is most of the 1 GB working file
    and this is the only thing the app used it for. Falls back to computing it
    live when running against the full database.
    """
    try:
        return _rows(con, """
            SELECT ip, n_ports, ports, org, asn, products
            FROM company_hosts WHERE company_id = ?
            ORDER BY n_ports DESC LIMIT 40
        """, [cid])
    except duckdb.CatalogException:
        return _rows(con, """
            SELECT ip, count(DISTINCT port) AS n_ports,
                   string_agg(DISTINCT CAST(port AS VARCHAR), ', ') AS ports,
                   any_value(org) AS org, any_value(asn) AS asn,
                   string_agg(DISTINCT product, ', ') AS products
            FROM obs_keyed WHERE entity_key = ?
            GROUP BY ip ORDER BY n_ports DESC LIMIT 40
        """, [cid])


# --- aggregates ------------------------------------------------------------
def facets(con) -> dict:
    return {
        "countries": _rows(con, """
            SELECT c.country AS v, count(*) AS n
            FROM scores s JOIN companies c USING (company_id)
            WHERE c.country IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 30
        """),
        "industries": _rows(con, """
            SELECT coalesce(c.industry, 'unclassified') AS v, count(*) AS n
            FROM scores s JOIN companies c USING (company_id)
            GROUP BY 1 ORDER BY n DESC LIMIT 25
        """),
        # unnest because products is a LIST. HAVING drops one-off junk from
        # ~1,500 distinct banner strings; LIMIT keeps the dropdown usable.
        "products": _rows(con, """
            SELECT p AS v, count(*) AS n FROM (
                SELECT unnest(c.products) AS p
                FROM scores s JOIN companies c USING (company_id)
            ) GROUP BY 1 HAVING count(*) >= 5 ORDER BY n DESC LIMIT 120
        """),
        "finding_types": _rows(con, """
            SELECT type AS v, n_companies AS n, prevalence
            FROM finding_rarity ORDER BY prevalence ASC
        """),
    }


def segment_stats(con, f: dict) -> dict:
    where, params = _where(f)
    total = con.execute(f"""
        SELECT count(*) FROM scores s JOIN companies c USING (company_id)
        WHERE {where}
    """, params).fetchone()[0]
    tiers = _rows(con, f"""
        SELECT s.tier AS v, count(*) AS n
        FROM scores s JOIN companies c USING (company_id)
        LEFT JOIN queue_cache qc ON qc.company_id = c.company_id
        WHERE {where} GROUP BY 1 ORDER BY 1
    """, params)
    top = _rows(con, f"""
        SELECT ff.type AS v, count(DISTINCT ff.company_id) AS n
        FROM findings ff
        JOIN scores s ON s.company_id = ff.company_id
        JOIN companies c ON c.company_id = ff.company_id
        WHERE {where} GROUP BY 1 ORDER BY n DESC LIMIT 10
    """, params)
    return {"total": total, "tiers": tiers, "top_findings": top}


def corpus_stats(con) -> dict:
    g = lambda q: con.execute(q).fetchone()[0]  # noqa: E731
    return {
        "observations": g("""SELECT coalesce(sum(n_records), 0)
                             FROM companies"""),
        "companies": g("SELECT count(*) FROM companies"),
        "findings": g("SELECT count(*) FROM findings"),
        "tier_a": g("SELECT count(*) FROM scores WHERE tier='A'"),
        "scan_date": g("SELECT max(last_seen) FROM companies"),
        "classified": g("""SELECT count(*) FROM companies
                           WHERE industry IS NOT NULL AND industry <> 'unknown'"""),
    }


# --- traces (separate store, so app reads never block pipeline writes) ------
def llm_stats() -> dict:
    if not TRACES.exists():
        return {"rows": [], "total_cost": 0.0, "total_calls": 0}
    con = sqlite3.connect(TRACES)
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("""
        SELECT feature, prompt_version, model, count(*) AS calls,
               round(sum(cost_usd), 5) AS cost,
               round(avg(latency_ms))  AS p50_ms,
               sum(ok) AS ok, sum(1 - ok) AS failed,
               sum(cache_read_tokens) AS cached_tokens
        FROM llm_calls GROUP BY feature, prompt_version, model
        ORDER BY calls DESC
    """)]
    tot = con.execute(
        "SELECT count(*), round(coalesce(sum(cost_usd),0), 5) FROM llm_calls"
    ).fetchone()
    con.close()
    return {"rows": rows, "total_calls": tot[0], "total_cost": tot[1]}
