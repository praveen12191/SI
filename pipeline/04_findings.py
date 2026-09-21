#!/usr/bin/env python3
"""
Apply the rules in core/rules.py to every observation, and write the findings
table that every score and every outreach line is traceable back to.

Two passes, because they see different things:

  observation-level  what one (ip, port) reveals on its own
  company-level      what only appears once a company's hosts are grouped
                     (CDN bypass, sprawl, absence of a patching process)

WRITE STRATEGY -- two measured constraints shaped this:

  1. `executemany` costs ~22s per 100k rows. At ~8M findings that is half an
     hour of pure insert overhead.
  2. Writing on a connection while a read cursor is open on it SILENTLY
     invalidates the cursor. A probe that asked for 100,000 rows after an
     interleaved write got back 1. Not an error -- just missing data.

So: stream the read, append findings to a CSV on disk, and bulk-load once at
the end. No interleaving, and DuckDB's CSV reader does the insert in one shot.

Usage:
    python3 pipeline/04_findings.py data/out/perimeter.duckdb
"""
import csv
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.rules import company_findings, observation_findings  # noqa: E402

COLS = ["company_id", "ip", "port", "type", "severity", "points",
        "title", "evidence", "cve", "cvss", "scope"]
BATCH = 100_000


def build(db_path: str) -> None:
    con = duckdb.connect(db_path)
    tmp = Path(tempfile.gettempdir()) / "perimeter_findings.csv"
    t0 = time.time()

    cur = con.execute("""
        SELECT o.entity_key, o.ip, o.port, o.transport, o.product, o.version,
               o.tags, o.vulns, o.ssl_expires
        FROM obs_keyed o
        JOIN companies c ON c.company_id = o.entity_key
    """)
    cols = ["entity_key", "ip", "port", "transport", "product", "version",
            "tags", "vulns", "ssl_expires"]

    # Company-level facts, accumulated during the single walk.
    ports_by_co = defaultdict(set)
    tags_by_co = defaultdict(set)
    oldest_cve: dict[str, int] = {}
    cdn_hosts = defaultdict(set)
    direct_hosts = defaultdict(set)

    seen = n_found = 0
    print("applying observation rules (streaming to CSV) ...", flush=True)

    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLS)

        while True:
            rows = cur.fetchmany(BATCH)   # no writes in this loop -- see above
            if not rows:
                break
            for r in rows:
                o = dict(zip(cols, r))
                o["vulns"] = [dict(v) if not isinstance(v, dict) else v
                              for v in (o.get("vulns") or [])]
                key = o["entity_key"]

                ports_by_co[key].add(o["port"])
                tags = set(o.get("tags") or [])
                tags_by_co[key] |= tags

                if o["port"] in (80, 443):
                    (cdn_hosts if "cdn" in tags else direct_hosts)[key].add(o["ip"])

                for v in o["vulns"]:
                    cve = (v or {}).get("cve") or ""
                    if cve.startswith("CVE-"):
                        try:
                            yr = int(cve.split("-")[1])
                            if key not in oldest_cve or yr < oldest_cve[key]:
                                oldest_cve[key] = yr
                        except (IndexError, ValueError):
                            pass

                for f in observation_findings(o):
                    w.writerow([key, o["ip"], f["port"], f["type"],
                                f["severity"], f["points"], f["title"],
                                f["evidence"], f["cve"], f["cvss"],
                                "observation"])
                    n_found += 1

            seen += len(rows)
            print(f"  {seen:>9,} observations -> {n_found:>10,} findings"
                  f"   {seen / (time.time() - t0):>7,.0f} obs/s", flush=True)

        # Company-level pass reuses the facts gathered above.
        print("applying company rules ...", flush=True)
        companies = con.execute(
            "SELECT company_id, n_ips, n_asns FROM companies").fetchall()
        for cid, n_ips, n_asns in companies:
            for f in company_findings({
                "tags": tags_by_co.get(cid, set()),
                "n_asns": n_asns, "n_ips": n_ips,
                "open_ports": ports_by_co.get(cid, set()),
                "has_direct_origin": bool(cdn_hosts.get(cid)
                                          and direct_hosts.get(cid)),
                "oldest_cve_year": oldest_cve.get(cid),
            }):
                w.writerow([cid, None, None, f["type"], f["severity"],
                            f["points"], f["title"], f["evidence"],
                            None, None, "company"])
                n_found += 1

    print(f"  {n_found:,} findings written to CSV "
          f"({tmp.stat().st_size / 1e6:.0f} MB) in {time.time() - t0:.0f}s",
          flush=True)

    print("bulk-loading into DuckDB ...", flush=True)
    con.execute("DROP TABLE IF EXISTS findings")
    con.execute(f"""
        CREATE TABLE findings AS
        SELECT * FROM read_csv('{tmp}', header=true, AUTO_DETECT=false,
            columns={{
                'company_id':'VARCHAR','ip':'VARCHAR','port':'INTEGER',
                'type':'VARCHAR','severity':'VARCHAR','points':'INTEGER',
                'title':'VARCHAR','evidence':'VARCHAR','cve':'VARCHAR',
                'cvss':'DOUBLE','scope':'VARCHAR'
            }})
    """)
    loaded = con.sql("SELECT count(*) FROM findings").fetchone()[0]
    if loaded != n_found:
        print(f"  MISMATCH: wrote {n_found:,} but loaded {loaded:,}",
              file=sys.stderr)
        sys.exit(2)
    print(f"  loaded {loaded:,} findings  (matches CSV)", flush=True)
    tmp.unlink(missing_ok=True)

    # --- rarity: the number that stops CVEs drowning everything -------------
    # A finding present on 40% of companies is not a differentiator. One on
    # 0.4% is the whole reason to make the call.
    print("computing finding rarity ...", flush=True)
    con.execute("DROP TABLE IF EXISTS finding_rarity")
    con.execute("""
        CREATE TABLE finding_rarity AS
        WITH total AS (SELECT count(*) n FROM companies)
        SELECT f.type,
               count(DISTINCT f.company_id)                        AS n_companies,
               count(DISTINCT f.company_id) / (SELECT n FROM total) AS prevalence
        FROM findings f GROUP BY f.type
    """)

    print("\nfinding prevalence (rarer == more valuable to a rep):")
    for t, nc, p in con.sql("""
        SELECT type, n_companies, prevalence FROM finding_rarity
        ORDER BY prevalence ASC
    """).fetchall():
        print(f"  {t:<26} {nc:>8,}  {p * 100:6.2f}%  "
              f"{'#' * max(1, int(p * 60))}")

    print(f"\ntotal {time.time() - t0:.0f}s")
    con.close()


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "data/out/perimeter.duckdb")
