#!/usr/bin/env python3
"""
Turn ~1M scan observations into a table of companies.

The hard part is telling a *tenant* (a real business we can sell to) from a
*landlord* (a hosting provider, ISP or registry whose name is on the record
only because they own the IP range).

Blocklists of provider names never finish -- "The Constant Company, LLC" is
Vultr, and nobody guesses that. So the primary test here is structural:

    A hosting provider's name appears across many networks and many IPs.
    A real business occupies a handful of addresses on one or two networks.

That is a property of the aggregate, which is why it cannot be decided during
the streaming ingest pass -- you need global counts first. Ingest is therefore
permissive and this stage is strict.

Usage:
    python3 pipeline/03_resolve.py data/out/scan.jsonl.gz data/out/perimeter.duckdb
"""
import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.domains import (clean_display_name, clean_title,  # noqa: E402
                          is_control_panel_cert, is_machine_hostname,
                          looks_like_provider_name, normalise_org, registrable)

# A single organisation legitimately spanning more than this many distinct
# autonomous systems is running infrastructure, not buying software.
MAX_ASNS = 3
MAX_IPS = 150
MAX_COUNTRIES = 3
# Fraction of an entity's hosts that must be machine-named to call it
# infrastructure. 0.5 keeps a company with one oddly-named box.
MACHINE_FRAC = 0.5


def build(src: str, db_path: str) -> None:
    con = duckdb.connect(db_path)
    con.execute("INSTALL json; LOAD json;")
    # null_handling='special': these UDFs legitimately return NULL for input
    # they cannot resolve, rather than being skipped.
    con.create_function("registrable", registrable, ["VARCHAR"], "VARCHAR",
                        null_handling="special")
    con.create_function("norm_org", normalise_org, ["VARCHAR"], "VARCHAR",
                        null_handling="special")
    # Certificate subjects carry the same placeholder junk as `org`
    # ("SomeOrganization", "Unknown"). Filter both paths, not just one.
    con.create_function("clean_name", clean_display_name,
                        ["VARCHAR"], "VARCHAR", null_handling="special")
    con.create_function("clean_title", clean_title,
                        ["VARCHAR"], "VARCHAR", null_handling="special")
    con.create_function("machine_host", is_machine_hostname,
                        ["VARCHAR", "VARCHAR"], "BOOLEAN",
                        null_handling="special")
    con.create_function("provider_name", looks_like_provider_name,
                        ["VARCHAR"], "BOOLEAN", null_handling="special")
    con.create_function("panel_cert", is_control_panel_cert,
                        ["VARCHAR"], "BOOLEAN", null_handling="special")

    print("reading observations ...")
    con.execute(f"""
        CREATE OR REPLACE TABLE observations AS
        SELECT * FROM read_json_auto('{src}', format='newline_delimited',
                                     ignore_errors=true, sample_size=-1)
    """)
    n = con.sql("SELECT count(*) FROM observations").fetchone()[0]
    print(f"  {n:,} observations")

    # --- which domain on a record actually names the tenant? ---------------
    # A record often carries several domains, e.g. ['cprapid.com',
    # 'bespokeit.com'] -- one is the hosting provider, one is the customer.
    # Picking arbitrarily merges unrelated businesses into their landlord: a
    # Tokyo hospital and an Armenian news site both became "ptrcloud.net".
    #
    # Measure instead of guessing. A hosting domain appears across a huge
    # number of unrelated IPs; a company domain appears on a handful. So rank
    # every domain by its footprint and let the RAREST one name the record.
    #
    # PERFORMANCE: the UDFs here are Python, so they are the slowest thing in
    # the pipeline by orders of magnitude. Call them once per DISTINCT string
    # (a few hundred thousand) rather than once per row (millions), and join
    # the results. An earlier version called registrable() three times per row
    # inside a correlated subquery and did not finish.
    print("mapping domains (UDF once per distinct value) ...")
    con.execute("""
        CREATE OR REPLACE TABLE dom_map AS
        SELECT raw, registrable(raw) AS dom
        FROM (SELECT DISTINCT unnest(domains_real) AS raw FROM observations)
        WHERE registrable(raw) IS NOT NULL
    """)
    con.execute("""
        CREATE OR REPLACE TABLE org_map AS
        SELECT raw, norm_org(raw) AS norm
        FROM (SELECT DISTINCT org AS raw FROM observations WHERE org IS NOT NULL)
        WHERE norm_org(raw) IS NOT NULL
    """)
    dm, om = con.sql("SELECT (SELECT count(*) FROM dom_map), "
                     "(SELECT count(*) FROM org_map)").fetchone()
    print(f"  {dm:,} distinct domains, {om:,} distinct orgs")

    print("ranking domains by footprint ...")
    con.execute("""
        CREATE OR REPLACE TABLE obs_dom AS
        SELECT o.rowid AS rid, m.dom, o.ip, o.asn
        FROM (SELECT rowid, unnest(domains_real) AS raw, ip, asn
              FROM observations) o
        JOIN dom_map m ON m.raw = o.raw
    """)
    con.execute("""
        CREATE OR REPLACE TABLE domain_shape AS
        SELECT dom, count(DISTINCT ip) AS n_ips, count(DISTINCT asn) AS n_asns
        FROM obs_dom GROUP BY dom
    """)
    shared = con.sql(f"""
        SELECT count(*) FROM domain_shape
        WHERE n_ips > {MAX_IPS} OR n_asns > {MAX_ASNS}
    """).fetchone()[0]
    print(f"  {shared:,} domains have a provider-sized footprint")

    # Materialise the winner per row -- a real table and a join, never a
    # correlated subquery against a CTE.
    print("assigning entity keys ...")
    con.execute("""
        CREATE OR REPLACE TABLE row_dom AS
        SELECT rid, dom FROM (
            SELECT d.rid, d.dom,
                   row_number() OVER (PARTITION BY d.rid
                                      ORDER BY s.n_ips ASC, s.n_asns ASC,
                                               length(d.dom) ASC) AS rk
            FROM (SELECT DISTINCT rid, dom FROM obs_dom) d
            JOIN domain_shape s ON s.dom = d.dom
        ) WHERE rk = 1
    """)
    con.execute("""
        CREATE OR REPLACE TABLE obs_keyed AS
        SELECT o.*,
               CASE WHEN o.identity = 'domain' THEN rd.dom ELSE om.norm END
                   AS entity_key,
               clean_title(o.http_title)   AS title_clean,
               clean_name(o.ssl_subject_o) AS legal_clean,
               coalesce(panel_cert(o.ssl_subject_o), false) AS panel_named,
               coalesce(machine_host(o.hostnames[1], o.ip), false)
                   AS machine_named
        FROM observations o
        LEFT JOIN row_dom rd ON rd.rid = o.rowid
        LEFT JOIN org_map om ON om.raw = o.org
    """)
    con.execute("DELETE FROM obs_keyed WHERE entity_key IS NULL")
    con.execute("DROP TABLE IF EXISTS obs_dom")

    # --- structural provider detection -------------------------------------
    # Three independent tests, because no single one catches everything:
    #
    #  1. Footprint AFTER keying -- the obvious case.
    #  2. Footprint BEFORE keying (domain_shape). The rarest-domain rule moves
    #     a provider's records onto its customers' domains, which shrinks the
    #     provider's own footprint and lets it escape test 1. Measured: 864
    #     known provider-sized domains became "companies" without this.
    #  3. Machine-generated hostnames. contabo.host has just 36 IPs and passes
    #     both footprint tests, but every hostname under it is auto-generated
    #     reverse DNS. This is what catches small hosts and regional ISPs.
    print("detecting providers by footprint and naming ...")
    con.execute(f"""
        CREATE OR REPLACE TABLE entity_shape AS
        SELECT o.entity_key,
               count(*)                       AS n_records,
               count(DISTINCT o.ip)           AS n_ips,
               count(DISTINCT o.asn)          AS n_asns,
               count(DISTINCT o.country)      AS n_countries,
               count(DISTINCT o.port)         AS n_ports,
               count(DISTINCT o.org)          AS n_orgs,
               avg(CASE WHEN o.machine_named THEN 1.0 ELSE 0.0 END)
                                              AS machine_frac,
               (
                    count(DISTINCT o.asn)       > {MAX_ASNS}
                 OR count(DISTINCT o.ip)        > {MAX_IPS}
                 OR count(DISTINCT o.country)   > {MAX_COUNTRIES}
                 OR coalesce(max(d.n_ips), 0)   > {MAX_IPS}
                 OR coalesce(max(d.n_asns), 0)  > {MAX_ASNS}
                 OR (avg(CASE WHEN o.machine_named THEN 1.0 ELSE 0.0 END)
                        >= {MACHINE_FRAC} AND count(DISTINCT o.ip) >= 2)
                 -- 4. The name itself reads as infrastructure. Only applied to
                 -- org-identified entities: a real company's DOMAIN may well
                 -- contain "host" or "cloud", but an org-only entity called
                 -- "crowncloud us" has no domain for a rep to contact anyway.
                 OR (any_value(o.identity) = 'org'
                     AND coalesce(provider_name(o.entity_key), false))
                 -- 5. A hosting control panel's certificate (Plesk, cPanel,
                 -- Hestia) is definitionally a shared-hosting box.
                 OR bool_or(o.panel_named)
               ) AS is_provider
        FROM obs_keyed o
        LEFT JOIN domain_shape d ON d.dom = o.entity_key
        GROUP BY o.entity_key
    """)

    tot, prov = con.sql("""
        SELECT count(*), count(*) FILTER (WHERE is_provider) FROM entity_shape
    """).fetchone()
    print(f"  {tot:,} entities -> {prov:,} look like providers "
          f"({prov / max(tot, 1) * 100:.1f}%), {tot - prov:,} look like companies")

    # --- companies ----------------------------------------------------------
    # The SSL certificate subject is the one place a legal name appears, so it
    # wins over the domain whenever present.
    print("building companies ...")
    con.execute("""
        CREATE OR REPLACE TABLE companies AS
        SELECT o.entity_key                                   AS company_id,
               any_value(o.entity_key)                        AS primary_domain,
               mode(o.legal_clean)                            AS legal_name,
               mode(o.country)                                AS country,
               mode(o.city)                                   AS city,
               s.n_ips, s.n_ports, s.n_asns, s.n_countries, s.n_records,
               list_distinct(flatten(list(o.domains_real)))   AS all_domains,
               list_distinct(list(o.product)
                   FILTER (WHERE o.product IS NOT NULL))      AS products,
               -- The page title is the single strongest industry signal in
               -- this dataset ("Patient Portal", "Online Banking"), so it must
               -- reach the classifier. Longest wins: the most descriptive one.
               max_by(o.title_clean, length(o.title_clean))
                   FILTER (WHERE o.title_clean IS NOT NULL)   AS page_title,
               list_distinct(list(o.port))                    AS open_ports,
               list_distinct(flatten(list(o.tags)))           AS tags,
               any_value(o.identity)                          AS identity,
               max(o.timestamp)                               AS last_seen
        FROM obs_keyed o
        JOIN entity_shape s USING (entity_key)
        WHERE NOT s.is_provider
        GROUP BY o.entity_key, s.n_ips, s.n_ports, s.n_asns,
                 s.n_countries, s.n_records
    """)

    # `industry` is filled by 05_enrich (optional, needs an API key). Create it
    # here so the schema is identical either way -- the app must not depend on
    # whether an optional stage ran.
    con.execute("ALTER TABLE companies ADD COLUMN IF NOT EXISTS industry VARCHAR")

    c = con.sql("SELECT count(*) FROM companies").fetchone()[0]
    print(f"  {c:,} companies")

    print("\ntop countries:")
    for row in con.sql("""
        SELECT country, count(*) c FROM companies
        WHERE country IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10
    """).fetchall():
        print(f"  {row[0]}  {row[1]:,}")

    print("\nsample companies:")
    for row in con.sql("""
        SELECT primary_domain, legal_name, country, n_ips, n_ports, identity
        FROM companies
        WHERE n_ips BETWEEN 2 AND 50
        ORDER BY n_records DESC LIMIT 12
    """).fetchall():
        print(f"  {str(row[0])[:34]:<34} {str(row[1])[:26]:<26} "
              f"{str(row[2]):<4} ips={row[3]:<4} ports={row[4]:<4} via={row[5]}")

    con.close()


if __name__ == "__main__":
    build(
        sys.argv[1] if len(sys.argv) > 1 else "data/out/scan.jsonl.gz",
        sys.argv[2] if len(sys.argv) > 2 else "data/out/perimeter.duckdb",
    )
