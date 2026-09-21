#!/usr/bin/env python3
"""
Stream-filter the Shodan-style scan dump.

Reads NDJSON on stdin (already decompressed by `zstd -dc`), keeps only records
that could identify a real company, projects ~15 fields out of ~40, and writes
gzipped NDJSON.

Constant memory. Constant disk. Never materialises the 74 GB.

Usage:
    curl -sL "$DATASET_URL" | zstd -dc | python3 pipeline/02_ingest.py data/out/companies_raw.jsonl.gz

Every input record is either kept or counted in a named reject bucket, so the
numbers always reconcile to the input total.
"""
import gzip
import json
import re
import sys
import time
from collections import Counter

# --- Landlords, not tenants -------------------------------------------------
# Cloud, CDN, hosting and telco domains identify the *provider*, not the
# customer. ~66% of this dataset is infrastructure. Dropping it is the single
# biggest filter in the pipeline.
INFRA_DOMAIN = re.compile(
    r"(?:^|\.)(?:"
    r"amazonaws|awsglobalaccelerator|cloudfront|ec2|elb|"
    r"googleusercontent|1e100|googlehosted|gvt\d|"
    r"azure|azurewebsites|cloudapp|windowsazure|"
    r"cloudflare|incapdns|imperva|akamai|akamaitechnologies|akamaiedge|fastly|"
    r"digitalocean|linodeusercontent|vultrusercontent|contaboserver|colocrossing|"
    r"ovh|your-server|hetzner|scw\.cloud|upcloud|flyio|herokuapp|render|"
    r"hwclouds-dns|aliyun|alicloud|myqcloud|"
    r"secureserver|cprapid|plesk|hostgator|bluehost|namecheap|"
    r"comcast|verizon|myvzw|charter|spectrum|qwest|megapath|btcentralplus|"
    r"t-ipconnect|telefonica|hinet|sakura|kpn|rr\.com|sl-reverse|bc\.googleusercontent|"
    r"datapacket|da\.direct|cable\.net"
    r")\.",
    re.IGNORECASE,
)

# Same idea, applied to the `org` field. A record with no usable domain can
# still name its owner here -- "Bitly Inc" is a prospect, "Korea Telecom" is a
# landlord. This is the fallback identity path.
INFRA_ORG = re.compile(
    r"(amazon|aws|google|microsoft|azure|oracle public cloud|ibm cloud|"
    r"cloudflare|akamai|fastly|imperva|incapsula|"
    r"digitalocean|linode|vultr|ovh|hetzner|contabo|scaleway|upcloud|leaseweb|"
    r"colocrossing|equinix|rackspace|godaddy|namecheap|hostinger|bluehost|"
    r"alibaba|aliyun|tencent|huawei cloud|fly\.io|heroku|netlify|vercel|"
    r"telecom|telecommunication|telekom|telefonica|vodafone|orange|"
    r"comcast|verizon|at&t|charter|spectrum|cox communications|centurylink|"
    r"\bbt\b|sky broadband|telstra|optus|ntt|kddi|softbank|"
    r"broadband|datacenter|data center|hosting|web services|"
    r"internet services|isp\b|cable|wireless|mobile)",
    re.IGNORECASE,
)


def _vulns(v) -> list:
    """[{cve, cvss}] -- keep the identifier and the score, drop the prose."""
    if isinstance(v, dict):
        return [
            {"cve": k, "cvss": (d or {}).get("cvss")}
            for k, d in sorted(v.items())
        ]
    return [{"cve": c, "cvss": None} for c in (v or [])]


# Fields worth keeping. Everything else (raw HTML, favicons, hashes, opts, …)
# is what makes the file 89 GB.
def project(r: dict) -> dict:
    loc = r.get("location") or {}
    ssl = r.get("ssl") or {}
    cert = ssl.get("cert") or {}
    subject = cert.get("subject") or {}
    http = r.get("http") or {}

    return {
        "ip": r.get("ip_str"),
        "port": r.get("port"),
        "transport": r.get("transport"),
        "domains": r.get("domains") or [],
        "hostnames": r.get("hostnames") or [],
        "org": r.get("org"),
        "isp": r.get("isp"),
        "asn": r.get("asn"),
        "country": loc.get("country_code"),
        "city": loc.get("city"),
        "product": r.get("product"),
        "version": r.get("version"),
        "cpe23": r.get("cpe23") or [],
        "tags": r.get("tags") or [],
        # `vulns` is 30% of the file's bytes, but almost all of that is prose
        # (summary + references). Keep the CVE id and its CVSS score and drop
        # the rest -- that's 99% of the bytes for 100% of the signal, and it
        # means we need no external CVE database.
        "vulns": _vulns(r.get("vulns")),
        "ssl_subject_o": subject.get("O"),
        "ssl_subject_cn": subject.get("CN"),
        "ssl_expires": cert.get("expires"),
        "ssl_issuer_o": ((cert.get("issuer") or {}).get("O")),
        "http_title": http.get("title"),
        "http_components": sorted((http.get("components") or {}).keys()),
        "timestamp": r.get("timestamp"),
    }


def main(out_path: str) -> None:
    n = Counter()
    t0 = time.time()

    with gzip.open(out_path, "wt", encoding="utf-8", compresslevel=6) as out:
        for line in sys.stdin:
            if not line.strip():
                continue
            n["total"] += 1

            try:
                r = json.loads(line)
            except Exception:
                n["reject_badjson"] += 1
                continue

            tags = set(r.get("tags") or [])

            # Decoy systems deliberately planted to attract attackers.
            # Would poison the prospect list.
            if "honeypot" in tags:
                n["reject_honeypot"] += 1
                continue

            domains = r.get("domains") or []
            real = [d for d in domains if not INFRA_DOMAIN.search("." + d + ".")]

            if real:
                identity = "domain"
            else:
                # No usable domain -- can `org` name the owner instead?
                # Recovers real businesses ("Bitly Inc") that would otherwise
                # be lost with the Chromecasts and rented cloud boxes.
                org = (r.get("org") or "").strip()
                if org and not INFRA_ORG.search(org):
                    identity = "org"
                    n["kept_via_org"] += 1
                elif not domains:
                    n["reject_no_domain"] += 1
                    continue
                else:
                    n["reject_infra_domain"] += 1
                    continue

            rec = project(r)
            rec["domains_real"] = real
            rec["identity"] = identity
            out.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False))
            out.write("\n")
            n["kept"] += 1

            if n["total"] % 250_000 == 0:
                el = time.time() - t0
                print(
                    f"  {n['total']:>10,} read  {n['kept']:>9,} kept  "
                    f"{n['total']/el:>8,.0f} rec/s  {el/60:5.1f} min",
                    file=sys.stderr,
                    flush=True,
                )

    el = time.time() - t0
    print("\n" + "=" * 58, file=sys.stderr)
    print(f"  {'read':<22} {n['total']:>12,}", file=sys.stderr)
    print(f"  {'kept':<22} {n['kept']:>12,}  "
          f"({n['kept']/max(n['total'],1)*100:.1f}%)", file=sys.stderr)
    print(f"  {'  via domain':<22} {n['kept']-n['kept_via_org']:>12,}", file=sys.stderr)
    print(f"  {'  via org name':<22} {n['kept_via_org']:>12,}", file=sys.stderr)
    for k in ("reject_no_domain", "reject_infra_domain",
              "reject_honeypot", "reject_badjson"):
        print(f"  {k:<22} {n[k]:>12,}", file=sys.stderr)

    # Nothing may vanish silently -- and an empty run is a failure, not a pass.
    # `0 == 0` reconciles trivially, which is exactly how a silently truncated
    # or empty stream sails through looking healthy. Ask for records first.
    checked = n["kept"] + sum(n[k] for k in n if k.startswith("reject_"))
    if n["total"] == 0:
        status = "NO INPUT"
    elif checked != n["total"]:
        status = f"MISMATCH ({checked})"
    else:
        status = "OK"
    print(f"  {'reconciles':<22} {status:>12}", file=sys.stderr)
    if status != "OK":
        sys.exit(2)
    print(f"  {'elapsed':<22} {el/60:>11.1f}m", file=sys.stderr)
    print("=" * 58, file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/out/companies_raw.jsonl.gz")
