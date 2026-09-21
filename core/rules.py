"""
Security findings: the rules that turn a scan record into a sales signal.

Deliberately 100% deterministic -- no LLM anywhere in this file. A rep may read
these findings aloud to a prospect's IT director, so every one must trace back
to an exact field in an exact record. A model that is right 95% of the time
would be wrong on one call in twenty, and that is the one failure this product
cannot survive.

Each rule returns findings shaped:
    {type, severity, points, title, evidence, port, cve, cvss}
"""
from __future__ import annotations

from datetime import datetime, timezone

CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

# --- Port intelligence ------------------------------------------------------
# A database answering the public internet is the single most alarming thing
# you can show a prospect, and needs no technical translation for a CFO.
DATASTORE_PORTS = {
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
    9200: "Elasticsearch", 1433: "Microsoft SQL Server", 5984: "CouchDB",
    11211: "Memcached", 9042: "Cassandra", 7000: "Cassandra",
    8086: "InfluxDB", 5433: "PostgreSQL", 3050: "Firebird", 50000: "DB2",
}

# The documented entry vector for most ransomware.
REMOTE_ACCESS_PORTS = {
    3389: "Remote Desktop (RDP)", 23: "Telnet", 5900: "VNC", 5901: "VNC",
    512: "rexec", 513: "rlogin", 514: "rsh",
}

FILE_SHARING_PORTS = {
    21: "FTP", 445: "SMB", 139: "NetBIOS", 2049: "NFS", 69: "TFTP",
}

# Operational technology. Exposed factory/building control is a different
# conversation entirely -- safety, not just data.
OT_PORTS = {
    502: "Modbus", 44818: "EtherNet/IP", 47808: "BACnet", 20000: "DNP3",
    102: "Siemens S7", 1911: "Niagara Fox", 4840: "OPC UA",
}

# --- Tag intelligence -------------------------------------------------------
TAG_FINDINGS = {
    "c2":           (CRITICAL, 30, "Command-and-control infrastructure detected",
                     "Host matches known C2 behaviour -- may already be compromised"),
    "eol-os":       (HIGH, 18, "End-of-life operating system",
                     "OS no longer receives security updates from its vendor"),
    "eol-product":  (HIGH, 15, "End-of-life software",
                     "Software no longer receives security patches -- cannot be fixed, only replaced"),
    "open-dir":     (HIGH, 14, "Open directory listing",
                     "Server exposes a browsable file listing to anonymous visitors"),
    "self-signed":  (MEDIUM, 6, "Self-signed TLS certificate",
                     "Certificate is not issued by a trusted authority -- breaks trust and warns users"),
    "database":     (HIGH, 16, "Database service exposed",
                     "A database service is reachable from the public internet"),
    "iot":          (MEDIUM, 8, "Internet-of-things device exposed",
                     "Consumer-grade device on the corporate perimeter"),
    "vpn":          (INFO, 0, "VPN endpoint",
                     "Remote-access endpoint present -- relevant to access-control conversations"),
}

# --- CVSS bands -------------------------------------------------------------
def cvss_band(score: float | None) -> tuple[str, int]:
    """CVSS v3 bands, per FIRST.org."""
    if score is None:
        return MEDIUM, 3
    if score >= 9.0:
        return CRITICAL, 12
    if score >= 7.0:
        return HIGH, 8
    if score >= 4.0:
        return MEDIUM, 3
    return LOW, 1


def _f(type_, severity, points, title, evidence, port=None, cve=None, cvss=None):
    return {
        "type": type_, "severity": severity, "points": points, "title": title,
        "evidence": evidence, "port": port, "cve": cve, "cvss": cvss,
    }


def observation_findings(obs: dict) -> list[dict]:
    """Findings visible in a single (ip, port) observation."""
    out: list[dict] = []
    port = obs.get("port")
    product = obs.get("product") or "unknown service"
    version = obs.get("version")
    banner = f"{product}{' ' + version if version else ''}"
    tags = set(obs.get("tags") or [])

    if port in DATASTORE_PORTS:
        name = DATASTORE_PORTS[port]
        out.append(_f("exposed_datastore", CRITICAL, 25,
                      f"{name} database reachable from the internet",
                      f"port {port}/{obs.get('transport', 'tcp')} answering as {name}"
                      f" ({banner})", port=port))

    if port in REMOTE_ACCESS_PORTS:
        name = REMOTE_ACCESS_PORTS[port]
        out.append(_f("exposed_remote_access", CRITICAL, 22,
                      f"{name} open to the internet",
                      f"port {port} answering as {name} ({banner}) -- the most"
                      f" common ransomware entry point", port=port))

    if port in OT_PORTS:
        out.append(_f("exposed_ot", CRITICAL, 24,
                      f"{OT_PORTS[port]} industrial control protocol exposed",
                      f"port {port} answering as {OT_PORTS[port]} -- operational"
                      f" technology reachable from the public internet", port=port))

    if port in FILE_SHARING_PORTS:
        name = FILE_SHARING_PORTS[port]
        sev, pts = (HIGH, 12) if port in (445, 139, 2049) else (MEDIUM, 6)
        out.append(_f("exposed_file_sharing", sev, pts,
                      f"{name} exposed",
                      f"port {port} answering as {name} ({banner})", port=port))

    for tag, (sev, pts, title, why) in TAG_FINDINGS.items():
        if tag in tags:
            out.append(_f(f"tag_{tag.replace('-', '_')}", sev, pts, title,
                          f"{why} -- observed on port {port} ({banner})", port=port))

    for v in obs.get("vulns") or []:
        cve, score = v.get("cve"), v.get("cvss")
        sev, pts = cvss_band(score)
        out.append(_f("cve", sev, pts, f"{cve} in {product}",
                      f"{banner} on port {port} matches {cve}"
                      f"{f' (CVSS {score})' if score else ''}",
                      port=port, cve=cve, cvss=score))

    expires = obs.get("ssl_expires")
    if expires:
        days = _days_until(expires)
        if days is not None:
            if days < 0:
                out.append(_f("cert_expired", HIGH, 10,
                              "TLS certificate has expired",
                              f"certificate on port {port} expired"
                              f" {abs(days)} days ago ({expires})", port=port))
            elif days <= 30:
                out.append(_f("cert_expiring", MEDIUM, 5,
                              f"TLS certificate expires in {days} days",
                              f"certificate on port {port} expires {expires}",
                              port=port))
    return out


def company_findings(company: dict) -> list[dict]:
    """
    Findings only visible once every observation for a company is grouped.

    These are the interesting ones -- nobody selling from a port list alone
    can see them.
    """
    out: list[dict] = []
    tags = set(company.get("tags") or [])
    n_asns = company.get("n_asns") or 0
    n_ips = company.get("n_ips") or 0
    ports = set(company.get("open_ports") or [])

    # CDN bypass: paying for edge protection while the origin answers directly.
    # The protection can simply be walked around.
    if ("cdn" in tags or "cloud" in tags) and n_asns >= 2 and ports & {80, 443}:
        if company.get("has_direct_origin"):
            out.append(_f("cdn_bypass", HIGH, 12,
                          "Origin server reachable behind the CDN",
                          f"edge protection present, but an origin IP answers"
                          f" directly on {sorted(ports & {80, 443})}"
                          f" across {n_asns} networks -- the CDN can be bypassed"))

    # Unmanaged sprawl: assets scattered across providers usually means no
    # single team can see the whole estate.
    if n_asns >= 3:
        out.append(_f("cloud_sprawl", MEDIUM, 8,
                      f"Attack surface spread across {n_asns} networks",
                      f"{n_ips} hosts across {n_asns} autonomous systems --"
                      f" typically indicates unmanaged or shadow IT"))

    # A 2011 CVE still open in 2026 is not one missed patch; it is the absence
    # of any patching process at all.
    oldest = company.get("oldest_cve_year")
    if oldest and (datetime.now(timezone.utc).year - oldest) >= 5:
        out.append(_f("no_patch_process", HIGH, 14,
                      f"Unpatched vulnerabilities dating to {oldest}",
                      f"oldest outstanding CVE is from {oldest} --"
                      f" indicates no routine patching programme"))
    return out


def _days_until(ts: str) -> int | None:
    for fmt in ("%Y%m%d%H%M%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            d = datetime.strptime(ts[:19] if "-" in ts else ts, fmt)
            return (d.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        except (ValueError, TypeError):
            continue
    return None
