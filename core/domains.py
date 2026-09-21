"""Registrable-domain ("eTLD+1") extraction.

`mail.shop.acme.co.uk` -> `acme.co.uk`, not `co.uk`.

Uses a bundled table of common multi-label public suffixes. This is a
deliberate simplification of the full Public Suffix List (~9,000 entries):
it covers the overwhelming majority of real-world corporate domains with no
network dependency and no extra package. Domains under rarer suffixes may
resolve one label too shallow -- a known, documented limitation.
"""

import re

# Second-level suffixes where the registrable name is the THIRD label.
MULTI_SUFFIX = {
    # UK / IE
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk",
    "plc.uk", "sch.uk", "nhs.uk", "police.uk", "mod.uk",
    # AU / NZ
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "school.nz", "geek.nz",
    # Asia
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "lg.jp", "gr.jp",
    "co.kr", "or.kr", "ne.kr", "re.kr", "go.kr", "ac.kr", "pe.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "firm.in",
    "co.id", "or.id", "ac.id", "go.id", "web.id", "net.id",
    "com.ph", "com.vn", "com.pk", "com.bd", "com.np", "com.lk",
    "co.th", "in.th", "ac.th", "go.th", "or.th",
    # Middle East
    "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.sa", "com.eg", "com.qa", "com.kw", "com.bh", "com.om",
    "com.jo", "com.lb", "co.ae", "net.ae", "org.ae", "gov.ae",
    # Americas
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.ec",
    "com.uy", "com.py", "com.bo", "com.do", "com.gt", "com.pa",
    # Europe
    "com.pl", "net.pl", "org.pl", "gov.pl", "com.ua", "net.ua", "org.ua",
    "com.ru", "net.ru", "org.ru", "com.es", "com.pt", "com.gr", "com.cy",
    "co.at", "or.at", "ac.at", "gv.at",
    # Africa
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
    "com.ng", "com.gh", "co.ke", "co.tz", "co.ug", "co.zw", "com.ma",
}


def registrable(domain: str) -> str | None:
    """`mail.shop.acme.co.uk` -> `acme.co.uk`. Returns None if not resolvable."""
    if not domain:
        return None
    d = domain.strip().lower().rstrip(".")
    if not d or "." not in d:
        return None

    parts = d.split(".")
    if len(parts) < 2:
        return None

    if ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:]) if len(parts) >= 3 else None

    return ".".join(parts[-2:])


# Placeholder values that appear in `org` where a real name should be. Left in,
# they become high-scoring "companies" made of thousands of unrelated hosts --
# "SomeOrganization" alone carried 1,064 findings in testing.
JUNK_ORG = {
    "someorganization", "some organization", "unknown", "n/a", "na", "none",
    "null", "private", "not disclosed", "undisclosed", "test", "example",
    "no name", "noname", "default", "placeholder", "-", "--", ".",
    "organization", "company", "customer", "client", "reserved",
}


def normalise_org(org: str) -> str | None:
    """Fold legal-entity noise so 'Acme Inc.' and 'ACME, INC' are one key."""
    if not org:
        return None
    s = org.strip().lower().rstrip(".,")
    if s in JUNK_ORG or len(s) < 3:
        return None
    for suffix in (
        " inc", " inc.", " llc", " l.l.c.", " ltd", " ltd.", " limited",
        " gmbh", " ag", " sa", " s.a.", " bv", " b.v.", " nv", " n.v.",
        " pty", " pty.", " pte", " pte.", " plc", " corp", " corp.",
        " corporation", " company", " co", " co.", " srl", " s.r.l.",
        " oy", " ab", " as", " a/s", " aps", " kk", " k.k.", " spa",
    ):
        if s.endswith(suffix):
            s = s[: -len(suffix)].rstrip(" ,.")
    return " ".join(s.split()) or None


def clean_display_name(name: str) -> str | None:
    """Certificate subjects carry the same placeholder junk as `org`."""
    if not name:
        return None
    s = name.strip()
    if s.lower().rstrip(".,") in JUNK_ORG or len(s) < 3:
        return None
    # A wildcard CN is a hostname, not a company name.
    if s.startswith("*."):
        return None
    # Software, CA and appliance names are not organisations.
    if is_vendor_cert(s):
        return None
    return s


# Default server pages masquerading as company pages. Left in, they are worse
# than no title: "Apache HTTP Server Test Page" tells a classifier nothing but
# looks like evidence, and burns tokens pretending to be a signal.
DEFAULT_TITLE = re.compile(
    # vendor default pages
    r"(apache\w* (http server )?(test|default) page|welcome to nginx|"
    r"^http server test page|iis windows( server)?|it works!?|"
    r"default web site page|test page for|plesk|cpanel|directadmin|"
    r"new account|suspended|domain (default|parking)|"
    # HTTP status pages masquerading as titles
    r"^\s*(30[0-9]|40[0-9]|50[0-9])\b|moved permanently|permanent redirect|"
    r"^\s*30[0-9] found|document moved|forbidden|bad request|not found|"
    # error and interstitial pages
    r"error: the requ(est|ested url)|the request could not be satisfied|"
    r"could not be retrieved|dns (resolution error|points to)|invalid url|"
    r"^\s*error\s*$|checking your browser|this site can'?t be reached|"
    r"no such app|site not (found|configured)|under construction|"
    r"website has been stopped|coming soon|index of /|directory listing for|"
    r"525: ssl|glitch)",
    re.IGNORECASE,
)


def clean_title(title: str) -> str | None:
    """Drop boilerplate server pages; keep titles that describe a business."""
    if not title:
        return None
    s = " ".join(title.split())
    if len(s) < 3 or DEFAULT_TITLE.search(s):
        return None
    return s[:160]


# Auto-generated reverse DNS: the signature of infrastructure.
#
# Hosting providers and ISPs name machines from their IP address
# (107.181.238.196.static.gorillaservers.com) or a sequential id
# (vmi80310.contabo.host). A real organisation names hosts after what they do
# (wp3.itz.uni-halle.de, health4life.usana.com).
#
# This is the discriminator that footprint thresholds miss: contabo.host has
# only 36 IPs in this scan and sails past any IP-count filter, but 100% of its
# hostnames are machine-generated.
SEQ_HOST = re.compile(
    r"^(?:vmi?|srv|server|host|node|vps|cust|client|static|dyn|dynamic|ip|"
    r"pool|user|cpe|dsl|adsl|cable|fibre|fiber|broadband|res|customer)?[-._]?"
    r"\d{3,}[-._]",
    re.IGNORECASE,
)


def is_machine_hostname(hostname: str, ip: str | None) -> bool:
    """True if the hostname embeds its own IP, or looks sequentially generated."""
    if not hostname:
        return False
    h = hostname.lower()

    if ip:
        parts = ip.split(".")
        if len(parts) == 4:
            # 1.2.3.4 / 1-2-3-4 / reversed 4.3.2.1 (common in PTR records)
            for sep in (".", "-"):
                if sep.join(parts) in h or sep.join(reversed(parts)) in h:
                    return True
            # zero-padded: 001-002-003-004
            if "-".join(p.zfill(3) for p in parts) in h:
                return True

    return bool(SEQ_HOST.match(h))


# Hosting/infrastructure tokens inside an organisation name.
#
# The org path recovers real businesses (Equifax, LA Municipal Court) that have
# no usable domain, which is why it exists. But it also admits hosting brands
# -- "crowncloud us", "80vps", "ServerAvatar", "impact host". Those are not
# prospects, and unlike a domain-identified company there is nothing for a rep
# to look up or contact.
# Two tiers, because the tokens differ in how safely they can be matched.
#
# STRONG tokens are matched anywhere, including inside compound words
# ("crowncloud", "serveravatar", "alphavps") -- these essentially never appear
# inside a real company name in this corpus.
STRONG_PROVIDER_TOKEN = re.compile(
    r"(vps|vds|kvm\b|cloud|hosting|webhost|datacenter|datacentre|colocation|"
    r"colo\b|dedicated|serverav|servers?\b|idc\b|host\b|hosts\b)",
    re.IGNORECASE,
)

# WEAK tokens need a word boundary -- "network" and "online" do appear inside
# legitimate names, so matching them mid-word would cost real prospects.
WEAK_PROVIDER_TOKEN = re.compile(
    r"(?:^|[\s\-_.])(network|networks|internet|online|telecom|telecoms|isp|"
    r"dns|cdn|proxy|bandwidth|infra|infrastructure|rack|racks|node|nodes|"
    r"broadband|as\d{3,}|\d{2,}vps)(?:$|[\s\-_.])",
    re.IGNORECASE,
)


def looks_like_provider_name(name: str) -> bool:
    """True if an organisation name reads as infrastructure rather than a business."""
    if not name:
        return False
    return bool(STRONG_PROVIDER_TOKEN.search(name)
                or WEAK_PROVIDER_TOKEN.search(name))


# Certificate subjects that name SOFTWARE, not an organisation.
#
# A cert saying "Plesk" or "Hestia Control Panel" is a hosting control panel's
# self-signed default -- it identifies the software running on the box, and by
# implication that the box is shared hosting. "Internet Widgits Pty Ltd" is
# OpenSSL's placeholder. "American Megatrends" is a BIOS vendor on a management
# interface. None of these is a company a salesperson can call.
CONTROL_PANEL_CERT = {
    "plesk", "parallels", "cpanel", "cpanel, inc.", "fastpanel", "hestia",
    "hestia control panel", "vesta", "vesta control panel", "serveravatar",
    "directadmin", "cyberpanel", "webmin", "virtualmin", "ispconfig",
    "froxlor", "keyhelp", "cloudpanel", "aapanel", "baota", "runcloud",
    "gridpane", "enhance", "solidcp", "websitepanel", "interworx",
}

VENDOR_CERT = CONTROL_PANEL_CERT | {
    # OpenSSL / framework placeholders
    "internet widgits pty ltd", "internet widgits", "default company ltd",
    "acme co", "acme", "example", "example corp", "my company", "company",
    "k3s", "kubernetes", "traefik", "traefik default cert", "minio", "nginx",
    "apache", "haproxy", "docker", "portainer",
    # certificate authorities -- the ISSUER leaking into the subject
    "globalsign nv-sa", "globalsign", "let's encrypt", "digicert", "sectigo",
    "comodo", "comodo ca limited", "thawte", "geotrust", "rapidssl",
    "starfield technologies", "go daddy", "godaddy.com",
    # hardware / appliance vendors -- a device, not the operator
    "american megatrends", "american megatrends inc", "ugreen", "synology",
    "qnap", "ubiquiti networks", "ubiquiti", "mikrotik", "zyxel", "tp-link",
    "d-link", "netgear", "asus", "asustek", "hikvision", "dahua",
    "cyberoam", "fortinet", "fortinet ltd.", "sonicwall", "sophos",
    "advantech", "advantech b+b smartworx s.r.o.", "ikuai", "dis",
}


def is_vendor_cert(name: str) -> bool:
    """True if a certificate subject names software or hardware, not a company."""
    if not name:
        return False
    return name.strip().lower().rstrip(".,") in VENDOR_CERT


def is_control_panel_cert(name: str) -> bool:
    """True if the subject is a hosting control panel -- i.e. the box is shared hosting."""
    if not name:
        return False
    return name.strip().lower().rstrip(".,") in CONTROL_PANEL_CERT
