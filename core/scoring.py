"""
The arithmetic. Deliberately plain, deliberately auditable, no LLM.

Two scores, never blended into one:

    FIT       who they are      -- slow-moving, attribute-based
    EXPOSURE  what's broken now -- volatile, evidence-based

Blending them produces a single number that cannot be argued with or debugged,
and within a quarter everything drifts to 80+ and the ranking becomes
decorative. Kept apart, they answer different questions and route differently
(see `tier`).

Every score returns a breakdown listing each component, so a rep can click any
number and land on the raw scan record that produced it.
"""
from __future__ import annotations

import math

# --- Exposure ---------------------------------------------------------------
# Findings are grouped into categories, and each category is capped. Without
# caps, CVEs (97% of all findings) would swamp everything: a company with 40
# stale CVEs on one web server would outrank a company with an open production
# database. The cap is what keeps the score measuring *risk* rather than
# *how chatty your version strings are*.
CATEGORY = {
    "exposed_datastore":     ("critical_exposure", 40),
    "exposed_remote_access": ("critical_exposure", 40),
    "exposed_ot":            ("critical_exposure", 40),
    "tag_c2":                ("critical_exposure", 40),
    "tag_database":          ("critical_exposure", 40),
    "exposed_file_sharing":  ("critical_exposure", 40),

    "tag_eol_product":       ("unsupported_software", 20),
    "tag_eol_os":            ("unsupported_software", 20),

    "cve":                   ("known_vulnerabilities", 25),

    "cert_expired":          ("certificate_hygiene", 10),
    "cert_expiring":         ("certificate_hygiene", 10),
    "tag_self_signed":       ("certificate_hygiene", 10),

    "cdn_bypass":            ("structural_weakness", 20),
    "cloud_sprawl":          ("structural_weakness", 20),
    "no_patch_process":      ("structural_weakness", 20),
    "tag_open_dir":          ("structural_weakness", 20),
    "tag_iot":               ("structural_weakness", 20),
}
MAX_RAW = 40 + 20 + 25 + 10 + 20  # 115


def rarity_multiplier(prevalence: float) -> float:
    """
    Rare findings are worth more *because* they are rare.

    A finding present on 11% of companies (CVEs) is table stakes -- every
    competitor's tool shows it. One present on 0.3% (exposed industrial
    control) is the entire reason to make the call today.

        prevalence 11.0%  ->  1.0   (no boost)
        prevalence  0.3%  ->  2.5   (maximum boost)
    """
    if prevalence <= 0:
        return 2.5
    return min(2.5, max(1.0, math.log10(1.0 / prevalence)))


def exposure_score(findings: list[dict], prevalence: dict[str, float]) -> dict:
    """findings: [{type, points, severity, title}] -> {score, breakdown}"""
    per_category: dict[str, float] = {}
    contributors: dict[str, list] = {}

    for f in findings:
        cat, cap = CATEGORY.get(f["type"], ("structural_weakness", 20))
        mult = rarity_multiplier(prevalence.get(f["type"], 0.05))
        pts = f["points"] * mult
        per_category[cat] = per_category.get(cat, 0.0) + pts
        contributors.setdefault(cat, []).append(
            {"type": f["type"], "title": f["title"], "raw": f["points"],
             "rarity_x": round(mult, 2), "points": round(pts, 1)}
        )

    capped, total = {}, 0.0
    for cat, raw in per_category.items():
        cap = next(c for t, (n, c) in CATEGORY.items() if n == cat)
        val = min(raw, cap)
        capped[cat] = {"raw": round(raw, 1), "capped_at": cap,
                       "awarded": round(val, 1),
                       "was_capped": raw > cap,
                       "contributors": sorted(contributors[cat],
                                              key=lambda c: -c["points"])[:6]}
        total += val

    return {
        "score": round(min(100.0, total / MAX_RAW * 100), 1),
        "categories": capped,
        "n_findings": len(findings),
    }


# --- Fit --------------------------------------------------------------------
# Our fictional vendor sells managed detection + compliance to regulated
# mid-market organisations with a thin security team. Derived from the
# closed-won analysis in docs/PLANNING.md.
ICP_INDUSTRIES = {
    "healthcare", "manufacturing", "finance", "fintech", "insurance",
    "education", "government", "legal", "professional_services",
    "logistics", "energy", "utilities", "retail",
}
# Companies that sell security themselves -- they are competitors, not buyers.
ANTI_ICP_INDUSTRIES = {"cybersecurity", "hosting", "telecom", "cloud_provider"}

TERRITORY_DEFAULT = {"US", "CA", "GB", "AU", "NZ", "IE"}


def size_band(n_ips: int, n_ports: int) -> str:
    """
    The dataset has no employee count, so attack-surface footprint stands in.

    It is a proxy, not a fact, and is labelled as such everywhere it surfaces.
    """
    if n_ips <= 1 and n_ports <= 2:
        return "micro"
    if n_ips <= 4:
        return "small"
    if n_ips <= 40:
        return "mid_market"
    return "large"


def fit_score(company: dict, territory: set[str] | None = None) -> dict:
    territory = territory or TERRITORY_DEFAULT
    parts: list[dict] = []

    def add(label, pts, why):
        parts.append({"label": label, "points": pts, "why": why})

    industry = (company.get("industry") or "unknown").lower()
    band = size_band(company.get("n_ips") or 0, company.get("n_ports") or 0)

    if industry in ANTI_ICP_INDUSTRIES:
        add("anti-ICP industry", -40,
            f"{industry} -- sells security themselves, or is infrastructure")
    elif industry in ICP_INDUSTRIES:
        add("ICP industry", 30, f"{industry} is a core target segment")
    elif industry == "unknown":
        add("industry unclassified", 8, "insufficient evidence -- neutral score")
    else:
        add("outside ICP", 0, f"{industry} is not a target segment")

    if band == "mid_market":
        add("size band", 25, "mid-market footprint -- the sweet spot")
    elif band == "small":
        add("size band", 12, "small footprint -- may lack budget")
    elif band == "large":
        add("size band", 10, "large footprint -- likely has an incumbent vendor")
    else:
        add("size band", -25, "single host -- too small to carry a budget")

    if (company.get("country") or "") in territory:
        add("territory", 15, f"{company.get('country')} is in coverage")

    n_asns = company.get("n_asns") or 0
    if n_asns >= 1 and band != "micro":
        add("owns infrastructure", 15,
            f"{n_asns} network(s), {company.get('n_ips')} hosts -- real estate to defend")

    if company.get("identity") == "domain":
        add("identity confidence", 10, "identified by registered domain")
    else:
        add("identity confidence", 3, "identified by org name only -- weaker")

    total = max(0, min(100, sum(p["points"] for p in parts)))
    return {"score": total, "size_band": band, "components": parts}


# --- The 2x2 ----------------------------------------------------------------
FIT_BAR, EXPOSURE_BAR = 55, 55


def tier(fit: float, exposure: float) -> tuple[str, str]:
    """
                    HIGH EXPOSURE          LOW EXPOSURE
      HIGH FIT      A  strike now          B  nurture, wait for a trigger
      LOW FIT       C  SDR qualify only    D  suppress -- never surface
    """
    hi_f, hi_e = fit >= FIT_BAR, exposure >= EXPOSURE_BAR
    if hi_f and hi_e:
        return "A", "Right profile and something is badly wrong right now."
    if hi_f:
        return "B", "Right profile, nothing urgent. Nurture -- don't burn a call."
    if hi_e:
        return "C", "Exposed, but outside ICP. Qualify before spending AE time."
    return "D", "Neither a fit nor urgent. Suppressed."
