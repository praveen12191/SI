---
name: account-scoring
version: 1.2.0
description: >
  Score a company as a cybersecurity sales prospect from internet-scan
  evidence. Produces a fit score, an exposure score, a tier, and a
  finding-by-finding breakdown that every point traces back to.
owner: perimeter
last_reviewed: 2026-09-18
models:
  classification: claude-haiku-4-5
  narrative: claude-opus-5
prompts:
  - classify-industry@v1
  - account-brief@v1
---

# account-scoring

Turn raw internet-scan observations about an organisation into a prioritised
sales judgement: **should a rep call them, and why today?**

## When to use this

Trigger when any of these is true:

- a rep or agent asks "is this company worth calling?" / "score this account"
- a new scan snapshot has landed and accounts need re-ranking
- an account's evidence changed (new findings, new hosts, new certificate)
- building or refreshing a territory, segment or call list

**Do not** use this to decide whether something *is* a company — that is
`03_resolve.py`'s job and it is rules-only. This skill assumes a resolved
company and scores it.

## Inputs

| Field | Type | Required | Notes |
|---|---|---|---|
| `company_id` | string | ✅ | key in `companies` |
| `primary_domain` | string | ✅ | registrable domain or normalised org name |
| `legal_name` | string | | from TLS certificate subject, when present |
| `page_title` | string | | boilerplate already stripped by `clean_title` |
| `country`, `city` | string | | first observation location |
| `products` | string[] | | observed server software |
| `open_ports` | int[] | | ports that answered |
| `n_ips`, `n_ports`, `n_asns` | int | ✅ | footprint — also the size proxy |
| `identity` | enum | ✅ | `domain` (stronger) or `org` (weaker) |
| `findings` | Finding[] | ✅ | from `04_findings.py` |

```
Finding = { id, type, severity, points, title, evidence, port?, cve?, cvss? }
```

## Outputs

```json
{
  "company_id": "northwind-ortho.com",
  "fit_score": 88,
  "exposure_score": 94.2,
  "tier": "A",
  "rationale": "Right profile and something is badly wrong right now.",
  "size_band": "mid_market",
  "industry": "healthcare",
  "industry_confidence": 0.91,
  "breakdown": {
    "fit": { "components": [ { "label": "ICP industry", "points": 30, "why": "..." } ] },
    "exposure": {
      "categories": {
        "critical_exposure": {
          "raw": 62.5, "capped_at": 40, "awarded": 40, "was_capped": true,
          "contributors": [
            { "type": "exposed_datastore", "raw": 25, "rarity_x": 2.19, "points": 54.8 }
          ]
        }
      }
    }
  },
  "why_now": "<from account-brief@v1>",
  "lead_finding_id": "f_8821_3306",
  "caution": "Identified by org name only -- confirm before dialling."
}
```

## The split: what is a rule, what is the model

This is the load-bearing design decision.

| Step | Engine | Why |
|---|---|---|
| CVE → CVSS severity | **rule** | a lookup; a model here is slower, dearer and hallucinates scores |
| port / EOL / TLS risk | **rule** | fixed table, must be reproducible |
| rarity weighting | **rule** | computed from the corpus, not opinion |
| category caps, totals, tier | **rule** | never let a model do arithmetic you must defend |
| **industry classification** | **model** (Haiku 4.5) | weak text signals → judgement; genuinely not regexable |
| **"why now" narrative** | **model** (Opus 5) | synthesis into rep-readable language |

**The ranking works with the model switched off.** Fit and exposure are pure
arithmetic; the LLM adds an industry label and prose. If the API is down, the
queue still ranks correctly — it just reads more tersely. That is deliberate:
the model is not permitted to be load-bearing for a number a rep might have to
defend to a prospect.

## Scoring rules that are easy to get wrong

1. **Cap every category.** CVEs are ~97% of raw findings. Uncapped, a company
   with 40 stale CVEs on one web server outranks a company with an open
   production database. Caps are what keep the score measuring risk rather
   than version-string verbosity.

2. **Weight by rarity, `min(2.5, max(1, log10(1/prevalence)))`.** A finding on
   11% of companies is table stakes; one on 0.3% is the reason to call today.

3. **Never blend fit and exposure.** They route differently — see the tier
   table. A single blended number cannot be debugged or argued with, and
   drifts until everything is 80+.

4. **A high-fit, low-exposure account is a `B`, and B means do not call.**
   Suppressing good-looking accounts is the feature, not a bug.

## Tiers

| | High exposure | Low exposure |
|---|---|---|
| **High fit** | **A** — call this week | **B** — nurture, wait for a trigger |
| **Low fit** | **C** — qualify before spending AE time | **D** — suppress, never surface |

## Worked example

```bash
python3 - <<'PY'
import duckdb, json
from core.scoring import exposure_score, fit_score, tier

con = duckdb.connect("data/out/perimeter.duckdb")
cid = "northwind-ortho.com"

company = con.execute("""
    SELECT company_id, primary_domain, legal_name, country, city,
           n_ips, n_ports, n_asns, identity, industry
    FROM companies WHERE company_id = ?
""", [cid]).fetchone()
cols = [d[0] for d in con.description]
company = dict(zip(cols, company))

findings = [dict(zip(["type", "points", "severity", "title"], r))
            for r in con.execute("""
    SELECT type, points, severity, title FROM findings WHERE company_id = ?
""", [cid]).fetchall()]

prevalence = dict(con.execute(
    "SELECT type, prevalence FROM finding_rarity").fetchall())

fit = fit_score(company)
exp = exposure_score(findings, prevalence)
t, rationale = tier(fit["score"], exp["score"])

print(json.dumps({"tier": t, "rationale": rationale,
                  "fit": fit["score"], "exposure": exp["score"]}, indent=2))
PY
```

```json
{
  "tier": "A",
  "rationale": "Right profile and something is badly wrong right now.",
  "fit": 88,
  "exposure": 94.2
}
```

Whole-corpus run:

```bash
python3 pipeline/06_score.py data/out/perimeter.duckdb
```

## Failure modes to watch

| Symptom | Cause | Check |
|---|---|---|
| everything scores 80+ | caps removed or rarity inverted | exposure histogram in `06_score.py` — a real distribution is the pass condition |
| hosting providers in tier A | corpus too small for footprint detection | `SELECT count(*) FROM entity_shape WHERE is_provider` |
| tier A almost empty | `FIT_BAR`/`EXPOSURE_BAR` too high for this corpus | tier split table |
| industry always `unknown` | `page_title` not reaching the classifier | inspect `llm_calls.request` |

## Observability

Every model call writes to `data/out/traces.sqlite`:
`prompt_version`, `model`, tokens, `cache_read_tokens`, latency, `cost_usd`,
parsed `decision`. Scores themselves are rules, so they are reproducible
without any trace — re-running `06_score.py` on the same DB gives identical
output.

## Cost

| Stage | Volume | Model | Cost |
|---|---|---|---|
| fit + exposure + tier | all companies | none | **$0** |
| industry classification | ~5% passing the rules gate | Haiku 4.5 | ~$0.10 / 1k |
| `why_now` brief | on demand only | Opus 5 | ~$0.028 each |

Briefs are generated when a rep opens an account, never precomputed. Most
accounts are never opened, and paying Opus prices to write prose nobody reads
is the easiest money to waste in a product like this.
