---
name: outreach-draft
version: 1.1.0
description: >
  Draft a first outreach email to a cybersecurity prospect, grounded strictly
  in observed scan findings. Every technical claim cites a finding id, and
  drafts citing anything unrecognised are rejected in code, not in the prompt.
owner: perimeter
last_reviewed: 2026-09-18
models:
  draft: claude-opus-5
prompts:
  - outreach-draft@v1
depends_on:
  - account-scoring@1.2.0
---

# outreach-draft

Convert an account's evidence into an email a rep can send with a straight
face — and that the recipient can verify in five minutes.

## When to use this

- a rep opens a Tier **A** or **C** account and asks for a first-touch draft
- a sequence needs a personalised opener for a specific account

**Do not** use for: follow-ups (no thread context), replies, or any account
where `insufficient_evidence` came back true. Do not use on Tier **B** — the
point of Tier B is that there is nothing to say yet.

## Inputs

| Field | Required | Notes |
|---|---|---|
| `company` | ✅ | `primary_domain`, `legal_name`, `country`, `industry`, `identity` |
| `findings` | ✅ | **the full evidence table**, each with a stable `id` |
| `scores` | ✅ | `fit_score`, `exposure_score`, `tier` |
| `lead_finding_id` | | from `account-brief`; the model may override with reason |
| `scan_date` | ✅ | claims must be dated or they sound invented |

## Outputs

```json
{
  "subject": "Your patient portal database is publicly reachable",
  "body": "On 14 September a routine internet scan showed ...",
  "cited_finding_ids": ["f_8821_3306", "f_8821_443_eol"],
  "primary_finding_id": "f_8821_3306",
  "insufficient_evidence": false,
  "reasoning": "Exposed database needs no technical translation for a CFO."
}
```

## The guardrail — enforced in code, not in the prompt

```python
valid = {f["id"] for f in findings}
cited = set(draft["cited_finding_ids"])

if not cited <= valid:               # any unrecognised id -> reject
    log_violation(company_id, cited - valid)
    draft = retry_once() or rules_only_fallback(findings)
```

A prompt instruction is a request. This is a gate: the model **cannot** cite a
finding that does not exist, because a draft that does is discarded before a
human ever sees it.

This is the single most important line in the product. A rep emailing a
prospect about a fabricated CVE is the worst possible failure — worse than a
missed account, worse than downtime, because it is unrecoverable with that
buyer and it discredits every true finding in the same email.

The fallback is a plain templated email built from the top-ranked finding by
rules alone. It reads flatter. It is never wrong.

## Rules the prompt enforces

1. Every technical claim maps to a cited finding.
2. No claim about the company beyond what is in the evidence — no headcount,
   revenue, customers, current vendor or budget.
3. Never imply the sender probed, tested or accessed anything. The data is a
   public scan and the email should say so plainly — it reassures, and it
   pre-empts "how did you get this?".
4. Lead with **one** finding. One specific fact outperforms five.
5. 90–150 words, one ask, no urgency theatre.
6. Thin evidence → `insufficient_evidence: true` and an empty body. A generic
   email is worse than no email.

## Worked example

```bash
python3 - <<'PY'
import duckdb, json
from core.llm import call

con = duckdb.connect("data/out/perimeter.duckdb")
cid = "northwind-ortho.com"

findings = [dict(zip(["id", "type", "severity", "title", "evidence", "port"], r))
            for r in con.execute("""
    SELECT rowid AS id, type, severity, title, evidence, port
    FROM findings WHERE company_id = ?
    ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                           WHEN 'medium' THEN 2 ELSE 3 END
    LIMIT 12
""", [cid]).fetchall()]

payload = json.dumps({
    "company": {"primary_domain": cid, "legal_name": "Northwind Orthopedic Group",
                "country": "US", "industry": "healthcare"},
    "scan_date": "2026-09-14",
    "findings": findings,
}, indent=2)

res = call(feature="outreach-draft", prompt_name="outreach-draft",
           prompt_version="v1", model="claude-opus-5",
           user_content=payload, max_tokens=900, subject_id=cid)

draft = res["decision"]
valid = {str(f["id"]) for f in findings}
cited = {str(i) for i in draft.get("cited_finding_ids", [])}
assert cited <= valid, f"hallucinated finding ids: {cited - valid}"
print(draft["subject"]); print(); print(draft["body"])
PY
```

Expected shape:

```
Your patient portal database is publicly reachable

On 14 September a routine internet-wide scan showed a MySQL database at
Northwind answering directly on the public internet, and your patient portal
running a version of nginx that is end-of-life and carries a critical flaw
(CVE-2025-23419, CVSS 9.1).

Nothing here required special access -- this is visible to anyone scanning the
internet, which is the point. Four other findings came up alongside these.

Worth fifteen minutes this week to walk through them?
```

## Quality measurement

Unlike `classify-industry`, this has no single right answer, so it is graded
against a rubric rather than a label (`evals/labelled/outreach_rubric.jsonl`):

| Criterion | Pass condition | Automated? |
|---|---|---|
| **Grounding** | every cited id exists | ✅ exact |
| **No fabrication** | no CVE/port/product absent from evidence | ✅ regex + set check |
| **No invented context** | no headcount/revenue/vendor claim | ⚠️ LLM judge |
| **Leads with one finding** | primary finding appears in first two sentences | ✅ |
| **Length** | 90–150 words | ✅ exact |
| **Dated** | scan date present in body | ✅ exact |
| **Tone** | no urgency theatre, no flattery | ⚠️ LLM judge |

Five of seven are deterministic. Only tone and invented-context need a judge —
keep it that way; a rubric a machine can check does not drift.

## Cost

Opus 5 at ~1,800 in / 500 out ≈ **$0.021 per draft**. On-demand only: a rep
drafts maybe 20 a day → **~$8/month**. The system prompt is cached, so repeat
calls bill it at ~0.1×.

Do not batch-generate drafts for a whole territory. Most will never be sent,
and unsent Opus prose is the most expensive thing in this product.
