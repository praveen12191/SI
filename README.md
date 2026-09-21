# Perimeter

**Sales intelligence from attack surface.**

Every other prospecting tool scores companies on *who they are*. This one scores
them on *how exposed they actually are* — measured from the outside, from public
data, with evidence a rep can paste into an email and the prospect can verify in
five minutes.

```
1  TIER A  northwind-ortho.com  🔴          healthcare · US · 7 hosts · 12 ports
   [ MySQL database reachable from the internet ]
   [ End-of-life software ]  [ CVE-2025-23419 · CVSS 9.1 ]
   fit ████████▉░ 88    exp █████████▌ 94    23 findings        [ Open → ]
```

---

## Quickstart

```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt

./.venv/bin/python pipeline/01_download.py data/raw/scan.zst        # ~12.4 GB, resumable
zstd -dc data/raw/scan.zst | ./.venv/bin/python pipeline/02_ingest.py data/out/scan.jsonl.gz
./.venv/bin/python pipeline/03_resolve.py  data/out/scan.jsonl.gz data/out/perimeter.duckdb
./.venv/bin/python pipeline/04_findings.py data/out/perimeter.duckdb
./.venv/bin/python pipeline/05_enrich.py   data/out/perimeter.duckdb   # needs ANTHROPIC_API_KEY
./.venv/bin/python pipeline/06_score.py    data/out/perimeter.duckdb

./.venv/bin/uvicorn app.main:app --port 8000
```

Or `make all`.

Without an API key everything still works — `05_enrich` is the only stage that
needs one, and the ranking is pure arithmetic. Set `PERIMETER_LLM_DISABLED=1`
to run the app in rules-only mode.

---

## What the data is

A **Shodan-style internet-wide port scan** — 12.4 GB of zstd-compressed NDJSON,
~89 GB raw, ~8.6M records, one per `(IP, port)` observed in a one-hour window
on 2026-09-14.

There are **no firmographics in it at all** — no employee count, no revenue, no
industry, no company name. Turning it into a prospect list is the work:

```
  8.6M records                                        89 GB
     ↓  02  drop honeypots, no-domain, cloud/CDN
  ~2.5M kept                                         150 MB
     ↓  03  eTLD+1 · footprint ranking · cert clustering
   ~60k companies
     ↓  04  rules: exposed ports, EOL, CVE→CVSS, CDN bypass
  ~200k findings
     ↓  05  LLM: industry (only for companies that pass a rules gate)
     ↓  06  fit + exposure + tier
  the queue
```

The whole 89 GB is read. Peak memory is ~31 MB — it streams.

---

## Repo

```
pipeline/     01 download · 02 ingest · 03 resolve · 04 findings · 05 enrich · 06 score
core/         domains (eTLD+1) · rules (findings) · scoring (fit/exposure) · llm (traced client)
app/          FastAPI + HTMX. Queue · Account · Segments · Ops
prompts/      versioned prompt files + registry.yaml
skills/       account-scoring · outreach-draft (SKILL.md)
evals/        30 hand-labelled examples · harness · results
docs/         PLANNING · ARCHITECTURE · HOW-I-BUILD
```

---

## Design in one table

| | Engine | Why |
|---|---|---|
| CVE→CVSS, port risk, EOL, caps, tier | **rules** | never let a model do arithmetic you must defend to a customer |
| industry classification | **Haiku 4.5** | weak text → judgement; genuinely not regexable |
| why-now brief, outreach draft | **Opus 5** | synthesis; quality is customer-visible |

**The ranking works with every model switched off.** The LLM adds language,
never a number.

Steady-state cost: **~$36/month**. Ceiling: $150/month hard cap.

---

## Evals

```bash
./.venv/bin/python evals/run_evals.py --version v1      # exits non-zero on a release blocker
```

30 hand-labelled examples, stratified — 11 of them anti-ICP (hosting/telecom),
because labelling a hosting provider as `healthcare` puts a landlord at the top
of a rep's Monday queue and they will never trust the list again. That metric
(`anti_icp_confusion`) gates the build.

---

## Known limitations

Written up properly in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#known-limitations).
The short version:

- **One snapshot, one hour.** No trend, no decay, no "newly exposed" delta.
- **Size and industry are inferred**, not known. Labelled as such everywhere.
- **Entity resolution is lossy.** Shared hosting merges unrelated companies;
  large organisations fragment.
- Findings are **public observations**, not proof of vulnerability — a patched
  backport can look unpatched by version string.

---

## Ethics

Every finding comes from a public internet scan. No exploitation, no
authentication bypass, no probing. The product surfaces severity and evidence,
never how to exploit anything, and outreach copy is required to state plainly
that the information is public.
