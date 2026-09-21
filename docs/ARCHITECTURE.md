# Architecture

## The constraint that shaped everything

Before writing a line, I spent 6 MB of bandwidth on a 12.4 GB file:

| Probe | Finding | Consequence |
|---|---|---|
| `curl -I` | `Accept-Ranges: bytes` | can sample without downloading |
| `head -3` on a slice | **NDJSON**, not a JSON array | stream line by line; constant memory |
| read from byte 6e9 | **single zstd frame** — not seekable | one sequential pass; no parallelism |
| top-level keys | `_shodan` | it's an attack-surface map, not company data |

Measured on a 300k-row test: a JSON array costs **117 MB** of RAM; the same data
as NDJSON costs **0.1 MB**. At 89 GB the array form is simply impossible. That
one observation is why this runs on a laptop.

The single-frame finding is the more expensive one: no random access, no
splitting across cores, no resuming from the middle. **Everything needed must be
extracted in one read.**

---

## Pipeline

```
   12.4 GB .zst  ──01──►  verified on disk  ──02──►  150 MB .jsonl.gz
                                                          │
                                                          03
                                                          ▼
   scores ◄──06──  findings ◄──04──  companies ◄───  obs_keyed
      ▲                                   │
      └───────────── 05 (LLM) ────────────┘
```

Each stage writes to disk. If `05` breaks, `05` re-runs — nothing re-downloads.
With a 12.4 GB input that is not a nicety; it is the difference between a
2-minute fix and a 90-minute one.

### 02 — ingest: two independent reductions

```
  89 GB  ──① keep 13.4% of rows──►  11.9 GB
         ──② keep 7.5% of bytes──►   0.9 GB
         ──③ gzip 5.8×───────────►   150 MB
```

Row filter drops honeypots (decoys, not businesses), records with no
identifiable owner, and cloud/CDN infrastructure — **66% of the file is AWS,
Akamai, Google and Cloudflare**, i.e. landlords, not tenants.

Column filter drops `http.html` (41% of all bytes), CVE prose (30%) and
favicons (9%). Measured, not guessed.

> **One measurement changed the design.** `vulns` is 30% of the file, but it
> carries `cvss` inline. Keeping `{cve, cvss}` and dropping `summary` +
> `references` costs 11 MB and **removes an entire external dependency** — no
> CVE database to sync or keep current.

Every record lands in exactly one named bucket, and the run prints
`reconciles OK` only if `kept + Σ rejects == total`.

### 03 — entity resolution: the hard part

Given an IP, who actually rents this space? Two sub-problems, both solved by
**measuring footprint instead of maintaining name lists**.

**(a) Which domain on a record names the tenant?** A record may carry
`['cprapid.com', 'bespokeit.com']` — one is the host, one is the customer. My
first version took `domains_real[1]`, an arbitrary pick, and a Tokyo hospital
and an Armenian news site both got merged into their hosting providers.

> A hosting domain appears across a huge number of unrelated IPs. A company
> domain appears on a handful. **Rank every domain by footprint; the rarest one
> names the record.**

**(b) Is this entity a provider at all?** Same principle:

```sql
count(DISTINCT asn) > 3  OR  count(DISTINCT ip) > 150  OR  count(DISTINCT country) > 3
```

Name blocklists never finish — *"The Constant Company, LLC"* is Vultr, and
nobody guesses that. A structural test needs no maintenance and catches
providers it has never heard of.

**This is why ingest is permissive and resolve is strict.** Provider detection
is a property of the *aggregate*, so it cannot be decided during the streaming
pass — there are no global counts yet.

The SSL certificate subject is the only place a legal name appears (1.3%
coverage, high precision). It also collapses `douglas.at` + `douglas.de` + 12
more into one company.

### 04 — findings: rules only, on purpose

14 finding types. Zero AI in this file. A rep may read these aloud to a
prospect's IT director, so every finding carries an evidence string traceable
to an exact field in an exact record. A model that is right 95% of the time is
wrong on one call in twenty, and that is the one failure this product cannot
survive.

Beyond the obvious, three derived signals nobody gets from a port list alone:

| Signal | Computed from | Why it sells |
|---|---|---|
| **CDN bypass** | edge-fronted domains **and** an origin IP answering directly | "the protection you pay for can be walked around" |
| **Cloud sprawl** | distinct ASNs per company | unmanaged estate — the MDR pitch |
| **No patch process** | oldest outstanding CVE ≥ 5 years | not one missed patch; the absence of a programme |

### 06 — scoring: two scores, never blended

**Fit** (who they are, slow) and **Exposure** (what's broken, volatile) route
differently and are never merged. A single blended number cannot be debugged or
argued with, and drifts until everything is 80+.

```
                HIGH EXPOSURE          LOW EXPOSURE
 HIGH FIT       A  call this week      B  nurture — do NOT call
 LOW FIT        C  qualify first       D  suppress
```

**Tier B is the feature.** 267 companies in testing fit perfectly but had
nothing wrong; the tool explicitly tells the rep not to spend a call. Restraint
is what a prospecting tool is for.

#### Two corrections that make the score mean something

**Caps.** CVEs were **97% of raw findings**. Uncapped, a company with 40 stale
CVEs on one web server outranks a company with an open production database.
Each category is capped (`critical_exposure` 40, `cve` 25, …) so the score
measures risk rather than version-string verbosity.

**Rarity weighting.** `min(2.5, max(1, log10(1/prevalence)))`.

```
  exposed_ot              0.34%  →  2.5×    ← the reason to call today
  cve                    11.10%  →  1.0×    ← table stakes, every tool has it
```

Rare findings are worth more *because* they are rare — that is what makes them
a differentiated signal rather than something a competitor also shows.

**The pass condition is the histogram**, not the maths:

```
    0-9     2,844  ###############################################
   10-59      705  ##########
   60-100      23  #
```

Most companies are clean; a thin tail is badly exposed. If everything clustered
at 80+, the score would be decorative.

---

## Rule vs LLM

| Task | Engine | Reasoning |
|---|---|---|
| CVE → CVSS | rule | a lookup; a model is slower, dearer, and hallucinates scores |
| port / EOL / TLS risk | rule | fixed table, must be reproducible |
| rarity, caps, totals, tier | rule | never let a model do arithmetic you must defend |
| entity resolution | rule | exact; footprint is measurable |
| **industry classification** | **Haiku 4.5** | weak text signals → judgement. Not regexable |
| **why-now brief** | **Opus 5** | synthesis into rep-readable language |
| **outreach draft** | **Opus 5** | tone and restraint; goes to a real prospect |

**The ranking works with every model switched off.** `PERIMETER_LLM_DISABLED=1`
degrades to rules-only; the queue ranks identically, just terser. The LLM is
never load-bearing for a number a rep might have to defend.

### The guardrail

```python
valid = {f["id"] for f in findings}
cited = set(draft["cited_finding_ids"])
if not cited <= valid:
    draft = retry_once() or rules_only_fallback(findings)
```

A prompt instruction is a request; this is a gate. A rep emailing a prospect
about a **fabricated CVE** is unrecoverable with that buyer and discredits every
true finding in the same email. The fallback is a plain templated email. It
reads flatter. It is never wrong.

---

## Cost model

| Stage | Volume | Model | Cost |
|---|---|---|---|
| ingest, resolve, findings, scoring | 8.6M records | **none** | **$0** |
| industry classification | ~5% passing the rules gate | Haiku 4.5 | ~$0.10 / 1k |
| account brief | on demand (~50/day) | Opus 5 | ~$28/mo |
| outreach draft | on demand (~20/day) | Opus 5 | ~$8/mo |

**≈ $36/month steady state.** Levers, in the order they matter:

1. **The rules gate.** 8.6M → ~3k LLM calls. Everything else is rounding.
2. **Cheap model for the crisp task.** Classification has a right answer; Opus
   would cost 5× for no gain.
3. **Prompt caching** on the rubric — repeat calls bill the system prompt at ~0.1×.
4. **On demand, never precomputed.** Most accounts are never opened, and unsent
   Opus prose is the easiest money to waste in a product like this.
5. **Batch API** at 50% for the bulk classification pass.

Production ceiling: **$150/month hard cap**, per-endpoint rate limit, and a
kill switch that degrades to rules-only rather than failing.

---

## Stack, and what I did not use

| Layer | Choice | Rejected |
|---|---|---|
| Pipeline | plain Python, stdlib | Spark/Dask — data is 150 MB after filtering |
| Storage | **DuckDB** | Postgres — no server, and the DB is one file to bake into an image |
| UI | **HTMX + Jinja2 + Tailwind CDN** | React/Next — a build step, `node_modules`, and no benefit for six tables |
| Traces | SQLite, separate file | same DuckDB — app reads would contend with writes |

The HTMX call is the one to challenge. It is right for a repo judged on
clarity — a reviewer opens a template and understands the page — and wrong if
this needed a real front-end team.

---

## Observability

Every LLM call goes through one function. There is no second path — observability
you can bypass is not observability.

```sql
llm_calls(id, ts, feature, prompt_name, prompt_version, model, subject_id,
          input_tokens, output_tokens, cache_read_tokens, latency_ms,
          cost_usd, stop_reason, decision, ok, error, request, response,
          eval_run_id)
```

`prompt_version` is in the schema so v1 vs v2 is a `GROUP BY`, not archaeology.
Scores are rules, so they need no trace — re-running `06_score.py` on the same
DB gives byte-identical output.

---

## Evals

30 hand-labelled examples, stratified: 8 clear, 9 genuinely ambiguous,
**11 anti-ICP**, 2 abstain-correct.

Accuracy is the wrong metric because the classifier may answer `unknown`, and
accuracy punishes a correct abstention exactly as hard as a confident lie. So:
**coverage**, **precision**, **near-miss vs wrong**, and the one that gates a
release:

```
ANTI-ICP CONFUSION  0  OK          # non-zero exit if > 0
```

Labelling a hosting provider as `healthcare` puts Linode at the top of a rep's
Monday queue. They would never trust the list again. That is qualitatively
worse than any other error, so it is a CI gate rather than a dashboard number.

---

## Known limitations

Stated plainly because a reviewer will find them anyway.

| Limitation | Reality | Mitigation |
|---|---|---|
| **No firmographics exist** | size and industry are *inferred* | labelled "(inferred)" in the UI; size from host count, never presented as fact |
| **Entity resolution is lossy — and this is the #1 weakness** | **Measured on the full corpus: only ~5 of the top 30 Tier A accounts are real prospects.** The rest are hosting providers, ISPs and appliances. See below. | five independent provider tests (below); `identity: org` warning in the UI |
| **One snapshot, one hour** | no trend, no decay, no "newly exposed" | schema is snapshot-ready; a second scan enables deltas |
| **Findings ≠ vulnerabilities** | a patched backport looks unpatched by version string | severity only; never "you are exploitable" |
| **Provider detection needs scale** | on a 40 MB sample Linode shows 30 IPs and passes the filter | thresholds tuned on the full corpus, not a sample |
| **Geographic skew unverified** | the scan is a time-slice, not a random sample | do not claim market coverage from it |

### Measured entity-resolution quality

Hand-checked the top 30 Tier A accounts on the full 8.9M-record corpus:

| | |
|---|---|
| Real prospects | **~5/30** — governments and universities (`gov.np`, `bme.hu`, `forth.gr`, `ntua.gr`, `ncu.edu.tw`) |
| Hosting / ISP / appliances | ~25/30 |

Five independent provider tests are applied, each catching cases the others
miss. Their measured effect on Tier A size:

```
  baseline (footprint after keying only)            1,574 Tier A
  + footprint BEFORE keying (domain_shape)            963      -39%
  + machine-generated hostname detection              942
  + provider tokens in org names                      848      -46% total
  + hosting control-panel certificates                848
```

Each fix is structural — measuring a property rather than maintaining a name
list — which is why they generalise. But **the job is not finished.** Residual
contamination is roughly 80% at the very top of the queue, falling further
down where scores are less extreme.

Why the top is worst: an exposure score near 100 requires many severe findings
on many hosts, and *shared hosting has exactly that shape*. The scoring is
working correctly; it is being fed entities that should never have been
created.

**What I would do next, in order:**

1. Hand-label 200 resolved entities as company/infrastructure and *measure*
   precision properly, rather than eyeballing 30.
2. Train the provider decision on those labels instead of hand-tuned
   thresholds — the features (footprint, hostname patterns, cert diversity,
   name tokens) are already computed.
3. Require a contactable identity: an entity with no domain and no meaningful
   certificate cannot be phoned or emailed, so it has no business in a queue
   whatever its exposure score.

---

## Ethics

The dual-use question is real: this is a ranked list of exposed organisations.

- Every finding comes from a **public** scan. No exploitation, no auth bypass,
  no probing. The same data is available to anyone.
- The product surfaces **severity and evidence**, never how to exploit anything.
- Outreach copy is **required** to state that the information is public — that
  is honest, it pre-empts "how did you get this?", and it is the difference
  between a security vendor and a shakedown.
- No individuals. Company infrastructure only.

If this shipped, I would add a suppression list for critical infrastructure and
a rate limit on how many exposures one account can be shown — neither is in
scope for a prototype, and both belong in the conversation.
