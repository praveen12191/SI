# How I build

## The loop

Claude Code, in a terminal, with the dataset open in the same session. The
cycle was consistently: **probe the data → write a stage → run it on real
records → read the actual output → find something wrong → fix it.**

The step that mattered most was the fourth one. Almost every real bug in this
project was found by *looking at output*, not by reasoning about code and not by
a test. Several of them were invisible to both.

I worked against a 40 MB slice of the file for the whole build, and only ran the
full 12.4 GB at the end. Cutting the feedback loop from 90 minutes to 3 seconds
was worth more than any other decision here.

---

## Where AI saved the most time

**Exploration under uncertainty.** The first 20 minutes were spent finding out
what the file even was — HEAD request, magic bytes, NDJSON-vs-array,
seekability, record density. Being able to write a probe, read the result, and
immediately write the next probe kept that to minutes. Six megabytes of
bandwidth told me the memory model, the parallelism model, and that the brief's
premise needed rethinking.

**Boilerplate with real judgement in it.** The findings rules (14 types, port
tables, CVSS bands), the eval harness metrics, the Jinja templates. These are
not hard, but they are long, and generating them in near-final shape left
attention for the parts that actually needed thinking.

**Being argued with.** The most valuable exchanges were when I said something
wrong and it got measured instead of accepted. I claimed the output would be
"~152 MB"; being asked *"how is it 152 MB?"* forced a real measurement, which
found that `vulns` carries CVSS inline — which deleted an entire external
dependency from the design. The estimate was roughly right. The reason I gave
for it was incomplete.

---

## Where it cost more than doing it by hand

**Three silent failures I introduced, then had to catch.**

1. **Truncated ingest.** `curl -sL | zstd -dc 2>/dev/null | python` — no
   `pipefail`, and stderr binned. The run processed **half the file**, printed
   `reconciles OK`, and exited 0. Every number would have been quietly halved.
   Caught by arithmetic, not by code: 43 min × 2.4 MB/s = 6 GB, but the file is
   12.4 GB.

2. **`curl --retry` + `--continue-at -`.** These do not compose. The resume
   offset is resolved once at launch, so every internal retry restarts from
   *that* offset and truncates. It reached 2.5 GB, dropped, and went back to
   zero. Fix: retry outside curl so each attempt re-reads the real file size.

3. **Arbitrary entity keys.** `registrable(domains_real[1])` — picking the first
   of several domains. A Tokyo hospital and an Armenian news site were both
   merged into their hosting providers. Found only by reading the rendered
   prompts and noticing a Japanese hospital name attached to `ptrcloud.net`.

All three share a shape: **the tool reported success while doing the wrong
thing.** Fast generation made it easy to produce plausible code quickly, and
plausible-and-wrong is more dangerous at 12 GB than at 12 KB. The habit that
saved me was refusing to trust any number I had not derived twice.

**Over-eager scaffolding.** I generated a 19-industry taxonomy prompt before
checking whether `page_title` — the single strongest signal — was even reaching
the classifier. It was not. The prompt was good; it was being fed nothing.
Fifteen minutes wasted that reading one rendered prompt would have saved.

---

## What I would tell a teammate picking this up

### The one weakness I would flag

**Entity resolution is the weakest link, and every number downstream inherits
its error.**

The structural provider test — *an entity spanning many networks and IPs is
infrastructure* — is sound, and it needs no name blocklist, which is why it can
catch providers it has never heard of. But it only works **at scale**. On a
40 MB sample Linode shows 30 addresses and sails through; in the full corpus it
shows thousands and trips instantly. So:

> **Do not tune `MAX_ASNS` / `MAX_IPS` against a sample.** You will be fitting
> to noise. Tune them against the full corpus, and hand-verify 50 companies
> before trusting any aggregate.

Two failure modes remain even at full scale:

- **Shared hosting merges tenants.** Several small businesses behind one host
  can collapse into one "company". The `identity: org` warning in the UI is a
  mitigation, not a fix.
- **Large organisations fragment.** A company with subsidiaries on different
  domains appears as several accounts. Certificate clustering catches some of
  this; nothing catches all of it.

I did measure it, and the number is bad: **~5 of the top 30 Tier A accounts are
real prospects.** Five structural provider tests took Tier A from 1,574 to 848
and removed the worst offenders (Linode, DreamHost, Contabo, Plesk boxes), but
roughly 80% contamination remains at the very top of the queue.

The reason the top is worst is worth understanding: an exposure score near 100
needs many severe findings across many hosts, and shared hosting has exactly
that shape. The *scoring* is correct. It is being handed entities that should
never have been created.

So: **do not trust the top of the queue yet.** Fix resolution before touching
anything else. Hand-label 200 entities, measure precision properly, and train
the provider decision on those labels rather than on thresholds I tuned by
eye — the features are all already computed.

### Smaller things worth knowing

- **The ranking is pure arithmetic.** `PERIMETER_LLM_DISABLED=1` degrades to
  rules-only and the queue is identical. If you are debugging a ranking
  problem, the LLM is not involved — do not look there.
- **Re-running `06_score.py` on the same DB is byte-identical.** If it is not,
  something upstream changed.
- **The exposure histogram is the canary.** If it ever clusters at 80+, a cap
  or the rarity weighting has broken, and the score has quietly become
  decorative.
- **`evals/run_evals.py` exits non-zero on `anti_icp_confusion > 0`.** That is
  deliberate — it is a release gate, not a metric. Do not "fix" it by removing
  the exit code.

### What is not done

- No real eval numbers — the harness works and is dry-run tested, but needs
  `ANTHROPIC_API_KEY` to produce measured precision/recall. A full run costs
  about one cent.
- Only `v1` prompts exist. The v1→v2 iteration is the loop the harness was
  built for; it has not been run.
- The outreach rubric set (`outreach_rubric.jsonl`) is specified in the skill
  but not populated.
