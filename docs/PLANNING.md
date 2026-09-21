# Planning — the use cases, and why these

## How B2B teams actually prospect

Before building, I worked through how prospecting really runs. The funnel
throws away most of each stage:

```
Total market  →  ICP filter  →  Territory  →  Fit score  →  Signal  →  Today's queue
   500k             8k            600           180          30           8
```

The product is that last collapse. An AE actively works **25–40 accounts a
quarter**; an SDR sequences **60–100 a month**. A searchable database of 60,000
companies is not a product — **a ranked 30 with a reason attached** is.

Four things drive that, and they became the design:

**1. ICP is built backwards from closed-won, not forwards from ambition.**
You cohort won deals on win rate, ACV, cycle length and retention. A segment
that wins fast and *stays* is ICP. The corollary matters more: **anti-ICP is as
valuable as ICP.** A vendor with nine customers in a segment that wins 12% and
churns at 88% NRR does not have a market there — it has a leak. In this build
that became hard suppression: hosting providers, telcos and security vendors
never surface at all.

**2. Fit and intent are two scores, never one.** Fit is slow and
attribute-based; intent is volatile and event-based. Teams that blend them get
a number that cannot be debugged and drifts until everything is 80+.

**3. Signals decay, and they are the message.** "You were breached last week"
is a reason to call; "eight months ago" is embarrassing. And the score tells a
rep *who* — the signal tells them *what to say*. A tool that ranks without
handing over the "why now" just produces a better-sorted list of generic
emails.

**4. Proprietary signals are the moat.** Public triggers — funding rounds,
breach filings — reach every competitor the same morning. The differentiated
signal is one you computed yourself.

That last point is what made this dataset interesting rather than awkward.

---

## What the dataset actually is

Not company data. A **Shodan-style internet-wide port scan**: ~8.6M
`(IP, port)` observations, no employee count, no revenue, no industry, no
company name.

That absence could be read as the dataset being wrong for the brief. I read it
the other way:

> Every other prospecting tool scores companies on **who they are** — firmographics
> anyone can buy. This data scores them on **how exposed they actually are**,
> measured from outside, with evidence the prospect can verify in five minutes.

For a **cybersecurity** vendor specifically, that is not a consolation prize.
It is the strongest possible signal: proprietary, dated, provable, and it writes
the opening line.

```
❌  "Hi, I'd like to tell you about our security software."

✅  "On 14 September a routine internet scan showed a MySQL database at
     Northwind answering directly on the public internet, and your patient
     portal running nginx that is end-of-life with a critical flaw
     (CVE-2025-23419, CVSS 9.1). Nothing here required special access."
```

---

## The use cases I built

Chosen in priority order; each is a screen.

| # | Use case | Screen | Why it earns its place |
|---|---|---|---|
| 1 | *"Who do I call today?"* | **Queue** | The collapse from 60k to 20. The core deliverable |
| 2 | *"Is this worth my time?"* | **Account** | Ranking without evidence is not trusted. Every point itemised |
| 3 | *"Carve me a territory"* | **Segments** | Ownership is what makes reps adopt a tool at all |
| 4 | *"Is the AI behaving?"* | **Ops** | Spend, latency, failures, eval scores — an operator view |

### Deliberately out of scope

CRM sync, authentication, multi-user, email sending, live re-scanning.

One snapshot, one persona (the rep), done properly. In a week, depth on scoring
and evals beats breadth on features — and a half-built Salesforce integration
demonstrates nothing that the queue does not.

### Cut if time ran short

Segments first, then outreach drafting. **Never evals** — that is the
deliverable the brief weighs most, and the one that proves the rest is measured
rather than asserted.

---

## The ICP this is scored against

A fictional but concrete vendor, because "sells cybersecurity software" is not
specific enough to score anything:

> **Aegis** — managed detection + compliance automation. ACV $45k–$180k.
> Sells to regulated mid-market organisations with a thin security team.

| Layer | Attribute |
|---|---|
| Firmographic | 200–2,000 employees (proxied by host count) |
| Regulatory | healthcare, finance, government, manufacturing, education |
| Operational | owns infrastructure; no incumbent security vendor detected |
| Territory | configurable; default US/CA/GB/AU/NZ/IE |

**Hard disqualifiers** (suppressed, not penalised): hosting providers, telcos,
security vendors, single-host micro-entities.

The maturity ladder is the part that predicts the sale in cybersecurity:

```
no owner → IT does it part-time → first security hire → team of 3-5 → SOC + CISO
  ↑ no budget         ↑ buys tools      ↑ AEGIS SELLS HERE    ↑ has an incumbent
```

A 4,500-person company with its own SOC is not a bigger deal. It is a worse one.
The scoring reflects that — `large` footprint scores *lower* than `mid_market`.

---

## Signals: what this data can tell a salesperson

The brief asked what hidden signals could say *"this company needs help"*.
Beyond simply reading the CVE list:

| Signal | Prevalence | Sales meaning |
|---|---|---|
| **Industrial control exposed** | 0.34% | safety and production, not just data |
| **RDP / Telnet open** | 0.36% | the documented ransomware entry vector |
| **CDN bypass** | 0.45% | the protection being paid for can be walked around |
| **Exposed database** | 0.64% | customer data reachable without breaking in |
| **Cloud sprawl** | 0.36% | assets across N providers, no single view |
| **No patch process** | 9.3% | oldest open CVE ≥ 5 years — absence of a programme |
| CVEs | 11.1% | table stakes; every competitor's tool shows these |

The prevalence column *is* the weighting. A finding on 11% of companies is not
a differentiator. One on 0.34% is the entire reason to call today.

---

## What I would do next, with more than a week

1. **A second snapshot.** Everything interesting in prospecting is a *delta* —
   "newly exposed this week" outperforms "exposed" by a wide margin, because it
   is dated and it is news.
2. **Reverse-DNS and WHOIS enrichment** to rescue the 12% of records with no
   usable owner.
3. **Contact discovery** — the queue names companies, not people. A rep still
   has to find the human.
4. **Calibrate the fit model against real outcomes.** Right now the weights are
   reasoned from the closed-won analysis, not fitted to it. With outcome data I
   would fit them and backtest on a holdout.
5. **Suppression list for critical infrastructure**, before this is pointed at
   hospitals and water utilities at scale.
