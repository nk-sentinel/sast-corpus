# Match policy

This is the scoring contract. `spine/score/score.py` implements exactly what is
written here; changing one without the other is a bug.

Why it exists: tools report the same flaw at the source, at the sink, or somewhere
in between, with different CWEs and different path prefixes. Without a fixed
policy, a comparison measures reporting style rather than detection ability.

**Every scorecard states the policy that produced it.** A number quoted without
its tolerance and CWE rules is not comparable with anyone else's.

## 1. What a finding is

One SARIF `result` may carry several `locations`. Each becomes a candidate, but
all of them share a *result key*, and a result key can be credited **once**. A
single reported issue is a single claim, however many places the tool prints it.

Taint-path steps (`codeFlows[].threadFlows[].locations[]`) are **excluded by
default**. Including them would let a tool that emits a forty-step flow claim
credit for anything along the path. `--include-flow-locations` turns them on;
the scorecard records which mode ran.

## 2. Path matching

The reported URI is normalised: `file://` scheme stripped, leading `./` removed,
backslashes converted to `/`. It matches when it is **equal to** the answer-key
path, or **ends with `/` + the answer-key path**.

The separator anchor matters. `tier1/java/...` must not be satisfied by
`/x/notier1/java/...`.

Suffix matching is required, not a convenience: tools report container-internal
absolute paths (`/build/ws/tier1/...`) for a file the answer key names relatively.

## 3. Line matching

Tolerance **widens the whole ground-truth range**, so a long sink is not
penalised for its length. With `[start_line, end_line]` and tolerance `T`, a
finding matches when its own range overlaps `[start_line − T, end_line + T]`.

Default `T = 10`. Configurable via `--tolerance`, always recorded in the output.

## 4. CWE matching

| Tool emits | Rule |
|---|---|
| a CWE in `acceptable_cwes` | match |
| a CWE outside `acceptable_cwes` | no match |
| no CWE at all | **location-only match**, counted and reported separately |

`acceptable_cwes` lists every CWE a scanner could defensibly report for that
flaw. Scoring a tool down for choosing a reasonable sibling measures taxonomy
preference, not detection.

The location-only rule keeps tools that omit CWE from being unfairly zeroed,
without handing them free credit: the scorecard reports
`location_only_matches`, and any result leaning on them needs that caveat.

CWE is read from all five places tools put it — rule tags (`external/cwe/cwe-089`),
rule properties, result properties, SARIF taxa resolved against a CWE taxonomy,
and rule relationships. Zero padding is normalised (`CWE-089` → `CWE-89`).

## 5. Alternative locations

A case may declare `alt_locations` — normally the taint source, when the primary
location is the sink. A hit at **any** declared location counts. Tools that report
at the head of a chain of evidence are not penalised for it.

## 6. Assignment

Candidate `(case, finding)` pairs are ordered by quality — a CWE-bearing match
before a location-only one, then by line distance — and assigned greedily:

- a case may be claimed **once**
- a result key may claim **once**

So neither a verbose tool nor a long ground-truth range can inflate a score.

## 7. Outcomes

| Case label | Claimed | Outcome |
|---|---|---|
| `vulnerable` | yes | **TP** |
| `vulnerable` | no | **FN** |
| `safe` | yes | **FP** |
| `safe` | no | **TN** |

Findings that never became a candidate for any case are **unmatched**. Findings
that were candidates but lost the assignment are **surplus**. Neither counts as
a false positive.

That is deliberate. Counting every unrelated rule that fires anywhere in the
corpus as an FP would swamp the signal the traps exist to measure, and would
punish a tool for having broader coverage than this corpus scores. Both totals
are reported, and a large `unmatched` count is itself worth investigating.

## 8. Missing runs

`--strict` treats an absent results file as zero findings, so every vulnerable
case becomes a false negative. A crashed, timed-out, or unsupported scan is a
failure to detect, not an absence of evidence.

Without `--strict`, a missing file is an error (exit 2) rather than a silent zero.

## 9. Metrics

```
precision = TP / (TP + FP)          recall = TPR = TP / (TP + FN)
FPR       = FP / (FP + TN)          Youden's J = TPR − FPR
F_β       = (1 + β²)·P·R / (β²·P + R)
```

Both **F1** and **F3** are reported. F3 weights recall nine times over precision,
matching the asymmetry in a regulated setting: a missed critical finding is a
regulatory failure, a false positive is a developer-experience problem.

Undefined ratios (zero denominator) report `0.0` and are **named in `undefined`**,
so a tool that reported nothing is not quietly indistinguishable from one that
reported perfectly.

Results are broken down by language, tier, plane, CWE, severity, and each
difficulty dimension, with **both** micro (pooled) and macro (category-averaged)
aggregation. They disagree, and the disagreement is informative: macro exposes
blindness to a small category that pooling hides.

### Reporting rule

Never quote a composite alone, and never merge tiers. Published studies have
found tools at 100% precision and under 25% recall simultaneously; a single
number hides that entirely. Tier-1-only figures overstate every tool.
