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

### `unmatched` is a ground-truth smoke alarm

Treat a finding that landed inside a scored fixture but matched nothing as a
defect in the answer key until proven otherwise.

A real instance: command-injection cases were authored with
`acceptable_cwes: [CWE-78, CWE-77, CWE-88]`. Semgrep tags several of its
command-execution rules **CWE-94**, so its PHP, Ruby and Go findings landed in
`unmatched` and those languages scored 0.000, 0.333 and 0.000 recall. The
scorecard said the tool had no PHP or Ruby coverage. It had loaded 156 rules for
them and found the flaws.

Adding CWE-94 to the class moved overall recall from 0.478 to 0.609 and Youden's
J from 0.391 to 0.478. Nothing but the `unmatched` count would have revealed it:
every other number looked entirely plausible.

**That fix was wrong, and has been reversed.** It is kept here because the way it
was wrong is the more useful lesson. CWE-78 descends from CWE-77 and CWE-74, not
from CWE-94: injecting a shell metacharacter into a command string is not
injecting code into a language runtime. The widening was adopted because a
specific scanner tags its rules that way, which is taxonomy preference, not
defensibility — precisely what `acceptable_cwes` is supposed to exclude.

It was also applied unevenly. The change went into the generator template, so all
28 generated cases inherited it while 26 hand-authored ones never did. A tool
tagging CWE-94 therefore scored a true positive on some command-injection cases
and landed in `unmatched` on others — the same weakness, the same tool, the
outcome decided by which case it happened to reach. All 76 now carry
`[CWE-78, CWE-77, CWE-88]`, bar one that legitimately also accepts CWE-502.

So the rule the incident actually supports is narrower than it first looked: an
`unmatched` finding means *go read the code and the CWE definitions*. It does not
mean adopt the tool's taxonomy. Widening a class until a scanner's findings land
raises that scanner's score by construction, and [THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md)
now forbids doing it from a candidate's output.

So when a tool scores unexpectedly badly on a language, read the unmatched
findings before believing the result.

### Right place, other weakness — reported, never credited

`unmatched` pools two different things: a finding on code the corpus knows
nothing about, and a finding sitting squarely on a scored case under a name the
case does not accept. The scorer now splits the second out and reports it as
*right place, other weakness*. It still counts neither way.

That number is the one to read before anyone proposes widening a class. A run of
CodeQL `security-extended` over tier 1 produced 18 unmatched findings, **16** of
them on a known case's location:

| rule | reported | case | what it actually is |
|---|---|---|---|
| `py/reflective-xss` ×8 | CWE-79, CWE-116 | CWE-434, CWE-502, CWE-918 | a **real second weakness** — the handler echoes the value back |
| `py/log-injection` ×3 | CWE-117 | CWE-532 | a real second weakness at the same log call |
| `java/xss` ×2 | CWE-79 | CWE-862, CWE-863 | a real second weakness in an authz fixture |
| `rb/csrf-protection-not-enabled` | CWE-352 | CWE-78 | unrelated |
| `js/incomplete-sanitization` | CWE-116, CWE-20, CWE-80 | CWE-22 `only-one-occurrence` | genuine taxonomy disagreement |
| `js/regex/missing-regexp-anchor` | CWE-20 | CWE-918 `pattern-tests-anywhere` | genuine taxonomy disagreement |

So **14 of 16 are a different weakness, not a different name for the same one.**
Widening `acceptable_cwes` to absorb them would credit an SSRF case because a
tool found a cross-site scripting flaw three lines away. That is the CWE-94
failure mode again, in a form that looks more reasonable because the finding is
real.

### The CWE-20 and CWE-116 decision

Resolved 2026-10-10 from the CWE definitions, against widening. Both refused:

- **`CWE-20` is refused everywhere.** It is too broad to carry information, and
  it already exists as a `primary_cwe` in this corpus for cases that genuinely
  are nothing but a missing check. Accepting it elsewhere would make a precise
  case and a vague one indistinguishable in the scorecard.
- **`CWE-116` is refused outside the output-encoding classes.** It stays in the
  CWE-79 family, where improper escaping of output *is* the weakness. It is not
  added to CWE-22: CWE-116 is about encoding output for a downstream
  interpreter, and a filesystem path handed to `open()` is not that. The
  canonical answers for a path-traversal filter defect are CWE-22's own children
  and CWE-180/181 (validate-before-canonicalise), not CWE-116.

The cost of refusing is two findings that are correct about the mechanism and
land in `unmatched`. That costs the tool nothing — `unmatched` is charged neither
way — and the *right place, other weakness* count now makes the disagreement
visible without converting it into credit.

**A caveat this surfaced.** Several tier-1 fixtures carry an incidental second
weakness: the python handlers that return the request value also have a reflected
XSS, and the credential-logging cases also have log injection. The policy handles
it correctly — no credit, no penalty — but it means *right place, other weakness*
is not a pure taxonomy-disagreement signal. Read the rules before concluding
anything from the count.

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
