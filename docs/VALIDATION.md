# Validation

Evidence that `spine/score/score.py` counts what it claims to count.

A scorer that passes only its own unit tests proves the author was consistent,
not correct. So the scorer is checked differentially against a second
implementation written from a published rule, over published ground truth.

## Method

`spine/validate/owasp_benchmark.py` scores the same tool output twice:

**Path A — reference.** `reference_score` re-implements the OWASP Benchmark rule
directly from its definition: a test case is one file carrying one intentional
CWE, detected when the tool reports that CWE anywhere in that file, counted once.
It does not call `score.py`.

**Path B — the corpus scorer.** OWASP's `expectedresults-1.2.csv` is translated
into this corpus's answer-key format — each case spanning its whole file, to
match OWASP's file-level granularity — and run through `match_findings` with
tolerance 0.

The two must produce the same confusion matrix. A defect shared by both would
have to be invented twice, independently.

## Result

Ground truth: OWASP BenchmarkJava 1.2, **2740 cases** (1415 real, 1325 deliberate
non-vulnerabilities). Tool under test: Semgrep 1.163.0 with the community
`p/java` ruleset, 1909 findings.

```
                   tp       fp       fn       tn
reference         840      512      575      813
score.py          840      512      575      813

  [ok] scorers agree
  [ok] every case counted exactly once

recall 0.5936   precision 0.6213   tpr 0.5936   fpr 0.3864   youden j 0.2072
```

### Negative control

The same run with an empty ruleset:

```
                   tp       fp       fn       tn
reference           0        0     1415     1325
score.py            0        0     1415     1325
```

Zero true positives and zero false positives, with every case still accounted
for. The matcher is not fabricating matches, and conservation holds at scale.

## The positive control: can any engine find these cases at all?

The differential check above proves the scorer counts correctly. It says nothing
about whether the fixtures are *reachable*, and a fixture no tool can reach
scores identically to a tool that cannot analyse. `docs/METHODOLOGY.md` therefore
requires a positive control: a stock ruleset over tier 1 must produce non-trivial
recall **and** visibly trip some traps.

Instrument: **CodeQL 2.27.1**, `security-extended`, databases over `tier1/` for
Python, JavaScript/TypeScript, Java (`--build-mode=none`), Go and Ruby. CodeQL is
not a tool under evaluation — see
[THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md).

| | before (#7, 2026-10-10) | after #8 and #9 |
|---|---|---|
| tier-1 cases found | 3 of 223 | **21 of 223** |
| tier-1 traps tripped | 0 of 223 | **5 of 223** |
| recall / precision | 0.005 / 1.000 | 0.094 / 0.808 |
| youden j | 0.005 | 0.072 |

Per language, taking the scorer's true positives against the tier-1 case counts.
Every CodeQL finding here is in tier 1, because the database root was `tier1/`:

| language | found | of | traps tripped | of | scanned |
|---|---|---|---|---|---|
| python | 16 | 49 | 5 | 47 | yes |
| java | 2 | 37 | 0 | 39 | yes, `--build-mode=none` |
| javascript | 2 | 23 | 0 | 23 | yes |
| typescript | 1 | 10 | 0 | 10 | yes, via the JS extractor |
| go | 0 | 16 | 0 | 16 | yes — see below |
| ruby | 0 | 10 | 0 | 10 | yes |
| c, cpp, csharp, kotlin, php, rust, swift | — | 77 | — | 77 | no |

### What changed, and what did not

The gain is attributable, not incidental. Five of the newly found cases are ones
whose only change was an entry point:

```
c-355e5956  python/flask   CWE-89   concat-statement       py/sql-injection
c-b97304b5  python/flask   CWE-89   concat-statement       py/sql-injection
c-c0a8e07d  python/flask   CWE-89   concat-statement       py/sql-injection
c-eb56803d  python/flask   CWE-200  stack-trace-to-client  py/stack-trace-exposure
c-b26ddc35  typescript/nestjs CWE-78 shell-string          js/command-line-injection
```

Before #9 those fixtures named a framework they never imported, so there was no
remote source for a taint engine to start from. The traps went from 0 to 5 for
the same reason: a reachable source is what lets a tool form an opinion about a
sanitizer at all, and 4 of the 21 hits are on `sanitizer: ineffective` cases —
the slice that exists specifically to separate engines that evaluate a filter
from engines that merely notice one.

**The control still fails its first requirement.** 0.094 is not non-trivial
recall. Three causes are filed and open:

- **#12** — Go fixtures sit outside any module, so the Go extractor reads 3 of 60
  source files and the 16-case Go block produces no signal.
- **Java is read without a build.** `--build-mode=none` gives no dependency
  resolution, so Spring annotations do not resolve and framework-mediated flow is
  invisible. 2 of 37 is a reading of that setting, not of the fixtures.
- Seven languages have no CodeQL run here at all (**77 cases**), so a third of
  tier 1 is untested by this control rather than failed by it.

### This is not a verdict on CodeQL

It is one stock suite, with no dependency resolution for Java and no module for
Go, on a corpus that is still being repaired. The figure belongs in this document
as an instrument reading and nowhere else. Per
[THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md), nothing above was relabelled or
widened to make it match — every case it missed is still recorded as a miss.

Reproduce:

```bash
# scan a copy: the Go extractor rewrites go.mod in the tree it reads (#14)
codeql database create DB --language=python --source-root=tier1
codeql database analyze DB \
    codeql/python-queries:codeql-suites/python-security-extended.qls \
    --format=sarif-latest --output=out.sarif
# the database root is tier1/, so prefix every result URI with tier1/ first
python3 spine/score/score.py out.sarif answers/expectedresults-1.0.csv
```

## The adapters are validated separately, against real output

The differential check above covers the scorer. It says nothing about the
adapters, and an adapter is just as capable of producing a confidently wrong
scorecard — more so, because its failures are silent.

Two adapters are now driven by captured real output rather than fixtures written
here:

| Fixture | Captured from | What it proved |
|---|---|---|
| `spine/tests/data/real-semgrep.sarif` | a live Semgrep scan of `tier1` | the CSV round trip preserves every finding, path, line and CWE |
| `spine/tests/data/real-sonarqube.json` | a live SonarQube 25.1 Community scan of `tier1` | the adapter's CWE source did not exist |

The second is the reason this section exists. `sonarqube.py` read the CWE from
the rule's `securityStandards`; on that version the API rejects the field
outright. Every finding would have arrived with no CWE and fallen back to the
location-only rule. The unit tests all passed, because the fixture they ran
against was written by the same person who wrote the assumption.

A regression test now asserts that no rule in the captured export carries
`securityStandards`, so a return to the false premise fails loudly.

## What this does not establish

**SARIF parsing is not independently validated.** Both paths call `parse_sarif`,
so the agreement covers matching, deduplication and counting — not CWE
extraction or location reading. Those carry their own unit tests, including the
five encodings tools use for CWE, but a parser defect would appear identically
on both paths and go unnoticed here.

**The published-scorecard comparison is not exact.** OWASP's own scorecards were
produced with different tool versions and rulesets, so the figures above cannot
be matched against them number for number. What is validated is the *scoring
rule*, against ground truth this project did not author.

**The tool result is not a verdict on Semgrep.** It is one community ruleset on a
synthetic Java suite, which is the most favourable and least representative case
there is. See [THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md).

## Reproducing

```bash
curl -sSL -O https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git

cd BenchmarkJava && semgrep scan --config=p/java --sarif \
    --output=../benchmark.sarif --metrics=off --no-git-ignore \
    src/main/java/org/owasp/benchmark/testcode/ && cd ..

python3 spine/validate/owasp_benchmark.py \
    --expected expectedresults-1.2.csv \
    --source BenchmarkJava \
    --results benchmark.sarif
```

Exit code 0 means both scorers agreed and every case was counted once.
