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
