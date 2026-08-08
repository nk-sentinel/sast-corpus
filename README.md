# sast-corpus

A tool-neutral, multi-language corpus for measuring SAST **accuracy** (TP / FP / FN / TN)
and **scan time** under a documented, reproducible scoring contract.

Built to evaluate several SAST platforms head-to-head — source-only scanners,
build-required commercial engines, CodeQL, and LLM-based scanners — on the same
ground truth, with the same match rules.

## Design rules

Three rules make the numbers meaningful. Breaking any one of them invalidates a comparison.

**1. The answer key is external.** Ground truth lives in `answers/` and nowhere else.
No test file contains a CWE identifier, a category name, a hint comment, or a
telltale filename. A scanner — or an LLM — must analyse the code to score.
Enforced by `spine/lint/antileak.py` in CI.

**2. The match policy is written down before the scan.** `docs/MATCH-POLICY.md` fixes
path normalization, line tolerance, CWE equivalence, and deduplication. Tools report
findings at the source, at the sink, or mid-flow; without a fixed policy you measure
reporting style, not detection.

**3. Accuracy and performance use different corpora.** `tier1/`–`tier3/` are small and
densely labelled. `perf/` holds large real repositories and is never accuracy-scored.
Timing a few thousand lines of fixtures tells you nothing about a 200k-LOC repository.

## Is the scorer trustworthy?

It is checked differentially against a second implementation of the OWASP
Benchmark rule, over 2740 published cases. Both produce the same confusion
matrix, and an empty ruleset scores 0 TP / 0 FP with every case still accounted
for. See [docs/VALIDATION.md](docs/VALIDATION.md) — including what that does
*not* establish.

## What does it cover?

[docs/COVERAGE.md](docs/COVERAGE.md) — the language x weakness matrix, OWASP
and CWE rollups, and an explicit list of what is **not** covered. Generated
from the answer key and checked in CI, so it cannot drift.

Read the gaps first. A language with no cases contributes nothing to a
scorecard, which looks exactly like a tool having nothing to find.

## Layout

```
spine/           language-agnostic machinery — schema, scorer, adapters, lint, timing, generator
answers/         ground truth: cases/*.yml (authoring) → expectedresults-<version>.csv (scoring)
tier1/           synthetic micro-fixtures, generated + hand-authored
tier2/           real open-source vulnerable applications (pinned submodules)
tier3/           real CVE reproductions
perf/            large real repositories, LOC-bucketed, for scan-time measurement only
build/           hermetic build recipes + pinned toolchains
docs/            COVERAGE · MATCH-POLICY · METHODOLOGY · THREATS-TO-VALIDITY · VALIDATION
```

Directory and file names under `tier*/` carry no semantic content. Navigate via
`answers/`, not the tree.

## Scoring a tool

```bash
# 1. scan, exporting SARIF 2.1.0
your-tool scan ./tier1 --format sarif -o results.sarif

# 2. score against the answer key
python3 spine/score/score.py results.sarif answers/expectedresults-1.0.csv

# tools that cannot emit SARIF go through an adapter first
python3 spine/adapters/sonarqube.py raw.json > results.sarif
```

The scorer is a single standard-library Python file with no dependencies, so a
result can be reproduced offline by anyone holding the corpus.

## Timing a tool

```bash
python3 spine/timing/bench.py --tool <name> --target perf/java-200k \
    --runs 5 --warmup 1 --cache cold --out runs/<name>-java-200k.json
```

Build time, analysis time, and upload/queue-wait are recorded as separate phases.
Scanned LOC — source only, excluding vendored, generated and binary files — comes
from `codeprint`, so `seconds per 1k LOC` is comparable across tools.

## Reporting

Always report recall and precision separately, never a single composite. Published
studies have found tools at 100% precision and under 25% recall simultaneously; one
number hides that completely. Always report tiers separately too — tier-1-only
figures overstate every tool.

`docs/THREATS-TO-VALIDITY.md` lists what a result does **not** prove. Read it before
quoting a number.

### Publishing results

Commercial static-analysis licences commonly restrict publishing named benchmark
results. Internal evaluation is unaffected; anything leaving the organisation should
anonymise tool identities and be cleared first.

## Contributing a case

1. Write the fixture under `tier1/<lang>/<opaque-id>/` — no comments, no hints.
2. Write `answers/cases/<id>.yml` (see `spine/schema/case.schema.json`).
3. Run `python3 spine/schema/compile_answers.py` to regenerate the answer key.
4. Run `python3 spine/lint/antileak.py` — it must pass.

Every vulnerable case should have a matching `label: safe` sibling wherever a
plausible-but-safe variant exists. False-positive traps are first-class cases, not
an afterthought; a corpus without them cannot measure a false-positive rate.
