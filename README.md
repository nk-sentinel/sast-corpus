# sast-corpus

A tool-neutral, multi-language corpus for measuring SAST **accuracy** (TP / FP / FN / TN)
and **scan time** under a documented, reproducible scoring contract.

Built to evaluate several SAST platforms head-to-head — source-only scanners,
build-required commercial engines, CodeQL, and LLM-based scanners — on the same
ground truth, with the same match rules.

## What is in it

| | |
|---|---|
| Cases | **589** — 446 tier-1 synthetic, 46 tier-2 real-application, 97 tier-3 real CVEs |
| False-positive traps | **256 (43%)** |
| Weaknesses | **42 CWEs — all 25 of the 2025 CWE Top 25** |
| OWASP Top 10 (2021) | **10 of 10** categories |
| Languages | 13, **none below 10 weaknesses** |
| Detection planes | `vuln` 534 · `secret` 31 · `sca` 24 |
| Visible to build-required engines | tier-1 Java, plus 28 of 28 CVE projects that compile |
| Scan-time corpus | 4 real repositories, 15k → 4.6M measured code lines |

**Read the depth table before the totals.** 42 CWEs is a corpus-wide figure, and
no language carries all of them. Every language clears a floor of 10, which is
where a per-language number starts to mean something, but a row resting near the
floor is a sample rather than a verdict.

**105 of the cases are hard ones**, and they are the point. Obfuscation —
aliasing, collections, object fields, callbacks, reflection and strong updates —
was zero cases before; ineffective sanitizers were four. A direct flow with a
clean sibling is caught by a regular expression and by a commercial dataflow
engine alike, so a corpus made only of those cannot rank the tools it exists to
rank. Grid density is 34% of all cells, or **44% of the cells where the
weakness can actually arise** — use-after-free in Java and XXE in C are not
gaps, and `spine/report/applicability.json` says which pairs are real and is
checked against the answer key in CI. [docs/COVERAGE.md](docs/COVERAGE.md) ranks
languages thinnest-first for exactly that reason.

Phase 2 in [docs/ROADMAP.md](docs/ROADMAP.md) put the growth into the axes
that separate tools rather than into more direct flows: obfuscation went from
0 to 53 cases and ineffective sanitizers from 4 to 28. Four of its five items
are done; what remains is tier 3 at scale, at 97 of ~230 real-CVE cases.

[docs/COVERAGE.md](docs/COVERAGE.md) holds the language × weakness matrix,
depth per language, the mechanisms each weakness is tested through, and an
explicit list of what is **not** covered. It is generated from the answer key
and checked in CI, so it cannot drift.

Read the gaps before the coverage. A language with no cases contributes nothing
to a scorecard, which looks exactly like a tool having nothing to find.

Weaknesses are tested through **named mechanisms**, not one case each. SQL
injection alone spans concatenation into a statement, a query concatenated
*before* being prepared, and an identifier that cannot be bound at all — a tool
can catch the first and miss the rest. Context traps sit alongside them, asking
whether a scanner can tell code from a changelog, a comment, or test data.

## Design rules

Four rules make the numbers meaningful. Breaking any one invalidates a comparison.

**1. The answer key is external.** Ground truth lives in `answers/` and nowhere else.
No tier-1 fixture contains a CWE identifier, a category name, a hint comment, or a
telltale filename. A scanner — or an LLM — must analyse the code to score.
Enforced by `spine/lint/antileak.py` in CI.

**2. The match policy is written down before the scan.** [docs/MATCH-POLICY.md](docs/MATCH-POLICY.md)
fixes path normalization, line tolerance, CWE equivalence, and deduplication. Tools
report findings at the source, at the sink, or mid-flow; without a fixed policy you
measure reporting style, not detection.

**3. Accuracy and performance use different corpora.** `tier1/` and `tier3/` are small and
densely labelled. `perf/` holds large real repositories and is never accuracy-scored.
Timing a few thousand lines of fixtures tells you nothing about a 600k-LOC repository.

**4. Tiers are never merged.** Tier 1 is where every tool looks good; tier 3 is
where they separate. A combined figure hides the difference that matters most.

## Is the scorer trustworthy?

It is checked differentially against a second implementation of the OWASP
Benchmark rule, over **2740 published cases**. Both produce the same confusion
matrix, and an empty ruleset scores 0 TP / 0 FP with every case still accounted
for. See [docs/VALIDATION.md](docs/VALIDATION.md) — including what that does
*not* establish.

## Layout

```
spine/           machinery — schema, scorer, adapters, lint, timing, generator, corpora
answers/         ground truth: cases/*.yml (authoring) → expectedresults-<version>.csv (scoring)
tier1/           synthetic micro-fixtures, generated + hand-authored          (committed)
tier3/           real CVE reproductions, derived from cwe-bench-java          (fetched)
tier2/           real vulnerable applications — PyGoat labelled, 4 more pinned (fetched)
perf/            repositories for scan-time measurement only                  (fetched)
build/           build and syntax recipes, pinned toolchains
docs/            COVERAGE · ROADMAP · TIER3-DATASETS · AIRGAP-EXPORT · MATCH-POLICY · METHODOLOGY · EXTERNAL-CORPORA · THREATS-TO-VALIDITY · VALIDATION
```

Directory and file names under `tier1/` carry no semantic content. Navigate via
`answers/`, not the tree.

## Fetching the external corpora

```bash
python3 spine/corpora/fetch.py tier3          # CVE datasets
python3 spine/corpora/fetch.py perf           # scan-time targets
python3 spine/corpora/fetch.py perf --check   # status without cloning
```

**Exporting to an environment without GitHub access?** See
[docs/AIRGAP-EXPORT.md](docs/AIRGAP-EXPORT.md). 88% of the fetched footprint is
build output that is regenerated on arrival, so the transfer is ~2.5 GB rather
than 27 GB — but the dependency source has to be settled before the transfer,
not during the evaluation.

Pinned to full commit SHAs rather than vendored: those trees are far larger than
this repository and are code we did not write. A manifest whose revision is a
branch or an abbreviated SHA is rejected, because a corpus fetched from a moving
branch is not a corpus.

**Tier 3 is derived and usable** — 97 cases in four languages: 28 Java CVEs
from cwe-bench-java across path traversal, XSS, command injection and code
injection, 21 traps taken from their fixing commits, and 48 CVEs in Go, Python
and JavaScript from PatchEval. Growing it to ~230 is the open roadmap item.
**Tier 2 has its first labelled application**: 46 PyGoat cases, hand-labelled
from the code and cross-checked against RealVuln's independent labelling.
WebGoat, DVJA, NodeGoat and Juice Shop are pinned but unlabelled — see
[docs/EXTERNAL-CORPORA.md](docs/EXTERNAL-CORPORA.md).

## Scoring a tool

```bash
# 1. scan, exporting SARIF 2.1.0
your-tool scan ./tier1 --format sarif -o results.sarif

# 2. score against the answer key
python3 spine/score/score.py results.sarif answers/expectedresults-1.0.csv

# tools that cannot emit SARIF go through an adapter first
python3 spine/adapters/generic_csv.py fortify.csv --tool Fortify \
    --path-column File --line-column Line --cwe-column CWE > results.sarif
```

Add `--timing runs/<name>.json` to fold scan time into the same report.

The output states what the corpus knows, what the tool did, and how long it
took. It contains **no pass or fail** — no thresholds, no verdicts. Deciding
whether a number is good enough is the reader's job, and a threshold baked into
the tool would only be one more thing to argue with.

```
WHAT THE CORPUS KNOWS
      78  known issues
      69  pieces of code that resemble issues but are not (traps)

WHAT THE TOOL DID
      11  found, of 78 known issues
      67  missed
       2  false alarms — reported on code the corpus states is safe
       6  reported outside the answer key — not judged either way
```

Those last two lines stay separate on purpose. A finding on a deliberate trap is
a **confirmed** false positive — the corpus asserts that code is safe. A finding
somewhere else may be a real issue the corpus does not know about, since cases
exist only because someone thought to write them. Reporting the second as a
false positive would charge the tool for the corpus's blind spots.

The scorer is a single standard-library Python file with no dependencies, so a
result can be reproduced offline by anyone holding the corpus.

For SonarQube the whole path is one command:

```bash
SONAR_TOKEN=squ_xxx ./spine/adapters/capture-sonarqube.sh
```

It scans, waits for the compute engine, exports, enriches the rules with their
CWEs, converts and scores. Each of those steps exists because skipping it fails
silently — see [spine/adapters/README.md](spine/adapters/README.md).

## Timing a tool

```bash
python3 spine/timing/bench.py --tool <name> --target perf/commons-lang \
    --runs 5 --warmup 1 --cache cold --out runs/<name>-commons-lang.json
```

Targets: `perf/commons-cli` (15,716 code lines), `perf/commons-lang` (129,508),
`perf/spring-boot` (642,008), `perf/hadoop` (4,655,050) — all measured by
codeprint at the pinned revision, not estimated.

Build time, analysis time, and upload/queue-wait are recorded as separate phases,
because a hosted scanner's queue is not scan speed. The LOC denominator is
*scanned* lines — source only, excluding vendored, generated and binary files.

## Running the gates

```bash
pip install pyyaml jsonschema               # authoring side only; score.py needs nothing
python3 spine/lint/antileak.py              # < 0.1s — must pass
python3 spine/lint/antileak.py --disclose   # slow; leakage figure for a scorecard
python3 spine/schema/compile_answers.py     # regenerate the answer key
python3 spine/report/coverage.py            # regenerate docs/COVERAGE.md
./build/verify.sh                           # compile and parse every fixture
SYNTAX_USE_DOCKER=1 ./build/verify.sh       # additionally parse PHP and Ruby
python3 -m unittest discover -s spine/tests -t .
```

Enforcement and disclosure are deliberately separate. The gate covers fixtures we
authored and runs on every push; walking the vendored tiers reads whole real
repositories and is only wanted when writing a scorecard.

**8 of 13 languages are parse-verified**: Python, JavaScript, Go, C, C++ and Rust
from local toolchains, plus PHP and Ruby via `SYNTAX_USE_DOCKER=1` (on in CI).
TypeScript, C#, Kotlin and Swift have no toolchain here and are reported as
*skipped*, never as passed — a fixture that does not parse yields nothing from
any tool, which in a scorecard is indistinguishable from every tool missing it.

## Reporting

Always report recall and precision separately, never a single composite. Published
studies have found tools at 100% precision and under 25% recall simultaneously; one
number hides that completely. Always report tiers separately too — tier-1-only
figures overstate every tool, and by an amount that differs between tools.

Report the **location-only match count** alongside any result. Those are findings
that matched on position because the tool emitted no CWE, and they rest on weaker
evidence than the rest.

[docs/THREATS-TO-VALIDITY.md](docs/THREATS-TO-VALIDITY.md) lists what a result does
**not** prove. Read it before quoting a number.

### Publishing results

Commercial static-analysis licences commonly restrict publishing named benchmark
results. Internal evaluation is unaffected; anything leaving the organisation should
anonymise tool identities and be cleared first.

## Contributing a case

1. Write the fixture under `tier1/<lang>/<opaque-id>/` — no comments, no hints.
2. Write `answers/cases/<id>.yml` (see `spine/schema/case.schema.json`).
3. Run `python3 spine/schema/compile_answers.py` to regenerate the answer key.
4. Run `python3 spine/lint/antileak.py` — it must pass.
5. Run `python3 spine/report/coverage.py` and commit the result.

Generated cases come from `spine/gen/` instead; edit the template, not the output.

Every vulnerable case should have a matching `label: safe` sibling wherever a
plausible-but-safe variant exists. False-positive traps are first-class cases, not
an afterthought; a corpus without them cannot measure a false-positive rate at all,
and the false-positive rate is what decides whether developers trust a tool.
