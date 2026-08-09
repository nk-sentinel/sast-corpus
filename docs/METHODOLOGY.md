# Methodology

How the corpus is built and how a run is conducted. The scoring rules live in
[MATCH-POLICY.md](MATCH-POLICY.md); what the results do not prove lives in
[THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md).

## Tiers

Three tiers, always scored and reported separately, because they answer
different questions.

| Tier | What it is | Answers |
|---|---|---|
| **1** | Synthetic micro-fixtures, generated base plus hand-authored hard cases | Does the tool recognise this weakness pattern at all? |
| **2** | Real open-source vulnerable applications, pinned as submodules | Does it survive real framework code and cross-file flow? |
| **3** | Real CVE reproductions | Does it find what actually shipped and got exploited? |

Merging them produces a number that means nothing. Tier 1 is where every tool
looks good; tier 3 is where they separate.

## Planes

Four detection planes, each with its own ground-truth shape and its own traps.
A tool is scored only on planes it claims to cover.

| Plane | Ground truth | False-positive traps |
|---|---|---|
| `vuln` | CWE + location | ORM calls that resemble injection; sanitized-then-used flows; effective custom sanitizers |
| `secret` | secret kind, location, live-validatable | High-entropy non-secrets — UUIDs, hashes, base64 assets — plus example configs and test fixtures |
| `sca` | purl, version, CVE, scope | Vulnerable version present but unreachable; dev/test-scope only; patched fork |
| `crypto` | delegated to the `CipherRadarTestProj` submodule | already covered there |

## Authoring

**Generated base.** `spine/gen/` produces the combinatorial matrix — source ×
sink × sanitizer × framework — per language. This gives balanced CWE coverage
cheaply and enforces anti-leakage mechanically, since nothing is emitted that a
template did not put there.

**Hand-authored hard cases.** Generators cannot express the cases that actually
separate tools: inter-file taint through a field alias, framework-mediated flow,
a custom sanitizer that works, one that looks like it works but does not. These
are written and labelled by hand with a rationale in `evidence`.

**Traps are first-class.** Every vulnerable case gets a `label: safe` sibling
wherever a plausible-but-safe variant exists. A corpus without traps cannot
measure a false-positive rate at all, and the false-positive rate is the number
that decides whether developers trust the tool. Aim for roughly 15% of cases
being traps, which is where published real-world benchmarks sit.

**A long taint path is not the same as a hard case.** `flow` describes how far
the value travels. It does *not* say whether detection requires following it,
and the two come apart constantly.

The first inter-file cases written here put the concatenation and the sink in
the same method — the value had crossed two files to get there, but a single-file
pattern matcher flagged the sink on shape alone and scored full marks. The label
claimed a difficulty the fixture did not have.

A case only discriminates when **no single file contains both the untrusted
input and the suspicious sink pattern**. Split the roles:

| File | Holds | Looks like |
|---|---|---|
| controller | the framework binding | no query code at all |
| query builder | the concatenation | ordinary string work, no SQL API |
| runner | the sink | executes a string parameter, concatenates nothing |

Then write the safe sibling with the *same three roles* and the same sink
expression, differing only in provenance. A tool that cannot tell them apart
will either miss both or report both — and either way the corpus has learned
something a single case could not tell it.

When authoring, check the claim: run a single-file matcher and confirm it does
not score the case for free.

**Difficulty is labelled.** Every case records `flow`, `sanitizer` and
`obfuscation`. Existing suites omit this, which makes it impossible to tell
whether a tool handles easy cases or hard ones. With it, the output becomes
"handles intra-procedural, collapses on inter-file" rather than a bare
percentage — which is the finding that actually drives a decision.

## Anti-leakage

Fixtures under `tier1/` contain no CWE identifiers, no category names, no
giveaway identifiers, no rule-test annotations, and **no comments at all**. The
answer key lives only in `answers/`. Enforced by `spine/lint/antileak.py` in CI.

Engine rule unit-tests — Semgrep/OpenGrep `// ruleid:` style — must live in the
engine's own repository, never here. They are answer keys written into the code.

Tiers 2 and 3 are vendored unchanged and cannot meet this bar; their leaks are
reported as warnings and disclosed in the results.

Enforcement and disclosure are separate runs. The gate covers authored fixtures
and takes well under a second, so it can run on every push. Walking the vendored
tiers means reading whole real repositories and takes over a minute, so it is
opt-in behind `--disclose` and belongs with scorecard production. Charging every
push for a report nobody is reading at that moment is how a gate ends up
switched off. The error result is identical either way.

## Reproducible build

Build-required engines (Fortify, Coverity, Veracode) analyse compiled artifacts
and see nothing in a fixture that does not compile — scoring zero in a way that
is indistinguishable from poor detection. So the build gate is load-bearing, not
hygiene.

- Toolchain containers pinned **by digest**, one per language
- **Every dependency pinned to an exact version.** Not for connectivity — this
  environment has internet and resolves from Maven Central, npm and PyPI
  directly. Pinning is about time: a corpus that resolves a range would quietly
  change what it is testing between runs, and two scorecards taken a month apart
  would not be comparable. Ranges and `latest` are forbidden; lockfiles are
  committed.
- `build/verify.sh` compiles every buildable tier in CI on each pull request

Because versions are pinned rather than resolved, running this corpus inside an
air-gapped network later is a matter of pointing the toolchains at a mirror. No
fixture or recipe changes.

## Conducting a run

1. `python3 spine/lint/antileak.py` — must pass
2. `python3 spine/schema/compile_answers.py` — regenerate the answer key
3. `build/verify.sh` — required before any build-required engine
4. Scan, exporting SARIF 2.1.0 (or convert via `spine/adapters/`)
5. `python3 spine/score/score.py results.sarif answers/expectedresults-<v>.csv --json`

Record with every scorecard: tool version, ruleset and whether it was tuned,
container digest, corpus commit, and the match policy the scorer printed.

## Timing

Accuracy and performance use **different corpora**. `perf/` holds real
repositories bucketed at roughly 10k, 50k, 200k and 500k+ LOC, straddling the
thresholds the NFRs care about.

- At least 5 timed runs, 1 warmup; cold-cache runs use a drop-caches prepare step
- Phases recorded separately: provisioning, build, analysis, upload/queue-wait.
  A hosted scanner's queue time is not scan speed and must not be reported as such.
- The LOC denominator is *scanned* LOC from `codeprint` — source only, excluding
  vendored, generated and binary files. Raw line counts flatter tools unevenly.
- Reported: p50/p95 wall clock, peak RSS, and seconds per 1k scanned LOC
- A host whose repeated runs vary by more than 10% relative standard deviation is
  too noisy to publish from

## The reference scanner is an instrument, not a subject

A scanner is run against this corpus during development for one reason: to test
the corpus. Its scores are instrument readings. They are not an evaluation of
that tool and must never be quoted as one — one community ruleset on tier-1
synthetic fixtures is the most favourable and least representative measurement
available.

Running one is not optional, though. Without it there is no way to know whether
a fixture is detectable at all, whether the answer key's line numbers point at
the right place, or whether a trap is a fair trap rather than an impossible one.
Two real defects were found exactly this way:

- A stock ruleset scored 1.000 recall and 1.000 precision on fixtures labelled
  `inter-file` and `framework-mediated`, which proved the labels were wrong: the
  concatenation and the sink shared a method, so a single-file matcher scored
  them for free.
- The same ruleset's findings landed in `unmatched` on three languages because
  its CWE tagging was outside the `acceptable_cwes` those cases declared. The
  scorecard read as missing tool coverage; it was a defect in the ground truth.

Neither is visible from reading the fixtures.

## Controls

Two checks prove the harness is measuring rather than fabricating:

- **Negative control** — a scanner with all rules disabled must score 0 TP and
  0 FP. Anything else means the matcher is inventing matches.
- **Positive control** — a stock ruleset over tier-1 must produce non-trivial
  recall *and* visibly trip some traps. A perfect score means the corpus is too
  easy or is leaking.
