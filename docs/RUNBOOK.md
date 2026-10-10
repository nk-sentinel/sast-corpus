# Runbook: running an evaluation

The order below is the order things fail in. Steps 1–4 are the corpus proving
itself before any vendor sees it; 5–8 are one tool; 9 is the writeup.

Everything here runs from a laptop with internet access. For the air-gapped
variant see [AIRGAP-EXPORT.md](AIRGAP-EXPORT.md).

## 0. Once per machine

```bash
pip install pyyaml jsonschema      # authoring side only — score.py needs nothing
```

`score.py` is standard library on purpose, so whoever audits a number does not
have to reproduce an environment to do it.

## 1. Prove the corpus before trusting a score

```bash
python3 spine/validate/selftest.py        # key vs scorer, no scanner involved
python3 spine/lint/antileak.py            # no weakness names in authored fixtures
python3 -m unittest discover -s spine/tests -t .
SYNTAX_USE_DOCKER=1 ./build/verify.sh     # compile and parse every fixture
```

All four must be green. `selftest.py` is the one that matters most: it builds
SARIF from the answer key itself and requires exactly *N* true positives with
zero false alarms, then zero true positives with every trap tripped. A defect in
path resolution or line matching would otherwise surface for the first time in a
vendor's scorecard, where it reads as the vendor's fault.

`build/verify.sh` is load-bearing, not hygiene: Fortify, Coverity and Veracode
analyse compiled artifacts, and a fixture that does not build makes them score
zero in a way that looks identical to poor detection.

## 2. Fetch the tiers you intend to score

Tier 1 is committed. Tiers 2 and 3 are cloned at pinned revisions:

```bash
python3 spine/corpora/fetch.py --check    # what is present, what is missing
python3 spine/corpora/fetch.py tier2
python3 spine/corpora/fetch.py tier3
```

If you skip this, every tier-2/3 case still appears in the answer key and scores
as a miss. `selftest.py` says how many files are absent — read that line before
scoring anything.

## 3. Decide the denominators before the run, not after

```bash
python3 spine/report/applicability.py     # which (language, cwe) cells a tool claims
```

A tool with no Swift support is not bad at Swift. Cases in an unsupported
language or an unclaimed plane must be reported `n/a` and excluded from that
tool's denominators — **never** counted as false negatives. Fixing this after
seeing the numbers is indistinguishable from fitting the denominator to the
result.

Record, per tool, before the run:

- version **and edition** — SonarQube Community has no taint engine at all, so a
  community result says nothing about the commercial product
- ruleset and tuning state — default or full; these are different measurements
- which planes it claims (`vuln`, `secret`, `sca`)

## 4. Scan a copy, never the working tree

```bash
mkdir -p /tmp/scan && cp -R tier1 tier2 tier3 /tmp/scan/
```

Engines that drive a build mutate what they read. Building a CodeQL Go database
over `tier1/` ran the Go toolchain, which tidied two SCA manifests and deleted
the declared-but-never-imported dependency those cases exist to state. Nothing
warned.

If you do scan in place, assert afterwards:

```bash
./spine/validate/corpus_unchanged.sh
```

Non-zero exit means ground truth may have been rewritten. Restore it before
scoring — a scorecard from a mutated corpus is not comparable to any other.

## 5. Run the tool and get SARIF

Native SARIF goes straight to the scorer. Everything else needs an adapter, and
**no adapter may be trusted until it has been run against a real export from the
tool it claims to convert.** The SonarQube adapter read its CWEs from a field
that does not exist on 25.1 Community; every finding would have arrived with no
CWE, fallen back to a location-only match, and made the tool look like it does
not tag weaknesses. Every test passed, because the fixture was written by the
same person as the assumption.

```bash
# SonarQube: scan, wait, export, enrich with CWEs, convert, score — one command
SONAR_TOKEN=squ_xxx ./spine/adapters/capture-sonarqube.sh

# CSV-shaped exports (Fortify, Veracode, …)
python3 spine/adapters/generic_csv.py export.csv --map path=File,line=Line,cwe=CWE \
    > results.sarif
```

If the paths in the SARIF are relative to a scan root rather than to the repo,
prefix them before scoring. The scorer compares strings and never touches the
filesystem, so a prefix mismatch produces a flawless zero with no error.

## 6. Score

```bash
python3 spine/score/score.py results.sarif answers/expectedresults-1.0.csv
python3 spine/score/score.py results.sarif answers/expectedresults-1.0.csv --json \
    > scorecards/<tool>-<date>.json
```

Read these four lines before anything else:

| line | what a bad value means |
|---|---|
| `reported outside the answer key` | high means read the findings — it is a ground-truth smoke alarm first and tool noise second |
| `…sat on a known case but named a weakness it does not accept` | the tool found it and called it something else, **or** found a second real weakness. Read the rule ids; see [MATCH-POLICY.md](MATCH-POLICY.md) |
| `matched on position because the tool emitted no CWE` | those matches rest on weaker evidence and must be quoted with the figure |
| per-tier rows | a tool leading on tier 1 and collapsing on tier 3 has told you something important |

**Nothing a candidate reports may change the answer key.** Not a label, not a
line range, not an `acceptable_cwes` entry. A candidate's unmatched findings may
prompt re-reading a case; the case is then decided from the code and the CWE
definitions, and the reasoning recorded. The one breach of this rule raised a
candidate's measured recall from 0.478 to 0.609 before it was caught — see
[MATCH-POLICY.md](MATCH-POLICY.md).

## 7. Time it separately

```bash
python3 spine/timing/bench.py --tool <name> --target perf/commons-lang \
    --runs 5 --warmup 1 --cache cold --out runs/<tool>-commons-lang.json
```

The accuracy corpus is not a workload — it is orders of magnitude smaller than
the 50k–500k LOC the NFR thresholds concern. Build, analysis and queue-wait are
recorded as separate phases, because a hosted scanner's queue is not scan speed.

## 8. Positive control, once per corpus change

```bash
# a non-candidate instrument, over a copy
codeql database create /tmp/db --language=python --source-root=/tmp/scan/tier1
codeql database analyze /tmp/db \
    codeql/python-queries:codeql-suites/python-security-extended.qls \
    --format=sarif-latest --output=/tmp/control.sarif
```

A stock ruleset over tier 1 must produce non-trivial recall **and** visibly trip
some traps. A perfect score means the corpus is leaking or too easy; a zero means
the fixtures are unreachable and no vendor result from them means anything. The
current reading and what it does and does not establish are in
[VALIDATION.md](VALIDATION.md).

Use CodeQL or single-purpose OSS linters for this. **Not** Semgrep, Endor Labs,
Aikido or SonarQube — they are the tools under evaluation, and an instrument that
is also a subject means measuring a corpus built around it. OpenGrep does not
count as independent either: same engine, same rule taxonomy, same blind spots.

## 9. Writing it up

Report, per tool, in this shape:

- recall **and** precision separately, never a composite — published studies find
  tools at 100% precision and under 25% recall simultaneously, and one number
  hides that entirely
- **per tier**, always separate; tier-1 figures overstate every tool and overstate
  pattern-matching engines most
- the location-only match count
- the `n/a` cells excluded, and why
- version, edition, licence tier, ruleset, tuning state
- the match policy version — ±10 lines, `acceptable_cwes` equivalence,
  one TP per case. A different policy gives different numbers from identical
  scans, so comparisons across policies are invalid

Then read [THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md) and state which
threats apply to this particular run. Writing them down before anyone challenges
the numbers is the point.

**Commercial licences commonly forbid publishing named benchmark results.**
Internal evaluation is unaffected; anything leaving the organisation anonymises
tool identities and is cleared first.

## Known gaps, as of 2026-10-10

These do not block a run. They bound what it can tell you.

| gap | effect | issue |
|---|---|---|
| tier-1 positive control at 0.094 recall | tier 1 separates dataflow engines less than intended; tier 2 and 3 carry more of the signal | #7 |
| Java read without a build in the control | framework-mediated Java flow is untested by the control | #7 |
| 7 languages have no control run | c, cpp, csharp, kotlin, php, rust, swift — 77 tier-1 cases unverified-reachable | #7 |
| no C/C++ real-CVE cases | tier 3 has no C/C++; licence review outstanding | #11 |
| `sca` 27 cases, `secret` 33 | sized so a tool claiming those planes is not scored against nothing — **not** sized to rank one. Do not rank an SCA-first product on them | — |
| only 4 context traps, all crypto | the trap set leans on sanitizer defects rather than context | #5 |
