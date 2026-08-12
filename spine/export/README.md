# Export tooling

Moving the corpus into an environment with no GitHub access. See
[../docs/AIRGAP-EXPORT.md](../docs/AIRGAP-EXPORT.md) for what travels and why.

## `deps.py` — the artifact checklist

Enumerates every Maven and Gradle coordinate the tier-3 builds resolve, so an
internal package repository can be verified **before** the transfer. There is no
second attempt once the corpus is inside.

```bash
python3 spine/export/deps.py                                   # summary
python3 spine/export/deps.py --format text --out artifacts.txt # one per line
python3 spine/export/deps.py --format json --out check.json    # with per-project detail
```

**Run it online.** That is the default, and it matters more than it looks:

```
$ deps.py --only dromara__hutool --offline     2 artifacts
$ deps.py --only dromara__hutool               82 artifacts
```

`dependency:resolve-plugins` resolves plugins that are *declared but never
invoked*, and those were never downloaded by any build, so they are absent from
any cache. Generating the checklist offline omits them silently — which is the
exact failure the checklist exists to prevent. `--offline` still works and
labels its own output as incomplete.

Dependencies and plugins come from two separate commands, and one can fail while
the other succeeds. Per-stage failures are named per project rather than
collapsed into "some artifacts found", for the same reason.

### Measured result

27 projects resolved (nifi excluded — 13 GB, and its plugin tree dominates the
run): **5,533 distinct artifacts, 365 of them plugins**.

```
 18  resolved cleanly
  6  partial — resolved, with at least one module failing
  3  contributed nothing
  1  excluded by request
```

Partial and empty are separated deliberately. activemq reports one failed module
alongside 26,934 resolved coordinates, and listing it beside a project that
produced nothing would misstate what the checklist covers. The three that
contributed nothing — DSpace, tapestry-5, spring-framework — have their
artifacts **absent from the list**, and that is stated rather than left to be
discovered on the far side.

Two outputs: `export/jfrog-checklist.json` (per-project detail) and
`export/jfrog-artifacts.txt` (one coordinate per line, for handing over).

### Build routing follows the files, not the metadata

Five projects declare a `gradle` key in `build-info` and every one of them
contains `pom.xml` and no Gradle file at all — the key does not mean what its
name suggests. Two others use a separate `gradlew` key and do carry a wrapper.
Trusting the metadata routed 7 of 28 projects to a tool they do not use and cost
1,632 artifacts, which is why routing reads the build files on disk and takes
only versions from `build-info`.

## What the checklist does not tell you

That the repository will *serve* them. These projects pin releases from 2014 to
2023 and the vulnerable dependency is frequently the point of the case, so a
repository that quarantines known-vulnerable versions blocks precisely what
tier 3 is made of. The checklist makes that answerable in advance; it does not
answer it.

## `bundle.py` — the transfer archive

```bash
python3 spine/export/bundle.py --profile scoring          # ~403 MB compressed
python3 spine/export/bundle.py --profile build --split 4G # parts for transfer media
python3 spine/export/bundle.py --profile perf --keep-git  # keep vendored history
```

| profile | adds | measured |
|---|---|---|
| `scoring` | fixtures, answer key, spine, tier-3 sources | 403 MB compressed, 120,110 files |
| `perf` | + scan-time repositories | + ~400 MB |
| `build` | + JDKs and build tools | + 544 MB |
| `full` | + prefetched dependency caches | + up to 6.9 GB |

**Two archives, on purpose.** Rule 1 of this corpus is that the answer key lives
outside the fixtures. A single archive would undo it — a scanner pointed at the
extracted root reads every CWE identifier and rationale, and an LLM-based
scanner then scores on the answers rather than the code. The `-corpus` archive
holds the scan target and the `-answers` archive holds the ground truth, and
they should not be unpacked into the same tree before scanning.

**What is left behind, and why it is safe to leave:**

- `target/` — 17.6 of the 20 GB, regenerated on arrival by Maven in strict
  offline mode. Verified: projects rebuild given the toolchain their
  `build-info` declares
- `.git` in vendored trees — 602 MB, replaced by the pinned commit SHA in
  `MANIFEST.json`. `--keep-git` restores it for incremental scanning
- REEF — never bundled, at any profile. 737 MB of copied third-party source
  under no licence

**Verifying on arrival** needs nothing from us:

```bash
sha256sum -c SHA256SUMS      # run from the extracted corpus root
```

`MANIFEST.json` stays small enough to read — profile, corpus version, file
count, and the upstream commit for each vendored tree. Per-file digests live in
`SHA256SUMS` because embedding 120k of them made the manifest 31 MB, and because
the standard format needs no tooling of ours to check.

Provenance is scoped to what actually travelled: a `scoring` bundle pins
`cwe-bench-java` and `vul4j` and says nothing about `perf`.

## `verify.py` — the arrival check

A bundle that unpacks without error is not evidence. Run this before scoring:

```bash
python3 spine/export/verify.py --root /path/to/extracted     # integrity + gates
python3 spine/export/verify.py --root . --checksums-only     # integrity alone
```

Standard library only, no network, nothing to install — the same property that
lets the scorer run anywhere lets verification run anywhere.

```
ARRIVAL CHECK — sast-corpus 1.0, profile scoring

INTEGRITY
   119806  files checksummed
        0  missing
        0  modified — content differs from the manifest
        0  present but not in the manifest

Verified: this is the same corpus that left, and a scorecard
produced against it is comparable to one produced at origin.
```

Then it re-runs the corpus's own gates where it landed: the answer key must
regenerate identically, the anti-leak lint must stay clean, fixtures must parse,
the unit tests must pass, and the negative control must score an empty result
set at 0 found and 0 false alarms.

**A skipped gate fails the run.** "We could not check" is not "we checked and it
was fine" — the rule the syntax gate already follows for absent toolchains. A
run that reports green because nothing ran is the failure this file exists to
prevent.

**It catches the one mistake that quietly ruins a bake-off.** Extracting the
answers archive over the scannable tree leaves the ground truth where a scanner
reads it, and the scan still looks entirely normal. Each archive carries its own
`SHA256SUMS.<name>`, and a corpus tree with an `answers/` directory in it is
reported and fails:

```
GROUND TRUTH IS IN THE SCAN TARGET
306 answer-key file(s) sit under answers/ in a tree whose
checksum list does not cover them ...
```

Verified against real corruption, not only in unit tests: a modified file, a
deleted file and a misplaced answers archive each produce a non-zero exit.

## `fetch.py --offline`

```bash
python3 spine/corpora/fetch.py tier3 --offline
SAST_CORPUS_OFFLINE=1 python3 spine/corpora/fetch.py tier3   # same, via environment
```

Never reaches the network. Without it a fetch in an airgapped environment does
not fail fast — it hangs against an unreachable host, which reads as the corpus
being broken rather than the environment having no route out. The environment
variable exists so an airgapped host does not depend on anyone remembering the
flag.

**Presence is no longer judged by `.git`.** The export drops vendored history on
purpose, so the old check would have called every restored tree *absent* and
tried to clone it — the one thing that cannot work there. A populated directory
without history now reads as `restored`: usable, with its provenance in
`MANIFEST.json` rather than in git.

```
tier3: 2 source(s) [offline]
  vul4j                  absent
    optional and not present; it contributes no cases, so scoring is unaffected
  cwe-bench-java         restored
```

Sources may be declared `optional` in a manifest. `vul4j` is the first: it is
pinned and fetchable, and no case in the answer key derives from it, because
cwe-bench-java covered the same ground first. Failing an offline check over a
source that contributes nothing would make the check fail every time it runs,
and a check that always fails is one people learn to ignore.

## A note on which tooling runs

The bundle carries `spine/`, so an extracted corpus runs the tooling as it was
when the bundle was built, not whatever is on the host. When verifying an older
bundle, check `MANIFEST.json` for its corpus version before concluding that a
behaviour is a bug.
