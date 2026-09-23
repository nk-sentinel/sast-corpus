# Exporting the corpus to an airgapped environment

The corpus is designed around SHA-pinned fetching: `tier2`, `tier3` and `perf`
are cloned on demand rather than vendored, because those trees are far larger
than this repository and are code we did not write. In an environment with no
GitHub access that model does not work, and the corpus has to travel as a
bundle.

This document is what to ship, what deliberately not to ship, and what has to be
confirmed on the far side **before** the transfer rather than during the
evaluation.

## What is actually on disk

Measured, not estimated:

| | size | travels? |
|---|---|---|
| `tier1` + `answers` + `spine` + `build` + `docs` | 7 MB | **yes** — this is the corpus |
| `tier3` project sources (no `target/`, no `.git`) | 1.5 GB | **yes** |
| `perf` sources (no `.git`) | 403 MB | yes, if scan-time is in scope |
| JDKs, Maven and Gradle distributions (`java-env`) | 544 MB | **yes** — a package repository does not serve these |
| `tier3` `target/` — build output | **17.6 GB** | **no** — regenerated on arrival |
| `.git` inside vendored trees | 602 MB | **no** — replaced by a pinned-SHA manifest |
| `~/.m2` | 6.1 GB | **no**, if JFrog resolves — see below |
| `~/.gradle` | 761 MB | **no**, same condition |
| `tier2` sources for the labelled applications | ~90 MB | **yes**, if tier 2 is in scope — 97 cases score against them |

**88% of the 20 GB is build output.** That is the single fact that makes this
tractable: a ~2.5 GB transfer, not a 27 GB one.

## Rebuilding on arrival, rather than shipping artifacts

Shipping `target/` was tested against and rejected. Maven in strict offline mode
(`-o`, which refuses the network outright) rebuilds the projects from source
provided each one gets **its own declared toolchain**:

```
PASS  alibaba__one-java-agent          107 classes   jdk8u202 mvn3.5.0
PASS  dromara__hutool                  964 classes   jdk8u202 mvn3.5.0
PASS  SpringSource__spring-security-oauth  1172      jdk8u202 mvn3.5.0
PASS  jenkinsci__docker-commons-plugin   48 classes  jdk8u202 mvn3.5.0
```

Two findings came out of getting this wrong first:

**Toolchain is per project, and forcing one version breaks most of them.** An
initial run used Maven 3.9.8 for everything and 5 of 8 projects failed on
`maven-resources-plugin:3.3.1` — a version 3.9.x resolves by default and no
earlier build had ever cached. `tier3/cwe-bench-java/build-info/<project>.json`
declares the right pair; the export must carry it and the rebuild must honour
it. 21 of 28 projects want jdk 8u202 with Maven 3.5.0.

**5 of 28 projects build with Gradle, not Maven** (`activemq`, `DSpace`,
`tapestry-5`, and two others). They need Gradle 8.9 and jdk 17, and a separate
repository configuration. A Maven-only export silently loses them.

## Dependency resolution: the internal JFrog

The work environment has an internal JFrog holding open-source components, so
dependencies resolve there and neither `~/.m2` (6.1 GB) nor `~/.gradle`
(761 MB) needs to travel. That is a ~6.9 GB saving and it is also the more
robust option — a shipped cache is only correct for the exact toolchain that
populated it. One project in the test, `spark`, failed offline precisely
because its cached artifacts had been fetched by a different Maven version than
its `build-info` declares. A repository that holds every version has no such
coupling.

It moves the risk rather than removing it, and the risk has to be settled
before the transfer:

1. **The artifacts are old, and many carry known CVEs.** These projects are
   pinned to 2014–2023 releases, and the vulnerable dependency *is frequently
   the point of the case*. A security-conscious JFrog that quarantines or
   blocks vulnerable versions will block exactly what tier 3 needs. Confirm the
   policy before assuming availability.
2. **Confirm coverage from a list, not by trying.** Ship a manifest of every
   required artifact — group, artifact, version, for dependencies *and* plugins,
   Maven and Gradle — so the JFrog side can be verified up front. Discovering a
   missing 2014 artifact mid-evaluation with no way to fetch it is what this
   avoids.
3. **Pin plugin versions explicitly.** Maven resolves an unversioned plugin to
   whatever the repository offers, so the same source can build differently
   against a different repository. This already bit the corpus once: Maven
   3.8.7 defaults to compiler-plugin 3.1, which predates
   `maven.compiler.release` and silently falls back to source level 5.
4. **Point the build at JFrog and nowhere else.** A `settings.xml` with a
   `<mirror>` of `*`, and an `init.gradle` with the equivalent, so a missing
   artifact fails loudly instead of hanging on an unreachable Maven Central.

**Carry the caches as a separate, optional bundle anyway.** If JFrog turns out
to be missing old artifacts, an airgapped environment offers no second attempt.
A ~6.9 GB fallback that is restored only when needed costs a bigger transfer
once; being blocked costs the evaluation.

## What must not be exported

**REEF.** It ships 737 MB of copied source from thousands of projects with no
LICENSE file, which by default means all rights reserved. Cloning it here for
analysis is one thing; copying it into a corporate environment is another. The
roadmap's ~30 C/C++ cases should be derived with REEF used **as an index on this
side of the airgap**, and the sources themselves fetched from their own upstream
repositories, which carry real licences. See
[TIER3-DATASETS.md](TIER3-DATASETS.md).

**The unlabelled half of `tier2`.** DVJA and Juice Shop contribute nothing to a
scorecard yet, so they are fetchable rather than shipped. PyGoat, NodeGoat and
WebGoat do carry ground truth now and must travel if tier-2 accuracy is in scope;
all three are source-only for scanning, and WebGoat additionally needs its Maven
toolchain if a build-required engine is to see it.

Note also that `webgoat` is recorded as GPL-2.0-or-later (verified from its
`LICENSE.txt` and SPDX headers) and `vul4j` as GPL-3.0 in the source manifests.
Both are copyleft, so an export that carries WebGoat for tier-2 scoring is
redistribution in a way that fetching it was not: the obligations attach to
whoever moves the tree. The export should carry a generated licence manifest so
the question is answerable without re-deriving it.

## Phase-2 additions

PatchEval's tier-3 expansion is Go, JavaScript and Python — **source-only
languages with no build step**, so they need no package repository at all and
their per-CVE Docker images are unnecessary for scanning. Roughly 200 shallow
checkouts of source. This is the cheapest part of the export by a wide margin.

The two Docker images used by the syntax gate (`php:8.3-cli`, `ruby:3.3-slim`)
need `docker save` if PHP and Ruby are to stay parse-verified on the far side;
otherwise both drop back to *not checked*, which the gate already reports
honestly.

## Tooling

Four pieces, all standard library, no network anywhere in the restore path.
All four are built — see [../spine/export/README.md](../spine/export/README.md):

| | |
|---|---|
| `spine/export/bundle.py` | `--profile {scoring,perf,build,full}`, `--split <size>` for transfer-media limits. Writes `MANIFEST.json` — SHA-256 per file, pinned upstream commit per vendored tree, corpus version, profile, toolchain versions — and a generated `LICENSES.md` |
| `spine/export/deps.py` | Emits the JFrog checklist: every Maven GAV and Gradle coordinate, dependencies and plugins, per project |
| `spine/export/verify.py` | Runs on arrival: checksums, then the existing gates |
| `fetch.py --offline` | Refuses the network and reports what is present. Also set by `SAST_CORPUS_OFFLINE=1`. Recognises a bundle-restored tree that has no `.git` |

## Proving it arrived intact

The corpus can verify itself on the far side because every gate is
standard-library Python and none touches the network:

```bash
python3 spine/export/verify.py            # checksums against MANIFEST.json
python3 spine/schema/compile_answers.py   # answer key regenerates identically
python3 spine/lint/antileak.py            # no leakage
./build/syntax/check.sh                   # fixtures still parse
python3 -m unittest discover -s spine/tests -t .
```

Plus the negative control already in the corpus: scoring an empty SARIF must
give 0 TP and 0 FP with every case still accounted for. A corpus that passes all
of these is the same corpus that left, and a scorecard produced against it is
comparable to one produced here.

## Dropping `.git` — the tradeoff

Vendored trees ship without history, replaced by the pinned commit SHA and a
tree checksum in `MANIFEST.json`. That is smaller and more directly verifiable
than shipping 602 MB of packfiles. The cost is that tools using git metadata —
blame, changed-files, incremental scanning — have none. For a full-tree
bake-off that is not used; for anything incremental it would be, and the export
would need `--keep-git`.
