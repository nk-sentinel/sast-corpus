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
