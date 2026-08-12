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
