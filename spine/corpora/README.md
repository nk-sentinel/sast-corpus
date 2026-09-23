# Corpora tooling

Everything that fetches or derives the tiers that are not committed here —
tier 2, tier 3 and `perf`. [../../docs/EXTERNAL-CORPORA.md](../../docs/EXTERNAL-CORPORA.md)
says why they are fetched rather than vendored and what each contributes;
[../../docs/TIER3-DATASETS.md](../../docs/TIER3-DATASETS.md) records what was
measured about each dataset before a case was derived from it.

| | |
|---|---|
| `fetch.py` | Clone a corpus at the full SHA pinned in `<tier>/sources.json`. `--check` reports presence without cloning, `--only` limits it to one source, `--offline` (or `SAST_CORPUS_OFFLINE=1`) refuses the network and recognises a bundle-restored tree that has no `.git` |
| `tier3.py` | Derive Java cases from cwe-bench-java: locate the vulnerable method **by name in the buggy checkout** (the dataset's line numbers anchor to the fixed one), and take traps from the fixing commit with `--write-traps` / `--write-cases` |
| `patcheval.py` | Derive Go, JavaScript and Python cases from PatchEval, anchoring each location to the buggy commit it names, with a full clone rather than a shallow one. `--dataset <patcheval_verified.json> --write`; `--only` and `--limit` narrow a run |
| `reef.py` | Derive C and C++ cases using REEF as an **index only** — sources come from each project's own upstream, and REEF's unlicensed copies are never written into the corpus. `--data <reef/data> --wanted <n> --write` |
| `repos.py` | The size guard both derivations share: which repositories are too large to be worth cloning for one case |
| `tier3_build.py` | Build the tier-3 projects so build-required engines can be scored on them; records the result and the toolchain that produced it in `tier3/build-status.json`. `--all` builds every fetched checkout, not only the ones the answer key references |

Derivations write each case into `answers/cases/` as it is produced, under an
id that is stable across runs, so an interrupted run resumes rather than
duplicating — re-running converges on the same answer key. Checkouts are keyed
by commit and reused. After any derivation, regenerate the answer key and the
coverage doc:

```bash
python3 spine/schema/compile_answers.py
python3 spine/report/coverage.py
```
