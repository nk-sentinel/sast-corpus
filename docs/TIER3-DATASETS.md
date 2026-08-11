# Tier-3 dataset evaluation — roadmap item 0

Decision record for extending tier 3 past Java. Every figure below was measured,
not read off a paper: the datasets were cloned and their claims checked against
the repositories they point at.

**Outcome: PatchEval GO. REEF conditional, curated use only. C# no viable source.**

## Why this was spiked before planning around it

cwe-bench-java records line numbers anchored to the **fixed** commit while the
scan target is the **buggy** one. Taken at face value it mislabels every case,
and nothing about the schema reveals it — only comparing bytes does. Any new
dataset had to be checked the same way before a case count could be promised.

## PatchEval — GO

[bytedance/PatchEval](https://github.com/bytedance/PatchEval) ·
[HuggingFace](https://huggingface.co/datasets/ByteDance/PatchEval) ·
[arXiv:2511.11019](https://arxiv.org/abs/2511.11019)

| | |
|---|---|
| Licence | **Apache 2.0** |
| Verified cases | 230 CVEs — Go 83, JavaScript 77, Python 70 |
| Weaknesses | 41 CWEs; top are CWE-22 (40), CWE-94 (35), CWE-73 (33), CWE-78 (32), CWE-77 (31) |
| Granularity | `file_path` + `start_line` + `end_line` + `snippet`, per location |
| Build | Per-CVE Docker images on ghcr.io; languages are source-only anyway |

**Line anchoring verified.** Each location carries its own `commit`, and it is
the vulnerable one — checked by cloning every repository, checking out that
commit and comparing the recorded snippet to the bytes at the recorded lines:

```
203 / 230  exact byte match          264 / 296 locations exact
 19        mismatch or partial
  8        repository no longer fetches
```

Of the 19 mismatches, 5 resolve when the checkout targets the commit the
*location* names rather than the fix's parent — the two are not always the same.
11 more need a full clone, because an abbreviated SHA cannot be fetched from a
shallow one. 3 are genuinely wrong and get dropped.

**Realistic yield: 203–219 usable CVEs**, against a roadmap target of 100.

Three derivation rules fall out of the measurement, and skipping any of them
loses cases silently:

1. **Anchor to `vul_func[].commit`, never to the fix commit's parent.** They
   diverge on 5 of 230.
2. **Full clone, not shallow.** The recorded commit is abbreviated, and an
   abbreviated SHA is not fetchable — 11 cases turn on this alone.
3. **Coerce line numbers.** 6 of 296 locations store `start_line` as a string.
   Code that trusts the declared type crashes on 5 CVEs.

## REEF — conditional, curated use only

[ASE-REEF/REEF-data](https://github.com/ASE-REEF/REEF-data) ·
[arXiv:2309.08115](https://arxiv.org/pdf/2309.08115)

**No LICENSE file.** The repository ships 737 MB of copied source from thousands
of projects under a two-line README and no licence grant, which by default means
all rights reserved. That is the finding that decides how it can be used: fine
for internal analysis, not for anything whose derived ground truth is published
or leaves the organisation without a licence review first.

| | |
|---|---|
| Scale | 4,466 rows, **4,269 distinct** CVEs (188 appear more than once) |
| Languages | C 1,575 · Python 863 · JS 636 · Java 541 · C++ 411 · Go 355 · C# 85 |
| Granularity | **post-fix file content and unified-diff hunks — no line numbers** |

REEF stores the file as it looks *after* the fix. The vulnerable line range has
to be recovered from the `-<start>,<len>` side of each hunk and the parent
commit fetched separately. That works — 8 of 8 in the spike derived a valid
in-range location — but the result is an *index of fix commits*, not scoring-ready
ground truth, and two properties stop it being a bulk source:

- **53%** of fixes touch more than one file — which file holds the vulnerability
  is not recorded
- **43%** of files carry more than one hunk — which hunk is the vulnerability is
  not recorded either

The first hunk is not a safe default. In the spike, `CVE-2023-23145` derived to
`src/laser/lsr_dec.c:2-8` — an include block, not the bug. Automatic derivation
would label those confidently and wrongly, which is worse than not having them.

**Where it still earns its place:** C, C++ and C# are the languages PatchEval
does not cover, and REEF's C/C++ rows are dense in exactly the memory-safety
weaknesses this corpus currently tests only synthetically — CWE-787, CWE-476,
CWE-416, CWE-125, CWE-120. 68% of the C fixes touch a single file, which is the
tractable subset.

**Use: hand-pick roughly 30 C/C++ cases with per-case review of which hunk is
the vulnerability.** Not automatic derivation, and not 100 cases.

## C# — no viable source

REEF holds 85 C# rows, only 35% single-file, and PatchEval does not cover the
language. Neither supports a defensible set. C# tier-3 is **out of scope** for
this phase, and the coverage doc should say so rather than leave the gap looking
like an oversight.

## Revised plan for item 5

| language | source | expected |
|---|---|---|
| Go, JavaScript, Python | PatchEval | ~200 (of 203–219 usable) |
| C, C++ | REEF, hand-picked | ~30, gated on licence review |
| Java | cwe-bench-java (existing) | 49, unchanged |
| C# | none | out of scope, stated as such |

This lands item 5 at roughly **230 real-CVE cases** rather than the 100 planned,
and moves tier 3 from one language to six.

## Reproducing this evaluation

The spike scripts are not part of the corpus — they answered a question that is
now answered. What matters is that the checks are cheap to re-run when a dataset
publishes a new version: clone, check out the commit each location names,
compare the recorded snippet to the bytes at the recorded lines, and count. A
dataset that cannot pass that check cannot be scored against, whatever its
paper reports.
