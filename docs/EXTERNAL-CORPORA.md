# External corpora — tier 2, tier 3 and perf

These are upstream repositories, fetched at a pinned revision rather than
vendored:

```bash
python3 spine/corpora/fetch.py tier2          # real vulnerable applications
python3 spine/corpora/fetch.py tier3          # real CVE reproductions
python3 spine/corpora/fetch.py perf           # scan-time measurement targets
python3 spine/corpora/fetch.py perf --check   # status without cloning
```

Not vendored because these trees together are far larger than this repository,
and they are code we did not write and must not edit. Pinned to a full commit
SHA because a corpus fetched from a moving branch is not a corpus: two runs a
month apart would score different code, and nothing in either scorecard would
say so. `fetch.py` rejects a manifest whose revision is a branch name or an
abbreviated SHA.

## Status

| Corpus | Sources | Fetch | Ground truth |
|---|---|---|---|
| `perf` | 4 Java repos, 10k → 500k+ LOC | working | **not needed** — never accuracy-scored |
| `tier2` | 5 applications, 4 languages | working | **not authored** |
| `tier3` | 2 CVE datasets, Java | working | **derived, see below** |

## Tier 3 is derived, not hand-transcribed

`spine/corpora/tier3.py` turns `cwe-bench-java` into ground truth. That dataset
gives 120 manually vetted CVEs in real Java projects, all of which build, with
the fixing file, class and method recorded per CVE — far more than any other
source hands you, and the reason tier 3 was reachable at all.

**The recorded line numbers cannot be used directly.** They are anchored to the
*fixed* commit, while the commit that must be scanned is the *buggy* one. The
two differ, sometimes enormously: in `alibaba/one-java-agent` the fixed
`IOUtils.java` is 106 lines and the buggy one is 162, and the fix deleted the
vulnerable `unzip` method outright — which is why several rows carry no method
range at all. Deriving from those numbers would have produced ground truth
spanning lines 24–106 of the buggy file, ending exactly where the vulnerable
method begins.

So the method is located **by name in the buggy checkout**, and every case
records the granularity that search achieved.

Three rules the derivation enforces, each of which would otherwise corrupt the
ground truth:

- **One case per CVE, not one per touched method.** A fix commit routinely edits
  more than the flaw; one CVE here spans seventeen methods. Every touched method
  becomes an accepted location and a hit at any counts, so no tool is charged
  fifteen false negatives for declining to flag refactored helpers.
- **Test code is never ground truth.** Fixes update the tests that prove them.
  Tools skip test directories by default, so an entry pointing at one charges
  every tool a false negative for behaving correctly. 25 such rows were dropped.
- **The primary location prefers precision.** A located method beats a
  whole-class span; a narrow method beats a sprawling one. Everything else
  survives as an alternative.

### What is derived so far

14 CVEs, all resolving to method granularity, each spot-checked by reading the
code at the derived span.

**They are all CWE-22.** Path traversal is 55 of the dataset's 120 entries and
the first projects fetched happened to be all of that class, so tier 3 currently
tests one weakness. Fetching across the other three — XSS, code injection and
command injection — is the immediate next step, and until it is done a tier-3
number says something about path traversal and nothing else.

### Tier 3 has traps, taken from the fix commits

An earlier version of this document claimed tier 3 could only measure recall.
That was wrong. `project_info.csv` records the fix commit beside the buggy one,
and **the patched form of a vulnerable method is real-world, structurally
identical, correctly defended code** — better trap material than anything
hand-authored, because upstream wrote it under real constraints against a real
published attack. A tool that still reports there is matching on shape.

21 traps are derived this way. Three guards decide when not to emit one, and
each fired on real data:

- **The fix deleted the method.** `alibaba/one-java-agent` removed `unzip`
  outright; there is no safe sibling and inventing one would be fabrication.
  1 case.
- **The fix did not touch the method.** Then the "fixed" copy is still the
  vulnerable code, and labelling it safe would invert the ground truth and
  charge a correct finding as a false positive. 5 cases — the most dangerous
  category, and invisible without the check.
- **The fix commit or file could not be fetched.** 1 case.

Traps are compared ignoring whitespace, so a reindentation is never mistaken
for a fix.

They are marked `build.required: false`: a single patched file has no
surrounding project, so it is scannable by source-only tools and invisible to
build-required ones.

## Tier 2 is still unlabelled

The fetch mechanism, pinning discipline and licence records are done. The
labelling is not, and **every tier-2 accuracy number is therefore absent rather
than optimistic** — [THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md) records
what a synthetic-heavy result does and does not support.

`perf` is complete, because scan time needs no ground truth. `commons-cli` is
fetched and measured at 15,716 code lines by codeprint at its pinned revision.

## Why the labelling is the expensive part

A tier-2 case needs a human to read the code and decide three things a scanner
cannot be trusted to decide for us: that the flaw is real, where the ground
truth should point, and which CWEs a tool could defensibly report for it.
Labelling from a scanner's output would encode that scanner's opinion as truth
and guarantee it a perfect score.

## Labelling workflow

1. Fetch the source and read the region. Confirm the flaw is genuinely
   exploitable, not merely suspicious-looking.
2. Write `answers/cases/<id>.yml` with `tier: 2` or `3`, `evidence.source` of
   `walkthrough` or `cve`, and a rationale a reviewer can check without redoing
   the analysis.
3. Set `acceptable_cwes` to every CWE a tool could defensibly report. Getting
   this wrong reads as missing tool coverage — see the incident recorded in
   [MATCH-POLICY.md](MATCH-POLICY.md).
4. Add the safe sibling wherever the application contains a comparable pattern
   that is correctly defended. Without it the case measures recall only.
5. Run `compile_answers.py`; it fails if the file or line no longer exists.

`spine/schema/compile_answers.py` already validates tier-2 and tier-3 cases —
only the cases themselves are missing.

### Tier 3 can be partly derived

`cwe-bench-java` ships machine-readable metadata: 120 vetted CVEs with CWE
labels and fix commits. The fix commit identifies the changed lines, which is a
strong starting point for the ground-truth location. `vul4j` additionally ships
a proof-of-vulnerability test per entry, which makes a label checkable rather
than asserted — the strongest evidence available anywhere in this corpus.

Neither can be fully automatic. A fix commit often touches more than the flaw,
and the location a tool should report is not always the line that changed.

## Anti-leakage does not apply here

Tier-2 and tier-3 code names its own weaknesses — WebGoat ships
`SqlInjectionLesson5.java`. That cannot be edited away without forking upstream,
so `spine/lint/antileak.py` reports it as a warning rather than failing, and the
count belongs in the threats section of any scorecard. LLM-based scanners can
classify these cases partly from filenames rather than analysis, by an amount
this corpus cannot measure.

## Licences

Recorded per source in each `sources.json`, because the obligations differ and
some are copyleft. Nothing here is redistributed — the manifests hold URLs and
revisions, not code — but anyone publishing derived material needs to check.

**WebGoat is recorded as `VERIFY-BEFORE-USE`.** GitHub reports `NOASSERTION`,
meaning its licence could not be classified automatically. Read `LICENSE.txt` in
the checkout and record the finding before any use that redistributes or
publishes from it.

## Perf sources

| Source | Measured code lines | p50 scan (semgrep `p/java`) | s / 1k LOC |
|---|---|---|---|
| `commons-cli` | 15,716 | 1.07 s | 0.068 |
| `commons-lang` | 129,508 | 2.08 s | 0.016 |
| `spring-boot` | 642,008 | 5.49 s | 0.009 |
| `hadoop` | 4,655,050 | not yet timed | — |

**Bucket names were estimates and every one of them was wrong.** `commons-lang`
was guessed at 50k and measures 130k; `spring-boot` was guessed at 200k and
measures 642k. The labels now carry the measurement.

Against the service levels that matter — under three minutes at 50–200k LOC,
under ten minutes past 500k — `commons-lang` sits inside the pull-request band
and `spring-boot` past the large-repository threshold, so the two thresholds are
covered. `hadoop` is an extreme rather than a representative case.

**These timings do not answer the question they look like they answer.** Semgrep
is source-only and never compiles. A build-required engine must build
`spring-boot` before it analyses a line, and that cost is invisible here. The
harness records build time as its own phase precisely so the difference cannot
be hidden in a single number.

Buckets straddle the service levels that matter: under three minutes at
50–200k LOC, under ten minutes past 500k. The smallest bucket exists to expose
fixed overhead — process start, rule compilation — that a large-repository
number averages away.

Measured, not asserted: `approx_loc` is filled in from codeprint's `totals.code`
at the pinned revision, and is null until that has actually been run.
