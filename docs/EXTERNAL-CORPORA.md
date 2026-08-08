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

### Tier 3 measures recall only

There are no safe siblings. The dataset records where each CVE was fixed and
says nothing about which nearby code is correctly defended, so this tier cannot
contribute to a false-positive rate. That is a property of the tier, not an
oversight.

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

| Source | Bucket | Measured code lines |
|---|---|---|
| `commons-cli` | 10k | 15,716 |
| `commons-lang` | 50k | not yet fetched |
| `spring-boot` | 200k | not yet fetched |
| `hadoop` | 500k+ | not yet fetched |

Buckets straddle the service levels that matter: under three minutes at
50–200k LOC, under ten minutes past 500k. The smallest bucket exists to expose
fixed overhead — process start, rule compilation — that a large-repository
number averages away.

Measured, not asserted: `approx_loc` is filled in from codeprint's `totals.code`
at the pinned revision, and is null until that has actually been run.
