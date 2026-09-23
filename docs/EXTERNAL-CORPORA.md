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
| `tier2` | 5 applications, 4 languages | working | **PyGoat and NodeGoat labelled — 70 cases; WebGoat, DVJA and Juice Shop not yet** |
| `tier3` | cwe-bench-java (Java), PatchEval (Go, JS, Python); vul4j pinned but unused | working | **derived — 97 cases, see below** |

## Tier 3 is derived, not hand-transcribed

`spine/corpora/tier3.py` turns `cwe-bench-java` into ground truth. That dataset
gives 120 manually vetted CVEs in real Java projects, all of which build, with
the fixing file, class and method recorded per CVE — far more than any other
source hands you, and the reason tier 3 was reachable at all.
`spine/corpora/patcheval.py` does the same for PatchEval, which supplies Go,
JavaScript and Python; its line anchoring differs, and
[TIER3-DATASETS.md](TIER3-DATASETS.md) records what was verified before use.

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

### The tier-3 projects build

All 28 compile on this host: 28 succeeded, 0 failed. Recorded in
`tier3/build-status.json` alongside the toolchain that produced the result,
because a build result is only reproducible if the toolchain behind it is known.

```bash
python3 spine/corpora/tier3_build.py            # only projects the answer key references
python3 spine/corpora/tier3_build.py --all      # every fetched checkout
```

Two things made this harder than "run the dataset's script".

**The dataset's JDK setup cannot work unattended.** `setup_jdk.py` looks for
Oracle tarballs that must be downloaded by hand behind a licence click. Finding
none it skips silently, and every subsequent build dies with `should not
happen!` from a branch assuming a `gradlew` that is not there. Eclipse Temurin is
the same OpenJDK without the click, unpacked under the directory names the
scripts expect. The substitution is recorded in the output.

**A missing directory looked exactly like a build failure.** `build_one.py`
writes its result into `build-info/` without creating it, so projects compiled
successfully and then crashed on the bookkeeping write. Recorded naively that is
a build failure, and it would have shrunk the corpus visible to build-required
engines for a reason having nothing to do with the code.

A first pass with a 600-second cap left three large Apache multi-module projects
unfinished. That is a limit of the harness, not a defect in those projects, so
`timeout` is recorded as its own status rather than folded into `failed` — at
2400 seconds all three complete. Anything that genuinely does not build must be
excluded from a build-required engine's scorecard rather than counted as a miss,
since a missing artifact is not a missed detection.

### What is derived so far

**97 cases.** From cwe-bench-java, 28 Java CVEs — path traversal 14, XSS 5,
command injection 5, code injection 4 — every one resolving to method
granularity and spot-checked by reading the code at the derived span, plus the
21 traps described below. From PatchEval, 48 CVEs — Go 17, Python 16,
JavaScript 15 — across twelve weaknesses, command injection and path traversal
the largest. The roadmap target is ~230, and the derivation resumes where it
stopped — see [ROADMAP.md](ROADMAP.md) item 5.

### The tier-3 zero is not a measurement artifact

A score of zero invites the obvious suspicion that the ground truth points at
the wrong lines. It was checked rather than assumed.

Of 300 findings the reference scanner produced across the tier-3 checkouts,
exactly **one** lands in a file that carries ground truth — and it reports
CWE-319, cleartext transmission, at line 1124, against a CWE-22 span at 301–304.
An unrelated weakness in a large file, not a near-miss.

Had the derived spans been too tight, or anchored to the wrong lines, near-misses
in the right files would be the signature. There are none. The scanner is not
finding these CVEs, and its findings are somewhere else entirely.

This check is worth repeating whenever a tool scores unexpectedly low. It
distinguishes "the tool missed it" from "our ground truth is wrong", and those
two demand opposite responses.

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

## Tier 2: PyGoat and NodeGoat are labelled, three applications are not

**PyGoat carries 46 cases** at the pinned revision — 34 vulnerable across 17
weaknesses and 12 traps — written by reading the code, with the app's own
`Solutions/solution.md` as the first check on each label. The second check is
[RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark), an independent
hand-labelling of 26 Python applications whose 88 PyGoat entries were compared
one by one; its line numbers match this checkout exactly. Where the two agree on
the flaw but not the CWE, the case carries this corpus's primary and lists the
other in `acceptable_cwes` — MD5 password hashing is `CWE-327` here and
`CWE-328` there, plaintext storage `CWE-522` here and `CWE-256` there.

Left out on purpose, and why:

- flaws whose weakness is outside `spine/report/applicability.json` — `DEBUG =
  True` (CWE-215), the three-digit OTP and `random`-generated tokens (CWE-330),
  the reversed-SHA-256 password hash (CWE-916), and the three views that write
  submitted Python into modules the app later imports (CWE-73 by RealVuln's
  reading, code injection by any other). Adding a cell to the map is a decision,
  not a side effect of labelling
- the `@csrf_exempt` decorators on views that change no state, and the secret
  page with no admin check: real lessons, but not findings a scanner could
  reach without knowing the intent
- traps that sit within ten lines of a vulnerable case carrying the same
  weakness — `login.objects.filter(user=name)` two lines above the raw query it
  guards, the autoescaped `{{code}}` three lines above the one inside `<script>`.
  The scorer widens every range by the line tolerance, so a second finding on
  the vulnerable sink would claim the trap and charge a false positive the tool
  never made. See the rule added to the workflow below

**NodeGoat carries 24 cases** at the pinned revision — 20 vulnerable across 12
weaknesses, 4 traps — checked the same way. Its fixes ship as comments beside
each flaw, which makes the app its own answer key and leaves it almost no
correctly defended code to use as a trap: the four traps are the lookups, the
redirect and the log line that genuinely take nothing from the request.
RealVuln labelled the identical commit (28 entries, no traps), and the two agree
on every flaw inside the applicability map. Outside it, and therefore not
labelled: session fixation on login (CWE-384), the distinct invalid-username and
invalid-password messages (CWE-204), the catastrophic-backtracking routing-number
regex (CWE-1333), the session cookie without HttpOnly or Secure (CWE-614), SSN
and date of birth stored in the clear (CWE-312), and the plain-HTTP listener
(CWE-319). `marked` pinned to 0.3.5 is the corpus's first real-application SCA
case, reachable through the memo renderer.

**WebGoat, DVJA and Juice Shop are fetchable and unlabelled**, so a tier-2
number currently says something about Django, Flask and Express code and
nothing about Java or TypeScript — [THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md)
records what a synthetic-heavy result does and does not support.

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
   **Place it more than the line tolerance (10 lines) away from any vulnerable
   range carrying an overlapping CWE.** Closer than that, a tool that reports the
   real flaw twice — two rules on one sink is routine — has its second finding
   assigned to the trap, and the scorecard charges a false positive for a
   report the tool never made.
5. Run `compile_answers.py`; it fails if the file or line no longer exists.

`spine/schema/compile_answers.py` already validates tier-2 and tier-3 cases —
only the cases themselves are missing.

### Why tier 3 could be derived and tier 2 cannot

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
| `hadoop` | 4,655,050 | 27.28 s | 0.006 |

**Bucket names were estimates and every one of them was wrong.** `commons-lang`
was guessed at 50k and measures 130k; `spring-boot` was guessed at 200k and
measures 642k. The labels now carry the measurement.

Against the service levels that matter — under three minutes at 50–200k LOC,
under ten minutes past 500k — `commons-lang` sits inside the pull-request band
and `spring-boot` past the large-repository threshold, so the two thresholds are
covered. `hadoop` is an extreme rather than a representative case.

**Throughput is not a constant, and a single figure quoted from one repository
will be wrong for any other size.** Seconds per 1k LOC improves elevenfold across
this range — 0.068 at 15k, 0.006 at 4.6M — because fixed overhead (process
start, rule compilation, plugin loading) dominates a small repository entirely
and disappears into the noise on a large one. That is precisely why the smallest
bucket is here: a per-1k-LOC number derived only from large repositories would
badly understate the cost of scanning a small service, which is what most
pull-request gates actually scan.

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
