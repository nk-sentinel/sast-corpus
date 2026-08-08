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
| `tier3` | 2 CVE datasets, Java | working | **not authored** |

This is the honest state. The fetch mechanism, the pinning discipline and the
licence records are done. The labelling is not, and until it is, **every accuracy
number this corpus produces comes from tier-1 synthetic fixtures** — which
[THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md) records as the most favourable
and least representative measurement available.

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
