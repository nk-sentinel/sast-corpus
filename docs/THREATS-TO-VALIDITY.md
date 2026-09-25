# Threats to validity

What a result from this corpus does **not** prove. Write these down before
anyone challenges the numbers, not after.

## Synthetic code is easier than real code

Tier-1 fixtures are short and self-contained. Published measurements put
detection accuracy on synthetic suites around **10 percentage points higher**
than on real-world code, and the gap is not uniform across tools: pattern-matching
engines gain most, because short single-purpose files let them score without
cross-file dataflow or framework understanding.

**Consequence:** a tier-1 number overstates every tool, and overstates some more
than others. Always report tiers separately. A tool that leads on tier 1 and
collapses on tier 3 has told you something important.

## Tiers 2 and 3 leak their own answers

Vendored applications name their own weaknesses — WebGoat ships
`SqlInjectionLesson5.java`. That cannot be edited away without forking upstream,
so `spine/lint/antileak.py` reports it as a warning rather than failing.

**Consequence:** LLM-based scanners can classify tier-2/3 cases partly from
filenames and comments rather than analysis. Their tier-2/3 scores are inflated
relative to rule-based engines by an amount this corpus cannot measure. Report
the disclosed-leak count alongside the scores. Where a comparison hinges on it,
re-run with identifiers stripped and report both.

## Tuning state changes everything

Out-of-the-box and tuned configurations are different measurements. A tool
shipped with conservative defaults looks precise and blind; the same tool with
its full ruleset looks sensitive and noisy.

**Consequence:** declare per tool which was used. Where effort allows, measure
both — the delta is often more useful than either number.

## The instrument must not be a candidate

A scanner run during development shapes the corpus: its findings are what expose
wrong line numbers, wrong labels and wrong `acceptable_cwes`. That is the point of
running one. It also means the corpus quietly acquires the shape of whatever tool
was used — and if that tool is later a subject, the evaluation is measuring a
corpus built around it.

**Tools under evaluation here: Semgrep, Endor Labs, Aikido, and SonarQube** (the
incumbent being replaced). The standing rule:

- **No candidate's output may change the answer key.** Not a label, not a line
  range, not an `acceptable_cwes` entry. A candidate's `unmatched` findings may be
  read as a hint to re-examine a case; the case is then decided from the code and
  the CWE definitions, and the reasoning recorded.
- **Instrument runs use a non-candidate**: CodeQL, or single-purpose OSS linters
  (bandit, gosec, njsscan, brakeman, gitleaks), or the vendor-free probe described
  below.
- **OpenGrep does not count as independent.** It is a Semgrep fork sharing the
  engine and the community rule taxonomy, so it carries the same CWE tagging and
  the same blind spots.

One breach of this rule is already recorded: command-injection cases were widened
to accept CWE-94 because Semgrep tags its rules that way, which raised its
measured recall from 0.478 to 0.609. Reversed on 2026-09-25 and applied uniformly
to all 76 cases — see [MATCH-POLICY.md](MATCH-POLICY.md).

Not affected: the differential scorer check in [VALIDATION.md](VALIDATION.md) also
used Semgrep, but against OWASP Benchmark's ground truth rather than this
corpus's, so nothing here was tuned by it. Likewise the captured SonarQube and
Semgrep SARIF in `spine/tests/data/` — those fix *adapter* behaviour, and no
answer-key commit derives from them.

**The pipeline can be exercised with no vendor at all.** SARIF generated directly
from the answer key — one result per vulnerable case, then one per trap — must
score exactly `N` true positives with zero false alarms, and then zero true
positives with every trap tripped. That validates path resolution, line matching,
CWE matching and assignment without any scanner's opinion entering the corpus. It
does not establish that cases are *detectable*, which is a separate question and
not one a candidate should answer either.

## An adapter can be wrong in a way that looks like a bad tool

Every engine that cannot emit SARIF reaches the scorer through an adapter, and an
adapter built against a guessed API shape produces plausible SARIF and wrong
scores. The run completes, the scorecard looks credible, and nothing signals it.

This is not hypothetical. The SonarQube adapter here read the CWE from the rule's
`securityStandards`, which is what the documentation and every example suggest.
On 25.1 Community that field does not exist — the API rejects it as an unknown
value for `f` — and the rules returned with an issues export carry no CWE at all.
Every finding would have arrived without one, fallen back to the location-only
match rule, and made SonarQube look like a tool that does not tag weaknesses.

**Consequence:** no adapter may be trusted until it has been run against a real
export from the tool it claims to convert, and the regression fixture must be
that captured output rather than one written by hand. The tests built from a
hand-written fixture all passed.

## Location-only matches rest on weaker evidence

A tool that emits no CWE is matched on position alone, so it is neither unfairly
zeroed nor given free credit. But those matches are weaker than the rest: any
finding in the right place counts, whatever it was actually reporting.

**Consequence:** the count is in every scorecard and belongs in every quotation of
one. A result carrying many location-only matches is a weaker claim than the same
figure carrying none.

## Edition and licence tier decide capability

SonarQube Community has no taint-analysis engine; interfile dataflow is a
Developer Edition feature. Scored against an injection-heavy corpus it therefore
records low recall, and that measures the edition rather than the product.

**Consequence:** record the exact edition and licence tier beside the version. A
result against a community or trial build says nothing about the commercial one,
and quoting it as though it did would be straightforwardly misleading.

## The SCA and secret planes are not sized to discriminate

This corpus is aimed at SAST. The `sca` plane is 27 cases and the `secret` plane
33, most of them tier-1 synthetic manifests, and they exist so that a tool
claiming those planes is not scored against nothing — not to rank tools that
specialise in them. Software composition analysis turns on a reachability and
advisory-database question this corpus does not pose, and it deserves its own
evaluation with its own corpus.

**Consequence:** do not rank an SCA-first product on these numbers. Report the
`sca` and `secret` planes separately if at all, and treat a strong or weak result
there as indicative only.

## Coverage is not quality

A tool with no Swift support is not bad at Swift. Cases in an unsupported
language must be reported as `n/a` and excluded from that tool's denominators —
never counted as false negatives.

The same applies to planes: an engine that does not claim to do SCA should not
be scored on the SCA plane.

## Build-required engines fail differently

Fortify, Coverity and Veracode analyse compiled artifacts. If a fixture does not
build in the hermetic environment, those tools see nothing and score zero — which
reads identically to poor detection.

**Consequence:** `build/verify.sh` must be green before any run that includes
them, and a scorecard for a build-required tool must state the build succeeded.
This is why the check is load-bearing rather than hygiene.

A related trap: dependencies are pinned to exact versions, so what a fixture
compiles to does not drift. If a recipe is ever changed to resolve a range, two
scorecards taken at different times stop being comparable — and nothing in the
output would reveal it.

## Generated cases share a shape

Template-generated fixtures are combinatorially balanced but stylistically
uniform, and a tool can overfit to that uniformity just as it can to Juliet's
filenames. Hand-authored hard cases exist to break the pattern.

**Consequence:** track and report the generated/hand-authored ratio per language.
A result driven entirely by generated cases is weaker evidence than the case
count suggests.

## The match policy is a choice

±10 lines, `acceptable_cwes` equivalence, source-or-sink credit, one TP per case —
each is defensible and each moves the numbers. A different policy yields
different results from identical scans.

**Consequence:** the policy travels with every scorecard. Comparisons across
policies are invalid.

## This corpus is not a workload

`tier1/`–`tier3/` measure accuracy. They say nothing about scan time: the NFR
thresholds concern 50k–500k+ LOC repositories, and the accuracy corpus is orders
of magnitude smaller. Timing must come from `perf/`, on the same host, with the
phase split recorded.

## Sampling bias in what we chose to write

Cases exist because someone thought to author them. Weaknesses nobody on the team
thought of are absent from the corpus and therefore invisible in every score —
they inflate recall for all tools equally and silently.

**Consequence:** the corpus cannot establish an absolute recall figure. It
supports comparison between tools on the weaknesses it covers, which is a
narrower claim than "tool X detects 70% of vulnerabilities."

## Publication is contractually restricted

Commercial static-analysis licences commonly restrict publishing named benchmark
results without vendor approval. Internal evaluation is unaffected.

**Consequence:** anything leaving the organisation anonymises tool identities and
is cleared first.
