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
