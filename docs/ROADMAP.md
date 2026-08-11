# Roadmap — phase 2

Target: **305 → ~645 cases**, with the growth concentrated on the axes that
separate tools rather than on more of the shape every tool already catches.

## Why not simply more breadth

Phase 1 ended with 33 weaknesses, 13 languages, and a floor of 6 weaknesses per
language. The totals look healthy. The discriminating power is not, and the
answer key says so plainly:

| axis | phase 1 state |
|---|---|
| `obfuscation` | **0 of 256** tier-1 cases |
| `sanitizer: ineffective` | **4 of 256** |
| `flow: inter-procedural` | **2 of 256** |
| tier-3 (real CVEs) | **Java only**, 49 cases |
| `sca` plane | **4 cases** |

Every tier-1 case is a direct flow with a clean sibling. A regular expression
scores well on that shape; so does a commercial dataflow engine. A corpus whose
cases all agree cannot rank the tools it exists to rank.

The `difficulty` enums in `spine/schema/case.schema.json` already declare
`aliasing`, `collection`, `reflection`, `callback` and `ineffective`. The axes
were designed in during phase 0 and never populated. Phase 2 populates them.

Precedent: [Securibench Micro](https://resess.github.io/artifacts/StaticTaint/benchmark/)
organises its 122 servlets by exactly these categories — aliasing, collections,
data structures, factories, reflection, strong updates — because those are what
discriminate. DroidBench states the criterion bluntly: *"aliases must be
computed precisely or a false positive will be found."*

## Work items

### 0. Tier-3 spike — de-risk before planning around it

The largest item is also the least certain, so it gets tested first.

[REEF](https://arxiv.org/html/2503.01449v1) (4,466 CVEs, 30,987 patches across
C, C++, C#, Go, Java, JS, Python) and PatchEval (1,000 vulnerabilities across
Go/JS/Python, 65 CWEs) both post-date the choice of cwe-bench-java. Before
committing to a case count, establish for each:

- licence, and whether derived ground truth may be published
- granularity — **function-level extraction is not usable**. Scoring needs whole
  files at real paths with real line numbers, or a checkout that a tool can scan
- whether recorded line numbers anchor to the **fixed** or the **buggy** commit.
  cwe-bench-java anchors to the fixed one, and taking it at face value silently
  mislabels every case. Assume nothing; verify per dataset
- how many CVEs survive filtering to weaknesses SAST can reach at all

Deliverable is a written go/no-go per dataset, not fixtures. If both fail on
granularity, fall back to deriving directly from GitHub Advisory fix commits for
a smaller, hand-picked set.

### 1. Applicability matrix + retirement mechanics

Two pieces of bookkeeping that make every later number honest.

**Applicability.** Density is currently reported against 13 × 33 = 429 cells,
but XXE in C and use-after-free in Java are not cells anyone should fill. An
explicit `applicable(language, cwe)` map turns 25% density into a figure that
means something, and stops the coverage doc implying gaps that are not gaps.

**Retirement.** Growth without a lifecycle story ends in a corpus nobody prunes:

- **Saturation.** Once three or more tools have been scored, a case that every
  tool finds and none false-positives on carries no further information. Mark it
  `saturated` — kept for regression, excluded from the headline discriminating
  metrics, and reported as a count so the corpus's own decay is visible.
- **Monoculture cap.** Well over 90% of tier-1 cases come from one `pair()`
  generator, which is a shape tools can overfit. Track the generated:hand-authored
  ratio in `docs/COVERAGE.md` and state a cap rather than discovering the drift
  later.
- **Withdrawal.** A case whose upstream CVE is disputed or withdrawn, or whose
  fixture stops parsing on a newer toolchain, gets `retired: <reason>` in its YAML
  and drops out of the answer key — not deleted, so old scorecards stay
  reproducible against the version that produced them.
- **Pin staleness.** Tier-3 and perf pins are full SHAs; add a check that flags
  pins past an age threshold rather than letting them quietly rot.

### 2. Hard cases — ~120

The highest-value item, and the one that needs hand authoring.

**Obfuscation (~60).** Six mechanisms across the five languages where the
constructs are idiomatic (Java, Python, JS/TS, C#, Go). Both directions matter:

| mechanism | tests | direction |
|---|---|---|
| `aliasing` | taint reaches the sink through a second reference to the same object | FN |
| `collection` | taint stored in and read back from a List/Map; element vs container precision | FN |
| `reflection` | sink invoked dynamically — `Method.invoke`, `getattr`, bracket access, `InvokeMember` | FN |
| `callback` | taint crosses a lambda, callback or event handler | FN |
| `strong-update` | variable overwritten with a safe value before the sink | **FP trap** |
| `container-field` | taint held in an object field, the object passed around | FN |

`strong-update` is deliberately a trap: a tool that does not model overwriting
reports a vulnerability that is not there. Two new `obfuscation` enum values
(`strong-update`, `container-field`) are needed; the other four already exist.

**Ineffective sanitizers (~60).** Ten mechanisms, three languages, each with a
correct sibling. This is where tools disagree most, and where the most common
real-world false negative lives — *any sanitizer on the path → suppress the
finding*:

- blacklist missing a variant (`<script>` stripped, `<img onerror>` not)
- single-pass replace defeated by nesting (`....//` → `../` after one pass)
- right encoder, wrong context (HTML encoding inside a JS string or a URL)
- encode then decode (sanitised, then `URLDecoder.decode` before the sink)
- **sanitising the wrong variable** — validate `a`, use `b`
- **validation result discarded** — the check runs, nothing acts on it
- ordering — sanitise one fragment, concatenate another tainted one after
- unanchored allowlist regex (`.` unescaped, no `^`/`$`)
- `replace` vs `replaceAll` semantics
- canonicalise after the check rather than before (path TOCTOU)

The two in bold are FN tests specifically: a sanitizer call is present and
irrelevant, and a tool matching on its presence rather than its effect is wrong.

### 3. SCA + secrets — ~60

Cheap, highly testable, and currently the emptiest plane.

**SCA (~32).** Eight ecosystems (Maven, npm, PyPI, Go modules, NuGet, Cargo,
Composer, RubyGems) across four scenarios:

- direct vulnerable dependency, **reachable** — the vulnerable API is called
- direct vulnerable dependency, **unreachable** — present, never called
- transitive-only, and dev/test-only (neither should read as a production finding)
- version string implies vulnerable, code is a patched fork or backport

The last is the sharpest: a scanner that reads only the manifest cannot tell it
from a real hit, and one that reads the code can.

**Secrets (~28).** Currently 14 cases and mostly Python. Spread the existing
types across languages and add JWT signing keys, SSH private keys, `.env` files,
CI configuration, Kubernetes secrets, base64-wrapped credentials, and
history-only secrets. Traps stay the majority on this plane — telling a
credential from a UUID, digest or placeholder is the hard part, not matching a
prefix.

### 4. Breadth floor 6 → 10 — ~60

Mechanical and low-risk, so it goes last. Seven thinnest languages, roughly four
weaknesses each, chosen against the applicability matrix from item 1 so the new
cells are ones that should exist.

### 5. Tier-3 at scale — ~100

Gated on item 0. Source-only languages first (Python, JS, Go), since every tool
can see them without a build; C/C++ and C# after, where a build is required and
the recipe work is real.

## Sequencing

```
0. tier-3 spike            de-risks the largest item; go/no-go, no fixtures
1. applicability + retire   small; makes items 2-5 reportable honestly
2. hard cases               +120   highest value per case
3. SCA + secrets            +60    cheapest per case
4. breadth floor            +60    mechanical
5. tier-3 at scale          +100   gated on 0
                            ----
                            +340 → ~645 cases
```

## New gates

Each item ships with the check that keeps it honest, test-first as before:

- a case labelled with an `obfuscation` value must not be reachable by a direct
  flow — otherwise the label is decoration
- every `sanitizer: ineffective` case must have a `custom-effective` sibling, or
  it measures nothing
- SCA cases validate `purl`, version and CVE against the manifest they ship with
- the applicability matrix must cover every `(language, cwe)` pair present in the
  answer key — a new cell with no applicability entry fails CI
- generated:hand-authored ratio reported in `docs/COVERAGE.md` and capped

## What this does not fix

Tier 1 stays synthetic, and synthetic cases are documented as running ~10%
higher accuracy than real code for every tool. More hard synthetic cases narrow
that gap without closing it — which is why item 5 exists and why tier results
are never merged. See [THREATS-TO-VALIDITY.md](THREATS-TO-VALIDITY.md).
