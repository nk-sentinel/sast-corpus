# Coverage

Generated from `answers/expectedresults-1.0.csv` by `spine/report/coverage.py`. Do not edit by hand — CI regenerates it and fails if this file has drifted from the corpus.

A cell reads `v/s`: vulnerable cases and safe siblings. A weakness with no safe sibling cannot measure a false-positive rate, and a language with no cases at all contributes nothing to a scorecard — which looks exactly like a tool having nothing to find. Both are listed below.

## Totals

| | |
|---|---|
| Cases | 680 |
| False-positive traps | 275 (40%) |
| Languages covered | 13 of 13 |
| Target weaknesses covered | 10 of 10 |
| Distinct weaknesses | 42 |
| Weaknesses per language | 10 thinnest (typescript) → 18 deepest (java), tier 1 |
| Visible to build-required engines | 37 |

## Language × weakness

| language | CWE-89 | CWE-78 | CWE-79 | CWE-22 | CWE-502 | CWE-918 | CWE-611 | CWE-798 | CWE-327 | CWE-352 | CWE-20 | CWE-59 | CWE-77 | CWE-94 | CWE-116 | CWE-117 | CWE-120 | CWE-121 | CWE-122 | CWE-125 | CWE-134 | CWE-190 | CWE-200 | CWE-276 | CWE-284 | CWE-285 | CWE-287 | CWE-306 | CWE-307 | CWE-416 | CWE-434 | CWE-471 | CWE-476 | CWE-522 | CWE-532 | CWE-601 | CWE-639 | CWE-770 | CWE-787 | CWE-862 | CWE-863 | CWE-1395 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| java | 12/9 | 11/8 | 9/8 | 24/18 | 2/1 | 1/2 | 2/1 | 4/2 | 3/4 | 2/1 | · | · | 1/1 | 4/3 | · | 2/1 | · | · | · | · | · | · | 1/0 | · | 2/1 | · | 2/0 | · | · | · | · | 1/0 | · | · | 1/0 | 2/1 | 2/3 | 1/1 | · | 3/2 | 1/1 | 5/3 |
| kotlin | 1/1 | 1/1 | · | 1/1 | 1/1 | 1/1 | · | 1/1 | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | · |
| python | 9/8 | 10/7 | 8/4 | 14/7 | 4/2 | 3/3 | 2/1 | 17/14 | 2/2 | 1/0 | 2/1 | · | · | 4/0 | · | 1/0 | · | · | · | · | · | · | 3/1 | · | 4/0 | · | 1/0 | 1/1 | · | · | 2/2 | · | · | 1/1 | 1/1 | 3/0 | 1/1 | 1/1 | · | 1/0 | 1/0 | 2/2 |
| javascript | 5/5 | 9/4 | 9/2 | 6/5 | · | 5/2 | · | 3/1 | · | 1/0 | · | 1/0 | · | 4/1 | · | 2/2 | · | · | · | · | · | · | 2/1 | · | · | · | 1/0 | · | · | · | · | 1/0 | · | 1/0 | · | 2/1 | 1/1 | · | · | 2/0 | · | 3/2 |
| typescript | 3/2 | 1/1 | 2/2 | 4/2 | 1/1 | 2/1 | 1/0 | 3/1 | 1/0 | · | · | · | · | 4/0 | · | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | 1/0 | 1/0 | · | · | · | · | · | · | · | 1/0 | 1/1 | · | · | 1/1 | · | · |
| go | 5/3 | 3/2 | 1/1 | 4/3 | 1/1 | 1/1 | · | 2/2 | 1/1 | · | · | · | 1/1 | · | 1/0 | · | · | · | · | · | · | · | 1/0 | 1/0 | · | 1/0 | · | · | 1/0 | · | · | · | · | 1/0 | 1/0 | 1/0 | · | · | · | 3/0 | 2/0 | 1/1 |
| csharp | 3/3 | 3/3 | · | 3/3 | 1/1 | · | 1/1 | 2/2 | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 |
| c | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | · | · | · | · | · | · | · | 1/1 | · | · | 1/1 | · | · | · | · | · | 1/1 | · | · | · |
| cpp | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | 1/1 | 1/1 | 1/1 | · | 1/1 | 1/1 | · | · | · | · | · | · | · | · | 1/1 | · | · | 1/1 | · | · | · | · | · | 1/1 | · | · | · |
| swift | 1/1 | 1/1 | · | 1/1 | · | 1/1 | · | 1/1 | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | · | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | · |
| php | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | · | · | 1/1 | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | 1/1 |
| ruby | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | · | · | 1/1 | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | 1/1 |
| rust | 1/1 | 1/1 | · | 1/1 | · | 1/1 | · | 1/1 | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | 1/1 |

Weakness codes:

- `CWE-89` — SQL injection
- `CWE-78` — OS command injection
- `CWE-79` — cross-site scripting
- `CWE-22` — path traversal
- `CWE-502` — unsafe deserialisation
- `CWE-918` — server-side request forgery
- `CWE-611` — XML external entity
- `CWE-798` — hard-coded credentials
- `CWE-327` — broken crypto
- `CWE-352` — cross-site request forgery
- `CWE-20` — improper input validation
- `CWE-59` — link following
- `CWE-77` — command injection
- `CWE-94` — code injection
- `CWE-116` — improper encoding or escaping of output
- `CWE-117` — improper output neutralisation for logs
- `CWE-120` — buffer copy without size check
- `CWE-121` — stack-based buffer overflow
- `CWE-122` — heap-based buffer overflow
- `CWE-125` — out-of-bounds read
- `CWE-134` — externally controlled format string
- `CWE-190` — integer overflow or wraparound
- `CWE-200` — exposure of sensitive information
- `CWE-276` — incorrect default permissions
- `CWE-284` — improper access control
- `CWE-285` — improper authorisation
- `CWE-287` — improper authentication
- `CWE-306` — missing authentication for critical function
- `CWE-307` — improper restriction of excessive authentication attempts
- `CWE-416` — use after free
- `CWE-434` — unrestricted upload of dangerous file type
- `CWE-471` — modification of assumed-immutable data
- `CWE-476` — NULL pointer dereference
- `CWE-522` — insufficiently protected credentials
- `CWE-532` — sensitive information in a log file
- `CWE-601` — open redirect
- `CWE-639` — authorisation bypass through user-controlled key
- `CWE-770` — allocation without limits or throttling
- `CWE-787` — out-of-bounds write
- `CWE-862` — missing authorisation
- `CWE-863` — incorrect authorisation
- `CWE-1395` — dependency on a vulnerable component

## Gaps

**42 of 130 language-by-weakness cells are empty.** Full coverage of the grid is not the goal — CSRF has no meaning in a C program, and SQL injection none in a shell script — but an empty cell still means a tool is never tested on that combination, so it cannot pass or fail it. The languages carrying only one or two weaknesses are the ones where a result rests on the least evidence.

Weaknesses covered per language across every tier, thinnest first. Tier 1 alone is the depth table below, and the two differ wherever tier 3 brought weaknesses nobody designed in:

- `kotlin` — 10
- `csharp` — 10
- `cpp` — 10
- `swift` — 10
- `php` — 10
- `ruby` — 10
- `rust` — 10
- `c` — 11
- `typescript` — 17
- `javascript` — 18
- `go` — 20
- `java` — 24
- `python` — 26

**Covered but with no safe sibling** — a false-positive rate cannot be measured for these:

- python / `CWE-352`
- javascript / `CWE-352`
- typescript / `CWE-611`
- typescript / `CWE-327`

## Depth per language

The distinct-CWE total for the corpus says nothing about spread. This is what each language is actually tested on, and it is heavily uneven — a result for a language near the bottom of this table rests on very little.

**Tier 1 only.** Tier-3 rows come from whatever CVEs the upstream dataset happens to contain, so counting them would credit breadth nobody designed; the gaps list above counts every tier.

| language | weaknesses (tier 1) | cases (tier 1) |
|---|---|---|
| `java` | 18 | 76 |
| `python` | 16 | 96 |
| `c` | 11 | 22 |
| `cpp` | 10 | 20 |
| `csharp` | 10 | 34 |
| `go` | 10 | 32 |
| `javascript` | 10 | 46 |
| `kotlin` | 10 | 20 |
| `php` | 10 | 20 |
| `ruby` | 10 | 20 |
| `rust` | 10 | 20 |
| `swift` | 10 | 20 |
| `typescript` | 10 | 20 |

Grid density is **34%** — 145 of the 429 language-by-weakness cells the tier-1 material spans are filled.

That figure counts cells nobody should fill. Use-after-free in Java and XXE in C are not gaps, and measuring against them understates the corpus. Against the 328 cells where the weakness can arise at all — `spine/report/applicability.json`, which is checked against the answer key in CI — density is **44%**.

Neither figure should be read as an ambition to reach 100%. They bound how far a per-language result generalises: a row resting on few cells is a sample, not a verdict.

## Where the cases came from

Template-generated cases share a shape a tool can **overfit** to, so the hand-authored share is tracked rather than left to drift.

| provenance | cases |
|---|---|
| `generated` | 300 |
| `hand-authored` | 146 |
| `walkthrough` | 137 |
| `cve` | 97 |

**56% of cases are hand-authored or CVE-derived** — everything not produced by the generator. A corpus dominated by one generator measures how well a tool handles that generator.

## Variants per weakness

A cell in the matrix above holding one case proves only that the weakness class is represented. These are the distinct mechanisms each weakness is actually tested through, and the context traps that ask whether a tool can tell code from prose.

| weakness | mechanisms | context traps |
|---|---|---|
| `CWE-20` | `unknown`, `unvalidated-numeric-range` | · |
| `CWE-22` | `(unlabelled)`, `denylist-filter`, `fixed-path`, `input-rejected`, `loop-filter`, `null-byte-filter-bypass`, `single-pass-filter`, `unknown`, `unvalidated-concat`, `unvalidated-join`, `zip-slip` | · |
| `CWE-59` | `unknown` | · |
| `CWE-77` | `argument-injection` | · |
| `CWE-78` | `(unlabelled)`, `argument-vector`, `blocklist-filter`, `deserialized-command`, `shell-c-argument`, `shell-string`, `system-call`, `unknown` | · |
| `CWE-79` | `(unlabelled)`, `autoescaped-command-output`, `autoescaped-output`, `ineffective-tag-filter`, `recursive-sanitiser`, `scriptlet-raw-output`, `tag-filter`, `template-html-optout`, `unescaped-output`, `unescaped-url-attribute`, `unknown`, `wrong-context-escaping` | · |
| `CWE-89` | `(unlabelled)`, `concat-statement`, `dynamic-identifier`, `format-string`, `jpql-concat`, `jpql-like-concat`, `orm-parameterised`, `parsed-integer-key`, `prepared-but-concatenated`, `prepared-parameterised`, `typed-primary-key`, `unknown` | · |
| `CWE-94` | `dynamic-evaluation`, `nosql-where-injection`, `sandbox-evaluation`, `template-injection`, `unknown` | · |
| `CWE-116` | `unknown` | · |
| `CWE-117` | `constant-log-entry`, `unsanitised-entry`, `unsanitised-log-entry` | · |
| `CWE-120` | `unbounded-copy` | · |
| `CWE-121` | `stack-format-copy`, `unbounded-copy` | · |
| `CWE-122` | `off-by-one-allocation` | · |
| `CWE-125` | `unchecked-index-in-unsafe`, `unchecked-index-read` | · |
| `CWE-134` | `caller-controls-the-template`, `user-controlled-format` | · |
| `CWE-190` | `allocation-size-overflow`, `unchecked-arithmetic` | · |
| `CWE-200` | `error-detail-returned`, `stack-returned`, `stack-trace-to-client`, `unauthenticated-lookup`, `unknown` | · |
| `CWE-276` | `unknown` | · |
| `CWE-284` | `client-controlled-role`, `unknown` | · |
| `CWE-285` | `unknown` | · |
| `CWE-287` | `derivable-reset-token`, `optional-current-password`, `unknown`, `unsigned-session-token`, `unsigned-token` | · |
| `CWE-306` | `no-authentication` | · |
| `CWE-307` | `unknown` | · |
| `CWE-327` | `strong-hash-verify`, `weak-cipher-mode`, `weak-hash` | `in-comment`, `in-markdown`, `in-test-data` |
| `CWE-352` | `protection-disabled` | · |
| `CWE-416` | `dangling-reference`, `use-after-free` | · |
| `CWE-434` | `blocklist-extension`, `unchecked-upload` | · |
| `CWE-471` | `mass-assignment`, `unknown` | · |
| `CWE-476` | `unchecked-allocation` | · |
| `CWE-502` | `binaryformatter`, `marshal-untrusted`, `objectinputstream`, `pickle-untrusted`, `prototype-pollution`, `serialise-not-deserialise`, `unserialize-untrusted`, `yaml-untrusted` | · |
| `CWE-522` | `framework-hashed-password`, `plaintext-password-storage`, `unknown` | · |
| `CWE-532` | `credentials-in-log`, `unknown` | · |
| `CWE-601` | `allowlist-redirect`, `fixed-target-redirect`, `substring-allowlist`, `unknown`, `unvalidated-redirect` | · |
| `CWE-611` | `default-factory`, `default-resolver`, `entities-enabled` | · |
| `CWE-639` | `ownership-checked`, `session-bound-lookup`, `strong-update`, `user-controlled-key` | · |
| `CWE-770` | `unbounded-allocation` | · |
| `CWE-787` | `unchecked-index-write` | · |
| `CWE-798` | `(unlabelled)`, `chat-token`, `cloud-key-pair`, `connection-string`, `digest-not-secret`, `identifier-not-secret`, `literal-in-source`, `payment-key`, `pem-private-key`, `signing-key-literal`, `test-data-not-secret`, `vcs-token` | `in-example-config` |
| `CWE-862` | `intentionally-public`, `missing-annotation`, `no-ownership-check`, `unknown` | · |
| `CWE-863` | `unknown`, `wrong-role-checked` | · |
| `CWE-918` | `(unlabelled)`, `fixed-host-url`, `unknown`, `unvalidated-url` | · |
| `CWE-1395` | `(unlabelled)`, `vulnerable-version` | · |

**139 of 680 cases carry no variant label** and are counted as `(unlabelled)`. Until they are named the mechanism coverage above understates what exists and cannot show what is missing.

`unknown` is not the same gap. 97 derived tier-3 cases carry it because the mechanism is not knowable from the CVE metadata — only from reading the code — and guessing would be indistinguishable from a finding in the table above.

## OWASP Top 10 (2021)

| category | cases |
|---|---|
| A01 Broken Access Control | 139 |
| A02 Cryptographic Failures | 26 |
| A03 Injection | 225 |
| A04 Insecure Design | 10 |
| A05 Security Misconfiguration | 9 |
| A06 Vulnerable Components | 27 |
| A07 Identification and Authentication Failures | 73 |
| A08 Software and Data Integrity Failures | 22 |
| A09 Logging and Monitoring Failures | 27 |
| A10 Server-Side Request Forgery | 25 |

97 cases carry no category — the tier-3 derivations record the CWE only — and are not counted above.

## Detection planes

| plane | cases |
|---|---|
| vuln | 620 |
| secret | 33 |
| sca | 27 |
| crypto | · |

`crypto` is delegated to the `CipherRadarTestProj` submodule and is not counted here.

## Realism tiers

| tier | cases |
|---|---|
| 1 — synthetic fixtures | 446 |
| 2 — real applications | 137 |
| 3 — CVE reproductions | 97 |

## Difficulty

| taint path | cases |
|---|---|
| intra-procedural | 176 |
| inter-procedural | 5 |
| inter-file | 393 |
| framework-mediated | 9 |

| sanitizer | cases |
|---|---|
| none | 293 |
| ineffective | 43 |
| custom-effective | 225 |
| framework-implicit | 43 |
