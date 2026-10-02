# Coverage

Generated from `answers/expectedresults-1.0.csv` by `spine/report/coverage.py`. Do not edit by hand — CI regenerates it and fails if this file has drifted from the corpus.

A cell reads `v/s`: vulnerable cases and safe siblings. A weakness with no safe sibling cannot measure a false-positive rate, and a language with no cases at all contributes nothing to a scorecard — which looks exactly like a tool having nothing to find. Both are listed below.

## Totals

| | |
|---|---|
| Cases | 849 |
| False-positive traps | 275 (32%) |
| Languages covered | 13 of 13 |
| Target weaknesses covered | 10 of 10 |
| Distinct weaknesses | 53 |
| Weaknesses per language | 10 thinnest (typescript) → 18 deepest (java), tier 1 |
| Visible to build-required engines | 37 |

## Language × weakness

| language | CWE-89 | CWE-78 | CWE-79 | CWE-22 | CWE-502 | CWE-918 | CWE-611 | CWE-798 | CWE-327 | CWE-352 | CWE-20 | CWE-59 | CWE-74 | CWE-77 | CWE-88 | CWE-94 | CWE-116 | CWE-117 | CWE-120 | CWE-121 | CWE-122 | CWE-125 | CWE-134 | CWE-190 | CWE-200 | CWE-269 | CWE-276 | CWE-284 | CWE-285 | CWE-287 | CWE-306 | CWE-307 | CWE-312 | CWE-345 | CWE-384 | CWE-416 | CWE-434 | CWE-444 | CWE-471 | CWE-476 | CWE-522 | CWE-532 | CWE-601 | CWE-610 | CWE-613 | CWE-639 | CWE-668 | CWE-732 | CWE-770 | CWE-787 | CWE-862 | CWE-863 | CWE-1395 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| java | 12/9 | 11/8 | 9/8 | 24/18 | 2/1 | 1/2 | 2/1 | 4/2 | 3/4 | 2/1 | · | · | · | 1/1 | · | 4/3 | · | 2/1 | · | · | · | · | · | · | 1/0 | · | · | 2/1 | · | 2/0 | · | · | · | · | · | · | · | · | 1/0 | · | · | 1/0 | 2/1 | · | · | 2/3 | · | · | 1/1 | · | 3/2 | 1/1 | 5/3 |
| kotlin | 1/1 | 1/1 | · | 1/1 | 1/1 | 1/1 | · | 1/1 | 1/1 | · | · | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | · |
| python | 13/8 | 17/7 | 9/4 | 23/7 | 4/2 | 4/3 | 2/1 | 17/14 | 3/2 | 1/0 | 4/1 | · | 1/0 | · | · | 4/0 | · | 1/0 | · | · | · | · | · | · | 5/1 | 4/0 | 1/0 | 4/0 | · | 1/0 | 1/1 | · | · | · | · | · | 2/2 | 2/0 | · | · | 3/1 | 3/1 | 6/0 | · | · | 1/1 | · | 1/0 | 2/1 | · | 2/0 | 4/0 | 2/2 |
| javascript | 7/5 | 15/4 | 9/2 | 16/5 | 1/0 | 8/2 | · | 3/1 | · | 1/0 | 6/0 | 2/0 | 2/0 | 2/0 | 1/0 | 9/1 | 2/0 | 2/2 | · | · | · | · | · | · | 3/1 | 1/0 | · | 1/0 | · | 1/0 | · | · | · | · | 1/0 | · | · | 1/0 | 1/0 | · | 2/0 | · | 7/1 | · | · | 1/1 | · | · | · | · | 5/0 | 3/0 | 3/2 |
| typescript | 3/2 | 1/1 | 2/2 | 4/2 | 1/1 | 2/1 | 1/0 | 3/1 | 1/0 | · | · | · | · | · | · | 4/0 | · | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | 1/0 | 1/0 | · | · | · | · | · | · | · | · | · | · | · | 1/0 | · | · | 1/1 | · | · | · | · | 1/1 | · | · |
| go | 10/3 | 10/2 | 1/1 | 15/3 | 1/1 | 5/1 | · | 2/2 | 1/1 | 1/0 | 1/0 | 1/0 | 1/0 | 1/1 | · | · | 1/0 | · | · | · | · | · | · | · | 1/0 | 4/0 | 2/0 | 1/0 | 2/0 | 2/0 | · | 1/0 | 1/0 | 1/0 | · | · | · | · | · | · | 2/0 | 2/0 | 4/0 | 1/0 | 2/0 | 1/0 | 1/0 | 1/0 | · | · | 7/0 | 8/0 | 1/1 |
| csharp | 3/3 | 3/3 | · | 3/3 | 1/1 | · | 1/1 | 2/2 | 1/1 | · | · | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 |
| c | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | 1/1 | · | · | · |
| cpp | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | 1/1 | 1/1 | · | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | 1/1 | · | · | · |
| swift | 1/1 | 1/1 | · | 1/1 | · | 1/1 | · | 1/1 | 1/1 | · | · | · | · | · | · | · | · | 1/1 | · | · | · | · | · | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | · |
| php | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | · | · | 1/1 | 1/1 | · | · | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | 1/1 |
| ruby | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | · | · | 1/1 | 1/1 | · | · | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | 1/1 |
| rust | 1/1 | 1/1 | · | 1/1 | · | 1/1 | · | 1/1 | 1/1 | · | · | · | · | · | · | · | · | 1/1 | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | 1/1 |

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
- `CWE-74` — injection
- `CWE-77` — command injection
- `CWE-88` — argument injection
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
- `CWE-269` — improper privilege management
- `CWE-276` — incorrect default permissions
- `CWE-284` — improper access control
- `CWE-285` — improper authorisation
- `CWE-287` — improper authentication
- `CWE-306` — missing authentication for critical function
- `CWE-307` — improper restriction of excessive authentication attempts
- `CWE-312` — cleartext storage of sensitive information
- `CWE-345` — insufficient verification of data authenticity
- `CWE-384` — session fixation
- `CWE-416` — use after free
- `CWE-434` — unrestricted upload of dangerous file type
- `CWE-444` — inconsistent interpretation of HTTP requests
- `CWE-471` — modification of assumed-immutable data
- `CWE-476` — NULL pointer dereference
- `CWE-522` — insufficiently protected credentials
- `CWE-532` — sensitive information in a log file
- `CWE-601` — open redirect
- `CWE-610` — externally controlled reference to a resource in another sphere
- `CWE-613` — insufficient session expiration
- `CWE-639` — authorisation bypass through user-controlled key
- `CWE-668` — exposure of resource to wrong sphere
- `CWE-732` — incorrect permission assignment for critical resource
- `CWE-770` — allocation without limits or throttling
- `CWE-787` — out-of-bounds write
- `CWE-862` — missing authorisation
- `CWE-863` — incorrect authorisation
- `CWE-1395` — dependency on a vulnerable component

## Gaps

**40 of 130 language-by-weakness cells are empty.** Full coverage of the grid is not the goal — CSRF has no meaning in a C program, and SQL injection none in a shell script — but an empty cell still means a tool is never tested on that combination, so it cannot pass or fail it. The languages carrying only one or two weaknesses are the ones where a result rests on the least evidence.

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
- `java` — 24
- `javascript` — 29
- `python` — 31
- `go` — 34

**Covered but with no safe sibling** — a false-positive rate cannot be measured for these:

- python / `CWE-352`
- javascript / `CWE-502`
- javascript / `CWE-352`
- typescript / `CWE-611`
- typescript / `CWE-327`
- go / `CWE-352`

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
| `cve` | 266 |
| `hand-authored` | 146 |
| `walkthrough` | 137 |

**65% of cases are hand-authored or CVE-derived** — everything not produced by the generator. A corpus dominated by one generator measures how well a tool handles that generator.

## Variants per weakness

A cell in the matrix above holding one case proves only that the weakness class is represented. These are the distinct mechanisms each weakness is actually tested through, and the context traps that ask whether a tool can tell code from prose.

| weakness | mechanisms | context traps |
|---|---|---|
| `CWE-20` | `unknown`, `unvalidated-numeric-range` | · |
| `CWE-22` | `base-silently-dropped`, `canonicalise-after-check`, `check-before-resolving`, `check-then-undo-it`, `denylist-filter`, `fixed-path`, `input-rejected`, `loop-filter`, `nesting-restores-it`, `null-byte-filter-bypass`, `object-carried`, `only-one-occurrence`, `overwritten-before-sink`, `result-not-assigned`, `single-pass-filter`, `struct-carried`, `unknown`, `unvalidated-concat`, `unvalidated-join`, `zip-slip` | · |
| `CWE-59` | `unknown` | · |
| `CWE-74` | `unknown` | · |
| `CWE-77` | `argument-injection`, `unknown` | · |
| `CWE-78` | `anchored-only-at-the-start`, `argument-vector`, `blocklist-filter`, `check-runs-nothing-acts`, `deserialized-command`, `dict-round-trip`, `dictionary-round-trip`, `map-round-trip`, `runtime-named-sink`, `shell-c-argument`, `shell-string`, `system-call`, `unknown`, `validator-return-dropped` | · |
| `CWE-79` | `attribute-context`, `autoescaped-command-output`, `autoescaped-output`, `encoder-for-another-place`, `ineffective-tag-filter`, `misses-a-variant`, `recursive-sanitiser`, `scriptlet-raw-output`, `tag-filter`, `template-html-optout`, `unescaped-output`, `unescaped-url-attribute`, `unknown`, `url-escaping-for-markup`, `wrong-context-escaping` | · |
| `CWE-88` | `unknown` | · |
| `CWE-89` | `closure-boundary`, `concat-statement`, `delegate-boundary`, `dynamic-identifier`, `format-string`, `jpql-concat`, `jpql-like-concat`, `lambda-boundary`, `orm-parameterised`, `parsed-integer-key`, `prepared-but-concatenated`, `prepared-parameterised`, `sanitised-then-appended`, `second-reference`, `typed-primary-key`, `unknown`, `validated-one-used-another` | · |
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
| `CWE-269` | `unknown` | · |
| `CWE-276` | `unknown` | · |
| `CWE-284` | `client-controlled-role`, `unknown` | · |
| `CWE-285` | `unknown` | · |
| `CWE-287` | `derivable-reset-token`, `optional-current-password`, `unknown`, `unsigned-session-token`, `unsigned-token` | · |
| `CWE-306` | `no-authentication` | · |
| `CWE-307` | `unknown` | · |
| `CWE-312` | `unknown` | · |
| `CWE-327` | `strong-hash-verify`, `unknown`, `weak-cipher-mode`, `weak-hash` | `in-comment`, `in-markdown`, `in-test-data` |
| `CWE-345` | `unknown` | · |
| `CWE-352` | `protection-disabled`, `unknown` | · |
| `CWE-384` | `unknown` | · |
| `CWE-416` | `dangling-reference`, `use-after-free` | · |
| `CWE-434` | `blocklist-extension`, `unchecked-upload` | · |
| `CWE-444` | `unknown` | · |
| `CWE-471` | `mass-assignment`, `unknown` | · |
| `CWE-476` | `unchecked-allocation` | · |
| `CWE-502` | `binaryformatter`, `marshal-untrusted`, `objectinputstream`, `pickle-untrusted`, `prototype-pollution`, `serialise-not-deserialise`, `unknown`, `unserialize-untrusted`, `yaml-untrusted` | · |
| `CWE-522` | `framework-hashed-password`, `plaintext-password-storage`, `unknown` | · |
| `CWE-532` | `credentials-in-log`, `unknown` | · |
| `CWE-601` | `allowlist-redirect`, `fixed-target-redirect`, `substring-allowlist`, `unknown`, `unvalidated-redirect` | · |
| `CWE-610` | `unknown` | · |
| `CWE-611` | `default-factory`, `default-resolver`, `entities-enabled` | · |
| `CWE-613` | `unknown` | · |
| `CWE-639` | `ownership-checked`, `session-bound-lookup`, `strong-update`, `unknown`, `user-controlled-key` | · |
| `CWE-668` | `unknown` | · |
| `CWE-732` | `unknown` | · |
| `CWE-770` | `unbounded-allocation`, `unknown` | · |
| `CWE-787` | `unchecked-index-write` | · |
| `CWE-798` | `chat-token`, `cloud-key-pair`, `cloud-storage`, `committed-env-file`, `connection-string`, `digest-not-secret`, `identifier-not-secret`, `literal-in-source`, `manifest-literal`, `payment-key`, `pem-private-key`, `pipeline-configuration`, `private-key-file`, `signing-key`, `signing-key-literal`, `test-data-not-secret`, `vcs-token`, `wrapped-credential` | `in-example-config` |
| `CWE-862` | `intentionally-public`, `missing-annotation`, `no-ownership-check`, `unknown` | · |
| `CWE-863` | `unknown`, `wrong-role-checked` | · |
| `CWE-918` | `fixed-host-url`, `matches-anywhere`, `pattern-matches-anywhere`, `pattern-tests-anywhere`, `unknown`, `unvalidated-url` | · |
| `CWE-1395` | `development-only`, `just-outside-the-range`, `present-but-never-called`, `transitive-only`, `vulnerable-version` | · |

`unknown` is not the same gap. 266 derived tier-3 cases carry it because the mechanism is not knowable from the CVE metadata — only from reading the code — and guessing would be indistinguishable from a finding in the table above.

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

266 cases carry no category — the tier-3 derivations record the CWE only — and are not counted above.

## Detection planes

| plane | cases |
|---|---|
| vuln | 789 |
| secret | 33 |
| sca | 27 |
| crypto | · |

`crypto` is delegated to the `CipherRadarTestProj` submodule and is not counted here.

## Realism tiers

| tier | cases |
|---|---|
| 1 — synthetic fixtures | 446 |
| 2 — real applications | 137 |
| 3 — CVE reproductions | 266 |

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
