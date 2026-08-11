# Coverage

Generated from `answers/expectedresults-1.0.csv` by `spine/report/coverage.py`. Do not edit by hand — CI regenerates it and fails if this file has drifted from the corpus.

A cell reads `v/s`: vulnerable cases and safe siblings. A weakness with no safe sibling cannot measure a false-positive rate, and a language with no cases at all contributes nothing to a scorecard — which looks exactly like a tool having nothing to find. Both are listed below.

## Totals

| | |
|---|---|
| Cases | 219 |
| False-positive traps | 106 (48%) |
| Languages covered | 13 of 13 |
| Target weaknesses covered | 10 of 10 |
| Visible to build-required engines | 37 |

## Language × weakness

| language | CWE-89 | CWE-78 | CWE-79 | CWE-22 | CWE-502 | CWE-918 | CWE-611 | CWE-798 | CWE-327 | CWE-352 | CWE-20 | CWE-77 | CWE-94 | CWE-117 | CWE-120 | CWE-121 | CWE-122 | CWE-125 | CWE-134 | CWE-190 | CWE-200 | CWE-284 | CWE-306 | CWE-416 | CWE-434 | CWE-476 | CWE-532 | CWE-639 | CWE-770 | CWE-787 | CWE-862 | CWE-863 | CWE-1395 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| java | 2/1 | 6/5 | 5/4 | 15/11 | 1/1 | · | 1/1 | 1/1 | 1/4 | 1/1 | · | 1/1 | 4/3 | 1/1 | · | · | · | · | · | · | · | 1/1 | · | · | · | · | · | 1/1 | 1/1 | · | 2/2 | 1/1 | 1/1 |
| kotlin | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| python | 3/3 | 2/2 | 2/1 | 3/2 | 1/1 | 1/1 | 1/1 | 9/9 | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · | · | 1/1 | · | 1/1 | · | 2/2 | · | 1/1 | · | 1/1 | · | · | · | · |
| javascript | 1/1 | 1/1 | 1/1 | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 |
| typescript | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| go | 1/1 | 1/1 | · | 1/1 | · | · | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| csharp | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| c | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · | · | · | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | · | · | · | 1/1 | · | 1/1 | · | · | · | 1/1 | · | · | · |
| cpp | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1/1 | · | · | · | · | · | 1/1 | · | · | · | · | · | · | · | · | · |
| swift | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| php | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| ruby | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| rust | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |

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
- `CWE-20` — 
- `CWE-77` — 
- `CWE-94` — code injection
- `CWE-117` — 
- `CWE-120` — 
- `CWE-121` — 
- `CWE-122` — 
- `CWE-125` — 
- `CWE-134` — 
- `CWE-190` — 
- `CWE-200` — 
- `CWE-284` — 
- `CWE-306` — 
- `CWE-416` — 
- `CWE-434` — 
- `CWE-476` — 
- `CWE-532` — 
- `CWE-639` — 
- `CWE-770` — 
- `CWE-787` — 
- `CWE-862` — 
- `CWE-863` — 
- `CWE-1395` — dependency on a vulnerable component

## Gaps

**88 of 130 language-by-weakness cells are empty.** Full coverage of the grid is not the goal — CSRF has no meaning in a C program, and SQL injection none in a shell script — but an empty cell still means a tool is never tested on that combination, so it cannot pass or fail it. The languages carrying only one or two weaknesses are the ones where a result rests on the least evidence.

Weaknesses covered per language, thinnest first:

- `swift` — 1
- `kotlin` — 2
- `typescript` — 2
- `csharp` — 2
- `php` — 2
- `ruby` — 2
- `rust` — 2
- `cpp` — 3
- `go` — 4
- `javascript` — 6
- `c` — 11
- `python` — 15
- `java` — 18

## Depth per language

The distinct-CWE total for the corpus says nothing about spread. This is what each language is actually tested on, and it is heavily uneven — a result for a language near the bottom of this table rests on very little.

| language | weaknesses | cases |
|---|---|---|
| `java` | 16 | 38 |
| `python` | 15 | 58 |
| `c` | 11 | 22 |
| `javascript` | 6 | 12 |
| `go` | 4 | 8 |
| `cpp` | 3 | 6 |
| `csharp` | 2 | 4 |
| `kotlin` | 2 | 4 |
| `php` | 2 | 4 |
| `ruby` | 2 | 4 |
| `rust` | 2 | 4 |
| `typescript` | 2 | 4 |
| `swift` | 1 | 2 |

Grid density is **16%** — 68 of the language-by-weakness cells the present material spans are filled. Full density is not the goal, since many combinations are meaningless, but the figure is the honest measure of how far the corpus generalises beyond its deepest languages.

## Variants per weakness

A cell in the matrix above holding one case proves only that the weakness class is represented. These are the distinct mechanisms each weakness is actually tested through, and the context traps that ask whether a tool can tell code from prose.

| weakness | mechanisms | context traps |
|---|---|---|
| `CWE-20` | `unvalidated-numeric-range` | · |
| `CWE-22` | `loop-filter`, `single-pass-filter`, `unknown`, `unvalidated-concat`, `unvalidated-join` | · |
| `CWE-77` | `argument-injection` | · |
| `CWE-78` | `blocklist-filter`, `shell-string`, `system-call`, `unknown` | · |
| `CWE-79` | `tag-filter`, `unescaped-output`, `unknown` | · |
| `CWE-89` | `concat-statement`, `dynamic-identifier`, `format-string`, `prepared-but-concatenated` | · |
| `CWE-94` | `unknown` | · |
| `CWE-117` | `unsanitised-log-entry` | · |
| `CWE-120` | `unbounded-copy` | · |
| `CWE-121` | `stack-format-copy` | · |
| `CWE-122` | `off-by-one-allocation` | · |
| `CWE-125` | `unchecked-index-read` | · |
| `CWE-134` | `user-controlled-format` | · |
| `CWE-190` | `allocation-size-overflow` | · |
| `CWE-200` | `stack-trace-to-client` | · |
| `CWE-284` | `client-controlled-role` | · |
| `CWE-306` | `no-authentication` | · |
| `CWE-327` | `weak-cipher-mode`, `weak-hash` | `in-comment`, `in-markdown`, `in-test-data` |
| `CWE-352` | `protection-disabled` | · |
| `CWE-416` | `dangling-reference`, `use-after-free` | · |
| `CWE-434` | `blocklist-extension`, `unchecked-upload` | · |
| `CWE-476` | `unchecked-allocation` | · |
| `CWE-502` | `objectinputstream`, `pickle-untrusted` | · |
| `CWE-532` | `credentials-in-log` | · |
| `CWE-611` | `default-factory`, `entities-enabled` | · |
| `CWE-639` | `user-controlled-key` | · |
| `CWE-770` | `unbounded-allocation` | · |
| `CWE-787` | `unchecked-index-write` | · |
| `CWE-798` | `chat-token`, `cloud-key-pair`, `connection-string`, `identifier-not-secret`, `literal-in-source`, `payment-key`, `pem-private-key`, `signing-key-literal`, `vcs-token` | `in-example-config` |
| `CWE-862` | `intentionally-public`, `missing-annotation` | · |
| `CWE-863` | `wrong-role-checked` | · |
| `CWE-918` | `unvalidated-url` | · |
| `CWE-1395` | `vulnerable-version` | · |

`unknown` is not the same gap. 49 derived tier-3 cases carry it because the mechanism is not knowable from the CVE metadata — only from reading the code — and guessing would be indistinguishable from a finding in the table above.

## OWASP Top 10 (2021)

| category | cases |
|---|---|
| A01 Broken Access Control | 29 |
| A02 Cryptographic Failures | 7 |
| A03 Injection | 82 |
| A04 Insecure Design | 10 |
| A05 Security Misconfiguration | 4 |
| A06 Vulnerable Components | 4 |
| A07 Identification and Authentication Failures | 22 |
| A08 Software and Data Integrity Failures | 4 |
| A09 Logging and Monitoring Failures | 4 |
| A10 Server-Side Request Forgery | 4 |

## Detection planes

| plane | cases |
|---|---|
| vuln | 201 |
| secret | 14 |
| sca | 4 |
| crypto | · |

`crypto` is delegated to the `CipherRadarTestProj` submodule and is not counted here.

## Realism tiers

| tier | cases |
|---|---|
| 1 — synthetic fixtures | 170 |
| 2 — real applications | · |
| 3 — CVE reproductions | 49 |

## Difficulty

| taint path | cases |
|---|---|
| intra-procedural | 39 |
| inter-procedural | 2 |
| inter-file | 121 |
| framework-mediated | 8 |

| sanitizer | cases |
|---|---|
| none | 84 |
| ineffective | 4 |
| custom-effective | 75 |
| framework-implicit | 28 |
