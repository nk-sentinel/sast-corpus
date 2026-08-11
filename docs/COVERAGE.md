# Coverage

Generated from `answers/expectedresults-1.0.csv` by `spine/report/coverage.py`. Do not edit by hand — CI regenerates it and fails if this file has drifted from the corpus.

A cell reads `v/s`: vulnerable cases and safe siblings. A weakness with no safe sibling cannot measure a false-positive rate, and a language with no cases at all contributes nothing to a scorecard — which looks exactly like a tool having nothing to find. Both are listed below.

## Totals

| | |
|---|---|
| Cases | 153 |
| False-positive traps | 73 (48%) |
| Languages covered | 13 of 13 |
| Target weaknesses covered | 10 of 10 |
| Visible to build-required engines | 37 |

## Language × weakness

| language | CWE-89 | CWE-78 | CWE-79 | CWE-22 | CWE-502 | CWE-918 | CWE-611 | CWE-798 | CWE-327 | CWE-352 | CWE-94 | CWE-1395 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| java | 2/1 | 6/5 | 5/4 | 15/11 | 1/1 | · | 1/1 | 1/1 | 1/4 | 1/1 | 4/3 | 1/1 |
| kotlin | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · |
| python | 3/3 | 2/2 | 2/1 | 3/2 | 1/1 | 1/1 | 1/1 | 3/3 | 1/1 | · | · | · |
| javascript | 1/1 | 1/1 | 1/1 | 1/1 | · | 1/1 | · | · | · | · | · | 1/1 |
| typescript | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · |
| go | 1/1 | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · |
| csharp | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · |
| c | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · |
| cpp | · | 1/1 | · | · | · | · | · | · | · | · | · | · |
| swift | · | 1/1 | · | · | · | · | · | · | · | · | · | · |
| php | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · |
| ruby | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · | · |
| rust | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · | · |

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
- `CWE-94` — code injection
- `CWE-1395` — dependency on a vulnerable component

## Gaps

**88 of 130 language-by-weakness cells are empty.** Full coverage of the grid is not the goal — CSRF has no meaning in a C program, and SQL injection none in a shell script — but an empty cell still means a tool is never tested on that combination, so it cannot pass or fail it. The languages carrying only one or two weaknesses are the ones where a result rests on the least evidence.

Weaknesses covered per language, thinnest first:

- `cpp` — 1
- `swift` — 1
- `kotlin` — 2
- `typescript` — 2
- `csharp` — 2
- `c` — 2
- `php` — 2
- `ruby` — 2
- `rust` — 2
- `go` — 3
- `javascript` — 6
- `python` — 9
- `java` — 11

## Variants per weakness

A cell in the matrix above holding one case proves only that the weakness class is represented. These are the distinct mechanisms each weakness is actually tested through, and the context traps that ask whether a tool can tell code from prose.

| weakness | mechanisms | context traps |
|---|---|---|
| `CWE-22` | `(unlabelled)` | · |
| `CWE-78` | `(unlabelled)` | · |
| `CWE-79` | `(unlabelled)` | · |
| `CWE-89` | `(unlabelled)`, `dynamic-identifier`, `prepared-but-concatenated` | · |
| `CWE-94` | `(unlabelled)` | · |
| `CWE-327` | `(unlabelled)` | `in-comment`, `in-markdown`, `in-test-data` |
| `CWE-352` | `(unlabelled)` | · |
| `CWE-502` | `(unlabelled)` | · |
| `CWE-611` | `(unlabelled)` | · |
| `CWE-798` | `(unlabelled)` | · |
| `CWE-918` | `(unlabelled)` | · |
| `CWE-1395` | `(unlabelled)` | · |

**147 of 153 cases carry no variant label.** They were written before the field existed and are counted as `(unlabelled)`. Until they are named, the mechanism coverage above understates what exists and cannot show what is missing.

## OWASP Top 10 (2021)

| category | cases |
|---|---|
| A01 Broken Access Control | 17 |
| A02 Cryptographic Failures | 7 |
| A03 Injection | 56 |
| A04 Insecure Design | · |
| A05 Security Misconfiguration | 4 |
| A06 Vulnerable Components | 4 |
| A07 Identification and Authentication Failures | 8 |
| A08 Software and Data Integrity Failures | 4 |
| A09 Logging and Monitoring Failures | · |
| A10 Server-Side Request Forgery | 4 |

## Detection planes

| plane | cases |
|---|---|
| vuln | 145 |
| secret | 4 |
| sca | 4 |
| crypto | · |

`crypto` is delegated to the `CipherRadarTestProj` submodule and is not counted here.

## Realism tiers

| tier | cases |
|---|---|
| 1 — synthetic fixtures | 104 |
| 2 — real applications | · |
| 3 — CVE reproductions | 49 |

## Difficulty

| taint path | cases |
|---|---|
| intra-procedural | 27 |
| inter-procedural | 2 |
| inter-file | 75 |
| framework-mediated | · |

| sanitizer | cases |
|---|---|
| none | 51 |
| ineffective | 4 |
| custom-effective | 46 |
| framework-implicit | 24 |
