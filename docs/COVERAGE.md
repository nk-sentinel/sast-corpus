# Coverage

Generated from `answers/expectedresults-1.0.csv` by `spine/report/coverage.py`. Do not edit by hand — CI regenerates it and fails if this file has drifted from the corpus.

A cell reads `v/s`: vulnerable cases and safe siblings. A weakness with no safe sibling cannot measure a false-positive rate, and a language with no cases at all contributes nothing to a scorecard — which looks exactly like a tool having nothing to find. Both are listed below.

## Totals

| | |
|---|---|
| Cases | 126 |
| False-positive traps | 48 (38%) |
| Languages covered | 13 of 13 |
| Target weaknesses covered | 10 of 10 |
| Visible to build-required engines | 34 |

## Language × weakness

| language | CWE-89 | CWE-78 | CWE-79 | CWE-22 | CWE-502 | CWE-918 | CWE-611 | CWE-798 | CWE-327 | CWE-352 | CWE-94 | CWE-1395 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| java | · | 6/1 | 5/0 | 15/1 | 1/1 | · | 1/1 | 1/1 | 1/1 | 1/1 | 4/0 | 1/1 |
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

**89 of 130 language-by-weakness cells are empty.** Full coverage of the grid is not the goal — CSRF has no meaning in a C program, and SQL injection none in a shell script — but an empty cell still means a tool is never tested on that combination, so it cannot pass or fail it. The languages carrying only one or two weaknesses are the ones where a result rests on the least evidence.

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
- `java` — 10

**Covered but with no safe sibling** — a false-positive rate cannot be measured for these:

- java / `CWE-79`

## OWASP Top 10 (2021)

| category | cases |
|---|---|
| A01 Broken Access Control | 17 |
| A02 Cryptographic Failures | 4 |
| A03 Injection | 53 |
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
| vuln | 118 |
| secret | 4 |
| sca | 4 |
| crypto | · |

`crypto` is delegated to the `CipherRadarTestProj` submodule and is not counted here.

## Realism tiers

| tier | cases |
|---|---|
| 1 — synthetic fixtures | 98 |
| 2 — real applications | · |
| 3 — CVE reproductions | 28 |

## Difficulty

| taint path | cases |
|---|---|
| intra-procedural | 24 |
| inter-procedural | 2 |
| inter-file | 72 |
| framework-mediated | · |

| sanitizer | cases |
|---|---|
| none | 48 |
| ineffective | 2 |
| custom-effective | 24 |
| framework-implicit | 24 |
