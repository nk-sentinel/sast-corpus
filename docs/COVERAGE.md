# Coverage

Generated from `answers/expectedresults-1.0.csv` by `spine/report/coverage.py`. Do not edit by hand — CI regenerates it and fails if this file has drifted from the corpus.

A cell reads `v/s`: vulnerable cases and safe siblings. A weakness with no safe sibling cannot measure a false-positive rate, and a language with no cases at all contributes nothing to a scorecard — which looks exactly like a tool having nothing to find. Both are listed below.

## Totals

| | |
|---|---|
| Cases | 104 |
| False-positive traps | 51 (49%) |
| Languages covered | 13 of 13 |
| Target weaknesses covered | 10 of 10 |
| Visible to build-required engines | 12 |

## Language × weakness

| language | CWE-89 | CWE-78 | CWE-79 | CWE-22 | CWE-502 | CWE-918 | CWE-611 | CWE-798 | CWE-327 | CWE-352 | CWE-1395 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| java | 3/3 | 1/1 | · | 1/1 | 1/1 | · | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| kotlin | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · |
| python | 3/3 | 2/2 | 2/1 | 3/2 | 1/1 | 1/1 | 1/1 | 3/3 | 1/1 | · | · |
| javascript | 1/1 | 1/1 | 1/1 | 1/1 | · | 1/1 | · | · | · | · | 1/1 |
| typescript | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · |
| go | 1/1 | 1/1 | · | 1/1 | · | · | · | · | · | · | · |
| csharp | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · |
| c | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · |
| cpp | · | 1/1 | · | · | · | · | · | · | · | · | · |
| swift | · | 1/1 | · | · | · | · | · | · | · | · | · |
| php | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · |
| ruby | 1/1 | 1/1 | · | · | · | · | · | · | · | · | · |
| rust | · | 1/1 | · | 1/1 | · | · | · | · | · | · | · |

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
- `CWE-1395` — 

## Gaps

None. Every target language and weakness has a vulnerable case and a safe sibling.

## OWASP Top 10 (2021)

| category | cases |
|---|---|
| A01 Broken Access Control | 17 |
| A02 Cryptographic Failures | 4 |
| A03 Injection | 59 |
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
| vuln | 96 |
| secret | 4 |
| sca | 4 |
| crypto | · |

`crypto` is delegated to the `CipherRadarTestProj` submodule and is not counted here.

## Realism tiers

| tier | cases |
|---|---|
| 1 — synthetic fixtures | 104 |
| 2 — real applications | · |
| 3 — CVE reproductions | · |

## Difficulty

| taint path | cases |
|---|---|
| intra-procedural | 24 |
| inter-procedural | 2 |
| inter-file | 76 |
| framework-mediated | 2 |

| sanitizer | cases |
|---|---|
| none | 51 |
| ineffective | 2 |
| custom-effective | 24 |
| framework-implicit | 27 |
