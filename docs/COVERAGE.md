# Coverage

Generated from `answers/expectedresults-1.0.csv` by `spine/report/coverage.py`. Do not edit by hand — CI regenerates it and fails if this file has drifted from the corpus.

A cell reads `v/s`: vulnerable cases and safe siblings. A weakness with no safe sibling cannot measure a false-positive rate, and a language with no cases at all contributes nothing to a scorecard — which looks exactly like a tool having nothing to find. Both are listed below.

## Totals

| | |
|---|---|
| Cases | 46 |
| False-positive traps | 23 (50%) |
| Languages covered | 8 of 13 |
| Target weaknesses covered | 5 of 10 |
| Visible to build-required engines | 6 |

## Language × weakness

| language | CWE-89 | CWE-78 | CWE-22 | CWE-502 | CWE-918 |
|---|---|---|---|---|---|
| java | 3/3 | · | · | · | · |
| python | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| javascript | 1/1 | 1/1 | 1/1 | · | 1/1 |
| typescript | 1/1 | 1/1 | · | · | · |
| go | 1/1 | 1/1 | 1/1 | · | · |
| csharp | 1/1 | 1/1 | · | · | · |
| php | 1/1 | 1/1 | · | · | · |
| ruby | 1/1 | 1/1 | · | · | · |

Weakness codes:

- `CWE-89` — SQL injection
- `CWE-78` — OS command injection
- `CWE-22` — path traversal
- `CWE-502` — unsafe deserialisation
- `CWE-918` — server-side request forgery

## Gaps

**No cases at all — these languages cannot be evaluated:** `kotlin`, `c`, `cpp`, `swift`, `rust`

**No cases in any language:** `CWE-79` (cross-site scripting), `CWE-611` (XML external entity), `CWE-798` (hard-coded credentials), `CWE-327` (broken crypto), `CWE-352` (cross-site request forgery)

## OWASP Top 10 (2021)

| category | cases |
|---|---|
| A01 Broken Access Control | 6 |
| A02 Cryptographic Failures | · |
| A03 Injection | 34 |
| A04 Insecure Design | · |
| A05 Security Misconfiguration | · |
| A06 Vulnerable Components | · |
| A07 Identification and Authentication Failures | · |
| A08 Software and Data Integrity Failures | 2 |
| A09 Logging and Monitoring Failures | · |
| A10 Server-Side Request Forgery | 4 |

## Detection planes

| plane | cases |
|---|---|
| vuln | 46 |
| secret | · |
| sca | · |
| crypto | · |

`crypto` is delegated to the `CipherRadarTestProj` submodule and is not counted here.

## Realism tiers

| tier | cases |
|---|---|
| 1 — synthetic fixtures | 46 |
| 2 — real applications | · |
| 3 — CVE reproductions | · |

## Difficulty

| taint path | cases |
|---|---|
| intra-procedural | · |
| inter-procedural | · |
| inter-file | 44 |
| framework-mediated | 2 |

| sanitizer | cases |
|---|---|
| none | 23 |
| ineffective | · |
| custom-effective | 7 |
| framework-implicit | 16 |
