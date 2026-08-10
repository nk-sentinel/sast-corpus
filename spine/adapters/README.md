# Adapters

The scorer reads SARIF 2.1.0 and nothing else. Adding a tool means writing one
adapter; `score.py` never gains tool-specific logic.

## Contract

An adapter normalises its tool's native output into `Result` records and calls
`build_sarif`:

```python
from adapters._sarif import Result, build_sarif

results = [Result(rule_id="...", path="tier1/...", start_line=42, end_line=47,
                  cwes=["CWE-89"], level="error", message="...")]
doc = build_sarif("ToolName", "1.2.3", results)
```

Four rules, each of which exists because breaking it corrupts a score:

**Paths must be repo-relative, or a strippable prefix of one.** The scorer
anchors suffix matching at a separator, so `/build/ws/tier1/...` resolves
correctly but a mangled path silently becomes a miss.

**Never invent a line number.** A finding placed at line 0 will, under the ±10
tolerance, match any case near the top of a file and manufacture a true
positive. Drop the row instead, and say how many were dropped.

**Emit CWEs as a taxonomy, not a tag.** `build_sarif` does this. Findings with
no CWE are legitimate — they score under the location-only rule and are
reported separately — but a CWE the adapter *could* have supplied and didn't
understates the tool.

**One result per claim.** Several locations for one issue belong in one SARIF
result, so the scorer credits it once. Splitting them into separate results lets
one finding claim two cases.

## Available

| Adapter | Input | Notes |
|---|---|---|
| `sonarqube.py` | `/api/issues/search` JSON | See below — the CWE is harder to obtain than it looks |
| `generic_csv.py` | any CSV export | Column mapping given on the command line — covers Fortify, Checkmarx and Veracode CSV exports without three separate adapters |
| `sarif_to_rows.py` | any SARIF | Flattens SARIF to CSV rows; used to drive `generic_csv` with real scanner output |
| `capture-sonarqube.sh` | — | Scan, wait, export, enrich, convert, score, in one command |

## The SonarQube case is worth reading before writing any adapter

The first version of `sonarqube.py` read the CWE from the rule's
`securityStandards`. That is what the field is for, it is what the documentation
describes, and the unit tests passed against a fixture written to match.

On SonarQube 25.1 Community the field does not exist. The API rejects it:

```
Value of parameter 'f' (securityStandards) must be one of:
[actives, cleanCodeAttribute, createdAt, ...]
```

Rules returned alongside an issues export carry only `key`, `name`, `lang`,
`status` and `langName`. The issue itself carries a tag reading `cwe` — the word,
not the number. So every finding would have arrived with no CWE, fallen back to
the scorer's location-only rule, and produced a scorecard saying SonarQube barely
tags weaknesses. Wrong, and entirely plausible.

The CWE is recoverable only by fetching each rule's description and reading the
CWE out of its Standards section. `capture-sonarqube.sh` does that enrichment;
`cwes_for_rule` still prefers `securityStandards` where an edition supplies it.

Two things follow for any adapter you write:

- **A passing test suite proves nothing if you wrote the fixture.** The fixture
  and the adapter shared an assumption, so they agreed.
- **Capture a real export and build the regression test from it.** The one here
  is `spine/tests/data/real-sonarqube.json`, and one of its tests asserts that no
  rule carries `securityStandards` — recording the false premise so a regression
  toward it fails loudly.

SonarQube is also **not source-only**: its Java sensor refuses to run without
`sonar.java.binaries`. It belongs with the build-required engines.

Tools that already emit SARIF — Semgrep, OpenGrep, CodeQL, Snyk Code — need no
adapter. Pipe their output straight to `score.py`.

## Adding one

Write it only once you hold a real export from the tool. An adapter written
against a guessed schema produces plausible SARIF and wrong scores, which is
worse than having no adapter at all: the run completes and the number looks
credible.

If the tool exports CSV, try `generic_csv.py` first — it usually needs nothing
more than the right column names.
