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
| `sonarqube.py` | `/api/issues/search` JSON | Requires `additionalFields=rules`: the CWE lives on the rule's `securityStandards`, never on the issue |
| `generic_csv.py` | any CSV export | Column mapping given on the command line — covers Fortify, Checkmarx and Veracode CSV exports without three separate adapters |

Tools that already emit SARIF — Semgrep, OpenGrep, CodeQL, Snyk Code — need no
adapter. Pipe their output straight to `score.py`.

## Adding one

Write it only once you hold a real export from the tool. An adapter written
against a guessed schema produces plausible SARIF and wrong scores, which is
worse than having no adapter at all: the run completes and the number looks
credible.

If the tool exports CSV, try `generic_csv.py` first — it usually needs nothing
more than the right column names.
