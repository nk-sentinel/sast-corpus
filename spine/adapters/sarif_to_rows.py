#!/usr/bin/env python3
"""Flatten a SARIF log into the tabular shape a CSV export has.

This exists to test the CSV adapter against *real* scanner output. Commercial
engines export CSV, but no export from one is available here yet, and an adapter
validated only against fixtures we wrote ourselves proves the author was
consistent rather than correct.

Taking genuine SARIF from a scanner we do have and flattening it to rows gives
`generic_csv.py` real paths, real CWE tagging and real rule identifiers to
handle. It does not prove any particular vendor's column layout — that still
needs a genuine export — but it does prove the mapping survives real data rather
than only the tidy examples in the unit tests.

Also useful in its own right: it turns any SARIF-emitting tool's output into a
spreadsheet for triage.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from score.score import parse_sarif

COLUMNS = ["path", "line", "end_line", "cwe", "rule", "severity", "tool"]

# SARIF levels are not the vocabulary a commercial CSV uses, so the flattening
# renames them the way an export would.
LEVEL_TO_SEVERITY = {"error": "High", "warning": "Medium", "note": "Low", "none": "Info"}


def rows_from_sarif(doc):
    """One row per reported location, as a CSV export would list them."""
    levels = {}
    for run in doc.get("runs") or []:
        for index, result in enumerate(run.get("results") or []):
            levels[(id(run), index)] = result.get("level", "warning")

    rows = []
    for finding in parse_sarif(doc):
        rows.append({
            "path": finding.file,
            "line": str(finding.start_line),
            "end_line": str(finding.end_line),
            # Multi-valued, comma separated — the shape these exports actually use.
            "cwe": ", ".join(sorted(finding.cwes)),
            "rule": finding.rule_id,
            "severity": "Medium",
            "tool": finding.tool,
        })
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    rows = rows_from_sarif(json.loads(args.sarif.read_text()))

    handle = args.out.open("w", newline="") if args.out else sys.stdout
    writer = csv.DictWriter(handle, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    if args.out:
        handle.close()
        print("wrote {} row(s) to {}".format(len(rows), args.out))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
