#!/usr/bin/env python3
"""Convert any CSV finding export into SARIF 2.1.0 by declaring its columns.

Fortify, Checkmarx and Veracode all export CSV, with different headers. Rather
than three adapters coded against sample files nobody has yet, this one takes
the column mapping as an argument. When a real export arrives, the mapping goes
on the command line and the tool is scorable the same day.

    python3 spine/adapters/generic_csv.py fortify.csv \\
        --tool Fortify --tool-version 24.2 \\
        --path-column "File" --line-column "Line" --cwe-column "CWE" \\
        --rule-column "Category" --severity-column "Severity" \\
        --strip-prefix "/build/ws/" > results.sarif

Rows without a usable path or line are dropped, not defaulted. A finding pinned
to line 0 would, under the match tolerance, manufacture a hit against any case
near the top of a file.
"""

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adapters._sarif import Result, build_sarif

CWE_NUMBER = re.compile(r"(\d+)")

SEVERITY_TO_LEVEL = {
    "critical": "error", "high": "error", "blocker": "error",
    "medium": "warning", "major": "warning", "moderate": "warning",
    "low": "note", "minor": "note", "info": "note", "informational": "note",
}


@dataclass
class ColumnMap:
    path: str
    line: str
    cwe: str = None
    rule: str = None
    severity: str = None
    end_line: str = None
    message: str = None


def convert_rows(rows, column_map, tool_name, tool_version, strip_prefix=None):
    results = []

    for row in rows:
        path = _clean(row.get(column_map.path))
        start = _int(row.get(column_map.line))
        if not path or start is None:
            continue

        if strip_prefix and path.startswith(strip_prefix):
            path = path[len(strip_prefix) :]

        results.append(
            Result(
                rule_id=_clean(row.get(column_map.rule)) or "finding",
                path=path,
                start_line=start,
                end_line=_int(row.get(column_map.end_line)) or start,
                cwes=_cwes(row.get(column_map.cwe) if column_map.cwe else None),
                level=SEVERITY_TO_LEVEL.get(_clean(row.get(column_map.severity)).lower(), "warning"),
                message=_clean(row.get(column_map.message)),
            )
        )

    return build_sarif(tool_name, tool_version, results)


def _cwes(cell):
    """`89`, `CWE-89`, and `CWE-89, 943` all normalise to the same shape."""
    if not cell:
        return []
    return ["CWE-{}".format(int(number)) for number in CWE_NUMBER.findall(str(cell))]


def _clean(value):
    return (value or "").strip()


def _int(value):
    text = _clean(value)
    return int(text) if text.isdigit() else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("export")
    parser.add_argument("--tool", required=True)
    parser.add_argument("--tool-version", default="")
    parser.add_argument("--path-column", required=True)
    parser.add_argument("--line-column", required=True)
    parser.add_argument("--end-line-column", default=None)
    parser.add_argument("--cwe-column", default=None)
    parser.add_argument("--rule-column", default=None)
    parser.add_argument("--severity-column", default=None)
    parser.add_argument("--message-column", default=None)
    parser.add_argument("--strip-prefix", default=None)
    parser.add_argument("--delimiter", default=",")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    with open(args.export, newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle, delimiter=args.delimiter))

    column_map = ColumnMap(
        path=args.path_column, line=args.line_column, end_line=args.end_line_column,
        cwe=args.cwe_column, rule=args.rule_column, severity=args.severity_column,
        message=args.message_column,
    )
    doc = convert_rows(rows, column_map, args.tool, args.tool_version, args.strip_prefix)

    kept = len(doc["runs"][0]["results"])
    if kept < len(rows):
        print("note: {} of {} rows dropped for a missing path or line".format(
            len(rows) - kept, len(rows)), file=sys.stderr)
    if not args.cwe_column:
        print("note: no CWE column mapped; every finding will be scored under the "
              "location-only rule", file=sys.stderr)

    text = json.dumps(doc, indent=2)
    if args.out:
        args.out.write_text(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
