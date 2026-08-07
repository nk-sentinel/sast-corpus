#!/usr/bin/env python3
"""Convert a SonarQube issues export into SARIF 2.1.0.

SonarQube does not put the CWE on the issue. The issue carries tags such as
`cwe` and `sql` — the word, not the number — and the actual mapping lives on the
rule as `securityStandards: ["cwe:89", "owaspTop10:a3"]`. So the export must
include the rules block, or every finding arrives without a CWE and is scored
under the location-only rule.

Produce the input with:

    curl -u "$TOKEN:" \\
      "$SONAR/api/issues/search?componentKeys=$KEY&ps=500&additionalFields=rules" \\
      > sonar-issues.json

    python3 spine/adapters/sonarqube.py sonar-issues.json > results.sarif
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adapters._sarif import Result, build_sarif

# SonarQube ships two severity vocabularies depending on version and whether
# clean-code mode is on; both are mapped here.
SEVERITY_TO_LEVEL = {
    "BLOCKER": "error",
    "CRITICAL": "error",
    "HIGH": "error",
    "MAJOR": "warning",
    "MEDIUM": "warning",
    "MINOR": "note",
    "LOW": "note",
    "INFO": "note",
}


def convert(export, tool_version=""):
    """SonarQube issues JSON to a SARIF log."""
    cwes_by_rule = _cwes_by_rule(export.get("rules") or [])
    results = []

    for issue in export.get("issues") or []:
        start, end = _line_range(issue)
        if start is None:
            # An issue with no line would land at line 0 and, under the match
            # tolerance, manufacture a hit against any case near the top of a
            # file. Dropping it is the conservative choice.
            continue

        rule_id = issue.get("rule", "")
        results.append(
            Result(
                rule_id=rule_id,
                path=_component_path(issue),
                start_line=start,
                end_line=end,
                cwes=cwes_by_rule.get(rule_id, []),
                level=_level(issue),
                message=(issue.get("message") or "").strip(),
            )
        )

    return build_sarif("SonarQube", tool_version, results)


def _cwes_by_rule(rules):
    mapping = {}
    for rule in rules:
        cwes = []
        for standard in rule.get("securityStandards") or []:
            if str(standard).lower().startswith("cwe:"):
                number = str(standard).split(":", 1)[1]
                if number.isdigit():
                    cwes.append("CWE-{}".format(int(number)))
        mapping[rule.get("key")] = cwes
    return mapping


def _component_path(issue):
    """`projectKey:path/to/File.java` to `path/to/File.java`."""
    component = issue.get("component", "")
    project = issue.get("project")
    if project and component.startswith(project + ":"):
        return component[len(project) + 1 :]
    return component.split(":", 1)[1] if ":" in component else component


def _line_range(issue):
    text_range = issue.get("textRange") or {}
    start = text_range.get("startLine") or issue.get("line")
    if not start:
        return None, None
    return int(start), int(text_range.get("endLine") or start)


def _level(issue):
    severity = (issue.get("severity") or "").upper()
    if not severity:
        impacts = issue.get("impacts") or []
        severity = (impacts[0].get("severity") or "").upper() if impacts else ""
    return SEVERITY_TO_LEVEL.get(severity, "warning")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("export", help="SonarQube /api/issues/search JSON, with additionalFields=rules")
    parser.add_argument("--tool-version", default="")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    export = json.loads(Path(args.export).read_text())
    doc = convert(export, tool_version=args.tool_version)

    if not (export.get("rules")):
        print("warning: export has no rules block, so no finding carries a CWE; "
              "re-export with additionalFields=rules", file=sys.stderr)

    text = json.dumps(doc, indent=2)
    if args.out:
        args.out.write_text(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
