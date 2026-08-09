#!/usr/bin/env python3
"""Convert a SonarQube issues export into SARIF 2.1.0.

SonarQube never puts the CWE on the issue. The issue carries tags such as `cwe`
and `sql` — the word, not the number.

Nor, on 25.1 Community, does it put the CWE on the rule in any structured form.
`securityStandards` does not exist there: the API rejects it outright with
`Value of parameter 'f' (securityStandards) must be one of: [actives,
cleanCodeAttribute, ...]`, and the rules returned by the issues export carry only
key, name, lang, status and langName. This was found by running it, after the
first version of this adapter was written against `securityStandards` and would
have produced findings with no CWE at all — every one falling back to the
location-only match rule, making SonarQube look like it does not tag weaknesses.

The CWE is recoverable only from the rule's own description, whose Standards
section links each one by name. So the capture step fetches rule details
separately and merges them in. See spine/adapters/capture-sonarqube.sh.

    python3 spine/adapters/sonarqube.py sonar-issues.json > results.sarif
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adapters._sarif import Result, build_sarif

CWE_IN_TEXT = re.compile(r"\bCWE-(\d+)\b")


def cwes_for_rule(rule):
    """Every CWE a SonarQube rule maps to.

    `securityStandards` is checked first because some versions and editions do
    expose it — but SonarQube 25.1 Community does not have the field at all. The
    API rejects it outright: `Value of parameter 'f' (securityStandards) must be
    one of: [actives, cleanCodeAttribute, ...]`. The issues export returns rules
    carrying only key, name, lang, status and langName.

    So the fallback is the rule's own description, whose Standards section links
    each CWE by name. That is scraping, and it is stated plainly rather than
    dressed up — but the alternative is every finding arriving with no CWE,
    falling back to the location-only match rule, and SonarQube appearing not to
    tag weaknesses at all.

    The pattern requires the `CWE-` prefix, so a bare number in prose ("version
    327 of the spec") is not mistaken for one.
    """
    standards = rule.get("securityStandards") or []
    from_standards = []
    for standard in standards:
        text = str(standard)
        if text.lower().startswith("cwe:"):
            number = text.split(":", 1)[1]
            if number.isdigit():
                from_standards.append("CWE-{}".format(int(number)))
    if from_standards:
        return sorted(set(from_standards), key=lambda c: int(c.split("-")[1]))

    blob = " ".join(section.get("content", "")
                    for section in (rule.get("descriptionSections") or []))
    blob += " " + str(rule.get("htmlDesc") or "")
    found = {"CWE-{}".format(int(n)) for n in CWE_IN_TEXT.findall(blob)}
    return sorted(found, key=lambda c: int(c.split("-")[1]))


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
    return {rule.get("key"): cwes_for_rule(rule) for rule in rules}


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
