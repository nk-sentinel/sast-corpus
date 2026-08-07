"""Shared SARIF 2.1.0 emitter for adapters.

Every adapter normalises its tool's native output into `Result` records and
hands them here. The scorer then needs no tool-specific logic at all: adding a
tool means writing one adapter, never touching `score.py`.

CWEs are emitted as a proper SARIF taxonomy rather than smuggled into tags,
because that is the encoding least likely to be misread by anything downstream.
"""

from dataclasses import dataclass, field

CWE_TAXONOMY_GUID = "8f6bb0a3-2f3a-4f2c-9b17-6b1f0c9e4d21"

LEVELS = {"error", "warning", "note", "none"}


@dataclass
class Result:
    rule_id: str
    path: str
    start_line: int
    end_line: int = 0
    cwes: list = field(default_factory=list)
    level: str = "warning"
    message: str = ""

    def __post_init__(self):
        if not self.end_line:
            self.end_line = self.start_line
        if self.level not in LEVELS:
            self.level = "warning"


def build_sarif(tool_name, tool_version, results):
    """Assemble a SARIF 2.1.0 log from normalised results."""
    rules = {}
    cwe_ids = set()

    for result in results:
        cwe_ids.update(_number(cwe) for cwe in result.cwes if _number(cwe))
        rule = rules.setdefault(result.rule_id, {"id": result.rule_id, "properties": {"cwe": []}})
        for cwe in result.cwes:
            if cwe not in rule["properties"]["cwe"]:
                rule["properties"]["cwe"].append(cwe)

    run = {
        "tool": {
            "driver": {
                "name": tool_name,
                "semanticVersion": tool_version,
                "informationUri": "https://github.com/nk-sentinel/sast-corpus",
                "rules": list(rules.values()),
            }
        },
        "results": [_result(result) for result in results],
    }

    if cwe_ids:
        run["taxonomies"] = [
            {
                "name": "CWE",
                "guid": CWE_TAXONOMY_GUID,
                "organization": "MITRE",
                "informationUri": "https://cwe.mitre.org/data/published/cwe_latest.pdf",
                "taxa": [{"id": identifier} for identifier in sorted(cwe_ids, key=int)],
            }
        ]

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }


def _result(result):
    payload = {
        "ruleId": result.rule_id,
        "level": result.level,
        "message": {"text": result.message or result.rule_id},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": result.path},
                    "region": {"startLine": result.start_line, "endLine": result.end_line},
                }
            }
        ],
    }

    taxa = [
        {"id": _number(cwe), "toolComponent": {"guid": CWE_TAXONOMY_GUID}}
        for cwe in result.cwes
        if _number(cwe)
    ]
    if taxa:
        payload["taxa"] = taxa

    return payload


def _number(cwe):
    text = str(cwe).strip().upper()
    if text.startswith("CWE-"):
        text = text[4:]
    return text if text.isdigit() else None
