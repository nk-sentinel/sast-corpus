import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adapters._sarif import Result, build_sarif
from adapters.sonarqube import convert
from score.score import parse_sarif

SONAR_EXPORT = {
    "total": 3,
    "issues": [
        {
            "key": "AY001",
            "rule": "java:S2077",
            "severity": "BLOCKER",
            "component": "gauntlet-corpus:tier1/java/4b19d7a2/src/main/java/app/OrderRepository.java",
            "project": "gauntlet-corpus",
            "line": 19,
            "textRange": {"startLine": 19, "endLine": 19},
            "message": "Formatting SQL queries is security-sensitive.",
            "type": "VULNERABILITY",
        },
        {
            "key": "AY002",
            "rule": "java:S1104",
            "severity": "MINOR",
            "component": "gauntlet-corpus:tier1/java/4b19d7a2/src/main/java/app/Cli.java",
            "project": "gauntlet-corpus",
            "line": 7,
            "message": "Make this field private.",
            "type": "CODE_SMELL",
        },
        {
            "key": "AY003",
            "rule": "java:S2076",
            "severity": "CRITICAL",
            "component": "gauntlet-corpus:tier1/java/other/X.java",
            "project": "gauntlet-corpus",
            "message": "no line number at all",
            "type": "VULNERABILITY",
        },
    ],
    "rules": [
        {"key": "java:S2077", "name": "SQL binding", "securityStandards": ["cwe:89", "owaspTop10:a3"]},
        {"key": "java:S1104", "name": "Field visibility", "securityStandards": []},
        {"key": "java:S2076", "name": "OS command", "securityStandards": ["cwe:78"]},
    ],
}


class SarifBuilder(unittest.TestCase):
    def setUp(self):
        self.doc = build_sarif(
            "acme", "1.2.3",
            [Result(rule_id="R1", path="a/B.java", start_line=10, end_line=12,
                    cwes=["CWE-89"], level="error", message="m")],
        )

    def test_declares_sarif_2_1_0(self):
        self.assertEqual(self.doc["version"], "2.1.0")

    def test_records_the_tool_name_and_version(self):
        driver = self.doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "acme")
        self.assertEqual(driver["semanticVersion"], "1.2.3")

    def test_emits_a_cwe_taxonomy_so_the_scorer_needs_no_tool_specific_logic(self):
        taxonomies = self.doc["runs"][0]["taxonomies"]

        self.assertEqual(taxonomies[0]["name"], "CWE")
        self.assertIn("89", [t["id"] for t in taxonomies[0]["taxa"]])

    def test_the_scorer_reads_back_exactly_what_was_put_in(self):
        finding = parse_sarif(self.doc)[0]

        self.assertEqual(finding.file, "a/B.java")
        self.assertEqual(finding.start_line, 10)
        self.assertEqual(finding.end_line, 12)
        self.assertEqual(finding.cwes, {"CWE-89"})

    def test_a_result_with_no_cwe_still_produces_a_valid_finding(self):
        doc = build_sarif("acme", "1", [Result(rule_id="R2", path="a/B.java", start_line=3)])

        finding = parse_sarif(doc)[0]

        self.assertEqual(finding.cwes, set())
        self.assertEqual(finding.end_line, 3)


class SonarQubeAdapter(unittest.TestCase):
    def setUp(self):
        self.doc = convert(SONAR_EXPORT, tool_version="2025.1")
        self.findings = parse_sarif(self.doc)
        self.by_path = {Path(f.file).name: f for f in self.findings}

    def test_strips_the_project_key_from_the_component_path(self):
        """SonarQube reports `projectKey:path`; the answer key holds bare paths."""
        self.assertIn(
            "tier1/java/4b19d7a2/src/main/java/app/OrderRepository.java",
            [f.file for f in self.findings],
        )

    def test_maps_security_standards_to_cwes(self):
        self.assertEqual(self.by_path["OrderRepository.java"].cwes, {"CWE-89"})

    def test_a_rule_with_no_security_standard_carries_no_cwe(self):
        self.assertEqual(self.by_path["Cli.java"].cwes, set())

    def test_uses_the_text_range_when_present(self):
        self.assertEqual(self.by_path["OrderRepository.java"].start_line, 19)

    def test_an_issue_without_any_line_is_dropped_rather_than_placed_at_line_zero(self):
        """A finding pinned to line 0 would match a case at line 1-10 under
        tolerance and manufacture a true positive."""
        self.assertNotIn("X.java", self.by_path)

    def test_maps_sonar_severity_onto_sarif_levels(self):
        levels = {
            r["ruleId"]: r["level"]
            for r in self.doc["runs"][0]["results"]
        }
        self.assertEqual(levels["java:S2077"], "error")
        self.assertEqual(levels["java:S1104"], "note")

    def test_the_conversion_survives_a_json_round_trip(self):
        reloaded = json.loads(json.dumps(self.doc))

        self.assertEqual(len(parse_sarif(reloaded)), len(self.findings))

    def test_an_export_with_no_rules_block_still_converts(self):
        doc = convert({"issues": SONAR_EXPORT["issues"]}, tool_version="2025.1")

        self.assertTrue(parse_sarif(doc))


REAL_SHAPED_RULE = {
    "key": "java:S5542",
    "name": "Encryption algorithms should be used with secure mode and padding scheme",
    "lang": "java",
    "descriptionSections": [
        {"key": "root_cause", "content": "<p>Encryption operates ...</p>"},
        {"key": "resources", "content":
            "<h3>Standards</h3><ul>"
            "<li>OWASP - <a href='...'>Top 10 2021 Category A2</a></li>"
            "<li>CWE - <a href='https://cwe.mitre.org/data/definitions/327'>"
            "CWE-327 - Use of a Broken or Risky Cryptographic Algorithm</a></li>"
            "</ul>"},
    ],
}


class SonarQubeCweExtraction(unittest.TestCase):
    """SonarQube 25.1 Community has no `securityStandards` field at all — the
    API rejects it as an unknown value for `f`. The CWE is only recoverable from
    the rule's description text. An adapter built on securityStandards silently
    produces findings with no CWE, every one of which falls back to the
    location-only rule, and the tool looks like it does not tag CWEs."""

    def test_reads_the_cwe_from_a_rule_description(self):
        from adapters.sonarqube import cwes_for_rule

        self.assertEqual(cwes_for_rule(REAL_SHAPED_RULE), ["CWE-327"])

    def test_still_reads_security_standards_when_a_version_supplies_them(self):
        from adapters.sonarqube import cwes_for_rule
        rule = {"key": "java:S3649", "securityStandards": ["cwe:89", "owaspTop10:a3"]}

        self.assertEqual(cwes_for_rule(rule), ["CWE-89"])

    def test_prefers_security_standards_over_description_scraping(self):
        from adapters.sonarqube import cwes_for_rule
        rule = dict(REAL_SHAPED_RULE, securityStandards=["cwe:999"])

        self.assertEqual(cwes_for_rule(rule), ["CWE-999"])

    def test_collects_several_cwes_from_one_description(self):
        from adapters.sonarqube import cwes_for_rule
        rule = {"key": "java:S2755", "descriptionSections": [
            {"key": "resources", "content": "CWE-611 - XXE ... CWE-827 - Improper Control"}]}

        self.assertEqual(cwes_for_rule(rule), ["CWE-611", "CWE-827"])

    def test_a_rule_with_no_cwe_anywhere_yields_none(self):
        from adapters.sonarqube import cwes_for_rule

        self.assertEqual(cwes_for_rule({"key": "java:S1234", "name": "Tidy up"}), [])

    def test_does_not_mistake_a_cwe_looking_number_in_prose(self):
        from adapters.sonarqube import cwes_for_rule
        rule = {"key": "x", "descriptionSections": [
            {"key": "root_cause", "content": "Introduced in version 327 of the spec."}]}

        self.assertEqual(cwes_for_rule(rule), [])


if __name__ == "__main__":
    unittest.main()
