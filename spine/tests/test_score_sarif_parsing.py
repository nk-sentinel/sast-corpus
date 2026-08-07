import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from score.score import parse_sarif


def sarif(rules=None, results=None, taxonomies=None, tool_name="acme"):
    run = {
        "tool": {"driver": {"name": tool_name, "rules": rules or []}},
        "results": results or [],
    }
    if taxonomies:
        run["taxonomies"] = taxonomies
    return {"version": "2.1.0", "runs": [run]}


def a_result(rule_id="R1", uri="tier1/java/a7f3e91b/OrderRepository.java", line=42, **extra):
    result = {
        "ruleId": rule_id,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    result.update(extra)
    return result


class CweExtraction(unittest.TestCase):
    """Every tool encodes CWE somewhere different. Missing one silently zeroes
    that tool's score, which reads as poor detection rather than a parser gap."""

    def test_reads_cwe_from_codeql_style_rule_tags(self):
        doc = sarif(
            rules=[{"id": "R1", "properties": {"tags": ["security", "external/cwe/cwe-089"]}}],
            results=[a_result()],
        )

        self.assertEqual(parse_sarif(doc)[0].cwes, {"CWE-89"})

    def test_reads_cwe_from_a_rule_property_list(self):
        doc = sarif(
            rules=[{"id": "R1", "properties": {"cwe": ["CWE-89", "CWE-943"]}}],
            results=[a_result()],
        )

        self.assertEqual(parse_sarif(doc)[0].cwes, {"CWE-89", "CWE-943"})

    def test_reads_cwe_from_a_rule_property_string(self):
        doc = sarif(
            rules=[{"id": "R1", "properties": {"cwe": "CWE-89: Improper Neutralization"}}],
            results=[a_result()],
        )

        self.assertEqual(parse_sarif(doc)[0].cwes, {"CWE-89"})

    def test_reads_cwe_from_result_taxa_against_a_cwe_taxonomy(self):
        doc = sarif(
            rules=[{"id": "R1"}],
            taxonomies=[{"name": "CWE", "guid": "T1", "taxa": [{"id": "89"}]}],
            results=[a_result(taxa=[{"id": "89", "toolComponent": {"guid": "T1"}}])],
        )

        self.assertEqual(parse_sarif(doc)[0].cwes, {"CWE-89"})

    def test_reads_cwe_from_result_properties(self):
        doc = sarif(rules=[{"id": "R1"}], results=[a_result(properties={"cwe": "CWE-79"})])

        self.assertEqual(parse_sarif(doc)[0].cwes, {"CWE-79"})

    def test_normalises_zero_padded_cwe_ids(self):
        doc = sarif(
            rules=[{"id": "R1", "properties": {"tags": ["CWE-089"]}}], results=[a_result()]
        )

        self.assertEqual(parse_sarif(doc)[0].cwes, {"CWE-89"})

    def test_a_finding_with_no_cwe_anywhere_parses_with_an_empty_set(self):
        """Not an error. Such tools are scored under the location-only rule."""
        doc = sarif(rules=[{"id": "R1"}], results=[a_result()])

        self.assertEqual(parse_sarif(doc)[0].cwes, set())

    def test_does_not_mistake_an_unrelated_number_for_a_cwe(self):
        doc = sarif(
            rules=[{"id": "R1", "properties": {"tags": ["security", "confidence-89"]}}],
            results=[a_result()],
        )

        self.assertEqual(parse_sarif(doc)[0].cwes, set())


class LocationExtraction(unittest.TestCase):
    def test_reads_path_and_line_from_the_physical_location(self):
        finding = parse_sarif(sarif(rules=[{"id": "R1"}], results=[a_result(line=42)]))[0]

        self.assertEqual(finding.file, "tier1/java/a7f3e91b/OrderRepository.java")
        self.assertEqual(finding.start_line, 42)
        self.assertEqual(finding.end_line, 42)

    def test_uses_end_line_when_the_region_declares_one(self):
        result = a_result()
        result["locations"][0]["physicalLocation"]["region"]["endLine"] = 47

        finding = parse_sarif(sarif(rules=[{"id": "R1"}], results=[result]))[0]

        self.assertEqual(finding.end_line, 47)

    def test_strips_a_file_uri_scheme(self):
        doc = sarif(
            rules=[{"id": "R1"}],
            results=[a_result(uri="file:///build/tier1/java/a7f3e91b/OrderRepository.java")],
        )

        self.assertEqual(parse_sarif(doc)[0].file, "/build/tier1/java/a7f3e91b/OrderRepository.java")

    def test_strips_a_leading_dot_slash(self):
        doc = sarif(rules=[{"id": "R1"}], results=[a_result(uri="./tier1/java/x/A.java")])

        self.assertEqual(parse_sarif(doc)[0].file, "tier1/java/x/A.java")

    def test_a_result_with_several_locations_yields_one_finding_per_location(self):
        """Both are places the tool chose to report; either may match the answer key."""
        result = a_result()
        result["locations"].append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "tier1/java/a7f3e91b/OrderController.java"},
                    "region": {"startLine": 18},
                }
            }
        )

        findings = parse_sarif(sarif(rules=[{"id": "R1"}], results=[result]))

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {f.file for f in findings},
            {
                "tier1/java/a7f3e91b/OrderRepository.java",
                "tier1/java/a7f3e91b/OrderController.java",
            },
        )

    def test_findings_from_one_result_share_a_result_key(self):
        """So the scorer can collapse them and never award one result two TPs."""
        result = a_result()
        result["locations"].append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "tier1/java/a7f3e91b/OrderController.java"},
                    "region": {"startLine": 18},
                }
            }
        )

        findings = parse_sarif(sarif(rules=[{"id": "R1"}], results=[result]))

        self.assertEqual(findings[0].result_key, findings[1].result_key)

    def test_findings_from_different_results_have_different_result_keys(self):
        doc = sarif(rules=[{"id": "R1"}], results=[a_result(line=42), a_result(line=88)])

        findings = parse_sarif(doc)

        self.assertNotEqual(findings[0].result_key, findings[1].result_key)


class FlowLocations(unittest.TestCase):
    """Taint-path steps are opt-in. Counting them by default would let a tool
    that dumps a forty-step flow claim credit for anything along it."""

    def setUp(self):
        result = a_result()
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "tier1/java/a7f3e91b/OrderController.java"},
                                        "region": {"startLine": 18},
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
        self.doc = sarif(rules=[{"id": "R1"}], results=[result])

    def test_flow_steps_are_ignored_by_default(self):
        self.assertEqual(len(parse_sarif(self.doc)), 1)

    def test_flow_steps_are_included_when_asked_for(self):
        findings = parse_sarif(self.doc, include_flow_locations=True)

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {Path(f.file).name for f in findings},
            {"OrderRepository.java", "OrderController.java"},
        )


class MultipleRuns(unittest.TestCase):
    def test_reads_results_from_every_run_in_the_log(self):
        doc = sarif(rules=[{"id": "R1"}], results=[a_result()])
        doc["runs"].append(sarif(rules=[{"id": "R2"}], results=[a_result(rule_id="R2")])["runs"][0])

        self.assertEqual(len(parse_sarif(doc)), 2)

    def test_records_the_tool_name_on_each_finding(self):
        doc = sarif(rules=[{"id": "R1"}], results=[a_result()], tool_name="opengrep")

        self.assertEqual(parse_sarif(doc)[0].tool, "opengrep")


if __name__ == "__main__":
    unittest.main()
