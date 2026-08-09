import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adapters.generic_csv import ColumnMap, convert_rows
from adapters.sarif_to_rows import rows_from_sarif
from score.score import parse_sarif

REAL = Path(__file__).parent / "data" / "real-semgrep.sarif"


class RealToolOutputSurvivesTheCsvAdapter(unittest.TestCase):
    """Every commercial engine in the bake-off reaches the scorer through an
    adapter, and until now those adapters had only ever seen fixtures we wrote
    ourselves. This drives real scanner output — genuine paths, genuine CWE
    tagging, genuine rule ids — through the CSV path that Fortify, Checkmarx and
    Veracode exports will take."""

    def setUp(self):
        self.doc = json.loads(REAL.read_text())
        self.original = parse_sarif(self.doc)
        self.rows = rows_from_sarif(self.doc)
        column_map = ColumnMap(path="path", line="line", end_line="end_line",
                               cwe="cwe", rule="rule", severity="severity")
        self.round_tripped = parse_sarif(
            convert_rows(self.rows, column_map, "acme", "1.0"))

    def test_the_fixture_is_genuine_scanner_output(self):
        """The driver name is `Semgrep OSS`, not `semgrep` — which is the point
        in miniature: this file was captured from a real run, so it carries the
        values the tool actually emits rather than the ones we would guess."""
        driver = self.doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "Semgrep OSS")
        self.assertTrue(self.original)

    def test_no_finding_is_lost_in_the_round_trip(self):
        self.assertEqual(len(self.round_tripped), len(self.original))

    def test_every_path_survives_unchanged(self):
        self.assertEqual({f.file for f in self.round_tripped},
                         {f.file for f in self.original})

    def test_every_line_survives_unchanged(self):
        self.assertEqual(sorted((f.file, f.start_line) for f in self.round_tripped),
                         sorted((f.file, f.start_line) for f in self.original))

    def test_cwes_survive_the_round_trip(self):
        """Semgrep buries the CWE in free-text tags. If the flattening drops it,
        every finding silently falls back to the location-only rule."""
        self.assertEqual(sorted(sorted(f.cwes) for f in self.round_tripped),
                         sorted(sorted(f.cwes) for f in self.original))

    def test_at_least_one_real_finding_actually_carried_a_cwe(self):
        """Otherwise the test above passes vacuously on empty sets."""
        self.assertTrue(any(f.cwes for f in self.original))


if __name__ == "__main__":
    unittest.main()


REAL_SONARQUBE = Path(__file__).parent / "data" / "real-sonarqube.json"


class RealSonarQubeExport(unittest.TestCase):
    """Captured from a live SonarQube 25.1 Community scan of tier1. Written
    only after running it for real, because the adapter's original premise —
    that the CWE lives on the rule's securityStandards — turned out to be false
    for this version, and no fixture I invented would ever have said so."""

    def setUp(self):
        from adapters.sonarqube import convert
        self.export = json.loads(REAL_SONARQUBE.read_text())
        self.findings = parse_sarif(convert(self.export, tool_version="25.1.0.102122"))

    def test_the_export_is_genuine(self):
        self.assertTrue(self.export["issues"])
        self.assertTrue(any(i.get("component", "").startswith("sast-corpus-tier1:")
                            for i in self.export["issues"]))

    def test_no_rule_carries_security_standards_on_this_version(self):
        """The premise the adapter was originally built on. Recorded so a
        regression toward it fails loudly."""
        self.assertFalse(any(r.get("securityStandards") for r in self.export["rules"]))

    def test_cwes_are_still_recovered_despite_that(self):
        with_cwe = [f for f in self.findings if f.cwes]

        self.assertTrue(with_cwe, "no finding carried a CWE — the enrichment step is broken")

    def test_a_known_rule_resolves_to_its_known_cwe(self):
        from adapters.sonarqube import cwes_for_rule
        rule = next(r for r in self.export["rules"] if r["key"] == "java:S5542")

        self.assertEqual(cwes_for_rule(rule), ["CWE-327"])

    def test_project_key_is_stripped_from_every_path(self):
        self.assertFalse(any(":" in f.file for f in self.findings))

    def test_no_finding_lands_on_line_zero(self):
        self.assertTrue(all(f.start_line >= 1 for f in self.findings))
