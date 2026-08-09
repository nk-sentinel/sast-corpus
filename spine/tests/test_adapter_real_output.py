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
