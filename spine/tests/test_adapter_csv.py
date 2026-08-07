import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adapters.generic_csv import ColumnMap, convert_rows
from score.score import parse_sarif

DEFAULT_MAP = ColumnMap(path="File", line="Line", cwe="CWE", rule="Category", severity="Severity")


class GenericCsvAdapter(unittest.TestCase):
    def convert(self, rows, column_map=DEFAULT_MAP, **kwargs):
        return parse_sarif(convert_rows(rows, column_map, "acme", "1.0", **kwargs))

    def test_maps_the_declared_columns_onto_a_finding(self):
        rows = [{"File": "tier1/java/x/A.java", "Line": "42", "CWE": "89",
                 "Category": "SQL Injection", "Severity": "High"}]

        finding = self.convert(rows)[0]

        self.assertEqual(finding.file, "tier1/java/x/A.java")
        self.assertEqual(finding.start_line, 42)
        self.assertEqual(finding.cwes, {"CWE-89"})

    def test_accepts_a_cwe_already_carrying_its_prefix(self):
        rows = [{"File": "a.java", "Line": "1", "CWE": "CWE-79", "Category": "XSS", "Severity": "High"}]

        self.assertEqual(self.convert(rows)[0].cwes, {"CWE-79"})

    def test_splits_a_multi_valued_cwe_cell(self):
        rows = [{"File": "a.java", "Line": "1", "CWE": "CWE-89, 943", "Category": "c", "Severity": "High"}]

        self.assertEqual(self.convert(rows)[0].cwes, {"CWE-89", "CWE-943"})

    def test_strips_a_leading_path_prefix_from_an_absolute_export(self):
        """Commercial tools export paths rooted at the build workspace."""
        rows = [{"File": "/build/ws/tier1/java/x/A.java", "Line": "1", "CWE": "89",
                 "Category": "c", "Severity": "High"}]

        finding = self.convert(rows, strip_prefix="/build/ws/")[0]

        self.assertEqual(finding.file, "tier1/java/x/A.java")

    def test_a_row_with_no_usable_line_is_dropped(self):
        rows = [{"File": "a.java", "Line": "", "CWE": "89", "Category": "c", "Severity": "High"}]

        self.assertEqual(self.convert(rows), [])

    def test_a_row_with_no_path_is_dropped(self):
        rows = [{"File": "", "Line": "4", "CWE": "89", "Category": "c", "Severity": "High"}]

        self.assertEqual(self.convert(rows), [])

    def test_a_non_numeric_line_is_dropped_rather_than_defaulting_to_zero(self):
        rows = [{"File": "a.java", "Line": "n/a", "CWE": "89", "Category": "c", "Severity": "High"}]

        self.assertEqual(self.convert(rows), [])

    def test_a_missing_cwe_column_yields_a_finding_with_no_cwe(self):
        column_map = ColumnMap(path="File", line="Line", cwe=None, rule="Category", severity="Severity")
        rows = [{"File": "a.java", "Line": "4", "Category": "c", "Severity": "High"}]

        self.assertEqual(self.convert(rows, column_map)[0].cwes, set())

    def test_each_row_is_an_independent_claim(self):
        rows = [
            {"File": "a.java", "Line": "4", "CWE": "89", "Category": "c", "Severity": "High"},
            {"File": "a.java", "Line": "9", "CWE": "89", "Category": "c", "Severity": "High"},
        ]

        findings = self.convert(rows)

        self.assertNotEqual(findings[0].result_key, findings[1].result_key)

    def test_an_unknown_severity_does_not_crash_the_conversion(self):
        rows = [{"File": "a.java", "Line": "4", "CWE": "89", "Category": "c", "Severity": "Wobbly"}]

        self.assertEqual(len(self.convert(rows)), 1)


if __name__ == "__main__":
    unittest.main()
