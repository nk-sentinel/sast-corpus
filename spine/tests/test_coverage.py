import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from report.coverage import Cell, gaps, matrix, render, summarise


def a_row(**overrides):
    row = {
        "id": "c-aaaaaaaa",
        "label": "vulnerable",
        "plane": "vuln",
        "tier": "1",
        "language": "python",
        "framework": "flask",
        "primary_cwe": "CWE-89",
        "acceptable_cwes": "CWE-89;CWE-943",
        "owasp_2021": "A03",
        "severity": "high",
        "file": "tier1/python/aaaaaaaa/store.py",
        "start_line": "6",
        "end_line": "6",
        "alt_locations": "",
        "flow": "inter-file",
        "sanitizer": "none",
        "obfuscation": "none",
        "build_required": "false",
    }
    row.update({k: str(v) for k, v in overrides.items()})
    return row


class Matrix(unittest.TestCase):
    def test_counts_vulnerable_and_safe_separately_per_cell(self):
        rows = [
            a_row(language="python", primary_cwe="CWE-89", label="vulnerable"),
            a_row(language="python", primary_cwe="CWE-89", label="safe"),
            a_row(language="python", primary_cwe="CWE-89", label="safe"),
        ]

        cell = matrix(rows)[("python", "CWE-89")]

        self.assertEqual(cell, Cell(vulnerable=1, safe=2))

    def test_separates_languages(self):
        rows = [a_row(language="python"), a_row(language="go")]

        self.assertEqual(sorted(k[0] for k in matrix(rows)), ["go", "python"])

    def test_a_cell_with_no_cases_is_absent_rather_than_zero(self):
        self.assertNotIn(("go", "CWE-89"), matrix([a_row(language="python")]))


class Gaps(unittest.TestCase):
    """The empty cells are the actionable part. A coverage doc that only lists
    what exists lets a missing language quietly look like a passing tool."""

    def test_reports_a_target_cell_with_no_cases_at_all(self):
        found = gaps([a_row(language="python", primary_cwe="CWE-89")],
                     languages=["python", "go"], cwes=["CWE-89"])

        self.assertIn(("go", "CWE-89"), found["missing"])

    def test_a_covered_cell_is_not_a_gap(self):
        found = gaps([a_row(language="python", primary_cwe="CWE-89")],
                     languages=["python"], cwes=["CWE-89"])

        self.assertEqual(found["missing"], [])

    def test_a_cell_with_no_trap_is_flagged_separately_from_one_with_nothing(self):
        """A vulnerable case without a safe sibling cannot measure a false
        positive rate, which is a different problem from having no cases."""
        found = gaps([a_row(language="python", primary_cwe="CWE-89", label="vulnerable")],
                     languages=["python"], cwes=["CWE-89"])

        self.assertIn(("python", "CWE-89"), found["untrapped"])
        self.assertEqual(found["missing"], [])

    def test_a_cell_with_only_traps_is_flagged_as_having_no_positive_case(self):
        found = gaps([a_row(language="python", primary_cwe="CWE-89", label="safe")],
                     languages=["python"], cwes=["CWE-89"])

        self.assertIn(("python", "CWE-89"), found["no_positive"])


class Summarise(unittest.TestCase):
    def test_counts_cases_traps_languages_and_cwes(self):
        rows = [
            a_row(language="python", primary_cwe="CWE-89", label="vulnerable"),
            a_row(language="go", primary_cwe="CWE-78", label="safe"),
        ]

        summary = summarise(rows)

        self.assertEqual(summary["cases"], 2)
        self.assertEqual(summary["traps"], 1)
        self.assertEqual(summary["languages"], 2)
        self.assertEqual(summary["cwes"], 2)

    def test_reports_how_many_cases_a_build_required_engine_can_see(self):
        """Fortify, Coverity and Veracode analyse compiled artifacts, so cases
        that do not build are invisible to them and this number is their real
        corpus size."""
        rows = [a_row(build_required="true"), a_row(build_required="false")]

        self.assertEqual(summarise(rows)["build_required"], 1)

    def test_counts_cases_by_difficulty_flow(self):
        rows = [a_row(flow="inter-file"), a_row(flow="framework-mediated")]

        self.assertEqual(summarise(rows)["by_flow"]["inter-file"], 1)


class Render(unittest.TestCase):
    def setUp(self):
        self.rows = [
            a_row(id="c-1", language="python", primary_cwe="CWE-89", label="vulnerable"),
            a_row(id="c-2", language="python", primary_cwe="CWE-89", label="safe"),
        ]
        self.text = render(self.rows, languages=["python", "swift"], cwes=["CWE-89", "CWE-79"])

    def test_includes_the_matrix(self):
        self.assertIn("CWE-89", self.text)
        self.assertIn("python", self.text)

    def test_names_an_uncovered_language(self):
        self.assertIn("swift", self.text)

    def test_names_an_uncovered_weakness(self):
        self.assertIn("CWE-79", self.text)

    def test_is_deterministic_so_it_can_be_checked_for_staleness_in_ci(self):
        self.assertEqual(self.text, render(self.rows, languages=["python", "swift"],
                                           cwes=["CWE-89", "CWE-79"]))

    def test_carries_no_case_ids_or_line_numbers(self):
        """The coverage doc travels with the corpus. It must describe shape, not
        leak which file holds which answer."""
        self.assertNotIn("c-1", self.text)
        self.assertNotIn("store.py", self.text)


class GapsAreActuallyRendered(unittest.TestCase):
    """The gap list is the reason the document exists. Computing it and then
    not printing it is worse than not computing it: the report says 'None' while
    most of the grid is empty."""

    def setUp(self):
        self.rows = [a_row(language="python", primary_cwe="CWE-89", label="vulnerable"),
                     a_row(language="python", primary_cwe="CWE-89", label="safe")]
        self.text = render(self.rows, languages=["python", "go"], cwes=["CWE-89", "CWE-79"])

    def test_does_not_claim_full_coverage_when_cells_are_empty(self):
        self.assertNotIn("None. Every target", self.text)

    def test_reports_how_many_cells_are_uncovered(self):
        # python/CWE-79, go/CWE-89, go/CWE-79 = 3 of 4 cells empty
        self.assertIn("3 of 4", self.text)

    def test_a_fully_covered_grid_does_say_so(self):
        rows = [a_row(language="python", primary_cwe="CWE-89", label=l) for l in ("vulnerable", "safe")]

        text = render(rows, languages=["python"], cwes=["CWE-89"])

        self.assertIn("None.", text)

    def test_every_named_weakness_has_a_description(self):
        from report.coverage import CWE_NAMES, TARGET_CWES

        for cwe in TARGET_CWES + ["CWE-1395"]:
            self.assertTrue(CWE_NAMES.get(cwe), "{} has no name".format(cwe))


if __name__ == "__main__":
    unittest.main()
