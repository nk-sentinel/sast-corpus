import csv
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from report.applicability import density as applicable_density
from report.applicability import load as load_applicability
from report.coverage import (CWE_NAMES, Cell, density, gaps, matrix,
                             render, summarise)


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


class VariantCoverage(unittest.TestCase):
    """One case in a (language, CWE) cell used to mean the cell was covered. It
    does not: a tool can catch concat-into-Statement and miss every other route
    to the same CWE."""

    def test_counts_variants_per_weakness(self):
        from report.coverage import variants_by_cwe
        rows = [a_row(primary_cwe="CWE-89", variant="concat-statement"),
                a_row(primary_cwe="CWE-89", variant="dynamic-identifier"),
                a_row(primary_cwe="CWE-78", variant="shell-true")]

        found = variants_by_cwe(rows)

        self.assertEqual(found["CWE-89"], {"concat-statement", "dynamic-identifier"})

    def test_cases_with_no_variant_are_grouped_as_unlabelled(self):
        from report.coverage import variants_by_cwe
        rows = [a_row(primary_cwe="CWE-89", variant="")]

        self.assertEqual(variants_by_cwe(rows)["CWE-89"], {"(unlabelled)"})

    def test_context_traps_are_reported_separately_from_mechanisms(self):
        from report.coverage import split_variants
        mechanisms, contexts = split_variants({"concat-statement", "in-markdown", "in-comment"})

        self.assertEqual(mechanisms, ["concat-statement"])
        self.assertEqual(contexts, ["in-comment", "in-markdown"])

    def test_the_rendered_report_names_the_variants(self):
        rows = [a_row(primary_cwe="CWE-89", variant="prepared-but-concatenated")]

        self.assertIn("prepared-but-concatenated", render(rows))


class BreadthIsReportedHonestly(unittest.TestCase):
    """A distinct-CWE total says nothing about spread. 33 CWEs concentrated in
    three languages is a different corpus from 33 spread evenly, and only the
    second supports a claim about a polyglot estate."""

    def setUp(self):
        self.rows = ([a_row(language="java", primary_cwe=f"CWE-{n}") for n in (89, 78, 22, 79)] +
                     [a_row(language="swift", primary_cwe="CWE-78")])

    def test_reports_cwe_depth_per_language(self):
        from report.coverage import depth_by_language

        depth = depth_by_language(self.rows)

        self.assertEqual(depth["java"], 4)
        self.assertEqual(depth["swift"], 1)

    def test_reports_matrix_density(self):
        from report.coverage import density
        # 2 languages x 4 CWEs = 8 cells; 5 are filled
        self.assertAlmostEqual(density(self.rows), 5 / 8)

    def test_density_of_an_empty_corpus_is_zero_not_a_crash(self):
        from report.coverage import density
        self.assertEqual(density([]), 0.0)

    def test_the_report_states_the_concentration(self):
        text = render(self.rows, languages=["java", "swift"], cwes=["CWE-89"])

        self.assertIn("depth", text.lower())


class DensityAgainstApplicableCells(unittest.TestCase):
    """Raw density counts cells nobody should fill, so it understates the corpus
    and the doc had to hand-wave that 'many combinations are meaningless'. The
    applicability map replaces the hand-wave with a denominator."""

    def rendered(self):
        root = Path(__file__).resolve().parents[2]
        with (root / "answers" / "expectedresults-1.0.csv").open() as handle:
            return render(list(csv.DictReader(handle)))

    def test_the_report_states_density_against_applicable_cells(self):
        self.assertIn("cells where the weakness can arise", self.rendered())

    def test_it_still_states_the_raw_figure(self):
        # Both are true and they answer different questions.
        self.assertIn("Grid density", self.rendered())

    def test_applicable_density_exceeds_raw_density(self):
        root = Path(__file__).resolve().parents[2]
        with (root / "answers" / "expectedresults-1.0.csv").open() as handle:
            rows = [r for r in csv.DictReader(handle) if r["tier"] == "1"]
        mapping = load_applicability()
        languages = {r["language"] for r in rows}
        cwes = {r["primary_cwe"] for r in rows}
        grid = {(r["language"], r["primary_cwe"]) for r in rows}

        self.assertGreater(applicable_density(grid, mapping, languages, cwes),
                           density(rows))


class MonocultureIsReported(unittest.TestCase):
    """Template-generated cases share a shape a tool can overfit to. The
    roadmap's cap only means something if the ratio is on the page."""

    def rendered(self):
        root = Path(__file__).resolve().parents[2]
        with (root / "answers" / "expectedresults-1.0.csv").open() as handle:
            return render(list(csv.DictReader(handle)))

    def test_the_hand_authored_share_is_stated(self):
        self.assertIn("hand-authored", self.rendered().lower())

    def test_the_generator_is_named_as_the_risk(self):
        self.assertIn("overfit", self.rendered().lower())


class EveryWeaknessIsNamed(unittest.TestCase):
    """A CWE with no entry in CWE_NAMES renders as `- CWE-476 — ` — an empty
    bullet that reads as an oversight in a document vendors will be shown. The
    table has to keep pace with the corpus, so the corpus checks it."""

    def test_no_cwe_in_the_answer_key_is_unnamed(self):
        root = Path(__file__).resolve().parents[2]
        key = root / "answers" / "expectedresults-1.0.csv"
        with key.open() as handle:
            used = {row["primary_cwe"] for row in csv.DictReader(handle)}

        unnamed = sorted(c for c in used if not CWE_NAMES.get(c))

        self.assertEqual(unnamed, [], f"{len(unnamed)} weakness(es) render blank")


class TotalsReportBreadthHonestly(unittest.TestCase):
    """`33 weaknesses` and `13 languages` sitting next to each other invite the
    reading that every language carries every weakness. It carries far fewer.
    The totals block states the distinct count and the per-language floor
    together, so the narrow-base caveat is visible without opening the matrix."""

    def rendered(self):
        root = Path(__file__).resolve().parents[2]
        with (root / "answers" / "expectedresults-1.0.csv").open() as handle:
            return render(list(csv.DictReader(handle)))

    def test_distinct_weakness_count_is_stated(self):
        self.assertIn("| Distinct weaknesses |", self.rendered())

    def test_thinnest_language_is_stated(self):
        self.assertIn("| Weaknesses per language |", self.rendered())

    def test_the_floor_is_the_minimum_not_the_average(self):
        line = [l for l in self.rendered().splitlines()
                if l.startswith("| Weaknesses per language |")][0]

        # java is the deepest and swift among the thinnest; the row must show
        # the spread, not a single flattering figure.
        self.assertRegex(line, r"\b6\b.*\b16\b|\b16\b.*\b6\b")
