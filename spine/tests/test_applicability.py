import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from report.applicability import (applicable, applicable_cells, contradictions,
                                  density, load, unmapped_cwes)

ROOT = Path(__file__).resolve().parents[2]


class Lookup(unittest.TestCase):
    def setUp(self):
        self.mapping = {"CWE-125": {"applies_to": ["c", "cpp"],
                                    "reason": "bounds-checked elsewhere"},
                        "CWE-89": {"applies_to": ["c", "java", "python"]}}

    def test_a_listed_language_applies(self):
        self.assertTrue(applicable(self.mapping, "c", "CWE-125"))

    def test_an_unlisted_language_does_not(self):
        self.assertFalse(applicable(self.mapping, "java", "CWE-125"))

    def test_an_unmapped_weakness_applies_everywhere(self):
        # Better to overstate the grid than to silently shrink it: an unmapped
        # weakness shows as a gap, and the CI check below makes it visible.
        self.assertTrue(applicable(self.mapping, "swift", "CWE-999"))


class Density(unittest.TestCase):
    """Density against every possible cell understates coverage, because most
    cells are ones nobody should fill. Use-after-free in Java is not a gap."""

    def test_counts_only_applicable_cells(self):
        mapping = {"CWE-125": {"applies_to": ["c", "cpp"], "reason": "x"}}

        self.assertEqual(applicable_cells(mapping, ["c", "cpp", "java"], ["CWE-125"]), 2)

    def test_density_is_measured_against_them(self):
        mapping = {"CWE-125": {"applies_to": ["c", "cpp"], "reason": "x"}}
        grid = {("c", "CWE-125")}

        self.assertAlmostEqual(density(grid, mapping, ["c", "cpp", "java"], ["CWE-125"]), 0.5)

    def test_full_coverage_of_applicable_cells_is_one(self):
        mapping = {"CWE-125": {"applies_to": ["c"], "reason": "x"}}
        grid = {("c", "CWE-125")}

        self.assertEqual(density(grid, mapping, ["c", "java"], ["CWE-125"]), 1.0)

    def test_no_applicable_cells_is_not_a_division_error(self):
        self.assertEqual(density(set(), {}, [], []), 0.0)


class ValidatedAgainstTheCorpus(unittest.TestCase):
    """The map is a claim about the world, and the corpus is evidence. A case
    that exists for a pair the map calls inapplicable means one of the two is
    wrong, and silently trusting either would be worse than failing."""

    def test_a_case_contradicting_the_map_is_reported(self):
        mapping = {"CWE-125": {"applies_to": ["c"], "reason": "x"}}
        rows = [{"language": "java", "primary_cwe": "CWE-125", "tier": "1"}]

        self.assertEqual(contradictions(rows, mapping), [("java", "CWE-125")])

    def test_a_case_agreeing_with_the_map_is_not_reported(self):
        mapping = {"CWE-125": {"applies_to": ["c"], "reason": "x"}}
        rows = [{"language": "c", "primary_cwe": "CWE-125", "tier": "1"}]

        self.assertEqual(contradictions(rows, mapping), [])

    def test_tier_three_does_not_contradict(self):
        # Tier 3 comes from whatever CVEs upstream happens to contain; it is
        # evidence about the world, not about what we chose to author.
        mapping = {"CWE-125": {"applies_to": ["c"], "reason": "x"}}
        rows = [{"language": "java", "primary_cwe": "CWE-125", "tier": "3"}]

        self.assertEqual(contradictions(rows, mapping), [])

    def test_a_weakness_with_no_entry_is_reported(self):
        rows = [{"language": "c", "primary_cwe": "CWE-777", "tier": "1"}]

        self.assertEqual(unmapped_cwes(rows, {}), ["CWE-777"])


class TheShippedMap(unittest.TestCase):
    """The real file, checked against the real answer key. These are the tests
    that fail when someone adds a case the map does not expect."""

    @classmethod
    def setUpClass(cls):
        cls.mapping = load(ROOT / "spine" / "report" / "applicability.json")
        with (ROOT / "answers" / "expectedresults-1.0.csv").open() as handle:
            cls.rows = list(csv.DictReader(handle))

    def test_every_weakness_in_the_answer_key_is_mapped(self):
        self.assertEqual(unmapped_cwes(self.rows, self.mapping), [])

    def test_no_case_contradicts_the_map(self):
        self.assertEqual(contradictions(self.rows, self.mapping), [])

    def test_every_exclusion_carries_a_reason(self):
        # An exclusion without a reason is an assertion nobody can check.
        languages = {row["language"] for row in self.rows}
        unreasoned = [cwe for cwe, entry in self.mapping.items()
                      if set(entry["applies_to"]) < languages and not entry.get("reason")]

        self.assertEqual(unreasoned, [])

    def test_memory_safety_is_not_claimed_for_managed_languages(self):
        for cwe in ("CWE-125", "CWE-787", "CWE-416", "CWE-121", "CWE-122"):
            applies = set(self.mapping[cwe]["applies_to"])

            self.assertNotIn("python", applies, f"{cwe} should not apply to python")
            self.assertNotIn("java", applies, f"{cwe} should not apply to java")

    def test_integer_overflow_excludes_arbitrary_precision_languages(self):
        # Python integers do not wrap.
        self.assertNotIn("python", self.mapping["CWE-190"]["applies_to"])

    def test_injection_applies_broadly(self):
        # Anything that talks to a database can do it wrong.
        self.assertGreaterEqual(len(self.mapping["CWE-89"]["applies_to"]), 10)


if __name__ == "__main__":
    unittest.main()
