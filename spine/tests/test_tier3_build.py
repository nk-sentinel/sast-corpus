import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from corpora.tier3_build import buildable_slugs, record_results, summarise_builds


class BuildableSlugs(unittest.TestCase):
    """Only projects we actually derived cases from are worth building. Building
    all 120 costs hours for cases nothing scores against."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        for slug in ("a__x_CVE-2020-1_1.0", "b__y_CVE-2020-2_1.0"):
            (self.root / "project-sources" / slug).mkdir(parents=True)

    def test_lists_slugs_that_have_a_checkout(self):
        found = buildable_slugs(self.root / "project-sources", None)

        self.assertEqual(len(found), 2)

    def test_restricts_to_the_slugs_that_carry_derived_cases(self):
        found = buildable_slugs(self.root / "project-sources", {"a__x_CVE-2020-1_1.0"})

        self.assertEqual(found, ["a__x_CVE-2020-1_1.0"])

    def test_a_slug_with_no_checkout_is_not_offered(self):
        found = buildable_slugs(self.root / "project-sources", {"never__fetched_CVE-1_1.0"})

        self.assertEqual(found, [])


class SummariseBuilds(unittest.TestCase):
    """The real success rate gets recorded, not upstream's claim. If it is not
    120 of 120 on this host, saying so is the whole point of running it."""

    def test_counts_each_outcome(self):
        summary = summarise_builds({"a": "success", "b": "success", "c": "failed"})

        self.assertEqual(summary["success"], 2)
        self.assertEqual(summary["failed"], 1)

    def test_reports_the_rate(self):
        summary = summarise_builds({"a": "success", "b": "failed"})

        self.assertAlmostEqual(summary["rate"], 0.5)

    def test_an_empty_run_has_no_rate_rather_than_a_perfect_one(self):
        """Zero of zero must not report as 100%."""
        self.assertIsNone(summarise_builds({})["rate"])


class RecordResults(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)

    def test_writes_a_status_per_slug(self):
        path = record_results({"a__x_CVE-1_1.0": "success"}, self.root / "build-status.json")

        import json
        self.assertEqual(json.loads(path.read_text())["results"]["a__x_CVE-1_1.0"], "success")

    def test_records_the_toolchain_so_a_result_is_reproducible(self):
        import json
        path = record_results({"a": "success"}, self.root / "s.json")

        self.assertIn("host", json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
