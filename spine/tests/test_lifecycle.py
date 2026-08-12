import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from report.lifecycle import (Saturation, authored_ratio, pin_age_warnings,
                              retired_reason, saturation, stale_pins)


class Retirement(unittest.TestCase):
    """A case is retired rather than deleted, so a scorecard produced against an
    earlier corpus version stays reproducible. Deleting the YAML would make the
    old answer key unexplainable."""

    def test_a_case_with_a_reason_is_retired(self):
        self.assertEqual(retired_reason({"retired": "CVE withdrawn upstream"}),
                         "CVE withdrawn upstream")

    def test_a_case_without_the_field_is_live(self):
        self.assertIsNone(retired_reason({"id": "c-1"}))

    def test_retiring_without_a_reason_is_rejected(self):
        # `retired: true` records that someone stopped trusting a case and not
        # why, which is the part a later reader needs.
        with self.assertRaises(ValueError):
            retired_reason({"retired": True})

    def test_an_empty_reason_is_rejected(self):
        with self.assertRaises(ValueError):
            retired_reason({"retired": "  "})


class SaturationMarking(unittest.TestCase):
    """Once several tools have been scored, a case every tool finds and none
    false-positives on carries no further information. It stays for regression
    and leaves the headline discriminating metrics, and the count is reported so
    the corpus's own decay is visible."""

    def test_a_case_every_tool_found_is_saturated(self):
        result = saturation({"tool-a": True, "tool-b": True, "tool-c": True})

        self.assertEqual(result, Saturation.SATURATED)

    def test_a_case_some_tools_missed_still_discriminates(self):
        result = saturation({"tool-a": True, "tool-b": False, "tool-c": True})

        self.assertEqual(result, Saturation.DISCRIMINATING)

    def test_a_case_no_tool_found_also_discriminates(self):
        # Nobody finding it is informative — it is the hard end of the corpus,
        # not a case to retire.
        result = saturation({"tool-a": False, "tool-b": False, "tool-c": False})

        self.assertEqual(result, Saturation.DISCRIMINATING)

    def test_too_few_tools_is_not_yet_judged(self):
        # Two agreeing tools is a coincidence, not saturation.
        self.assertEqual(saturation({"tool-a": True, "tool-b": True}),
                         Saturation.UNJUDGED)

    def test_no_results_at_all_is_not_yet_judged(self):
        self.assertEqual(saturation({}), Saturation.UNJUDGED)

    def test_the_threshold_can_be_raised(self):
        self.assertEqual(saturation({"a": True, "b": True, "c": True}, minimum=4),
                         Saturation.UNJUDGED)


class MonocultureRatio(unittest.TestCase):
    """Template-generated cases share a shape tools can overfit to. The ratio is
    tracked and reported so the drift is visible rather than discovered."""

    def test_counts_generated_against_hand_authored(self):
        rows = [{"source": "generated"}, {"source": "generated"},
                {"source": "hand-authored"}]

        self.assertAlmostEqual(authored_ratio(rows), 1 / 3)

    def test_an_empty_corpus_is_not_a_division_error(self):
        self.assertEqual(authored_ratio([]), 0.0)

    def test_cve_derived_cases_count_as_hand_authored(self):
        # They were not produced by the generator, which is what the ratio is
        # actually about.
        rows = [{"source": "generated"}, {"source": "cve"}]

        self.assertAlmostEqual(authored_ratio(rows), 0.5)

    def test_an_unknown_source_is_not_counted_as_authored(self):
        rows = [{"source": "generated"}, {"source": ""}]

        self.assertAlmostEqual(authored_ratio(rows), 0.0)


class PinStaleness(unittest.TestCase):
    """Pins are full SHAs and never move, which is the point — and also means
    nothing tells you when one has rotted."""

    def test_a_recent_pin_is_fine(self):
        sources = [{"name": "x", "pinned_on": "2026-06-01"}]

        self.assertEqual(stale_pins(sources, today="2026-08-12", months=12), [])

    def test_an_old_pin_is_flagged(self):
        sources = [{"name": "x", "pinned_on": "2024-01-01"}]

        self.assertEqual([s["name"] for s in
                          stale_pins(sources, today="2026-08-12", months=12)], ["x"])

    def test_a_pin_with_no_date_is_flagged_as_unknown(self):
        # Silence about age is not evidence of freshness.
        sources = [{"name": "x"}]

        self.assertEqual([s["name"] for s in
                          stale_pins(sources, today="2026-08-12", months=12)], ["x"])

    def test_the_warning_says_which_and_why(self):
        sources = [{"name": "hadoop", "pinned_on": "2023-01-01"}]

        text = pin_age_warnings(sources, today="2026-08-12", months=12)

        self.assertIn("hadoop", text)
        self.assertIn("2023-01-01", text)

    def test_nothing_stale_produces_no_warning(self):
        sources = [{"name": "x", "pinned_on": "2026-08-01"}]

        self.assertEqual(pin_age_warnings(sources, today="2026-08-12", months=12), "")


if __name__ == "__main__":
    unittest.main()
