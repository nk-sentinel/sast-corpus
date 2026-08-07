import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from timing.bench import (
    PhaseTimings,
    RunResult,
    parse_codeprint_output,
    percentile,
    seconds_per_1k_loc,
    summarise,
)


def a_run(analysis=10.0, build=0.0, provision=0.0, upload_wait=0.0, ok=True, rss=100 * 1024 * 1024):
    return RunResult(
        ok=ok,
        phases=PhaseTimings(
            provision=provision, build=build, analysis=analysis, upload_wait=upload_wait
        ),
        peak_rss_bytes=rss,
        exit_code=0 if ok else 1,
    )


class Percentile(unittest.TestCase):
    """Nearest-rank, so a reported p95 is always a value that actually occurred
    rather than an interpolation between two runs."""

    def test_median_of_an_odd_sample(self):
        self.assertEqual(percentile([1, 2, 3, 4, 5], 50), 3)

    def test_p95_of_five_runs_is_the_slowest(self):
        self.assertEqual(percentile([1, 2, 3, 4, 5], 95), 5)

    def test_order_of_the_input_does_not_matter(self):
        self.assertEqual(percentile([5, 1, 4, 2, 3], 50), 3)

    def test_a_single_run_is_its_own_percentile(self):
        self.assertEqual(percentile([7.5], 95), 7.5)

    def test_an_empty_sample_has_no_percentile(self):
        self.assertIsNone(percentile([], 50))


class PhaseAccounting(unittest.TestCase):
    def test_total_is_the_sum_of_the_phases(self):
        phases = PhaseTimings(provision=1.0, build=20.0, analysis=100.0, upload_wait=30.0)

        self.assertAlmostEqual(phases.total, 151.0)

    def test_phases_are_reported_separately_not_only_as_a_total(self):
        """A hosted scanner's queue time is not scan speed and must never be
        reported as though it were."""
        summary = summarise([a_run(analysis=100.0, upload_wait=300.0)], scanned_loc=1000)

        self.assertAlmostEqual(summary["phases"]["analysis"]["p50"], 100.0)
        self.assertAlmostEqual(summary["phases"]["upload_wait"]["p50"], 300.0)


class Summarise(unittest.TestCase):
    def test_reports_p50_and_p95_of_total_wall_clock(self):
        runs = [a_run(analysis=t) for t in (10, 11, 12, 13, 40)]

        summary = summarise(runs, scanned_loc=1000)

        self.assertAlmostEqual(summary["total"]["p50"], 12)
        self.assertAlmostEqual(summary["total"]["p95"], 40)

    def test_reports_peak_resident_memory(self):
        runs = [a_run(rss=100), a_run(rss=900)]

        self.assertEqual(summarise(runs, scanned_loc=1000)["peak_rss_bytes"], 900)

    def test_counts_runs_and_failures(self):
        runs = [a_run(), a_run(ok=False), a_run()]

        summary = summarise(runs, scanned_loc=1000)

        self.assertEqual(summary["runs"], 3)
        self.assertEqual(summary["failed_runs"], 1)

    def test_failed_runs_are_excluded_from_the_timings(self):
        """A tool that crashes in 0.2s must not look fast."""
        runs = [a_run(analysis=100.0), a_run(analysis=0.2, ok=False), a_run(analysis=100.0)]

        summary = summarise(runs, scanned_loc=1000)

        self.assertAlmostEqual(summary["total"]["p50"], 100.0)

    def test_a_run_where_every_attempt_failed_reports_no_timings(self):
        summary = summarise([a_run(ok=False)], scanned_loc=1000)

        self.assertIsNone(summary["total"]["p50"])


class Throughput(unittest.TestCase):
    def test_seconds_per_1k_loc_scales_by_the_line_count(self):
        self.assertAlmostEqual(seconds_per_1k_loc(60.0, 200_000), 0.3)

    def test_a_corpus_with_no_counted_lines_has_no_throughput(self):
        self.assertIsNone(seconds_per_1k_loc(60.0, 0))

    def test_summary_reports_throughput_for_analysis_and_for_the_whole_run(self):
        runs = [a_run(analysis=100.0, build=100.0)]

        summary = summarise(runs, scanned_loc=100_000)

        self.assertAlmostEqual(summary["seconds_per_1k_loc"]["analysis"], 1.0)
        self.assertAlmostEqual(summary["seconds_per_1k_loc"]["total"], 2.0)


class Stability(unittest.TestCase):
    """A host whose repeated runs scatter is too noisy to publish from."""

    def test_consistent_runs_are_stable(self):
        runs = [a_run(analysis=t) for t in (100.0, 101.0, 99.0, 100.5, 100.2)]

        self.assertTrue(summarise(runs, scanned_loc=1000)["stable"])

    def test_scattered_runs_are_not_stable(self):
        runs = [a_run(analysis=t) for t in (50.0, 150.0, 80.0, 200.0, 60.0)]

        self.assertFalse(summarise(runs, scanned_loc=1000)["stable"])

    def test_the_relative_standard_deviation_is_reported_so_the_verdict_is_checkable(self):
        runs = [a_run(analysis=t) for t in (100.0, 100.0, 100.0)]

        self.assertAlmostEqual(summarise(runs, scanned_loc=1000)["relative_stddev"], 0.0)

    def test_a_single_run_cannot_be_called_stable(self):
        self.assertFalse(summarise([a_run()], scanned_loc=1000)["stable"])


CODEPRINT_JSON = """{
  "_meta": {"schema_version": "1.0", "producer": {"name": "codeprint"}},
  "fingerprint": {
    "totals": {"files": 4, "code": 58, "comment": 0, "blank": 13, "bytes": 2273},
    "languages": [{"language": "Java", "files": 4, "code": 58}]
  }
}"""


class CodeprintParsing(unittest.TestCase):
    """The denominator is code lines only. Counting comments and blanks would
    flatter tools unevenly, since each skips a different share of a repository."""

    def test_reads_code_lines_from_the_totals(self):
        self.assertEqual(parse_codeprint_output(CODEPRINT_JSON), 58)

    def test_ignores_comment_and_blank_lines(self):
        self.assertNotEqual(parse_codeprint_output(CODEPRINT_JSON), 58 + 13)

    def test_output_that_is_not_json_yields_nothing(self):
        self.assertIsNone(parse_codeprint_output("codeprint: no such directory"))

    def test_json_without_a_fingerprint_yields_nothing(self):
        self.assertIsNone(parse_codeprint_output('{"_meta": {}}'))


if __name__ == "__main__":
    unittest.main()
