import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from score.score import group_counts, macro_average, metrics
from spine.tests.test_score_matching import a_case, a_finding, match_findings


class Metrics(unittest.TestCase):
    """Worked example throughout: tp=6, fp=2, fn=4, tn=8.
    precision 0.75, recall 0.60 — deliberately asymmetric so recall weighting shows."""

    def setUp(self):
        self.m = metrics({"tp": 6, "fp": 2, "fn": 4, "tn": 8})

    def test_precision_is_tp_over_reported(self):
        self.assertAlmostEqual(self.m["precision"], 0.75)

    def test_recall_is_tp_over_all_real_vulnerabilities(self):
        self.assertAlmostEqual(self.m["recall"], 0.60)

    def test_f1_balances_precision_and_recall(self):
        self.assertAlmostEqual(self.m["f1"], 2 / 3, places=6)

    def test_f3_weights_recall_nine_times_over_precision(self):
        self.assertAlmostEqual(self.m["f3"], 4.5 / 7.35, places=6)

    def test_f3_sits_below_f1_when_recall_trails_precision(self):
        """The whole point of reporting it: a tool that misses things is
        penalised harder than one that is merely noisy."""
        self.assertLess(self.m["f3"], self.m["f1"])

    def test_true_positive_rate_equals_recall(self):
        self.assertAlmostEqual(self.m["tpr"], self.m["recall"])

    def test_false_positive_rate_is_fp_over_all_safe_cases(self):
        self.assertAlmostEqual(self.m["fpr"], 0.20)

    def test_youden_j_is_tpr_minus_fpr(self):
        self.assertAlmostEqual(self.m["youden_j"], 0.40)


class UndefinedMetrics(unittest.TestCase):
    def test_a_tool_that_reported_nothing_scores_zero_precision_not_a_crash(self):
        self.assertEqual(metrics({"tp": 0, "fp": 0, "fn": 5, "tn": 5})["precision"], 0.0)

    def test_a_corpus_with_no_traps_scores_zero_false_positive_rate(self):
        self.assertEqual(metrics({"tp": 5, "fp": 0, "fn": 0, "tn": 0})["fpr"], 0.0)

    def test_undefined_metrics_are_flagged_rather_than_silently_reported_as_zero(self):
        result = metrics({"tp": 0, "fp": 0, "fn": 5, "tn": 5})

        self.assertIn("precision", result["undefined"])

    def test_a_fully_defined_scorecard_flags_nothing(self):
        self.assertEqual(metrics({"tp": 6, "fp": 2, "fn": 4, "tn": 8})["undefined"], [])


class Grouping(unittest.TestCase):
    def setUp(self):
        self.cases = [
            a_case(id="c-aaaaaaaa", language="java", primary_cwe="CWE-89"),
            a_case(id="c-bbbbbbbb", language="java", primary_cwe="CWE-79"),
            a_case(id="c-cccccccc", language="python", primary_cwe="CWE-89"),
        ]
        # Only the first case is detected.
        self.report = match_findings([a_finding(key=(0, 0))], self.cases)

    def test_counts_are_split_by_the_requested_dimension(self):
        by_language = group_counts(self.report, "language")

        self.assertEqual(by_language["java"], {"tp": 1, "fp": 0, "fn": 1, "tn": 0})
        self.assertEqual(by_language["python"], {"tp": 0, "fp": 0, "fn": 1, "tn": 0})

    def test_grouping_by_cwe_uses_the_primary_cwe(self):
        by_cwe = group_counts(self.report, "primary_cwe")

        self.assertEqual(sorted(by_cwe), ["CWE-79", "CWE-89"])

    def test_grouping_by_a_difficulty_dimension_works(self):
        by_flow = group_counts(self.report, "flow")

        self.assertEqual(by_flow["inter-file"]["fn"], 2)


class MacroAveraging(unittest.TestCase):
    """Macro weights every category equally, so one enormous category cannot
    hide a tool's blindness to a small one. It routinely disagrees with micro,
    and the disagreement is itself worth reporting."""

    def test_averages_the_metric_across_groups_not_across_cases(self):
        groups = {
            "big": {"tp": 90, "fp": 0, "fn": 10, "tn": 0},   # recall 0.90
            "small": {"tp": 1, "fp": 0, "fn": 9, "tn": 0},   # recall 0.10
        }

        self.assertAlmostEqual(macro_average(groups, "recall"), 0.50)

    def test_micro_pooling_of_the_same_data_disagrees_with_macro(self):
        pooled = metrics({"tp": 91, "fp": 0, "fn": 19, "tn": 0})

        self.assertAlmostEqual(pooled["recall"], 91 / 110, places=6)
        self.assertNotAlmostEqual(pooled["recall"], 0.50, places=2)

    def test_an_empty_group_set_averages_to_zero(self):
        self.assertEqual(macro_average({}, "recall"), 0.0)


if __name__ == "__main__":
    unittest.main()
