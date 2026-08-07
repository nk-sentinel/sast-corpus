import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from score.score import load_answer_key, main, scorecard
from spine.tests.test_score_matching import a_case, a_finding, match_findings

HEADER = (
    "id,label,plane,tier,language,framework,primary_cwe,acceptable_cwes,owasp_2021,"
    "severity,file,start_line,end_line,alt_locations,flow,sanitizer,obfuscation,build_required"
)
ROW = (
    "c-a7f3e91b,vulnerable,vuln,1,java,spring-mvc,CWE-89,CWE-89;CWE-943,A03,high,"
    "tier1/java/a7f3e91b/OrderRepository.java,42,47,"
    "tier1/java/a7f3e91b/OrderController.java:18:18,inter-file,none,none,true"
)


class LoadAnswerKey(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = self.dir / "expectedresults-test.csv"
        self.path.write_text(HEADER + "\n" + ROW + "\n")

    def test_reads_one_case_per_row(self):
        cases = load_answer_key(self.path)

        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].id, "c-a7f3e91b")

    def test_splits_acceptable_cwes_on_semicolons(self):
        self.assertEqual(
            load_answer_key(self.path)[0].acceptable_cwes, frozenset({"CWE-89", "CWE-943"})
        )

    def test_parses_alt_locations_into_file_start_end_triples(self):
        self.assertEqual(
            load_answer_key(self.path)[0].alt_locations,
            (("tier1/java/a7f3e91b/OrderController.java", 18, 18),),
        )

    def test_an_empty_alt_locations_cell_yields_no_alternatives(self):
        self.path.write_text(
            HEADER + "\n" + ROW.replace("tier1/java/a7f3e91b/OrderController.java:18:18", "") + "\n"
        )

        self.assertEqual(load_answer_key(self.path)[0].alt_locations, ())

    def test_coerces_numeric_and_boolean_columns(self):
        case = load_answer_key(self.path)[0]

        self.assertEqual(case.tier, 1)
        self.assertEqual(case.start_line, 42)
        self.assertIs(case.build_required, True)


class Scorecard(unittest.TestCase):
    def setUp(self):
        cases = [
            a_case(id="c-aaaaaaaa", language="java", primary_cwe="CWE-89"),
            a_case(id="c-bbbbbbbb", language="python", primary_cwe="CWE-79"),
            a_case(id="c-cccccccc", language="python", primary_cwe="CWE-79", label="safe"),
        ]
        self.report = match_findings([a_finding(key=(0, 0))], cases)
        self.card = scorecard(self.report)

    def test_reports_pooled_micro_metrics_at_the_top(self):
        self.assertEqual(self.card["overall"]["tp"], 1)
        self.assertEqual(self.card["overall"]["fn"], 1)
        self.assertEqual(self.card["overall"]["tn"], 1)

    def test_breaks_results_down_by_every_reported_dimension(self):
        for dimension in ("language", "tier", "plane", "primary_cwe", "flow", "sanitizer", "severity"):
            self.assertIn(dimension, self.card["by"], dimension)

    def test_includes_macro_averages_alongside_micro(self):
        self.assertIn("recall", self.card["macro"]["language"])

    def test_counts_location_only_matches_so_the_report_can_caveat_them(self):
        self.assertEqual(self.card["location_only_matches"], 0)

    def test_records_the_tolerance_actually_used(self):
        """A scorecard that does not state its match policy is not comparable."""
        self.assertEqual(self.card["match_policy"]["line_tolerance"], 10)


class Cli(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / "key.csv").write_text(HEADER + "\n" + ROW + "\n")
        self.sarif = self.dir / "results.sarif"
        self.sarif.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "acme", "rules": [{"id": "R1", "properties": {"cwe": "CWE-89"}}]}},
                            "results": [
                                {
                                    "ruleId": "R1",
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "tier1/java/a7f3e91b/OrderRepository.java"},
                                                "region": {"startLine": 44},
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            )
        )

    def run_cli(self, *args):
        buffer = io.StringIO()
        stdout, sys.stdout = sys.stdout, buffer
        try:
            code = main([str(self.sarif), str(self.dir / "key.csv"), *args])
        finally:
            sys.stdout = stdout
        return code, buffer.getvalue()

    def test_scores_a_run_and_exits_zero(self):
        code, output = self.run_cli()

        self.assertEqual(code, 0)
        self.assertIn("recall", output.lower())

    def test_emits_machine_readable_json_when_asked(self):
        _, output = self.run_cli("--json")

        self.assertEqual(json.loads(output)["overall"]["tp"], 1)

    def test_a_missing_results_file_scores_every_case_as_a_miss(self):
        """Strict aggregation: a crashed or timed-out scan is a failure to
        detect, not an absence of evidence."""
        self.sarif = self.dir / "never-written.sarif"

        code, output = self.run_cli("--json", "--strict")

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["overall"]["fn"], 1)

    def test_a_missing_results_file_is_an_error_without_strict(self):
        self.sarif = self.dir / "never-written.sarif"

        code, _ = self.run_cli("--json")

        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
