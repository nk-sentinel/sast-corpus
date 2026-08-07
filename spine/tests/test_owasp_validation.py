import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from score.score import Finding
from validate.owasp_benchmark import TestCase, parse_expected_results, reference_score

EXPECTED_CSV = """# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00002,pathtraver,false,22
BenchmarkTest00003,hash,true,328
"""


def a_finding(name="BenchmarkTest00001", line=50, cwes=("CWE-22",), key=(0, 0)):
    return Finding(
        file="src/main/java/org/owasp/benchmark/testcode/{}.java".format(name),
        start_line=line,
        end_line=line,
        cwes=frozenset(cwes),
        rule_id="R",
        tool="t",
        result_key=key,
    )


class ParseExpectedResults(unittest.TestCase):
    def test_skips_the_comment_header(self):
        self.assertEqual(len(parse_expected_results(EXPECTED_CSV)), 3)

    def test_reads_the_declared_cwe(self):
        self.assertEqual(parse_expected_results(EXPECTED_CSV)[0].cwe, "CWE-22")

    def test_true_marks_a_real_vulnerability(self):
        self.assertTrue(parse_expected_results(EXPECTED_CSV)[0].is_real)

    def test_false_marks_a_deliberate_non_vulnerability(self):
        self.assertFalse(parse_expected_results(EXPECTED_CSV)[1].is_real)

    def test_reads_the_category(self):
        self.assertEqual(parse_expected_results(EXPECTED_CSV)[2].category, "hash")


class ReferenceScore(unittest.TestCase):
    """An independent implementation of the OWASP Benchmark rule, written from
    its definition rather than from score.py. Agreement between the two is the
    evidence that score.py counts what it claims to count; a bug shared by both
    would have to be invented twice, independently.

    The rule: a test case is one file with one intentional CWE. It counts as
    detected when the tool reports that CWE anywhere in that file.
    """

    def setUp(self):
        self.cases = parse_expected_results(EXPECTED_CSV)

    def test_a_real_case_reported_with_the_right_cwe_is_a_true_positive(self):
        counts = reference_score([a_finding()], self.cases)

        self.assertEqual(counts["tp"], 1)

    def test_a_real_case_nobody_reported_is_a_false_negative(self):
        counts = reference_score([], self.cases)

        self.assertEqual(counts["fn"], 2)

    def test_a_fake_case_reported_is_a_false_positive(self):
        counts = reference_score([a_finding(name="BenchmarkTest00002")], self.cases)

        self.assertEqual(counts["fp"], 1)

    def test_a_fake_case_nobody_reported_is_a_true_negative(self):
        counts = reference_score([], self.cases)

        self.assertEqual(counts["tn"], 1)

    def test_the_wrong_cwe_in_the_right_file_does_not_count_as_detection(self):
        counts = reference_score([a_finding(cwes=("CWE-79",))], self.cases)

        self.assertEqual(counts["tp"], 0)

    def test_the_line_number_is_irrelevant_because_the_case_is_the_whole_file(self):
        counts = reference_score([a_finding(line=9999)], self.cases)

        self.assertEqual(counts["tp"], 1)

    def test_several_findings_in_one_file_still_count_once(self):
        findings = [a_finding(key=(0, i)) for i in range(4)]

        counts = reference_score(findings, self.cases)

        self.assertEqual(counts["tp"], 1)

    def test_findings_outside_any_test_case_are_ignored(self):
        counts = reference_score([a_finding(name="NotATestCase")], self.cases)

        self.assertEqual(counts["tp"], 0)
        self.assertEqual(counts["fp"], 0)

    def test_every_case_lands_in_exactly_one_bucket(self):
        counts = reference_score([a_finding()], self.cases)

        self.assertEqual(counts["tp"] + counts["fp"] + counts["fn"] + counts["tn"], 3)


if __name__ == "__main__":
    unittest.main()
