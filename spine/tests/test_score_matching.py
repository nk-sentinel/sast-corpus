import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from score.score import Case, Finding, match_findings

SINK = "tier1/java/a7f3e91b/OrderRepository.java"
SOURCE = "tier1/java/a7f3e91b/OrderController.java"


def a_case(**overrides):
    fields = {
        "id": "c-a7f3e91b",
        "label": "vulnerable",
        "plane": "vuln",
        "tier": 1,
        "language": "java",
        "framework": "spring-mvc",
        "primary_cwe": "CWE-89",
        "variant": "concat-statement",
        "acceptable_cwes": frozenset({"CWE-89", "CWE-943"}),
        "owasp_2021": "A03",
        "severity": "high",
        "file": SINK,
        "start_line": 42,
        "end_line": 47,
        "alt_locations": (),
        "flow": "inter-file",
        "sanitizer": "none",
        "obfuscation": "none",
        "build_required": True,
    }
    fields.update(overrides)
    return Case(**fields)


def a_finding(file=SINK, line=42, cwes=("CWE-89",), key=(0, 0)):
    return Finding(
        file=file,
        start_line=line,
        end_line=line,
        cwes=frozenset(cwes),
        rule_id="R1",
        tool="acme",
        result_key=key,
    )


def outcome_for(report, case_id):
    return next(o for o in report.outcomes if o.case.id == case_id)


class ExactAndTolerantMatching(unittest.TestCase):
    def test_a_finding_on_the_sink_line_with_the_primary_cwe_is_a_true_positive(self):
        report = match_findings([a_finding(line=42)], [a_case()])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "tp")

    # Tolerance widens the whole ground-truth range, so a multi-line sink is not
    # penalised for being long: case lines 42-47 with tolerance 10 accept 32-57.

    def test_a_finding_on_the_last_tolerated_line_above_the_range_matches(self):
        report = match_findings([a_finding(line=57)], [a_case()], tolerance=10)

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "tp")

    def test_a_finding_one_line_beyond_the_tolerance_does_not_match(self):
        report = match_findings([a_finding(line=58)], [a_case()], tolerance=10)

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "fn")

    def test_a_finding_on_the_first_tolerated_line_below_the_range_matches(self):
        report = match_findings([a_finding(line=32)], [a_case()], tolerance=10)

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "tp")

    def test_a_finding_one_line_below_the_tolerance_does_not_match(self):
        report = match_findings([a_finding(line=31)], [a_case()], tolerance=10)

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "fn")

    def test_a_secondary_acceptable_cwe_counts_as_a_hit(self):
        """Scoring a tool down for a defensible sibling CWE measures taxonomy
        preference, not detection."""
        report = match_findings([a_finding(cwes=("CWE-943",))], [a_case()])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "tp")

    def test_an_unrelated_cwe_on_the_right_line_does_not_match(self):
        report = match_findings([a_finding(cwes=("CWE-79",))], [a_case()])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "fn")

    def test_a_case_with_no_finding_at_all_is_a_false_negative(self):
        report = match_findings([], [a_case()])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "fn")


class PathMatching(unittest.TestCase):
    def test_matches_an_absolute_path_ending_in_the_answer_key_path(self):
        """Tools report container-internal absolute paths; the corpus path is a
        suffix of them."""
        report = match_findings([a_finding(file="/build/ws/" + SINK)], [a_case()])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "tp")

    def test_does_not_match_a_different_file_with_the_same_basename(self):
        report = match_findings(
            [a_finding(file="tier1/java/other/OrderRepository.java")], [a_case()]
        )

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "fn")

    def test_does_not_match_a_path_that_merely_shares_a_suffix_mid_segment(self):
        report = match_findings([a_finding(file="/x/notier1/java/a7f3e91b/OrderRepository.java")], [a_case()])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "fn")


class AlternativeLocations(unittest.TestCase):
    def test_a_hit_at_the_declared_source_counts(self):
        case = a_case(alt_locations=((SOURCE, 18, 18),))

        report = match_findings([a_finding(file=SOURCE, line=18)], [case])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "tp")

    def test_a_hit_at_the_source_of_a_case_that_declares_none_does_not_count(self):
        report = match_findings([a_finding(file=SOURCE, line=18)], [a_case()])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "fn")


class FalsePositiveTraps(unittest.TestCase):
    def test_a_finding_on_a_safe_case_is_a_false_positive(self):
        case = a_case(id="c-bbbbbbbb", label="safe")

        report = match_findings([a_finding()], [case])

        self.assertEqual(outcome_for(report, "c-bbbbbbbb").kind, "fp")

    def test_a_safe_case_nobody_reported_is_a_true_negative(self):
        case = a_case(id="c-bbbbbbbb", label="safe")

        report = match_findings([], [case])

        self.assertEqual(outcome_for(report, "c-bbbbbbbb").kind, "tn")

    def test_a_finding_with_an_unrelated_cwe_does_not_trip_the_trap(self):
        """The trap measures whether a tool confuses this specific pattern for
        this specific weakness, not whether it reports anything at all here."""
        case = a_case(id="c-bbbbbbbb", label="safe")

        report = match_findings([a_finding(cwes=("CWE-798",))], [case])

        self.assertEqual(outcome_for(report, "c-bbbbbbbb").kind, "tn")


class Deduplication(unittest.TestCase):
    def test_many_findings_on_one_case_award_exactly_one_true_positive(self):
        findings = [a_finding(line=42, key=(0, i)) for i in range(5)]

        report = match_findings(findings, [a_case()])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "tp")
        self.assertEqual(report.counts()["tp"], 1)

    def test_surplus_findings_on_a_matched_case_are_not_counted_as_false_positives(self):
        findings = [a_finding(line=42, key=(0, i)) for i in range(5)]

        report = match_findings(findings, [a_case()])

        self.assertEqual(report.counts()["fp"], 0)

    def test_one_finding_cannot_satisfy_two_cases(self):
        cases = [a_case(id="c-aaaaaaaa"), a_case(id="c-bbbbbbbb")]

        report = match_findings([a_finding()], cases)

        kinds = sorted(o.kind for o in report.outcomes)
        self.assertEqual(kinds, ["fn", "tp"])

    def test_two_locations_of_one_result_do_not_satisfy_two_cases(self):
        """A single reported issue is a single claim, however many places the
        tool prints it."""
        cases = [
            a_case(id="c-aaaaaaaa"),
            a_case(id="c-bbbbbbbb", file=SOURCE, start_line=18, end_line=18),
        ]
        findings = [
            a_finding(file=SINK, line=42, key=(0, 0)),
            a_finding(file=SOURCE, line=18, key=(0, 0)),
        ]

        report = match_findings(findings, cases)

        self.assertEqual(report.counts()["tp"], 1)


class UnmatchedFindings(unittest.TestCase):
    def test_a_finding_outside_every_case_is_unmatched_not_a_false_positive(self):
        """Unrelated rules firing elsewhere in the corpus would otherwise swamp
        the false-positive signal the traps are there to measure."""
        report = match_findings([a_finding(file="tier1/java/zzzz/Other.java")], [a_case()])

        self.assertEqual(report.counts()["fp"], 0)
        self.assertEqual(len(report.unmatched), 1)

    def test_matched_findings_are_not_listed_as_unmatched(self):
        report = match_findings([a_finding()], [a_case()])

        self.assertEqual(report.unmatched, [])


class LocationOnlyMatches(unittest.TestCase):
    """Tools that emit no CWE must not be silently zeroed, nor given free credit."""

    def test_a_finding_without_a_cwe_matches_on_location_alone(self):
        report = match_findings([a_finding(cwes=())], [a_case()])

        self.assertEqual(outcome_for(report, "c-a7f3e91b").kind, "tp")

    def test_such_a_match_is_flagged_so_the_report_can_say_so(self):
        report = match_findings([a_finding(cwes=())], [a_case()])

        self.assertTrue(outcome_for(report, "c-a7f3e91b").location_only)

    def test_a_cwe_bearing_match_is_not_flagged(self):
        report = match_findings([a_finding()], [a_case()])

        self.assertFalse(outcome_for(report, "c-a7f3e91b").location_only)

    def test_a_cwe_bearing_finding_is_preferred_over_a_bare_one(self):
        findings = [a_finding(cwes=(), key=(0, 0)), a_finding(cwes=("CWE-89",), key=(0, 1))]

        report = match_findings(findings, [a_case()])

        self.assertFalse(outcome_for(report, "c-a7f3e91b").location_only)


if __name__ == "__main__":
    unittest.main()
