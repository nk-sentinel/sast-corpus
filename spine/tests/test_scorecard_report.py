import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from score.score import narrative, render_text, scorecard
from spine.tests.test_score_matching import a_case, a_finding, match_findings


class Narrative(unittest.TestCase):
    """Plain counts, in the terms the corpus owner thinks in: how many issues
    exist, how many the tool found, how many it missed, how many things it
    raised that are not issues. No verdict — pass and fail are the reader's."""

    def setUp(self):
        self.cases = [
            a_case(id="c-aaaaaaaa", label="vulnerable"),
            a_case(id="c-bbbbbbbb", label="vulnerable"),
            a_case(id="c-cccccccc", label="vulnerable"),
            a_case(id="c-dddddddd", label="safe"),
            a_case(id="c-eeeeeeee", label="safe"),
        ]
        findings = [
            a_finding(key=(0, 0)),                                        # hits one real issue
            a_finding(file="tier1/java/zzzz/Other.java", key=(0, 1)),      # outside the answer key
        ]
        self.report = match_findings(findings, self.cases)
        self.n = narrative(self.report)

    def test_states_how_many_issues_the_corpus_knows_about(self):
        self.assertEqual(self.n["known_issues"], 3)

    def test_states_how_many_the_tool_found(self):
        self.assertEqual(self.n["found"], 1)

    def test_states_how_many_it_missed(self):
        self.assertEqual(self.n["missed"], 2)

    def test_counts_traps_separately_from_issues(self):
        self.assertEqual(self.n["traps"], 2)

    def test_a_finding_on_a_trap_is_a_confirmed_false_alarm(self):
        report = match_findings([a_finding(file=a_case(label="safe").file, key=(0, 0))],
                                [a_case(id="c-dddddddd", label="safe")])

        self.assertEqual(narrative(report)["false_alarms"], 1)

    def test_findings_outside_the_answer_key_are_reported_but_not_judged(self):
        """They may be real issues the corpus does not know about. Calling them
        false positives would overstate what the corpus can actually say."""
        self.assertEqual(self.n["not_judged"], 1)

    def test_not_judged_is_never_folded_into_false_alarms(self):
        self.assertEqual(self.n["false_alarms"], 0)

    def test_found_and_missed_always_account_for_every_known_issue(self):
        self.assertEqual(self.n["found"] + self.n["missed"], self.n["known_issues"])


class PlainReport(unittest.TestCase):
    def setUp(self):
        cases = [a_case(id="c-aaaaaaaa"), a_case(id="c-bbbbbbbb"),
                 a_case(id="c-cccccccc", label="safe")]
        self.report = match_findings([a_finding(key=(0, 0))], cases)
        self.text = render_text(scorecard(self.report))

    def test_leads_with_what_the_corpus_knows(self):
        head = self.text.splitlines()[:8]
        self.assertTrue(any("known issue" in line for line in head), self.text[:300])

    def test_says_found_and_missed_in_words(self):
        self.assertIn("found", self.text)
        self.assertIn("missed", self.text)

    def test_carries_no_verdict_language(self):
        """The reader decides pass and fail."""
        lowered = self.text.lower()
        for word in ("pass", "fail", "threshold", "acceptable", "good", "poor"):
            self.assertNotIn(word, lowered)

    def test_includes_timing_when_supplied(self):
        text = render_text(scorecard(self.report),
                           timing={"summary": {"total": {"p50": 2.5},
                                               "scanned_loc": 15716,
                                               "seconds_per_1k_loc": {"total": 0.159}}})

        self.assertIn("2.5", text)
        self.assertIn("15,716", text)

    def test_omits_the_timing_section_when_absent(self):
        self.assertNotIn("how long", self.text.lower())


if __name__ == "__main__":
    unittest.main()
