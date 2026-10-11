import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from score import claims
from score.score import Case, Finding, match_findings, scorecard

GOOD = {
    "tool": "Acme",
    "languages": ["python", "java"],
    "planes": ["vuln"],
    "source": "vendor docs, accessed 2026-10-11",
}


def write(data):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(data, handle)
    handle.close()
    return handle.name


def a_case(identifier="c-00000001", language="python", plane="vuln", label="vulnerable"):
    return Case(
        id=identifier, label=label, plane=plane, tier=1, language=language,
        framework=None, primary_cwe="CWE-89", variant=None,
        acceptable_cwes=frozenset({"CWE-89"}), owasp_2021="A03", severity="high",
        file="tier1/{}/x/a".format(language), start_line=1, end_line=1,
        alt_locations=(), flow="inter-file", sanitizer="none", obfuscation="none",
        build_required=False,
    )


class AClaimIsCapabilityNotQuality(unittest.TestCase):
    """The rule that keeps this from becoming a way to flatter a tool.

    Excluding a language the product does not analyse is a fact. Excluding a
    CWE the product is bad at is marking its own homework, and the two look
    identical in a scorecard once the cases are gone.
    """

    def test_a_cwe_list_is_refused(self):
        path = write({**GOOD, "cwes": ["CWE-89"]})

        with self.assertRaises(claims.ClaimError) as caught:
            claims.load(path)

        self.assertIn("capability", str(caught.exception))

    def test_a_tier_list_is_refused(self):
        path = write({**GOOD, "tiers": [1]})

        with self.assertRaises(claims.ClaimError):
            claims.load(path)

    def test_a_severity_filter_is_refused(self):
        path = write({**GOOD, "severity": ["high"]})

        with self.assertRaises(claims.ClaimError):
            claims.load(path)

    def test_an_unknown_key_is_refused_rather_than_ignored(self):
        """Silently ignoring it would let a typo'd key mean nothing at all."""
        path = write({**GOOD, "langauges": ["python"]})

        with self.assertRaises(claims.ClaimError):
            claims.load(path)


class ClaimsMustBeWellFormed(unittest.TestCase):
    def test_a_source_is_required(self):
        path = write({k: v for k, v in GOOD.items() if k != "source"})

        with self.assertRaises(claims.ClaimError) as caught:
            claims.load(path)

        self.assertIn("source", str(caught.exception))

    def test_an_empty_language_list_is_refused(self):
        """It would exclude every case and report a flawless nothing."""
        path = write({**GOOD, "languages": []})

        with self.assertRaises(claims.ClaimError):
            claims.load(path)

    def test_malformed_json_is_refused(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write("{not json")
        handle.close()

        with self.assertRaises(claims.ClaimError):
            claims.load(handle.name)

    def test_a_good_claim_loads(self):
        loaded = claims.load(write(GOOD))

        self.assertEqual(loaded["languages"], ["java", "python"])
        self.assertEqual(loaded["planes"], ["vuln"])


class NoClaimScoresEverything(unittest.TestCase):
    """The default must stay what it has always been."""

    def test_partition_keeps_every_case(self):
        cases = [a_case(language="swift"), a_case(language="python")]

        scored, excluded = claims.partition(None, cases)

        self.assertEqual(len(scored), 2)
        self.assertEqual(excluded, [])

    def test_summarise_is_absent(self):
        self.assertIsNone(claims.summarise(None, []))


class PartitionExcludesOnlyWhatIsUnclaimed(unittest.TestCase):
    def setUp(self):
        self.claim = claims.load(write(GOOD))

    def test_an_unclaimed_language_is_excluded(self):
        scored, excluded = claims.partition(self.claim, [a_case(language="swift")])

        self.assertEqual(scored, [])
        self.assertEqual(len(excluded), 1)

    def test_an_unclaimed_plane_is_excluded(self):
        scored, excluded = claims.partition(self.claim, [a_case(plane="sca")])

        self.assertEqual(scored, [])
        self.assertEqual(len(excluded), 1)

    def test_a_claimed_pair_is_scored(self):
        scored, excluded = claims.partition(self.claim, [a_case()])

        self.assertEqual(len(scored), 1)
        self.assertEqual(excluded, [])


class TheSummaryAttributesTheReason(unittest.TestCase):
    """Reporting the language of every dropped case names languages the tool
    does analyse, which reads as a denominator narrowed behind a plane
    exclusion. SonarQube's claim covers java and drops the sca plane; saying
    "java excluded" would be false."""

    def setUp(self):
        self.claim = claims.load(write(GOOD))

    def test_a_case_dropped_for_its_plane_does_not_blame_its_language(self):
        _, excluded = claims.partition(self.claim, [a_case(language="java", plane="sca")])

        summary = claims.summarise(self.claim, excluded)

        self.assertEqual(summary["excluded_languages"], [])
        self.assertEqual(summary["excluded_planes"], ["sca"])

    def test_a_case_dropped_for_its_language_does_not_blame_its_plane(self):
        _, excluded = claims.partition(self.claim, [a_case(language="swift", plane="vuln")])

        summary = claims.summarise(self.claim, excluded)

        self.assertEqual(summary["excluded_languages"], ["swift"])
        self.assertEqual(summary["excluded_planes"], [])

    def test_the_source_is_carried_into_the_scorecard(self):
        summary = claims.summarise(self.claim, [])

        self.assertEqual(summary["source"], GOOD["source"])


class ExcludedCasesAreNotMisses(unittest.TestCase):
    def test_conservation_holds_with_the_excluded_cases_added_back(self):
        """tp + fp + fn + tn + n/a must still equal every case in the key."""
        everything = [a_case("c-00000001", "python"), a_case("c-00000002", "swift"),
                      a_case("c-00000003", "java", label="safe"),
                      a_case("c-00000004", "rust", label="safe")]
        claim = claims.load(write(GOOD))
        scored, excluded = claims.partition(claim, everything)

        report = match_findings([], scored, tolerance=10)
        card = scorecard(report, claim_summary=claims.summarise(claim, excluded),
                         not_applicable=len(excluded))
        counts = report.counts()

        total = counts["tp"] + counts["fp"] + counts["fn"] + counts["tn"] + card["not_applicable"]
        self.assertEqual(total, len(everything))

    def test_an_unsupported_language_is_not_a_false_negative(self):
        claim = claims.load(write(GOOD))
        scored, excluded = claims.partition(claim, [a_case(language="swift")])

        report = match_findings([], scored, tolerance=10)

        self.assertEqual(report.counts()["fn"], 0)
        self.assertEqual(len(excluded), 1)

    def test_the_narrative_reports_the_exclusion_rather_than_hiding_it(self):
        claim = claims.load(write(GOOD))
        scored, excluded = claims.partition(claim, [a_case(language="swift")])
        card = scorecard(match_findings([], scored, tolerance=10),
                         claim_summary=claims.summarise(claim, excluded),
                         not_applicable=len(excluded))

        self.assertEqual(card["narrative"]["not_applicable"], 1)
        self.assertEqual(card["capability_claim"]["tool"], "Acme")


class ShippedClaimFilesAreValid(unittest.TestCase):
    def test_every_claim_file_loads(self):
        directory = Path(__file__).resolve().parents[1] / "score" / "claims"
        files = sorted(directory.glob("*.json"))

        self.assertTrue(files, "no claim files found")
        for path in files:
            with self.subTest(claim=path.name):
                claims.load(path)


if __name__ == "__main__":
    unittest.main()
