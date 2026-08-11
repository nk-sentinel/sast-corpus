import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schema.compile_answers import (
    duplicate_id_errors,
    file_errors,
    semantic_errors,
    to_csv_row,
)


def a_case(**overrides):
    """A minimal valid case; override single fields per test."""
    case = {
        "id": "c-a7f3e91b",
        "label": "vulnerable",
        "plane": "vuln",
        "tier": 1,
        "language": "java",
        "framework": "spring-mvc",
        "primary_cwe": "CWE-89",
        "acceptable_cwes": ["CWE-89", "CWE-943"],
        "owasp_2021": "A03",
        "severity": "high",
        "location": {
            "file": "tier1/java/a7f3e91b/OrderRepository.java",
            "start_line": 42,
            "end_line": 47,
        },
        "alt_locations": [
            {
                "file": "tier1/java/a7f3e91b/OrderController.java",
                "start_line": 18,
                "end_line": 18,
            }
        ],
        "difficulty": {
            "flow": "inter-file",
            "sanitizer": "none",
            "obfuscation": "aliasing",
        },
        "evidence": {
            "source": "hand-authored",
            "rationale": "path variable reaches Statement.execute() unsanitized",
            "cve": None,
        },
        "build": {"required": True, "recipe": "build/java/maven-offline.sh"},
    }
    case.update(overrides)
    return case


class ToCsvRow(unittest.TestCase):
    def test_flattens_location_into_separate_columns(self):
        row = to_csv_row(a_case())

        self.assertEqual(row["file"], "tier1/java/a7f3e91b/OrderRepository.java")
        self.assertEqual(row["start_line"], 42)
        self.assertEqual(row["end_line"], 47)

    def test_joins_acceptable_cwes_with_semicolons(self):
        row = to_csv_row(a_case(acceptable_cwes=["CWE-89", "CWE-943", "CWE-564"]))

        self.assertEqual(row["acceptable_cwes"], "CWE-89;CWE-943;CWE-564")

    def test_encodes_alt_locations_as_file_start_end_triples(self):
        row = to_csv_row(a_case())

        self.assertEqual(
            row["alt_locations"], "tier1/java/a7f3e91b/OrderController.java:18:18"
        )

    def test_empty_alt_locations_becomes_empty_string(self):
        row = to_csv_row(a_case(alt_locations=[]))

        self.assertEqual(row["alt_locations"], "")

    def test_flattens_difficulty_into_separate_columns(self):
        row = to_csv_row(a_case())

        self.assertEqual(row["flow"], "inter-file")
        self.assertEqual(row["sanitizer"], "none")
        self.assertEqual(row["obfuscation"], "aliasing")

    def test_omits_the_rationale_so_the_answer_key_carries_no_prose_hints(self):
        row = to_csv_row(a_case())

        self.assertNotIn("rationale", row)


class SemanticErrors(unittest.TestCase):
    """Cross-field rules JSON Schema cannot express. These are the checks that
    stop the answer key rotting silently as fixtures move."""

    def test_accepts_a_well_formed_case(self):
        self.assertEqual(semantic_errors(a_case()), [])

    def test_rejects_primary_cwe_missing_from_acceptable_cwes(self):
        case = a_case(primary_cwe="CWE-89", acceptable_cwes=["CWE-79"])

        errors = semantic_errors(case)

        self.assertEqual(len(errors), 1)
        self.assertIn("CWE-89", errors[0])
        self.assertIn("acceptable_cwes", errors[0])

    def test_rejects_start_line_after_end_line(self):
        case = a_case(
            location={"file": "tier1/java/x/A.java", "start_line": 50, "end_line": 42}
        )

        errors = semantic_errors(case)

        self.assertEqual(len(errors), 1)
        self.assertIn("start_line", errors[0])

    def test_rejects_inverted_line_range_in_alt_locations(self):
        case = a_case(
            alt_locations=[
                {"file": "tier1/java/x/B.java", "start_line": 9, "end_line": 4}
            ]
        )

        errors = semantic_errors(case)

        self.assertEqual(len(errors), 1)
        self.assertIn("alt_locations", errors[0])

    def test_rejects_a_safe_case_that_claims_a_cve(self):
        """A CVE is proof the code was vulnerable, so it cannot label a trap."""
        case = a_case(
            label="safe",
            evidence={
                "source": "cve",
                "rationale": "ORM parameterizes this query automatically",
                "cve": "CVE-2021-44228",
            },
        )

        errors = semantic_errors(case)

        self.assertEqual(len(errors), 1)
        self.assertIn("cve", errors[0].lower())

    def test_rejects_tier_1_case_pointing_outside_tier1(self):
        case = a_case(
            tier=1,
            location={"file": "tier2/webgoat/A.java", "start_line": 1, "end_line": 2},
        )

        errors = semantic_errors(case)

        self.assertEqual(len(errors), 1)
        self.assertIn("tier", errors[0])

    def test_reports_every_problem_not_just_the_first(self):
        case = a_case(
            primary_cwe="CWE-89",
            acceptable_cwes=["CWE-79"],
            location={"file": "tier1/java/x/A.java", "start_line": 50, "end_line": 42},
        )

        self.assertEqual(len(semantic_errors(case)), 2)


class FileErrors(unittest.TestCase):
    """Answer keys rot silently when fixtures move. These checks make that loud."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        fixture = self.root / "tier1" / "java" / "a7f3e91b"
        fixture.mkdir(parents=True)
        (fixture / "OrderRepository.java").write_text("\n".join(f"line {n}" for n in range(1, 61)))
        (fixture / "OrderController.java").write_text("\n".join(f"line {n}" for n in range(1, 31)))

    def test_accepts_a_case_whose_lines_are_all_in_range(self):
        self.assertEqual(file_errors(a_case(), self.root), [])

    def test_reports_a_referenced_file_that_does_not_exist(self):
        case = a_case(
            location={"file": "tier1/java/a7f3e91b/Gone.java", "start_line": 1, "end_line": 2},
            alt_locations=[],
        )

        errors = file_errors(case, self.root)

        self.assertEqual(len(errors), 1)
        self.assertIn("Gone.java", errors[0])

    def test_reports_a_line_past_the_end_of_the_file(self):
        case = a_case(
            location={
                "file": "tier1/java/a7f3e91b/OrderRepository.java",
                "start_line": 59,
                "end_line": 900,
            },
            alt_locations=[],
        )

        errors = file_errors(case, self.root)

        self.assertEqual(len(errors), 1)
        self.assertIn("900", errors[0])

    def test_checks_alt_locations_too(self):
        case = a_case(
            alt_locations=[
                {"file": "tier1/java/a7f3e91b/OrderController.java", "start_line": 1, "end_line": 400}
            ]
        )

        self.assertEqual(len(file_errors(case, self.root)), 1)


class DuplicateIdErrors(unittest.TestCase):
    def test_accepts_distinct_ids(self):
        cases = [a_case(id="c-aaaaaaaa"), a_case(id="c-bbbbbbbb")]

        self.assertEqual(duplicate_id_errors(cases), [])

    def test_reports_a_reused_id(self):
        """Two cases sharing an id means one of them can never be scored."""
        cases = [a_case(id="c-aaaaaaaa"), a_case(id="c-aaaaaaaa")]

        errors = duplicate_id_errors(cases)

        self.assertEqual(len(errors), 1)
        self.assertIn("c-aaaaaaaa", errors[0])


if __name__ == "__main__":
    unittest.main()


class ExternalTierFilesMayBeAbsent(unittest.TestCase):
    """Tier 2 and tier 3 point into checkouts that are fetched on demand and
    never committed. Their absence means "not fetched", not "the answer key is
    broken" — but a tier-1 fixture is committed, so its absence really is."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)

    def test_a_missing_tier1_fixture_is_still_an_error(self):
        case = a_case(tier=1, location={"file": "tier1/java/x/Gone.java",
                                        "start_line": 1, "end_line": 2},
                      alt_locations=[])

        self.assertEqual(len(file_errors(case, self.root)), 1)

    def test_a_missing_tier3_checkout_is_not_an_error(self):
        case = a_case(tier=3, location={"file": "tier3/project-sources/p/A.java",
                                        "start_line": 1, "end_line": 2},
                      alt_locations=[])

        self.assertEqual(file_errors(case, self.root), [])

    def test_a_missing_tier2_checkout_is_not_an_error(self):
        case = a_case(tier=2, location={"file": "tier2/webgoat/A.java",
                                        "start_line": 1, "end_line": 2},
                      alt_locations=[])

        self.assertEqual(file_errors(case, self.root), [])

    def test_a_fetched_tier3_file_is_still_range_checked(self):
        """Absence is excused; being wrong is not."""
        path = self.root / "tier3" / "project-sources" / "p"
        path.mkdir(parents=True)
        (path / "A.java").write_text("one\ntwo\n")
        case = a_case(tier=3, location={"file": "tier3/project-sources/p/A.java",
                                        "start_line": 1, "end_line": 900},
                      alt_locations=[])

        errors = file_errors(case, self.root)

        self.assertEqual(len(errors), 1)
        self.assertIn("900", errors[0])


class VariantColumn(unittest.TestCase):
    """One case per CWE proves a tool knows the class exists. Variants are where
    tools separate: a matcher keyed on 'uses PreparedStatement' scores a
    concatenated-then-prepared query as safe."""

    def test_the_variant_reaches_the_answer_key(self):
        row = to_csv_row(a_case(variant="prepared-but-concatenated"))

        self.assertEqual(row["variant"], "prepared-but-concatenated")

    def test_a_case_without_a_variant_yields_an_empty_cell(self):
        self.assertEqual(to_csv_row(a_case())["variant"], "")

    def test_two_cases_may_share_a_cwe_and_differ_only_by_variant(self):
        a = to_csv_row(a_case(id="c-aaaaaaaa", variant="concat-statement"))
        b = to_csv_row(a_case(id="c-bbbbbbbb", variant="dynamic-identifier"))

        self.assertEqual(a["primary_cwe"], b["primary_cwe"])
        self.assertNotEqual(a["variant"], b["variant"])
