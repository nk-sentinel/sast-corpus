import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from export.verify import (GateResult, Integrity, exit_code, find_sum_files,
                           ground_truth_exposed, parse_sha256sums, render,
                           verify_checksums)


class VerifyCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, rel, text="x"):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path


class ParsingSha256Sums(unittest.TestCase):
    """`sha256sum` separates the digest from the path with TWO spaces, and the
    path may itself contain spaces. Splitting on whitespace truncates any path
    with a space in it and reports a file that exists as missing."""

    def test_reads_a_plain_line(self):
        got = parse_sha256sums("a" * 64 + "  tier1/java/A.java\n")

        self.assertEqual(got, {"tier1/java/A.java": "a" * 64})

    def test_a_path_containing_spaces_survives(self):
        got = parse_sha256sums("b" * 64 + "  tier3/some project/A.java\n")

        self.assertEqual(list(got), ["tier3/some project/A.java"])

    def test_binary_mode_marker_is_stripped(self):
        # GNU sha256sum writes ` *path` when the file was read in binary mode.
        got = parse_sha256sums("c" * 64 + " *tier1/a.bin\n")

        self.assertEqual(list(got), ["tier1/a.bin"])

    def test_blank_lines_are_ignored(self):
        self.assertEqual(parse_sha256sums("\n\n"), {})

    def test_a_malformed_line_is_not_silently_dropped(self):
        with self.assertRaises(ValueError):
            parse_sha256sums("not-a-checksum-line\n")


class ChecksumVerification(VerifyCase):
    def test_matching_files_produce_no_findings(self):
        self.write("tier1/a.java", "content")
        sums = parse_sha256sums(_sums(self.root, "tier1/a.java"))

        result = verify_checksums(self.root, sums)

        self.assertEqual((result.missing, result.modified), ([], []))
        self.assertEqual(result.checked, 1)

    def test_a_modified_file_is_reported(self):
        path = self.write("tier1/a.java", "before")
        sums = parse_sha256sums(_sums(self.root, "tier1/a.java"))
        path.write_text("after")

        self.assertEqual(verify_checksums(self.root, sums).modified, ["tier1/a.java"])

    def test_a_missing_file_is_reported(self):
        self.write("tier1/a.java")
        sums = parse_sha256sums(_sums(self.root, "tier1/a.java"))
        (self.root / "tier1/a.java").unlink()

        self.assertEqual(verify_checksums(self.root, sums).missing, ["tier1/a.java"])

    def test_an_unlisted_file_under_a_covered_root_is_reported(self):
        # Extracting the answers archive over the corpus archive would show up
        # here, and it is the one mistake that quietly ruins a scan.
        self.write("tier1/a.java")
        sums = parse_sha256sums(_sums(self.root, "tier1/a.java"))
        self.write("tier1/unexpected.java")

        self.assertEqual(verify_checksums(self.root, sums).unlisted, ["tier1/unexpected.java"])

    def test_files_outside_the_covered_roots_are_not_reported(self):
        # A scan output or a report written next to the corpus is not corruption.
        self.write("tier1/a.java")
        sums = parse_sha256sums(_sums(self.root, "tier1/a.java"))
        self.write("results/scan.sarif")

        self.assertEqual(verify_checksums(self.root, sums).unlisted, [])


class GroundTruthSittingInTheScanTarget(VerifyCase):
    """The one mistake that quietly ruins a bake-off: extracting the answers
    archive over the scannable tree. The scanner then reads every CWE
    identifier and rationale, and an LLM-based tool scores on the answers.

    The generic unlisted-file walk cannot catch it — that walk only inspects
    roots the checksum list already covers, and a corpus list has no `answers/`
    entries at all, so the directory is never looked at. It needs its own check
    because it is a specific, named, high-consequence error rather than a stray
    file."""

    def test_answers_beside_a_corpus_list_is_reported(self):
        sums = {"tier1/a.java": "0" * 64}
        self.write("tier1/a.java")
        self.write("answers/cases/c-0000aaaa.yml", "primary_cwe: CWE-89\n")

        self.assertTrue(ground_truth_exposed(self.root, sums))

    def test_the_answer_key_csv_counts_too(self):
        sums = {"tier1/a.java": "0" * 64}
        self.write("answers/expectedresults-1.0.csv", "id,label\n")

        self.assertTrue(ground_truth_exposed(self.root, sums))

    def test_no_answers_directory_is_fine(self):
        self.write("tier1/a.java")

        self.assertFalse(ground_truth_exposed(self.root, {"tier1/a.java": "0" * 64}))

    def test_verifying_the_answers_archive_itself_is_fine(self):
        # Here the answer key is exactly what is being checked, not a leak.
        self.write("answers/expectedresults-1.0.csv", "id,label\n")
        sums = {"answers/expectedresults-1.0.csv": "0" * 64}

        self.assertFalse(ground_truth_exposed(self.root, sums))

    def test_it_fails_the_run(self):
        integrity = Integrity(checked=1, exposed_ground_truth=["answers/cases"])

        self.assertNotEqual(exit_code(integrity, []), 0)

    def test_the_report_names_the_hazard(self):
        text = render(Integrity(checked=1, exposed_ground_truth=["answers/cases"]),
                      [], profile="scoring", version="1.0")

        self.assertIn("answers", text)
        self.assertIn("ground truth", text.lower())


class FindingChecksumLists(VerifyCase):
    """Each archive ships its own list, and the far side may have extracted only
    one of them. Verification runs against whichever are present rather than
    demanding both."""

    def test_finds_every_per_archive_list(self):
        self.write("SHA256SUMS.corpus")
        self.write("SHA256SUMS.answers")

        self.assertEqual([p.name for p in find_sum_files(self.root)],
                         ["SHA256SUMS.answers", "SHA256SUMS.corpus"])

    def test_a_single_extracted_archive_is_enough(self):
        self.write("SHA256SUMS.corpus")

        self.assertEqual([p.name for p in find_sum_files(self.root)],
                         ["SHA256SUMS.corpus"])

    def test_an_older_combined_list_is_still_accepted(self):
        self.write("SHA256SUMS")

        self.assertEqual([p.name for p in find_sum_files(self.root)], ["SHA256SUMS"])

    def test_nothing_to_verify_against_is_reported_not_assumed_fine(self):
        self.assertEqual(find_sum_files(self.root), [])


class ExitCode(unittest.TestCase):
    """A verification that cannot fail is decoration."""

    def test_clean_run_succeeds(self):
        integrity = Integrity(checked=10)

        self.assertEqual(exit_code(integrity, [GateResult("gate", "pass", "")]), 0)

    def test_a_modified_file_fails(self):
        integrity = Integrity(checked=10, modified=["tier1/a.java"])

        self.assertNotEqual(exit_code(integrity, []), 0)

    def test_a_missing_file_fails(self):
        self.assertNotEqual(exit_code(Integrity(checked=1, missing=["a"]), []), 0)

    def test_a_failed_gate_fails(self):
        result = [GateResult("anti-leak", "fail", "3 leaks")]

        self.assertNotEqual(exit_code(Integrity(checked=1), result), 0)

    def test_a_gate_that_could_not_run_does_not_pass_silently(self):
        # "We could not check" must not be reported as "we checked and it was
        # fine" — the rule the syntax gate already follows for absent toolchains.
        result = [GateResult("unit tests", "skipped", "python3 absent")]

        self.assertNotEqual(exit_code(Integrity(checked=1), result), 0)

    def test_an_unlisted_file_alone_does_not_fail(self):
        # Worth reporting, not worth refusing to score over.
        self.assertEqual(exit_code(Integrity(checked=1, unlisted=["x"]), []), 0)


class Reporting(unittest.TestCase):
    def test_states_what_was_checked(self):
        text = render(Integrity(checked=120110), [], profile="scoring", version="1.0")

        self.assertIn("120110", text)

    def test_a_skipped_gate_is_visibly_not_a_pass(self):
        text = render(Integrity(checked=1),
                      [GateResult("syntax", "skipped", "no toolchain")],
                      profile="scoring", version="1.0")

        self.assertIn("skipped", text.lower())
        self.assertIn("no toolchain", text)

    def test_failures_are_named(self):
        text = render(Integrity(checked=1, modified=["tier1/a.java"]), [],
                      profile="scoring", version="1.0")

        self.assertIn("tier1/a.java", text)

    def test_a_clean_run_says_so_without_hedging(self):
        text = render(Integrity(checked=5), [GateResult("g", "pass", "")],
                      profile="scoring", version="1.0")

        self.assertIn("same corpus", text.lower())


def _sums(root, *relatives):
    import hashlib
    lines = []
    for relative in relatives:
        digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        lines.append(f"{digest}  {relative}\n")
    return "".join(lines)


if __name__ == "__main__":
    unittest.main()
