import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from corpora.patcheval import (FALLBACK_TIMEOUT, FAST_FETCH_TIMEOUT, FETCH_DEPTH,
                               LANGUAGES, case_id, coerce_span,
                               fix_commit_of, is_recorded_commit, primary_cwe,
                               checkout_dir, render_case, usable_locations,
                               write_case)


class LineNumberTypes(unittest.TestCase):
    """6 of 296 locations record their line numbers as strings. Code that trusts
    the declared type crashes on 5 CVEs, and it crashes at the end of a long
    derivation rather than at the start."""

    def test_integers_pass_through(self):
        self.assertEqual(coerce_span({"start_line": 10, "end_line": 20}), (10, 20))

    def test_strings_are_coerced(self):
        self.assertEqual(coerce_span({"start_line": "10", "end_line": "20"}), (10, 20))

    def test_a_missing_bound_yields_nothing(self):
        self.assertIsNone(coerce_span({"start_line": 10}))

    def test_an_unparseable_bound_yields_nothing(self):
        self.assertIsNone(coerce_span({"start_line": "n/a", "end_line": "20"}))

    def test_a_reversed_span_is_rejected(self):
        self.assertIsNone(coerce_span({"start_line": 20, "end_line": 10}))


class WeaknessSelection(unittest.TestCase):
    def test_the_single_cwe_is_chosen(self):
        self.assertEqual(primary_cwe({"CWE-89": {"name": "SQL injection"}}), "CWE-89")

    def test_a_reachable_weakness_is_preferred_over_a_category(self):
        # CWE-284 is a class, CWE-22 is the thing a scanner can actually match.
        got = primary_cwe({"CWE-284": {"name": "improper access control"},
                           "CWE-22": {"name": "path traversal"}})

        self.assertEqual(got, "CWE-22")

    def test_no_weakness_yields_nothing(self):
        self.assertIsNone(primary_cwe({}))

    def test_an_nvd_placeholder_is_not_a_weakness(self):
        self.assertIsNone(primary_cwe({"NVD-CWE-noinfo": {"name": "insufficient info"}}))


class UsableLocations(unittest.TestCase):
    """A location is usable only if the snippet is actually at the recorded
    lines in the buggy checkout. Anything else points the answer key at code
    that is not the flaw."""

    def test_a_matching_location_is_kept(self):
        source = "a\nb\ntarget line\nd\n"
        locations = [{"file_path": "x.py", "start_line": 3, "end_line": 3,
                      "snippet": "target line"}]

        got = usable_locations(locations, {"x.py": source})

        self.assertEqual(len(got), 1)

    def test_a_mismatching_location_is_dropped(self):
        source = "a\nb\nsomething else\nd\n"
        locations = [{"file_path": "x.py", "start_line": 3, "end_line": 3,
                      "snippet": "target line"}]

        self.assertEqual(usable_locations(locations, {"x.py": source}), [])

    def test_an_absent_file_is_dropped(self):
        locations = [{"file_path": "gone.py", "start_line": 1, "end_line": 1,
                      "snippet": "x"}]

        self.assertEqual(usable_locations(locations, {}), [])

    def test_whitespace_differences_do_not_break_a_match(self):
        source = "a\n   target line   \nc\n"
        locations = [{"file_path": "x.py", "start_line": 2, "end_line": 2,
                      "snippet": "target line"}]

        self.assertEqual(len(usable_locations(locations, {"x.py": source})), 1)

    def test_a_leading_dot_slash_path_is_normalised(self):
        source = "a\ntarget\n"
        locations = [{"file_path": "./x.py", "start_line": 2, "end_line": 2,
                      "snippet": "target"}]

        self.assertEqual(len(usable_locations(locations, {"x.py": source})), 1)


class CaseIdentity(unittest.TestCase):
    def test_the_same_cve_and_path_give_the_same_id(self):
        self.assertEqual(case_id("CVE-2021-1", "a/b.py"), case_id("CVE-2021-1", "a/b.py"))

    def test_a_different_cve_gives_a_different_id(self):
        self.assertNotEqual(case_id("CVE-2021-1", "a.py"), case_id("CVE-2021-2", "a.py"))

    def test_the_id_has_the_corpus_shape(self):
        self.assertRegex(case_id("CVE-2021-1", "a.py"), r"^c-[0-9a-f]{8}$")


class Rendering(unittest.TestCase):
    def setUp(self):
        self.candidate = {
            "cve": "CVE-2021-23376", "repo": "https://github.com/o/r",
            "commit": "b7395da", "language": "javascript", "cwe": "CWE-78",
            "acceptable_cwes": ["CWE-78", "CWE-77"],
            "file": "tier3/patcheval/o__r/index.js",
            "start_line": 216, "end_line": 233, "alt_locations": [],
        }

    def test_it_is_tier_three(self):
        self.assertIn("tier: 3", render_case(self.candidate))

    def test_provenance_is_recorded_as_cve(self):
        self.assertIn("source: cve", render_case(self.candidate))

    def test_difficulty_is_unknown_rather_than_guessed(self):
        # The taint path is not knowable from the dataset, and a guess would be
        # indistinguishable from a measurement in the difficulty breakdown.
        text = render_case(self.candidate)

        self.assertIn("flow: unknown", text)
        self.assertIn("sanitizer: unknown", text)

    def test_the_buggy_commit_is_named(self):
        self.assertIn("b7395da", render_case(self.candidate))

    def test_no_build_is_required(self):
        # Go, JavaScript and Python are scanned from source.
        self.assertIn("required: false", render_case(self.candidate))

    def test_the_languages_are_the_three_patcheval_covers(self):
        self.assertEqual(set(LANGUAGES.values()), {"go", "javascript", "python"})



class FastPathAndFallback(unittest.TestCase):
    """The recorded commit is abbreviated and cannot be fetched directly, which
    is why the first version cloned whole histories. The fix commit URL carries
    a complete SHA, and for 225 of 230 entries the recorded commit is simply its
    parent — so a two-deep fetch reaches it. The other 5 still need the slow
    path, and telling them apart is a prefix comparison."""

    def test_a_parent_matching_the_recorded_prefix_is_the_fast_path(self):
        self.assertTrue(is_recorded_commit("b7395da1c2e3f4a5b6c7d8e9f0", "b7395da"))

    def test_a_different_parent_is_not(self):
        self.assertFalse(is_recorded_commit("aaaaaaa1c2e3f4a5", "b7395da"))

    def test_a_full_sha_matches_itself(self):
        sha = "b7395da1c2e3f4a5b6c7d8e9f011223344556677"
        self.assertTrue(is_recorded_commit(sha, sha))

    def test_an_empty_parent_never_matches(self):
        self.assertFalse(is_recorded_commit("", "b7395da"))

    def test_an_empty_record_never_matches(self):
        # Nothing to compare against is not a match.
        self.assertFalse(is_recorded_commit("b7395da1c2e3", ""))

    def test_the_fetch_depth_reaches_the_parent(self):
        self.assertGreaterEqual(FETCH_DEPTH, 2)


class FixCommitExtraction(unittest.TestCase):
    def test_reads_the_sha_from_a_patch_url(self):
        entry = {"patch_url": ["https://github.com/o/r/commit/" + "a" * 40]}

        self.assertEqual(fix_commit_of(entry), "a" * 40)

    def test_no_patch_url_yields_nothing(self):
        self.assertIsNone(fix_commit_of({}))


class ProgressIsNotLostOnInterruption(unittest.TestCase):
    """Deriving 230 CVEs means cloning 230 repositories, which takes hours. The
    first version collected every candidate and wrote them all at the end, so an
    interrupted run — a timeout, a killed process, a full disk — produced
    nothing at all despite hours of work.

    Each case is written as it is derived."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_a_candidate_is_written_immediately(self):
        candidate = {"cve": "CVE-2021-1", "repo": "https://github.com/o/r",
                     "commit": "abc1234", "language": "python", "cwe": "CWE-89",
                     "acceptable_cwes": ["CWE-89"], "file": "tier3/patcheval/o__r/a.py",
                     "start_line": 1, "end_line": 2, "alt_locations": []}

        written = write_case(candidate, self.root)

        self.assertTrue(written.is_file())
        self.assertIn("CVE-2021-1", written.read_text())

    def test_writing_twice_is_stable(self):
        candidate = {"cve": "CVE-2021-1", "repo": "https://github.com/o/r",
                     "commit": "abc1234", "language": "python", "cwe": "CWE-89",
                     "acceptable_cwes": ["CWE-89"], "file": "tier3/patcheval/o__r/a.py",
                     "start_line": 1, "end_line": 2, "alt_locations": []}

        first = write_case(candidate, self.root)
        second = write_case(candidate, self.root)

        self.assertEqual(first, second)


class OneCheckoutPerCommit(unittest.TestCase):
    """A repository can hold several CVEs at different commits — django has 12 —
    and they cannot share a working tree. Keying the checkout by repository
    alone means each derivation moves the tree away from the previous one, so
    every case but the last points at line numbers in a tree that has since
    changed. Two such cases reached the answer key before this was caught, both
    referencing lines past the end of their file."""

    def test_the_commit_is_part_of_the_directory(self):
        first = checkout_dir("django__django", "aaaaaaaaaaaa")
        second = checkout_dir("django__django", "bbbbbbbbbbbb")

        self.assertNotEqual(first, second)

    def test_the_same_commit_gives_the_same_directory(self):
        self.assertEqual(checkout_dir("o__r", "abc1234"), checkout_dir("o__r", "abc1234"))

    def test_the_repository_is_still_identifiable(self):
        self.assertIn("django__django", checkout_dir("django__django", "abc1234"))

    def test_the_directory_is_filesystem_safe(self):
        directory = checkout_dir("o__r", "abc1234")

        self.assertNotIn("/", directory)
        self.assertRegex(directory, r"^[A-Za-z0-9_.@-]+$")


class FastPathFailsFast(unittest.TestCase):
    """The fast path is an optimisation, so it has to give up quickly.

    Fetching a specific SHA works only when the server will serve it, and where
    it will not the negotiation hangs rather than refusing — with the same
    timeout as the fallback, each such repository cost fifteen minutes and the
    run crawled. The fallback is the slow path by definition and keeps a long
    timeout; the shortcut gets a short one."""

    def test_the_shortcut_gives_up_sooner_than_the_fallback(self):
        self.assertLess(FAST_FETCH_TIMEOUT, FALLBACK_TIMEOUT)

    def test_the_shortcut_timeout_is_measured_in_a_couple_of_minutes(self):
        self.assertLessEqual(FAST_FETCH_TIMEOUT, 180)

    def test_the_fallback_still_has_room_for_a_large_repository(self):
        self.assertGreaterEqual(FALLBACK_TIMEOUT, 900)

if __name__ == "__main__":
    unittest.main()
