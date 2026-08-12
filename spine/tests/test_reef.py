import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from corpora.reef import (ALWAYS_SKIP, FETCH_DEPTH, MAX_REPO_MB,
                          is_permitted_repo, is_unambiguous, parse_pre_fix_span,
                          path_from_raw_url, within_size_cap)


class HunkHeaders(unittest.TestCase):
    """The vulnerable line range comes from the `-` side of the hunk header —
    the file as it was BEFORE the fix, which is the checkout being scanned. The
    `+` side describes the fixed file and would point at the wrong lines."""

    def test_reads_the_pre_fix_range(self):
        self.assertEqual(parse_pre_fix_span("@@ -380,9 +380,10 @@ def f():"), (380, 388))

    def test_a_single_line_hunk_omits_the_length(self):
        self.assertEqual(parse_pre_fix_span("@@ -42 +42,3 @@"), (42, 42))

    def test_it_does_not_read_the_post_fix_side(self):
        # The two sides differ whenever the fix changes the line count.
        start, end = parse_pre_fix_span("@@ -100,2 +200,40 @@")

        self.assertEqual((start, end), (100, 101))

    def test_a_zero_length_hunk_is_a_pure_insertion(self):
        # Nothing existed there before the fix, so there is nothing to point at.
        self.assertIsNone(parse_pre_fix_span("@@ -0,0 +1,20 @@"))

    def test_a_line_that_is_not_a_header_yields_nothing(self):
        self.assertIsNone(parse_pre_fix_span("     context line"))


class Unambiguity(unittest.TestCase):
    """REEF records which commit fixed a CVE and not which file or hunk held the
    flaw. Where a fix touches one file with one hunk there is nothing to guess;
    anywhere else, automatic derivation would produce a confident wrong answer,
    which is worse than no case."""

    def test_one_file_one_hunk_is_derivable(self):
        entry = {"details": [{"patch": "@@ -1,2 +1,3 @@\n line\n"}]}

        self.assertTrue(is_unambiguous(entry))

    def test_two_files_is_not(self):
        entry = {"details": [{"patch": "@@ -1,2 +1,3 @@\n"},
                             {"patch": "@@ -5,2 +5,3 @@\n"}]}

        self.assertFalse(is_unambiguous(entry))

    def test_two_hunks_in_one_file_is_not(self):
        entry = {"details": [{"patch": "@@ -1,2 +1,3 @@\n x\n@@ -9,2 +9,3 @@\n y\n"}]}

        self.assertFalse(is_unambiguous(entry))

    def test_no_details_is_not(self):
        self.assertFalse(is_unambiguous({"details": []}))


class RawUrls(unittest.TestCase):
    def test_extracts_the_repository_relative_path(self):
        url = "https://github.com/o/r/raw/abc123/src/lib/ec_glob.c"

        self.assertEqual(path_from_raw_url(url, "abc123"), "src/lib/ec_glob.c")

    def test_decodes_percent_encoded_separators(self):
        url = "https://github.com/o/r/raw/abc123/psiturk%2Fexperiment.py"

        self.assertEqual(path_from_raw_url(url, "abc123"), "psiturk/experiment.py")

    def test_an_unrelated_url_yields_nothing(self):
        self.assertIsNone(path_from_raw_url("https://example.com/x", "abc123"))


class RepositorySize(unittest.TestCase):
    def test_there_is_a_cap(self):
        # torvalds/linux is in this dataset and is not a scan target anyone
        # wants in a corpus; a cap keeps the tier usable.
        self.assertTrue(MAX_REPO_MB > 0)


if __name__ == "__main__":
    unittest.main()


class SizeCapIsEnforced(unittest.TestCase):
    """MAX_REPO_MB was declared and never consulted — a cap that exists only as a
    constant is documentation, not a limit. The first run spent minutes fetching
    blobs for a repository it should never have started on."""

    def test_a_small_repository_is_allowed(self):
        self.assertTrue(within_size_cap({"size": 20_000}))       # 20 MB

    def test_a_large_repository_is_rejected(self):
        self.assertFalse(within_size_cap({"size": 4_000_000}))   # ~4 GB

    def test_the_boundary_is_the_cap(self):
        self.assertFalse(within_size_cap({"size": (MAX_REPO_MB + 1) * 1024}))
        self.assertTrue(within_size_cap({"size": MAX_REPO_MB * 1024}))

    def test_an_unknown_size_is_allowed_rather_than_guessed(self):
        # Silence from the API is not evidence that a repository is huge, and
        # refusing on it would drop cases for a reason unrelated to them.
        self.assertTrue(within_size_cap(None))
        self.assertTrue(within_size_cap({}))
        self.assertTrue(within_size_cap({"size": None}))


class FetchStrategy(unittest.TestCase):
    """A blobless clone followed by a full checkout fetches every blob in the
    tree in batches, which is the slowest possible way to obtain a large
    repository. REEF's fix commit SHA is complete, so its parent is two commits
    deep and a shallow fetch reaches it directly."""

    def test_the_fetch_depth_reaches_the_parent(self):
        self.assertGreaterEqual(FETCH_DEPTH, 2)


class SizeCapSurvivesRateLimiting(unittest.TestCase):
    """The API allows 60 unauthenticated requests an hour and a run asks for one
    per repository, so the limit is reached partway through and every later
    check returns nothing. Treating that as "allowed" turned the cap off exactly
    when it was still needed — chromium/chromium was admitted that way.

    A static denylist is the part that cannot be rate-limited."""

    def test_a_known_giant_is_refused_without_asking(self):
        self.assertFalse(is_permitted_repo("https://github.com/chromium/chromium"))

    def test_the_kernel_is_refused(self):
        self.assertFalse(is_permitted_repo("https://github.com/torvalds/linux"))

    def test_an_ordinary_repository_is_allowed(self):
        self.assertTrue(is_permitted_repo("https://github.com/protobuf-c/protobuf-c"))

    def test_matching_is_on_the_full_owner_and_name(self):
        # A project merely named after one of them is not one of them.
        self.assertTrue(is_permitted_repo("https://github.com/someone/linux-utils"))

    def test_the_denylist_names_why_each_entry_is_there(self):
        for repo, reason in ALWAYS_SKIP.items():
            self.assertTrue(reason, f"{repo} is refused with no reason recorded")


class SharedGuardCoversBothDerivations(unittest.TestCase):
    """Both derivations clone real projects and both hit the same monorepos, so
    the list lives in one place rather than being maintained twice. PatchEval
    stalled on a multi-gigabyte machine-learning tree that REEF's list would
    already have refused."""

    def test_patcheval_uses_the_same_list(self):
        from corpora.repos import worth_fetching

        self.assertFalse(worth_fetching("https://github.com/FederatedAI/FATE",
                                        ask_api=False))

    def test_an_ordinary_repository_passes_without_asking(self):
        from corpora.repos import worth_fetching

        self.assertTrue(worth_fetching("https://github.com/gogs/gogs", ask_api=False))
