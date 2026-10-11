import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from validate import corpus_unchanged

GUARD = Path(__file__).resolve().parents[1] / "validate" / "corpus_unchanged.py"


def run(*args):
    done = subprocess.run([sys.executable, str(GUARD), *args],
                          capture_output=True, text=True, check=False)
    return done.returncode, done.stdout + done.stderr


class ConfinesItsArguments(unittest.TestCase):
    """The target reaches a filesystem walk and a snapshot filename."""

    def test_a_path_outside_the_repository_is_refused(self):
        code, out = run("/etc")

        self.assertEqual(code, 1)
        self.assertIn("not a path inside the repository", out)

    def test_traversal_out_of_the_repository_is_refused(self):
        code, _ = run("../../../../etc")

        self.assertEqual(code, 1)

    def test_resolve_returns_none_for_an_escape(self):
        self.assertIsNone(corpus_unchanged.resolve("../.."))
        self.assertIsNotNone(corpus_unchanged.resolve("tier1"))


class TierOneIsWitnessedByGit(unittest.TestCase):
    def test_a_committed_tree_needs_no_snapshot(self):
        """tier1 has thousands of tracked files, so git is the authority."""
        code, out = run("tier1")

        self.assertEqual(code, 0, out)
        self.assertIn("corpus unchanged", out)


class UntrackedTiersRequireASnapshot(unittest.TestCase):
    """The defect this file exists for.

    `/tier2/*/` and `/tier3/*/` are gitignored, so git sees 3 files out of
    thousands. The first version of this guard used git alone and printed
    "corpus unchanged: tier2 tier3" — a pass it had no evidence for. A gate that
    cannot tell "we did not check" from "we checked and it was fine" is worse
    than no gate, because someone will trust it.
    """

    def test_git_really_does_see_almost_nothing_there(self):
        if not (corpus_unchanged.ROOT / "tier2").is_dir():
            self.skipTest("tier2 is not fetched")

        self.assertLess(corpus_unchanged.tracked_count("tier2"),
                        corpus_unchanged.TRACKED_ENOUGH)

    def test_verifying_without_a_snapshot_fails(self):
        if not (corpus_unchanged.ROOT / "tier2").is_dir():
            self.skipTest("tier2 is not fetched")
        stored = corpus_unchanged.snapshot_path("tier2")
        saved = stored.read_text() if stored.is_file() else None
        if saved is not None:
            stored.unlink()
        try:
            code, out = run("tier2")
        finally:
            if saved is not None:
                stored.write_text(saved)

        self.assertEqual(code, 1)
        self.assertIn("NOT VERIFIABLE", out)


class ManifestDetectsWhatGitCannot(unittest.TestCase):
    def setUp(self):
        self.tree = corpus_unchanged.ROOT / "build-out" / "guard-test"
        self.tree.mkdir(parents=True, exist_ok=True)
        (self.tree / "kept.txt").write_text("a")
        self.target = "build-out/guard-test"
        self.addCleanup(self._clean)
        run("--snapshot", self.target)

    def _clean(self):
        for path in sorted(self.tree.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        self.tree.rmdir()
        stored = corpus_unchanged.snapshot_path(self.target)
        if stored.is_file():
            stored.unlink()

    def test_an_unchanged_tree_passes(self):
        code, out = run(self.target)

        self.assertEqual(code, 0, out)

    def test_a_new_file_is_caught(self):
        """The go.sum case: `git status` does not show it without -uall."""
        (self.tree / "go.sum").write_text("x")

        code, out = run(self.target)

        self.assertEqual(code, 1)
        self.assertIn("NEW FILES", out)

    def test_a_rewritten_file_is_caught(self):
        """The go.mod case: a tidied manifest with a dependency removed."""
        target = self.tree / "kept.txt"
        target.write_text("a much longer body than before")
        os.utime(target, (0, 0))

        code, out = run(self.target)

        self.assertEqual(code, 1)
        self.assertIn("MODIFIED", out)

    def test_a_deleted_file_is_caught(self):
        (self.tree / "kept.txt").unlink()

        code, out = run(self.target)

        self.assertEqual(code, 1)
        self.assertIn("REMOVED", out)

    def test_the_snapshot_records_every_file(self):
        (self.tree / "second.txt").write_text("b")
        run("--snapshot", self.target)

        stored = json.loads(corpus_unchanged.snapshot_path(self.target).read_text())

        self.assertEqual(len(stored), 2)


if __name__ == "__main__":
    unittest.main()
