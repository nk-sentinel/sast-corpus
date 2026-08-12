import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from corpora.fetch import (Source, build_parser, checkout_state,
                           load_manifest, manifest_errors, offline_outcome,
                           offline_requested, load_manifest_data, target_path)

MANIFEST = {
    "corpus": "tier2",
    "description": "real vulnerable applications",
    "sources": [
        {
            "name": "webgoat",
            "repo": "https://github.com/WebGoat/WebGoat.git",
            "sha": "e75cfbeb110e3d3a2ca3c8fee2754992d89c419d",
            "license": "GPL-2.0",
            "languages": ["java"],
            "notes": "Spring-based training application",
        }
    ],
}


class LoadManifest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = self.dir / "sources.json"
        self.path.write_text(json.dumps(MANIFEST))

    def test_reads_each_source(self):
        sources = load_manifest(self.path)

        self.assertEqual(len(sources), 1)
        self.assertIsInstance(sources[0], Source)

    def test_keeps_the_pinned_revision(self):
        self.assertEqual(load_manifest(self.path)[0].sha, MANIFEST["sources"][0]["sha"])

    def test_keeps_the_licence_so_it_can_be_reviewed_before_use(self):
        self.assertEqual(load_manifest(self.path)[0].license, "GPL-2.0")


class ManifestErrors(unittest.TestCase):
    """A corpus fetched from a moving branch is not a corpus. Two runs a month
    apart would score different code and nothing in the output would say so."""

    def test_a_full_length_sha_is_accepted(self):
        self.assertEqual(manifest_errors(MANIFEST), [])

    def test_a_branch_name_instead_of_a_sha_is_rejected(self):
        broken = json.loads(json.dumps(MANIFEST))
        broken["sources"][0]["sha"] = "main"

        errors = manifest_errors(broken)

        self.assertEqual(len(errors), 1)
        self.assertIn("main", errors[0])

    def test_an_abbreviated_sha_is_rejected(self):
        broken = json.loads(json.dumps(MANIFEST))
        broken["sources"][0]["sha"] = "e75cfbe"

        self.assertEqual(len(manifest_errors(broken)), 1)

    def test_a_missing_licence_is_rejected(self):
        broken = json.loads(json.dumps(MANIFEST))
        del broken["sources"][0]["license"]

        errors = manifest_errors(broken)

        self.assertTrue(any("license" in e for e in errors))

    def test_a_duplicate_name_is_rejected(self):
        broken = json.loads(json.dumps(MANIFEST))
        broken["sources"].append(dict(broken["sources"][0]))

        errors = manifest_errors(broken)

        self.assertTrue(any("webgoat" in e for e in errors))

    def test_reports_every_problem_at_once(self):
        broken = json.loads(json.dumps(MANIFEST))
        broken["sources"][0]["sha"] = "main"
        del broken["sources"][0]["license"]

        self.assertEqual(len(manifest_errors(broken)), 2)


class TargetPath(unittest.TestCase):
    def test_a_source_lands_under_its_corpus_directory_by_name(self):
        source = load_manifest_source()

        self.assertEqual(target_path(Path("/repo"), "tier2", source), Path("/repo/tier2/webgoat"))

    def test_the_name_cannot_escape_the_corpus_directory(self):
        source = load_manifest_source(name="../../etc")

        with self.assertRaises(ValueError):
            target_path(Path("/repo"), "tier2", source)


def load_manifest_source(**overrides):
    data = dict(MANIFEST["sources"][0])
    data.update(overrides)
    return Source(**{k: data.get(k) for k in
                     ("name", "repo", "sha", "license", "languages", "notes")})


if __name__ == "__main__":
    unittest.main()


class OfflineOperation(unittest.TestCase):
    """In an airgapped environment there is nothing to clone from, and a fetch
    that tries anyway hangs on an unreachable host instead of saying so."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_a_bundle_restored_tree_is_not_absent(self):
        # The export drops .git deliberately — 602 MB of history for code we did
        # not write, replaced by the pinned SHA in MANIFEST.json. Judging
        # presence by .git would call every restored tree absent and try to
        # clone it, which is exactly what cannot work here.
        destination = self.root / "webgoat"
        (destination / "src").mkdir(parents=True)
        (destination / "src" / "A.java").write_text("class A {}")

        self.assertEqual(checkout_state(destination, "a" * 40), "restored")

    def test_a_checkout_at_the_pinned_revision_is_present(self):
        destination = self.root / "x"
        (destination / ".git").mkdir(parents=True)

        state = checkout_state(destination, "a" * 40,
                               head=lambda _: "a" * 40)

        self.assertEqual(state, "present")

    def test_a_checkout_at_another_revision_is_flagged(self):
        destination = self.root / "x"
        (destination / ".git").mkdir(parents=True)

        state = checkout_state(destination, "a" * 40, head=lambda _: "b" * 40)

        self.assertEqual(state, "wrong-revision")

    def test_an_empty_directory_is_absent(self):
        destination = self.root / "x"
        destination.mkdir()

        self.assertEqual(checkout_state(destination, "a" * 40), "absent")

    def test_a_missing_directory_is_absent(self):
        self.assertEqual(checkout_state(self.root / "nope", "a" * 40), "absent")


class OfflineOutcomes(unittest.TestCase):
    def test_a_restored_tree_is_usable(self):
        status, _ = offline_outcome("restored")

        self.assertEqual(status, "ok")

    def test_a_present_checkout_is_usable(self):
        self.assertEqual(offline_outcome("present")[0], "ok")

    def test_an_absent_source_is_an_error_offline(self):
        status, message = offline_outcome("absent")

        self.assertEqual(status, "error")

    def test_the_error_says_how_to_resolve_it(self):
        # There is no network here, so "run fetch again" is useless advice.
        _, message = offline_outcome("absent")

        self.assertIn("bundle", message.lower())

    def test_a_wrong_revision_is_an_error(self):
        self.assertEqual(offline_outcome("wrong-revision")[0], "error")


class OptionalSources(unittest.TestCase):
    """A manifest may declare a source that produces no cases. vul4j is one: it
    is fetched, it is 21 MB of GPL-3.0 code, and no case in the answer key
    references it. Treating its absence as a failure would make the offline
    check fail permanently, and a check that always fails is a check people
    learn to ignore."""

    def test_a_required_source_missing_offline_is_an_error(self):
        status, _ = offline_outcome("absent", optional=False)

        self.assertEqual(status, "error")

    def test_an_optional_source_missing_offline_is_not_an_error(self):
        status, _ = offline_outcome("absent", optional=True)

        self.assertNotEqual(status, "error")

    def test_an_optional_absence_is_still_reported(self):
        _, message = offline_outcome("absent", optional=True)

        self.assertTrue(message)

    def test_optional_defaults_to_required(self):
        # Silence about a missing source is worse than a noisy check.
        self.assertEqual(offline_outcome("absent")[0], "error")

    def test_the_manifest_can_declare_a_source_optional(self):
        sources = load_manifest_data({"sources": [
            {"name": "vul4j", "repo": "https://x/y", "sha": "a" * 40,
             "license": "GPL-3.0", "optional": True}]})

        self.assertTrue(sources[0].optional)

    def test_a_source_is_required_unless_it_says_otherwise(self):
        sources = load_manifest_data({"sources": [
            {"name": "cwe-bench-java", "repo": "https://x/y", "sha": "b" * 40,
             "license": "MIT"}]})

        self.assertFalse(sources[0].optional)


class OfflineFlag(unittest.TestCase):
    def test_offline_is_off_by_default(self):
        self.assertFalse(build_parser().parse_args(["tier2"]).offline)

    def test_offline_can_be_requested(self):
        self.assertTrue(build_parser().parse_args(["tier2", "--offline"]).offline)

    def test_the_environment_can_turn_it_on(self):
        # An airgapped host should not depend on anyone remembering a flag.
        self.assertTrue(offline_requested(argv_offline=False,
                                          environ={"SAST_CORPUS_OFFLINE": "1"}))

    def test_the_flag_alone_is_enough(self):
        self.assertTrue(offline_requested(argv_offline=True, environ={}))

    def test_neither_means_online(self):
        self.assertFalse(offline_requested(argv_offline=False, environ={}))
