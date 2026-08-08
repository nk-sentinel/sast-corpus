import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from corpora.fetch import Source, load_manifest, manifest_errors, target_path

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
