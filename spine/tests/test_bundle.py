import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from export.bundle import (PROFILES, build_manifest, bundle, checksum, components_for,
                           iter_files, render_checksums, render_licenses,
                           should_exclude, split_plan)


class BundleCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.dir if hasattr(self.tmp, "dir") else self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, rel, text="x"):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path


class ProfilesCarryWhatScoringNeeds(BundleCase):
    """A profile that omits the fixtures or the answer key produces a bundle
    that unpacks cleanly and scores nothing. In an airgapped environment that is
    discovered after the transfer, which is the whole problem."""

    def test_every_profile_carries_the_fixtures(self):
        for profile in PROFILES:
            names = {c.name for c in components_for(profile)}

            self.assertIn("tier1", names, f"{profile} has no fixtures")

    def test_every_profile_carries_the_answer_key(self):
        for profile in PROFILES:
            names = {c.name for c in components_for(profile)}

            self.assertIn("answers", names, f"{profile} cannot score")

    def test_every_profile_carries_the_scorer(self):
        for profile in PROFILES:
            self.assertIn("spine", {c.name for c in components_for(profile)})

    def test_scoring_profile_leaves_out_the_timing_corpus(self):
        # perf/ is 403 MB and is never accuracy-scored.
        self.assertNotIn("perf", {c.name for c in components_for("scoring")})

    def test_perf_profile_includes_it(self):
        self.assertIn("perf", {c.name for c in components_for("perf")})

    def test_build_profile_carries_the_toolchains(self):
        # A package repository does not serve JDK tarballs.
        self.assertIn("java-env", {c.name for c in components_for("build")})

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(KeyError):
            components_for("whatever")


class GroundTruthShipsSeparately(BundleCase):
    """Rule 1 of the corpus is that the answer key lives outside the fixtures.
    If both land in one archive, a scanner pointed at the extracted root reads
    every CWE identifier and rationale — and an LLM-based scanner scores on the
    answers rather than the code."""

    def test_the_answer_key_goes_to_its_own_archive(self):
        answers = [c for c in components_for("scoring") if c.name == "answers"]

        self.assertEqual(answers[0].archive, "answers")

    def test_fixtures_go_to_the_scannable_archive(self):
        tier1 = [c for c in components_for("scoring") if c.name == "tier1"]

        self.assertEqual(tier1[0].archive, "corpus")

    def test_no_component_puts_answers_in_the_scannable_archive(self):
        for profile in PROFILES:
            for component in components_for(profile):
                if component.archive == "corpus":
                    self.assertNotIn("answers", component.paths,
                                     f"{profile}/{component.name} leaks ground truth")


class ExclusionRules(BundleCase):
    def test_build_output_is_excluded(self):
        # 17.6 GB of the 20 GB, and regenerated on arrival.
        self.assertTrue(should_exclude(Path("tier3/project-sources/x/target/classes/A.class")))

    def test_a_source_path_merely_containing_the_word_is_kept(self):
        self.assertFalse(should_exclude(Path("tier1/java/a/TargetHandler.java")))

    def test_git_history_is_excluded_by_default(self):
        self.assertTrue(should_exclude(Path("perf/hadoop/.git/objects/ab/cdef")))

    def test_git_history_can_be_kept(self):
        self.assertFalse(should_exclude(Path("perf/hadoop/.git/objects/ab/cdef"),
                                        keep_git=True))

    def test_python_caches_are_excluded(self):
        self.assertTrue(should_exclude(Path("spine/score/__pycache__/score.cpython-311.pyc")))

    def test_reef_is_never_bundled(self):
        # 737 MB of copied third-party source under no licence at all. Cloning
        # it locally is not the same as copying it into another organisation.
        self.assertTrue(should_exclude(Path("tier3/reef/data/query_C_part0.jsonl")))
        self.assertTrue(should_exclude(Path("tier3/reef/README.md"), keep_git=True))


class FileCollection(BundleCase):
    def test_collects_files_under_a_component_path(self):
        self.write("tier1/java/a/A.java")
        self.write("tier1/python/b/b.py")

        got = iter_files(self.root, [Path("tier1")])

        self.assertEqual(len(got), 2)

    def test_applies_the_exclusion_rules(self):
        self.write("tier1/java/a/A.java")
        self.write("tier1/java/a/target/A.class")

        got = iter_files(self.root, [Path("tier1")])

        self.assertEqual([p.name for p in got], ["A.java"])

    def test_a_missing_path_is_not_an_error(self):
        # perf/ is absent until fetched; the bundle says so rather than crashing.
        self.assertEqual(iter_files(self.root, [Path("perf")]), [])

    def test_order_is_stable(self):
        for name in ("c", "a", "b"):
            self.write(f"tier1/{name}.java")

        self.assertEqual([p.name for p in iter_files(self.root, [Path("tier1")])],
                         ["a.java", "b.java", "c.java"])


class Manifest(BundleCase):
    def test_metadata_does_not_carry_per_file_hashes(self):
        # 120k files of embedded hashes made MANIFEST.json 31 MB. The bulk moves
        # to SHA256SUMS, leaving the metadata small enough to read.
        self.write("tier1/a.java", "content")

        manifest = build_manifest(self.root, iter_files(self.root, [Path("tier1")]),
                                  profile="scoring")

        self.assertNotIn("files", manifest)

    def test_a_changed_file_changes_its_checksum(self):
        path = self.write("tier1/a.java", "before")
        first = checksum(path)
        path.write_text("after")

        self.assertNotEqual(first, checksum(path))

    def test_records_the_profile(self):
        manifest = build_manifest(self.root, [], profile="perf")

        self.assertEqual(manifest["profile"], "perf")

    def test_records_pinned_upstream_commits(self):
        self.write("tier3/sources.json", json.dumps(
            {"sources": [{"name": "cwe-bench-java", "repo": "https://x/y",
                          "sha": "a" * 40, "license": "MIT"}]}))

        manifest = build_manifest(self.root, [], profile="scoring")

        self.assertEqual(manifest["pinned"]["cwe-bench-java"]["sha"], "a" * 40)

    def test_pins_only_corpora_that_are_in_the_bundle(self):
        # Claiming provenance for a tree that never travelled is how a manifest
        # stops being evidence — the same rule the licence page follows.
        self.write("tier3/sources.json", json.dumps(
            {"sources": [{"name": "cwe-bench-java", "sha": "a" * 40}]}))
        self.write("perf/sources.json", json.dumps(
            {"sources": [{"name": "hadoop", "sha": "d" * 40}]}))

        manifest = build_manifest(self.root, [], profile="scoring", corpora=["tier3"])

        self.assertIn("cwe-bench-java", manifest["pinned"])
        self.assertNotIn("hadoop", manifest["pinned"])

    def test_the_perf_profile_does_pin_perf(self):
        self.write("perf/sources.json", json.dumps(
            {"sources": [{"name": "hadoop", "sha": "d" * 40}]}))

        manifest = build_manifest(self.root, [], profile="perf", corpora=["tier3", "perf"])

        self.assertIn("hadoop", manifest["pinned"])

    def test_records_the_file_count_and_total_size(self):
        self.write("tier1/a.java", "1234567890")

        manifest = build_manifest(self.root, iter_files(self.root, [Path("tier1")]),
                                  profile="scoring")

        self.assertEqual(manifest["file_count"], 1)
        self.assertEqual(manifest["total_bytes"], 10)


class Checksums(BundleCase):
    """Written in `sha256sum` format rather than JSON, so the far side verifies
    with the standard tool and needs nothing from us to do it."""

    def test_one_line_per_file_in_the_standard_format(self):
        self.write("tier1/a.java", "content")
        files = iter_files(self.root, [Path("tier1")])

        line = render_checksums(self.root, files).strip()

        self.assertRegex(line, r"^[0-9a-f]{64}  tier1/a\.java$")

    def test_paths_are_relative_so_verification_works_anywhere(self):
        self.write("tier1/a.java")

        text = render_checksums(self.root, iter_files(self.root, [Path("tier1")]))

        self.assertNotIn(str(self.root), text)

    def test_every_file_appears(self):
        for name in ("a", "b", "c"):
            self.write(f"tier1/{name}.java")

        text = render_checksums(self.root, iter_files(self.root, [Path("tier1")]))

        self.assertEqual(len(text.strip().splitlines()), 3)


class ChecksumsAreWrittenPerArchive(BundleCase):
    """The two archives are meant to be extracted separately, so one checksum
    file covering both makes a correct extraction fail: verifying the corpus
    tree alone reports every answer-key file as missing. Each archive carries
    its own list."""

    def test_bundle_writes_one_checksum_file_per_archive(self):
        self.write("tier1/a.java")
        self.write("answers/expectedresults-1.0.csv", "id\n")
        self.write("spine/score/score.py")

        bundle(self.root, "scoring", self.root / "out")

        names = {p.name for p in (self.root / "out").glob("SHA256SUMS*")}
        self.assertEqual(names, {"SHA256SUMS.corpus", "SHA256SUMS.answers"})

    def test_the_corpus_list_holds_no_answer_key(self):
        self.write("tier1/a.java")
        self.write("answers/expectedresults-1.0.csv", "id\n")

        bundle(self.root, "scoring", self.root / "out")

        text = (self.root / "out" / "SHA256SUMS.corpus").read_text()
        self.assertNotIn("answers/", text)

    def test_the_answers_list_holds_the_answer_key(self):
        self.write("tier1/a.java")
        self.write("answers/expectedresults-1.0.csv", "id\n")

        bundle(self.root, "scoring", self.root / "out")

        text = (self.root / "out" / "SHA256SUMS.answers").read_text()
        self.assertIn("answers/expectedresults-1.0.csv", text)

    def test_the_manifest_names_both_lists(self):
        self.write("tier1/a.java")
        self.write("answers/expectedresults-1.0.csv", "id\n")

        bundle(self.root, "scoring", self.root / "out")

        manifest = json.loads((self.root / "out" / "MANIFEST.json").read_text())
        listed = {a["checksums"] for a in manifest["archives"]}
        self.assertEqual(listed, {"SHA256SUMS.corpus", "SHA256SUMS.answers"})


class Licences(BundleCase):
    """The bundle copies third-party source into another organisation, so the
    licence question has to be answerable without re-deriving it there."""

    def test_lists_a_declared_licence(self):
        self.write("tier3/sources.json", json.dumps(
            {"sources": [{"name": "vul4j", "repo": "https://x/y",
                          "sha": "b" * 40, "license": "GPL-3.0"}]}))

        text = render_licenses(self.root, ["tier3"])

        self.assertIn("vul4j", text)
        self.assertIn("GPL-3.0", text)

    def test_flags_a_licence_that_was_never_verified(self):
        self.write("tier2/sources.json", json.dumps(
            {"sources": [{"name": "webgoat", "repo": "https://x/y",
                          "sha": "c" * 40, "license": "VERIFY-BEFORE-USE"}]}))

        text = render_licenses(self.root, ["tier2"])

        self.assertIn("VERIFY-BEFORE-USE", text)
        self.assertIn("webgoat", text)

    def test_omits_corpora_that_are_not_in_the_bundle(self):
        self.write("perf/sources.json", json.dumps(
            {"sources": [{"name": "hadoop", "repo": "https://x/y",
                          "sha": "d" * 40, "license": "Apache-2.0"}]}))

        text = render_licenses(self.root, ["tier3"])

        self.assertNotIn("hadoop", text)


class Splitting(BundleCase):
    """Transfer media into an airgapped environment usually have a size cap."""

    def test_no_split_requested_is_one_part(self):
        self.assertEqual(split_plan(5_000, None), 1)

    def test_splits_into_enough_parts(self):
        self.assertEqual(split_plan(10_000, 4_000), 3)

    def test_an_exact_multiple_does_not_gain_an_empty_part(self):
        self.assertEqual(split_plan(8_000, 4_000), 2)

    def test_smaller_than_one_part_stays_whole(self):
        self.assertEqual(split_plan(100, 4_000), 1)


if __name__ == "__main__":
    unittest.main()
