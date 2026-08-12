import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from export.deps import (Coordinate, build_parser, build_plan, collect, dedupe,
                         describe_failure,
                         parse_gradle_tree, parse_maven_list,
                         parse_maven_plugins, render_text)


class MavenDependencyList(unittest.TestCase):
    """`mvn dependency:list` prints `group:artifact:type:version:scope` — except
    when a classifier is present, and then it prints six fields with the version
    in a different position. Reading the version positionally gets the
    classifier instead, and hands the repository a version that does not exist."""

    def test_reads_a_plain_five_field_coordinate(self):
        out = ("[INFO] The following files have been resolved:\n"
               "[INFO]    org.springframework:spring-core:jar:4.3.9.RELEASE:compile\n")

        got = parse_maven_list(out)

        self.assertEqual(got, [Coordinate("org.springframework", "spring-core",
                                          "4.3.9.RELEASE", "jar", None, "compile")])

    def test_reads_the_version_from_a_classifier_coordinate(self):
        out = "[INFO]    org.lwjgl:lwjgl:jar:natives-linux:3.3.1:runtime\n"

        got = parse_maven_list(out)

        self.assertEqual(got[0].version, "3.3.1")
        self.assertEqual(got[0].classifier, "natives-linux")

    def test_ignores_maven_chatter(self):
        out = ("[INFO] Scanning for projects...\n"
               "[INFO] --- maven-dependency-plugin:3.1.1:list ---\n"
               "[INFO] The following files have been resolved:\n"
               "[INFO]    commons-io:commons-io:jar:2.6:compile\n"
               "[INFO] BUILD SUCCESS\n"
               "[INFO] Total time:  2.401 s\n")

        self.assertEqual([c.artifact for c in parse_maven_list(out)], ["commons-io"])

    def test_a_none_line_yields_nothing(self):
        self.assertEqual(parse_maven_list("[INFO]    none\n"), [])

    def test_trailing_module_annotation_does_not_corrupt_the_scope(self):
        # Maven 3.9 appends module information after the coordinate.
        out = "[INFO]    commons-logging:commons-logging:jar:1.2:compile -- module commons.logging\n"

        self.assertEqual(parse_maven_list(out)[0].scope, "compile")


class MavenPluginList(unittest.TestCase):
    """Plugins are resolved separately from dependencies and are the half people
    forget. A repository missing a plugin fails the build just as hard, and this
    corpus has already been bitten by plugin version resolution once."""

    def test_reads_a_resolved_plugin(self):
        out = ("[INFO] The following plugins have been resolved:\n"
               "[INFO]    org.apache.maven.plugins:maven-compiler-plugin:jar:3.13.0:\n")

        got = parse_maven_plugins(out)

        self.assertEqual(got, [Coordinate("org.apache.maven.plugins",
                                          "maven-compiler-plugin", "3.13.0", "jar", None, None)])

    def test_does_not_confuse_plugins_with_dependencies(self):
        out = ("[INFO] The following files have been resolved:\n"
               "[INFO]    commons-io:commons-io:jar:2.6:compile\n")

        self.assertEqual(parse_maven_plugins(out), [])


class GradleDependencyTree(unittest.TestCase):
    """Gradle prints a tree, and marks conflict resolution with `->`. The
    version that actually gets fetched is the one on the RIGHT of the arrow.
    Taking the left one asks the repository for a version the build never uses."""

    def test_reads_a_flat_entry(self):
        out = ("compileClasspath - Compile classpath for source set 'main'.\n"
               "+--- org.slf4j:slf4j-api:1.7.25\n")

        self.assertEqual(parse_gradle_tree(out),
                         [Coordinate("org.slf4j", "slf4j-api", "1.7.25")])

    def test_takes_the_resolved_version_after_an_arrow(self):
        out = "+--- com.example:thing:2.0 -> 2.1\n"

        self.assertEqual(parse_gradle_tree(out)[0].version, "2.1")

    def test_reads_nested_entries(self):
        out = ("+--- org.slf4j:slf4j-api:1.7.25\n"
               "|    \\--- org.foo:bar:1.0\n"
               "\\--- com.example:thing:2.0\n")

        self.assertEqual({c.artifact for c in parse_gradle_tree(out)},
                         {"slf4j-api", "bar", "thing"})

    def test_skips_entries_with_no_version(self):
        # Project dependencies carry no coordinate a repository could serve.
        out = "+--- project :common\n"

        self.assertEqual(parse_gradle_tree(out), [])

    def test_drops_the_omitted_marker(self):
        out = "|    +--- org.foo:bar:1.0 (*)\n"

        self.assertEqual(parse_gradle_tree(out)[0].version, "1.0")

    def test_ignores_constraint_lines(self):
        out = "+--- org.foo:bar:{strictly 1.0} -> 1.0 (c)\n"

        got = parse_gradle_tree(out)

        self.assertEqual([(c.artifact, c.version) for c in got], [("bar", "1.0")])


class BuildRouting(unittest.TestCase):
    """Which tool builds a project is decided by the files on disk, not by
    build-info alone.

    Measured against the dataset: 5 projects declare `{"gradle": ..., "jdk": ...}`
    and every one of them contains `pom.xml` and no Gradle file whatsoever, so
    the `gradle` key does not mean "build with Gradle". Two others declare
    `{"gradlew": 1}` — a different key — and those genuinely do carry a wrapper.
    Trusting the metadata routed 7 of 28 projects to a tool they do not use, and
    each one contributed nothing to the checklist."""

    def test_a_pom_means_maven_whatever_build_info_says(self):
        tool, version = build_plan({"gradle": "8.9", "jdk": "17"}, {"pom.xml"})

        self.assertEqual(tool, "maven")

    def test_the_declared_maven_version_is_used(self):
        self.assertEqual(build_plan({"jdk": "8u202", "mvn": "3.5.0"}, {"pom.xml"}),
                         ("maven", "3.5.0"))

    def test_a_pom_with_no_declared_version_falls_back(self):
        tool, version = build_plan({"gradle": "8.9", "jdk": "17"}, {"pom.xml"})

        self.assertTrue(version, "a maven project needs some version to run")

    def test_a_wrapper_with_no_pom_uses_the_wrapper(self):
        self.assertEqual(build_plan({"gradlew": 1}, {"gradlew", "build.gradle"}),
                         ("gradlew", None))

    def test_a_pom_wins_when_both_are_present(self):
        # A polyglot tree still resolves through maven, which is what the
        # corpus's own build recipes use.
        tool, _ = build_plan({"gradlew": 1}, {"pom.xml", "gradlew"})

        self.assertEqual(tool, "maven")

    def test_no_build_file_is_unknown(self):
        self.assertEqual(build_plan({}, set())[0], "unknown")


class EveryProjectIsAccountedFor(unittest.TestCase):
    """A project whose toolchain is missing still has to appear in the progress
    output. Otherwise the log shows `resolving X ...` with no outcome and the
    reader is left guessing whether it hung, crashed, or was skipped — and this
    is a run people watch for tens of minutes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def project(self, name, info, build_file="pom.xml"):
        info_dir = self.root / "tier3" / "cwe-bench-java" / "build-info"
        info_dir.mkdir(parents=True, exist_ok=True)
        (info_dir / f"{name}.json").write_text(json.dumps(info))
        source = self.root / "tier3" / "project-sources" / name
        source.mkdir(parents=True, exist_ok=True)
        if build_file:
            (source / build_file).write_text("")

    def collect_output(self):
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream):
            projects = collect(self.root)
        return projects, stream.getvalue()

    def test_a_project_with_no_provisioned_maven_is_reported(self):
        self.project("x", {"jdk": "8u202", "mvn": "9.9.9"})

        projects, output = self.collect_output()

        self.assertEqual(len(projects), 1)
        self.assertIn("not provisioned", output)

    def test_a_project_with_no_build_file_is_reported(self):
        self.project("y", {"jdk": "17", "gradle": "8.9"}, build_file=None)

        projects, output = self.collect_output()

        self.assertEqual(len(projects), 1)
        self.assertIn("no build file", output)

    def test_no_project_starts_without_finishing(self):
        self.project("x", {"jdk": "8u202", "mvn": "9.9.9"})
        self.project("y", {"jdk": "17", "gradle": "8.9"}, build_file=None)

        _, output = self.collect_output()

        started = output.count("resolving ")
        finished = sum(1 for line in output.splitlines()
                       if line.strip().startswith(("x:", "y:")))
        self.assertEqual(started, finished)


class Deduplication(unittest.TestCase):
    """The checklist handed over is one list of distinct artifacts. 28 projects
    sharing a logging library must not appear as 28 rows to check."""

    def test_identical_coordinates_collapse(self):
        a = Coordinate("g", "a", "1.0")

        self.assertEqual(len(dedupe([a, Coordinate("g", "a", "1.0")])), 1)

    def test_different_versions_are_kept_apart(self):
        got = dedupe([Coordinate("g", "a", "1.0"), Coordinate("g", "a", "2.0")])

        self.assertEqual(len(got), 2)

    def test_scope_does_not_split_an_artifact(self):
        # The repository serves a file; which scope consumed it is irrelevant.
        got = dedupe([Coordinate("g", "a", "1.0", scope="compile"),
                      Coordinate("g", "a", "1.0", scope="test")])

        self.assertEqual(len(got), 1)

    def test_a_mix_of_classifiers_and_none_can_be_sorted(self):
        # Real output mixes both. Ordering by a tuple holding None in one row
        # and a string in another raises, and it raises at the END of a long
        # resolution run — after every project has been walked.
        got = dedupe([Coordinate("g", "a", "1.0", classifier="natives-linux"),
                      Coordinate("g", "a", "1.0", classifier=None)])

        self.assertEqual(len(got), 2)

    def test_a_mix_of_packagings_and_none_can_be_sorted(self):
        got = dedupe([Coordinate("g", "a", "1.0", packaging=None),
                      Coordinate("g", "a", "1.0", packaging="jar")])

        self.assertEqual(len(got), 2)

    def test_classifierless_rows_sort_before_classified_ones(self):
        got = dedupe([Coordinate("g", "a", "1.0", classifier="x"),
                      Coordinate("g", "a", "1.0")])

        self.assertIsNone(got[0].classifier)

    def test_output_is_ordered_for_a_reviewable_diff(self):
        got = dedupe([Coordinate("z", "a", "1"), Coordinate("a", "b", "1")])

        self.assertEqual([c.group for c in got], ["a", "z"])


class Rendering(unittest.TestCase):
    def test_text_output_is_one_coordinate_per_line(self):
        text = render_text([Coordinate("org.foo", "bar", "1.2.3")])

        self.assertIn("org.foo:bar:1.2.3", text)

    def test_classifier_appears_in_the_rendered_coordinate(self):
        text = render_text([Coordinate("org.foo", "bar", "1.2.3",
                                       classifier="natives-linux")])

        self.assertIn("natives-linux", text)



class PartialResolutionIsNotSuccess(unittest.TestCase):
    """Dependencies and plugins are resolved by two separate commands, and one
    can fail while the other succeeds. `dependency:resolve-plugins` in
    particular resolves plugins that are declared but never invoked, so it fails
    offline against a cache populated by an actual build.

    A checklist that quietly omits every plugin looks complete and is the exact
    failure this tool exists to prevent."""

    def test_all_stages_succeeding_is_no_error(self):
        self.assertIsNone(describe_failure({"dependencies": (True, ""),
                                            "plugins": (True, "")}))

    def test_a_failed_stage_is_named(self):
        got = describe_failure({"dependencies": (True, ""),
                                "plugins": (False, "offline mode")})

        self.assertIn("plugins", got)

    def test_the_reason_survives_into_the_message(self):
        got = describe_failure({"plugins": (False, "Cannot access central in offline mode")})

        self.assertIn("offline", got)

    def test_several_failures_are_all_reported(self):
        got = describe_failure({"dependencies": (False, "boom"), "plugins": (False, "bang")})

        self.assertIn("dependencies", got)
        self.assertIn("plugins", got)


class ChecklistDefaultsToOnline(unittest.TestCase):
    """The checklist is generated on the networked side precisely to enumerate
    artifacts the far side does not have. Defaulting to offline would enumerate
    only what this machine already cached."""

    def test_offline_is_opt_in(self):
        args = build_parser().parse_args([])

        self.assertFalse(args.offline)

    def test_offline_can_still_be_requested(self):
        self.assertTrue(build_parser().parse_args(["--offline"]).offline)

if __name__ == "__main__":
    unittest.main()
