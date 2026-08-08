import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from corpora.tier3 import (
    acceptable_for,
    find_class,
    find_method,
    normalise_cwe,
    resolve_location,
)

SOURCE = """package com.example;

import java.io.File;

public class IOUtils {

    private static final int BUFFER = 4096;

    public static String describe(String name) {
        return "file: " + name;
    }

    public static void unzip(String zipFile, String extractFolder) throws IOException {
        ZipFile zip = new ZipFile(zipFile);
        for (ZipEntry entry : zip.entries()) {
            File target = new File(extractFolder, entry.getName());
            write(target);
        }
    }

    private static void write(File target) {
        target.createNewFile();
    }
}
"""


class NormaliseCwe(unittest.TestCase):
    """The dataset writes CWE-022; the corpus and every SARIF producer write
    CWE-22. Left unnormalised the two never match and every case is a miss."""

    def test_strips_the_zero_padding(self):
        self.assertEqual(normalise_cwe("CWE-022"), "CWE-22")

    def test_leaves_an_unpadded_identifier_alone(self):
        self.assertEqual(normalise_cwe("CWE-79"), "CWE-79")

    def test_accepts_a_bare_number(self):
        self.assertEqual(normalise_cwe("094"), "CWE-94")


class AcceptableFor(unittest.TestCase):
    def test_includes_the_primary(self):
        self.assertIn("CWE-22", acceptable_for("CWE-22"))

    def test_path_traversal_admits_its_siblings(self):
        self.assertIn("CWE-23", acceptable_for("CWE-22"))

    def test_command_injection_admits_code_injection(self):
        """The same collision that made PHP and Ruby look uncovered."""
        self.assertIn("CWE-94", acceptable_for("CWE-78"))

    def test_an_unlisted_weakness_still_yields_itself(self):
        self.assertEqual(acceptable_for("CWE-1234"), ["CWE-1234"])


class FindMethod(unittest.TestCase):
    """Located by name in the buggy checkout, never by the line number the
    dataset records — those belong to the fixed file, which has different
    content and sometimes does not contain the method at all."""

    def test_finds_a_method_and_spans_its_whole_body(self):
        start, end = find_method(SOURCE, "unzip")

        lines = SOURCE.splitlines()
        self.assertIn("void unzip", lines[start - 1])
        self.assertEqual(lines[end - 1].strip(), "}")

    def test_the_span_contains_the_body(self):
        start, end = find_method(SOURCE, "unzip")
        body = "\n".join(SOURCE.splitlines()[start - 1:end])

        self.assertIn("new File(extractFolder", body)
        self.assertNotIn("private static void write", body)

    def test_finds_a_different_method_in_the_same_file(self):
        start, _end = find_method(SOURCE, "describe")

        self.assertIn("String describe", SOURCE.splitlines()[start - 1])

    def test_a_method_that_is_not_present_returns_nothing(self):
        self.assertIsNone(find_method(SOURCE, "missingMethod"))

    def test_a_call_site_is_not_mistaken_for_a_declaration(self):
        """`write(target)` is called inside unzip before it is declared."""
        start, _end = find_method(SOURCE, "write")

        self.assertIn("private static void write", SOURCE.splitlines()[start - 1])

    def test_a_brace_inside_a_string_does_not_end_the_method(self):
        source = 'class A {\n    void go() {\n        String s = "}";\n        run();\n    }\n}\n'

        start, end = find_method(source, "go")

        self.assertEqual((start, end), (2, 5))


class FindClass(unittest.TestCase):
    def test_spans_the_class_declaration_to_its_closing_brace(self):
        start, end = find_class(SOURCE, "IOUtils")

        lines = SOURCE.splitlines()
        self.assertIn("class IOUtils", lines[start - 1])
        self.assertEqual(end, len(lines))

    def test_a_class_that_is_not_present_returns_nothing(self):
        self.assertIsNone(find_class(SOURCE, "Nowhere"))


class ResolveLocation(unittest.TestCase):
    """Granularity is recorded, because a whole-file span in a 1600-line class
    is a far weaker claim than a method span and a scorecard must be able to
    say which it relied on."""

    def test_prefers_the_method(self):
        start, end, granularity = resolve_location(SOURCE, "IOUtils", "unzip")

        self.assertEqual(granularity, "method")
        self.assertIn("void unzip", SOURCE.splitlines()[start - 1])

    def test_falls_back_to_the_class_when_the_method_is_gone(self):
        _start, _end, granularity = resolve_location(SOURCE, "IOUtils", "deletedMethod")

        self.assertEqual(granularity, "class")

    def test_falls_back_to_the_whole_file_when_neither_is_found(self):
        start, end, granularity = resolve_location(SOURCE, "Nowhere", "nothing")

        self.assertEqual(granularity, "file")
        self.assertEqual((start, end), (1, len(SOURCE.splitlines())))

    def test_a_row_with_no_method_name_resolves_to_the_class(self):
        _start, _end, granularity = resolve_location(SOURCE, "IOUtils", "")

        self.assertEqual(granularity, "class")


class RenderCase(unittest.TestCase):
    """A derived candidate becomes an answer-key case only after a human has
    confirmed it, so the rendered YAML must carry everything a reviewer needs
    to check the call without redoing the analysis."""

    def setUp(self):
        from corpora.tier3 import render_case
        self.candidate = {
            "slug": "alibaba__one-java-agent_CVE-2022-25842_0.0.1",
            "cve": "CVE-2022-25842",
            "cwe": "CWE-22",
            "acceptable_cwes": ["CWE-22", "CWE-23"],
            "file": "tier3/project-sources/alibaba__one-java-agent_CVE-2022-25842_0.0.1/a/IOUtils.java",
            "start_line": 106,
            "end_line": 161,
            "granularity": "method",
            "class": "IOUtils",
            "method": "unzip",
            "signature": "unzip(String zipFile, String extractFolder)",
            "buggy_commit": "b911af2bb779917c84a016350700745dc31c642a",
            "repo": "https://github.com/alibaba/one-java-agent",
        }
        self.text = render_case(self.candidate)

    def test_is_tier_three(self):
        self.assertIn("tier: 3", self.text)

    def test_is_labelled_vulnerable(self):
        self.assertIn("label: vulnerable", self.text)

    def test_cites_the_cve_as_evidence(self):
        self.assertIn("source: cve", self.text)
        self.assertIn("cve: CVE-2022-25842", self.text)

    def test_records_the_buggy_commit_so_the_case_is_reproducible(self):
        self.assertIn("b911af2bb779917c84a016350700745dc31c642a", self.text)

    def test_records_the_granularity_the_search_achieved(self):
        self.assertIn("method", self.text)

    def test_the_id_is_derived_from_the_cve_and_location_so_it_is_stable(self):
        from corpora.tier3 import render_case
        self.assertEqual(self.text, render_case(self.candidate))

    def test_a_whole_file_span_says_so_in_the_rationale(self):
        from corpora.tier3 import render_case
        loose = dict(self.candidate, granularity="file", start_line=1, end_line=900)

        self.assertIn("whole file", render_case(loose))


class TestCodeIsNotGroundTruth(unittest.TestCase):
    """A fix commit routinely updates the test that proves it. Tools skip test
    directories by default, so a ground-truth entry pointing at one charges
    every tool a false negative for behaving correctly."""

    def test_a_maven_test_path_is_excluded(self):
        from corpora.tier3 import is_test_path
        self.assertTrue(is_test_path("core/src/test/java/com/example/FooTest.java"))

    def test_a_testsuite_directory_is_excluded(self):
        from corpora.tier3 import is_test_path
        self.assertTrue(is_test_path(
            "testsuite/integration/web/src/test/java/org/jboss/ServletResourceOverlaysTestCase.java"))

    def test_a_class_named_TestCase_is_excluded(self):
        from corpora.tier3 import is_test_path
        self.assertTrue(is_test_path("src/main/java/com/example/ServletOverlaysTestCase.java"))

    def test_ordinary_main_source_is_kept(self):
        from corpora.tier3 import is_test_path
        self.assertFalse(is_test_path("undertow/src/main/java/org/wildfly/ServletResourceManager.java"))

    def test_a_path_merely_containing_the_word_latest_is_kept(self):
        from corpora.tier3 import is_test_path
        self.assertFalse(is_test_path("src/main/java/com/example/LatestBuild.java"))


class DeduplicatesLocations(unittest.TestCase):
    def test_overloaded_methods_resolving_to_one_span_yield_one_location(self):
        """Overloads share a name, so every signature locates the same span."""
        from corpora.tier3 import group_by_cve
        row = {"slug": "s", "cve": "CVE-2020-1", "cwe": "CWE-22", "acceptable_cwes": ["CWE-22"],
               "file": "tier3/project-sources/s/A.java", "start_line": 10, "end_line": 20,
               "granularity": "method", "class": "A", "method": "go", "signature": "go(String)",
               "buggy_commit": "a" * 40, "repo": "https://github.com/x/y"}
        grouped = group_by_cve([row, dict(row, signature="go(int)"), dict(row, signature="go()")])

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["alt_locations"], [])


class PrimaryLocationPrefersPrecision(unittest.TestCase):
    """The primary location is what a reader checks first and what a narrow
    tolerance matches against. A whole-class span there is a far weaker claim
    than a method, so a method row wins even if a class row came first."""

    def _row(self, **over):
        row = {"slug": "s", "cve": "CVE-2020-1", "cwe": "CWE-22", "acceptable_cwes": ["CWE-22"],
               "file": "tier3/project-sources/s/A.java", "start_line": 1, "end_line": 300,
               "granularity": "class", "class": "A", "method": "", "signature": "",
               "buggy_commit": "a" * 40, "repo": "https://github.com/x/y"}
        row.update(over)
        return row

    def test_a_method_row_becomes_primary_over_a_class_row(self):
        from corpora.tier3 import group_by_cve
        rows = [self._row(), self._row(granularity="method", method="go",
                                       start_line=40, end_line=60,
                                       file="tier3/project-sources/s/B.java")]

        primary = group_by_cve(rows)[0]

        self.assertEqual(primary["granularity"], "method")
        self.assertEqual(primary["start_line"], 40)

    def test_the_class_row_survives_as_an_alternative(self):
        from corpora.tier3 import group_by_cve
        rows = [self._row(), self._row(granularity="method", method="go",
                                       start_line=40, end_line=60,
                                       file="tier3/project-sources/s/B.java")]

        self.assertEqual(len(group_by_cve(rows)[0]["alt_locations"]), 1)

    def test_dataset_order_decides_between_two_method_rows(self):
        """Not size. Preferring the narrowest method biases hard toward trivial
        getters — a fix that adds a field also adds its accessor, and a
        three-line `getPath()` is never the vulnerability. The dataset is
        manually vetted, so its own ordering is better evidence than length."""
        from corpora.tier3 import group_by_cve
        rows = [self._row(granularity="method", method="core", start_line=1, end_line=200),
                self._row(granularity="method", method="accessor", start_line=40, end_line=42,
                          file="tier3/project-sources/s/B.java")]

        self.assertEqual(group_by_cve(rows)[0]["method"], "core")

    def test_a_class_only_cve_still_produces_a_case(self):
        from corpora.tier3 import group_by_cve
        self.assertEqual(group_by_cve([self._row()])[0]["granularity"], "class")


if __name__ == "__main__":
    unittest.main()
