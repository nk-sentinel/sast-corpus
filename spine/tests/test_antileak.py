import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lint.antileak import scan_tree


class LintCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def scan(self):
        return scan_tree(self.root)

    def kinds(self, leaks):
        return sorted({leak.kind for leak in leaks})


CLEAN_JAVA = """package app;

import java.sql.Connection;
import java.sql.Statement;

public class OrderRepository {
    private final Connection connection;

    OrderRepository(Connection connection) {
        this.connection = connection;
    }

    public void fetch(String id) throws Exception {
        Statement statement = connection.createStatement();
        statement.execute("SELECT * FROM orders WHERE id = '" + id + "'");
    }
}
"""


class CleanFixtures(unittest.TestCase, ):
    pass


class Tier1IsStrict(LintCase):
    """Tier 1 is ours, so every leak is fixable and therefore fatal."""

    def test_a_clean_fixture_passes(self):
        self.write("tier1/java/a7f3e91b/OrderRepository.java", CLEAN_JAVA)

        errors, _warnings = self.scan()

        self.assertEqual(errors, [])

    def test_a_cwe_identifier_in_the_content_is_an_error(self):
        self.write("tier1/java/a7f3e91b/A.java", "// CWE-89 lives here\nclass A {}\n")

        errors, _ = self.scan()

        self.assertIn("cwe-in-content", self.kinds(errors))

    def test_a_cwe_identifier_in_the_path_is_an_error(self):
        self.write("tier1/java/cwe-89/A.java", "class A {}\n")

        errors, _ = self.scan()

        self.assertIn("cwe-in-path", self.kinds(errors))

    def test_a_giveaway_word_in_a_filename_is_an_error(self):
        self.write("tier1/java/a7f3e91b/VulnerableOrder.java", "class VulnerableOrder {}\n")

        errors, _ = self.scan()

        self.assertIn("hint-in-path", self.kinds(errors))

    def test_a_giveaway_word_in_an_identifier_is_an_error(self):
        self.write("tier1/java/a7f3e91b/A.java", "class A { void unsafeQuery() {} }\n")

        errors, _ = self.scan()

        self.assertIn("hint-in-content", self.kinds(errors))

    def test_juliet_style_good_and_bad_naming_is_an_error(self):
        self.write("tier1/java/a7f3e91b/A.java", "class A { void badSink() {} }\n")

        errors, _ = self.scan()

        self.assertIn("hint-in-content", self.kinds(errors))

    def test_a_semgrep_rule_annotation_is_an_error(self):
        self.write("tier1/python/a7f3e91b/v.py", "# ruleid: sql-injection\nq(x)\n")

        errors, _ = self.scan()

        self.assertIn("rule-annotation", self.kinds(errors))

    def test_a_semgrep_ok_annotation_is_an_error(self):
        self.write("tier1/python/a7f3e91b/v.py", "# ok: sql-injection\nq(x)\n")

        errors, _ = self.scan()

        self.assertIn("rule-annotation", self.kinds(errors))

    def test_an_answer_key_committed_inside_a_tier_is_an_error(self):
        self.write("tier1/java/a7f3e91b/expectedresults-1.0.csv", "id,label\n")

        errors, _ = self.scan()

        self.assertIn("answer-key-in-tier", self.kinds(errors))


class CommentsInTier1(LintCase):
    """Generated fixtures carry no prose at all — there is no natural-language
    hint for a model to latch onto."""

    def test_a_line_comment_is_an_error(self):
        self.write("tier1/java/a7f3e91b/A.java", "class A {\n    // build the query\n}\n")

        errors, _ = self.scan()

        self.assertIn("comment", self.kinds(errors))

    def test_a_block_comment_is_an_error(self):
        self.write("tier1/java/a7f3e91b/A.java", "/* helper */\nclass A {}\n")

        errors, _ = self.scan()

        self.assertIn("comment", self.kinds(errors))

    def test_a_hash_comment_is_an_error(self):
        self.write("tier1/python/a7f3e91b/v.py", "# helper\nx = 1\n")

        errors, _ = self.scan()

        self.assertIn("comment", self.kinds(errors))

    def test_a_url_containing_a_double_slash_is_not_a_comment(self):
        self.write("tier1/java/a7f3e91b/A.java", 'class A { String u = "https://example.com/x"; }\n')

        errors, _ = self.scan()

        self.assertNotIn("comment", self.kinds(errors))

    def test_a_hash_inside_a_string_is_not_a_comment(self):
        self.write("tier1/python/a7f3e91b/v.py", 'x = "#ffffff"\n')

        errors, _ = self.scan()

        self.assertNotIn("comment", self.kinds(errors))


class AmbiguousWordsMatchWholeTokensOnly(LintCase):
    """Fixtures for build-required engines must compile, which means standard
    project layout. A lint that rejects src/main/resources/ is a lint people
    will disable."""

    def test_a_maven_resources_directory_is_not_a_leak(self):
        self.write("tier1/java/a7f3e91b/src/main/resources/app.properties", "a=b\n")

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_a_directory_actually_named_source_is_a_leak(self):
        self.write("tier1/java/a7f3e91b/source/A.java", "class A {}\n")

        errors, _ = self.scan()

        self.assertIn("hint-in-path", self.kinds(errors))

    def test_a_file_named_taintSource_is_a_leak(self):
        self.write("tier1/java/a7f3e91b/TaintSource.java", "class TaintSource {}\n")

        errors, _ = self.scan()

        self.assertIn("hint-in-path", self.kinds(errors))

    def test_an_unambiguous_giveaway_is_caught_even_inside_a_longer_word(self):
        self.write("tier1/java/a7f3e91b/SqliDemoRunner.java", "class SqliDemoRunner {}\n")

        errors, _ = self.scan()

        self.assertIn("hint-in-path", self.kinds(errors))

    def test_the_sqlite_library_is_not_mistaken_for_a_giveaway(self):
        """`sqlite3` contains `sqli`. Flagging it would make every fixture that
        uses the stdlib database module unusable."""
        self.write("tier1/python/a7f3e91b/store.py", "import sqlite3\n\nx = sqlite3.connect('a.db')\n")

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_a_sqlite_filename_is_not_a_giveaway_either(self):
        self.write("tier1/python/a7f3e91b/sqlite_store.py", "x = 1\n")

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_the_mysqli_extension_is_not_mistaken_for_a_giveaway(self):
        """`mysqli` contains `sqli` too. Patching one library name at a time is
        whack-a-mole; the word has to be matched as a token."""
        self.write("tier1/php/a7f3e91b/store.php", "<?php\n\n$r = mysqli_query($link, $statement);\n")

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_a_giveaway_token_inside_an_identifier_is_still_caught(self):
        self.write("tier1/python/a7f3e91b/store.py", "def sqli_demo():\n    pass\n")

        errors, _ = self.scan()

        self.assertIn("hint-in-content", self.kinds(errors))

    def test_a_camel_case_giveaway_token_is_still_caught(self):
        self.write("tier1/java/a7f3e91b/A.java", "class A { void runSqliCheck() {} }\n")

        errors, _ = self.scan()

        self.assertIn("hint-in-content", self.kinds(errors))


class Tier2And3AreDisclosedNotFailed(LintCase):
    """Real applications cannot be edited to remove their own hints. WebGoat
    ships classes literally named SqlInjectionLesson5. Failing CI on that would
    only push people to drop the realistic tiers, so it is reported instead and
    the scorecard discloses it."""

    def test_a_leak_in_tier2_is_a_warning_not_an_error(self):
        self.write("tier2/webgoat/SqlInjectionLesson5.java", "// CWE-89\nclass X {}\n")

        errors, warnings = self.scan()

        self.assertEqual(errors, [])
        self.assertTrue(warnings)

    def test_a_leak_in_tier3_is_a_warning_not_an_error(self):
        self.write("tier3/cve-2021-44228/Vulnerable.java", "// unsafe lookup\nclass X {}\n")

        errors, warnings = self.scan()

        self.assertEqual(errors, [])
        self.assertTrue(warnings)


class ScopeOfTheScan(LintCase):
    def test_documentation_may_discuss_cwes_freely(self):
        self.write("docs/METHODOLOGY.md", "We cover CWE-89 and CWE-79.\n")

        errors, warnings = self.scan()

        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_the_answer_key_itself_is_not_scanned(self):
        self.write("answers/cases/c-a7f3e91b.yml", "primary_cwe: CWE-89\n")

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_the_spine_may_mention_cwes(self):
        self.write("spine/score/score.py", 'CWE_PATTERN = "CWE-89"\n')

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_binary_files_are_skipped_rather_than_crashing_the_lint(self):
        path = self.root / "tier1" / "java" / "a7f3e91b" / "blob.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(range(256)))

        errors, _ = self.scan()

        self.assertEqual(errors, [])


class LeakDetail(LintCase):
    def test_a_leak_reports_the_file_and_line_so_it_can_be_fixed(self):
        self.write("tier1/java/a7f3e91b/A.java", "class A {}\n// CWE-89\n")

        errors, _ = self.scan()

        self.assertEqual(errors[0].line, 2)
        self.assertIn("A.java", errors[0].path)


if __name__ == "__main__":
    unittest.main()


class CorpusMetadataIsNotFixtureCode(LintCase):
    """A tier's own manifest describes what is in it, so it names weaknesses by
    design. Reporting it as a leak buries the real disclosed leaks from vendored
    code underneath noise on every run."""

    def test_a_tier_manifest_is_not_scanned(self):
        self.write("tier2/sources.json",
                   '{"description": "vulnerable applications", "sources": []}')

        errors, warnings = self.scan()

        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_a_readme_at_the_tier_root_is_not_scanned(self):
        self.write("tier3/README.md", "These reproduce real injection CVEs.\n")

        errors, warnings = self.scan()

        self.assertEqual(warnings, [])

    def test_vendored_code_below_a_tier_is_still_scanned(self):
        self.write("tier2/webgoat/SqlInjectionLesson5.java", "// CWE-89\nclass X {}\n")

        _errors, warnings = self.scan()

        self.assertTrue(warnings)
