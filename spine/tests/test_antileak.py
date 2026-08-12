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

    def scan(self, disclose=False):
        return scan_tree(self.root, disclose=disclose)

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

        errors, warnings = self.scan(disclose=True)

        self.assertEqual(errors, [])
        self.assertTrue(warnings)

    def test_a_leak_in_tier3_is_a_warning_not_an_error(self):
        self.write("tier3/cve-2021-44228/Vulnerable.java", "// unsafe lookup\nclass X {}\n")

        errors, warnings = self.scan(disclose=True)

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

        _errors, warnings = self.scan(disclose=True)

        self.assertTrue(warnings)


class DisclosedLeaksAreSummarised(unittest.TestCase):
    """Vendored tiers hold whole real repositories. Printing every leaking line
    buries the errors that matter under thousands of lines nobody reads, and the
    disclosure a scorecard needs is a count, not a listing."""

    def test_summary_counts_by_kind(self):
        from lint.antileak import summarise_warnings
        from lint.antileak import Leak
        warnings = [Leak("tier2/a/A.java", 1, "cwe-in-content", "x"),
                    Leak("tier2/a/B.java", 2, "cwe-in-content", "y"),
                    Leak("tier2/a/C.java", 0, "hint-in-path", "z")]

        summary = summarise_warnings(warnings)

        self.assertEqual(summary["by_kind"]["cwe-in-content"], 2)
        self.assertEqual(summary["total"], 3)

    def test_summary_counts_affected_files_not_just_lines(self):
        from lint.antileak import summarise_warnings, Leak
        warnings = [Leak("tier2/a/A.java", 1, "cwe-in-content", "x"),
                    Leak("tier2/a/A.java", 9, "cwe-in-content", "y")]

        self.assertEqual(summarise_warnings(warnings)["files"], 1)

    def test_summary_groups_by_tier(self):
        from lint.antileak import summarise_warnings, Leak
        warnings = [Leak("tier2/a/A.java", 1, "cwe-in-content", "x"),
                    Leak("tier3/b/B.java", 1, "cwe-in-content", "y")]

        summary = summarise_warnings(warnings)

        self.assertEqual(summary["by_tier"], {"tier2": 1, "tier3": 1})

    def test_an_empty_warning_set_summarises_cleanly(self):
        from lint.antileak import summarise_warnings
        self.assertEqual(summarise_warnings([])["total"], 0)


class ProvisionedToolchainsAreNotCorpusContent(LintCase):
    """Fetching tier 3 puts whole JDK and Maven distributions under it. Walking
    those made the lint take minutes instead of a second, and CI runs this gate
    on every push — a slow gate is a gate people route around."""

    def test_a_downloaded_jdk_is_not_scanned(self):
        self.write("tier3/cwe-bench-java/java-env/jdk-17/lib/src.zip.txt", "unsafe\n")

        _errors, warnings = self.scan(disclose=True)

        self.assertEqual(warnings, [])

    def test_a_maven_distribution_is_not_scanned(self):
        self.write("tier3/cwe-bench-java/java-env/apache-maven-3.9.8/README.txt", "vulnerable\n")

        _errors, warnings = self.scan(disclose=True)

        self.assertEqual(warnings, [])

    def test_build_output_is_not_scanned(self):
        self.write("tier3/project-sources/p/target/classes/X.class.txt", "unsafe\n")
        self.write("tier1/java/aaaa/target/classes/Y.txt", "unsafe\n")

        errors, warnings = self.scan(disclose=True)

        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_git_internals_are_not_scanned(self):
        self.write("tier3/project-sources/p/.git/COMMIT_EDITMSG", "fix the vulnerable parser\n")

        _errors, warnings = self.scan(disclose=True)

        self.assertEqual(warnings, [])

    def test_actual_project_source_is_still_scanned(self):
        self.write("tier3/project-sources/p/src/main/java/A.java", "// CWE-89\nclass A {}\n")

        _errors, warnings = self.scan(disclose=True)

        self.assertTrue(warnings)


class TheGateAndTheDisclosureAreDifferentJobs(LintCase):
    """Enforcement is about fixtures we authored and must run on every push.
    The disclosure statistic covers whole vendored repositories, costs a minute,
    and is only needed when producing a scorecard. Charging every push for the
    report is how a gate ends up disabled."""

    def test_by_default_only_authored_tiers_are_walked(self):
        self.write("tier1/java/aaaa/A.java", "// CWE-89\nclass A {}\n")
        self.write("tier2/webgoat/B.java", "// CWE-89\nclass B {}\n")

        errors, warnings = self.scan()

        self.assertTrue(errors)
        self.assertEqual(warnings, [])

    def test_the_disclosure_pass_covers_vendored_tiers_when_asked(self):
        from lint.antileak import scan_tree
        self.write("tier2/webgoat/B.java", "// CWE-89\nclass B {}\n")

        _errors, warnings = scan_tree(self.root, disclose=True)

        self.assertTrue(warnings)

    def test_the_gate_result_is_identical_either_way(self):
        from lint.antileak import scan_tree
        self.write("tier1/java/aaaa/A.java", "// CWE-89\nclass A {}\n")
        self.write("tier2/webgoat/B.java", "// CWE-89\nclass B {}\n")

        fast, _ = scan_tree(self.root)
        full, _ = scan_tree(self.root, disclose=True)

        self.assertEqual(fast, full)


class ContextTrapsNeedTheThingTheLintForbids(LintCase):
    """A trap testing 'MD5 named in a changelog is not a crypto finding' has to
    contain the word MD5 in a changelog. A trap testing 'a weak algorithm named
    in a comment is not a finding' has to contain a comment.

    The waiver is read from the answer key rather than from a marker beside the
    fixture, because a marker beside the fixture is ground truth outside
    `answers/` — the one rule the whole corpus rests on.
    """

    def key(self, *rows):
        header = ("id,label,plane,tier,language,framework,primary_cwe,variant,acceptable_cwes,"
                  "owasp_2021,severity,file,start_line,end_line,alt_locations,flow,sanitizer,"
                  "obfuscation,build_required")
        self.write("answers/expectedresults-1.0.csv", header + "\n" + "\n".join(rows) + "\n")

    def row(self, path, variant, label="safe"):
        return ("c-aaaaaaaa,{label},vuln,1,java,,CWE-327,{variant},CWE-327,A02,high,"
                "{path},1,1,,intra-procedural,none,none,false").format(
                    label=label, variant=variant, path=path)

    def test_a_context_trap_may_carry_a_comment(self):
        self.write("tier1/java/aaaa/Notes.java", "// uses MD5 for cache keys\nclass Notes {}\n")
        self.key(self.row("tier1/java/aaaa/Notes.java", "in-comment"))

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_a_context_trap_may_name_the_weakness_in_markdown(self):
        self.write("tier1/java/aaaa/CHANGELOG.md", "# Changes\n\n- replaced MD5 with SHA-256\n")
        self.key(self.row("tier1/java/aaaa/CHANGELOG.md", "in-markdown"))

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_the_waiver_applies_only_to_the_file_the_answer_key_names(self):
        self.write("tier1/java/aaaa/Notes.java", "// uses MD5 for cache keys\nclass Notes {}\n")
        self.write("tier1/java/aaaa/Other.java", "// an ordinary comment\nclass Other {}\n")
        self.key(self.row("tier1/java/aaaa/Notes.java", "in-comment"))

        errors, _ = self.scan()

        self.assertTrue(any("Other.java" in e.path for e in errors))
        self.assertFalse(any("Notes.java" in e.path for e in errors))

    def test_a_non_context_variant_earns_no_waiver(self):
        self.write("tier1/java/aaaa/Store.java", "// build the query\nclass Store {}\n")
        self.key(self.row("tier1/java/aaaa/Store.java", "concat-statement", label="vulnerable"))

        errors, _ = self.scan()

        self.assertTrue(errors)

    def test_without_an_answer_key_nothing_is_waived(self):
        self.write("tier1/java/aaaa/Notes.java", "// uses MD5\nclass Notes {}\n")

        errors, _ = self.scan()

        self.assertTrue(errors)


class RealApiNamesThatLookLikeHints(LintCase):
    """CryptoKit puts MD5 and SHA1 under an enum literally named `Insecure`, so
    the correct Swift spelling of a weak-hash fixture contains one of the lint's
    own hint words. Flagging it would make every Swift crypto case unusable —
    the same failure as `sqlite3` containing `sqli`."""

    def test_cryptokit_insecure_namespace_is_not_a_hint(self):
        self.write("tier1/swift/aaaa/Work.swift",
                   "import CryptoKit\n\nlet d = Insecure.MD5.hash(data: Data())\n")

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_insecure_sha1_is_also_permitted(self):
        self.write("tier1/swift/aaaa/Work.swift",
                   "import CryptoKit\n\nlet d = Insecure.SHA1.hash(data: Data())\n")

        self.assertEqual(self.scan()[0], [])

    def test_an_identifier_actually_named_insecure_is_still_a_hint(self):
        self.write("tier1/swift/aaaa/Work.swift", "let insecureQuery = 1\n")

        errors, _ = self.scan()

        self.assertIn("hint-in-content", self.kinds(errors))

    def test_the_word_on_its_own_is_still_a_hint(self):
        self.write("tier1/java/aaaa/A.java", "class A { void insecure() {} }\n")

        self.assertIn("hint-in-content", self.kinds(self.scan()[0]))


class LanguageIdiomsThatLookLikeAnnotations(LintCase):
    """Semgrep marks expected findings with `ruleid:` and `ok:` in comments. Go's
    comma-ok idiom writes `value, ok := m[key]`, which contains `ok :` and is one
    of the most common lines in the language — flagging it would make Go
    fixtures unwritable."""

    def test_go_comma_ok_is_not_an_annotation(self):
        self.write("tier1/go/aaaa/work.go",
                   "package main\n\nfunc f(m map[string]string, k string) string {\n"
                   "\tv, ok := m[k]\n\tif !ok {\n\t\treturn \"\"\n\t}\n\treturn v\n}\n")

        errors, _ = self.scan()

        self.assertEqual(errors, [])

    def test_a_real_annotation_is_still_caught(self):
        self.write("tier1/go/aaaa/work.go", "package main\n\n// ok: some-rule-name\n")

        self.assertIn("rule-annotation", self.kinds(self.scan()[0]))

    def test_a_ruleid_annotation_is_still_caught(self):
        self.write("tier1/python/aaaa/work.py", "# ruleid: taint-flow\nx = 1\n")

        self.assertIn("rule-annotation", self.kinds(self.scan()[0]))

    def test_a_walrus_assignment_is_not_an_annotation(self):
        # Python's := has the same shape.
        self.write("tier1/python/aaaa/work.py", "if (ok := check()):\n    pass\n")

        self.assertEqual(self.scan()[0], [])
