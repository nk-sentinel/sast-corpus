import csv
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schema.compile_answers import compile_answer_key

CASE_YAML = """
id: c-a7f3e91b
label: vulnerable
plane: vuln
tier: 1
language: java
framework: spring-mvc
primary_cwe: CWE-89
acceptable_cwes: [CWE-89, CWE-943]
owasp_2021: A03
severity: high
location:
  file: tier1/java/a7f3e91b/OrderRepository.java
  start_line: 4
  end_line: 6
alt_locations: []
difficulty:
  flow: intra-procedural
  sanitizer: none
  obfuscation: none
evidence:
  source: hand-authored
  rationale: request parameter is concatenated into a Statement.execute call
  cve: null
build:
  required: true
  recipe: build/java/maven-offline.sh
"""

BROKEN_CASE_YAML = CASE_YAML.replace(
    "acceptable_cwes: [CWE-89, CWE-943]", "acceptable_cwes: [CWE-79]"
)


class CompileAnswerKey(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "answers" / "cases").mkdir(parents=True)
        fixture = self.root / "tier1" / "java" / "a7f3e91b"
        fixture.mkdir(parents=True)
        (fixture / "OrderRepository.java").write_text("a\nb\nc\nd\ne\nf\ng\n")
        shutil.copy(
            Path(__file__).resolve().parents[1] / "schema" / "case.schema.json",
            self.root / "case.schema.json",
        )

    def write_case(self, name, body):
        (self.root / "answers" / "cases" / name).write_text(body)

    def compile(self):
        return compile_answer_key(
            self.root,
            schema_path=self.root / "case.schema.json",
            out_path=self.root / "answers" / "expectedresults-test.csv",
        )

    def test_writes_one_row_per_case_with_the_declared_columns(self):
        self.write_case("c-a7f3e91b.yml", CASE_YAML)

        errors = self.compile()

        self.assertEqual(errors, [])
        with (self.root / "answers" / "expectedresults-test.csv").open() as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "c-a7f3e91b")
        self.assertEqual(rows[0]["acceptable_cwes"], "CWE-89;CWE-943")
        self.assertEqual(rows[0]["build_required"], "true")

    def test_reports_errors_and_writes_nothing_when_a_case_is_invalid(self):
        self.write_case("c-a7f3e91b.yml", BROKEN_CASE_YAML)

        errors = self.compile()

        self.assertEqual(len(errors), 1)
        self.assertIn("c-a7f3e91b", errors[0])
        self.assertFalse((self.root / "answers" / "expectedresults-test.csv").exists())

    def test_reports_schema_violations_with_the_offending_case_id(self):
        self.write_case("c-a7f3e91b.yml", CASE_YAML.replace("severity: high", "severity: urgent"))

        errors = self.compile()

        self.assertTrue(any("urgent" in e for e in errors), errors)

    def test_sorts_rows_by_id_so_the_answer_key_diffs_cleanly(self):
        self.write_case("b.yml", CASE_YAML.replace("c-a7f3e91b", "c-bbbbbbbb"))
        self.write_case("a.yml", CASE_YAML.replace("c-a7f3e91b", "c-aaaaaaaa"))

        self.assertEqual(self.compile(), [])

        with (self.root / "answers" / "expectedresults-test.csv").open() as handle:
            ids = [row["id"] for row in csv.DictReader(handle)]
        self.assertEqual(ids, ["c-aaaaaaaa", "c-bbbbbbbb"])


if __name__ == "__main__":
    unittest.main()
