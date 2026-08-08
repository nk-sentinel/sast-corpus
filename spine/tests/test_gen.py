import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gen.generate import Template, Variant, case_id, emit, locate

TEMPLATE = Template(
    slug="py-sqli",
    language="python",
    framework="flask",
    extension="py",
    primary_cwe="CWE-89",
    acceptable_cwes=["CWE-89", "CWE-943"],
    owasp_2021="A03",
    severity="high",
    flow="inter-file",
    obfuscation="none",
    variants={"vulnerable": Variant(
        files={
            "handler.py": "from store import lookup\n\n\ndef show(code):\n    return lookup(code)\n",
            "store.py": 'import sqlite3\n\n\ndef lookup(code):\n    cur = sqlite3.connect("d").cursor()\n    return cur.execute("SELECT a FROM t WHERE c = \'" + code + "\'").fetchone()\n',
        },
        sink_file="store.py",
        sink_match="cur.execute",
        source_file="handler.py",
        source_match="def show",
        sanitizer="none",
        rationale="the request value is concatenated into the statement text with no binding at all",
    ), "safe": Variant(
        files={
            "handler.py": "from store import lookup\n\n\ndef show(code):\n    return lookup(code)\n",
            "store.py": 'import sqlite3\n\n\ndef lookup(code):\n    cur = sqlite3.connect("d").cursor()\n    return cur.execute("SELECT a FROM t WHERE c = ?", (code,)).fetchone()\n',
        },
        sink_file="store.py",
        sink_match="cur.execute",
        source_file="handler.py",
        source_match="def show",
        sanitizer="framework-implicit",
        rationale="the value travels as a bound parameter, so the statement text never contains it",
        label="safe",
    )},
)


class MultipleVariants(unittest.TestCase):
    """A template must be able to emit more than a pair. The most realistic
    false-positive source in real code is a sanitizer that looks effective and
    is not, and that case is vulnerable — so it cannot be the 'safe' slot."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)

        weak = Variant(
            files=TEMPLATE.variants["vulnerable"].files,
            sink_file="store.py",
            sink_match="cur.execute",
            source_file="handler.py",
            source_match="def show",
            sanitizer="ineffective",
            label="vulnerable",
            rationale="the filter strips one quote form and the other still terminates the literal",
        )
        self.template = replace(
            TEMPLATE,
            variants=dict(TEMPLATE.variants, **{"vulnerable-weak-filter": weak}),
        )
        self.cases = emit(self.template, self.root)

    def test_emits_one_case_per_variant(self):
        self.assertEqual(len(self.cases), 3)

    def test_a_third_variant_gets_its_own_directory(self):
        directories = {Path(c["location"]["file"]).parts[2] for c in self.cases}

        self.assertEqual(len(directories), 3)

    def test_an_ineffective_sanitizer_case_is_still_labelled_vulnerable(self):
        case = next(c for c in self.cases if c["difficulty"]["sanitizer"] == "ineffective")

        self.assertEqual(case["label"], "vulnerable")

    def test_adding_a_variant_does_not_change_the_ids_of_the_existing_ones(self):
        """Otherwise every extension rewrites the whole answer key and buries
        the real change."""
        before = emit(TEMPLATE, self.root)

        for case in before:
            self.assertIn(case["id"], {c["id"] for c in self.cases})

    def test_a_variant_may_override_the_template_flow(self):
        single = replace(
            TEMPLATE,
            variants={"vulnerable": replace(TEMPLATE.variants["vulnerable"], flow="intra-procedural")},
        )

        case = emit(single, self.root)[0]

        self.assertEqual(case["difficulty"]["flow"], "intra-procedural")

    def test_a_variant_without_an_override_inherits_the_template_flow(self):
        case = next(c for c in self.cases if c["label"] == "safe")

        self.assertEqual(case["difficulty"]["flow"], TEMPLATE.flow)


class CaseId(unittest.TestCase):
    def test_is_derived_from_the_template_so_regeneration_is_stable(self):
        """A regenerated corpus must diff cleanly; random ids would rewrite the
        whole answer key on every run."""
        self.assertEqual(case_id("py-sqli", "vulnerable"), case_id("py-sqli", "vulnerable"))

    def test_differs_between_the_vulnerable_and_safe_variants(self):
        self.assertNotEqual(case_id("py-sqli", "vulnerable"), case_id("py-sqli", "safe"))

    def test_matches_the_schema_pattern(self):
        import re

        self.assertRegex(case_id("py-sqli", "vulnerable"), r"^c-[0-9a-f]{8}$")

    def test_carries_no_hint_about_which_variant_it_is(self):
        identifier = case_id("py-sqli", "vulnerable")

        for word in ("vuln", "safe", "sqli", "89"):
            self.assertNotIn(word, identifier)


class Locate(unittest.TestCase):
    def test_finds_the_line_holding_the_marker(self):
        self.assertEqual(locate("a\nb\ntarget\nc\n", "target"), (3, 3))

    def test_spans_every_line_holding_the_marker(self):
        self.assertEqual(locate("target\nb\ntarget\n", "target"), (1, 3))

    def test_a_marker_that_is_absent_is_an_error_rather_than_a_silent_line_one(self):
        with self.assertRaises(ValueError):
            locate("a\nb\n", "missing")


class Emit(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.cases = emit(TEMPLATE, self.root)

    def test_produces_a_vulnerable_and_a_safe_case(self):
        self.assertEqual(sorted(c["label"] for c in self.cases), ["safe", "vulnerable"])

    def test_writes_every_file_of_each_variant(self):
        for case in self.cases:
            directory = self.root / Path(case["location"]["file"]).parent
            self.assertTrue((directory / "store.py").is_file())
            self.assertTrue((directory / "handler.py").is_file())

    def test_the_two_variants_live_in_different_directories(self):
        directories = {Path(c["location"]["file"]).parts[2] for c in self.cases}

        self.assertEqual(len(directories), 2)

    def test_resolves_the_sink_to_a_real_line(self):
        case = next(c for c in self.cases if c["label"] == "vulnerable")
        path = self.root / case["location"]["file"]
        lines = path.read_text().splitlines()

        self.assertIn("cur.execute", lines[case["location"]["start_line"] - 1])

    def test_records_the_source_as_an_alternative_location(self):
        case = next(c for c in self.cases if c["label"] == "vulnerable")

        self.assertTrue(case["alt_locations"])
        self.assertTrue(case["alt_locations"][0]["file"].endswith("handler.py"))

    def test_the_safe_variant_carries_its_own_sanitizer_label(self):
        case = next(c for c in self.cases if c["label"] == "safe")

        self.assertEqual(case["difficulty"]["sanitizer"], "framework-implicit")

    def test_marks_the_evidence_as_generated(self):
        self.assertTrue(all(c["evidence"]["source"] == "generated" for c in self.cases))

    def test_emitted_paths_live_under_tier1_and_the_language(self):
        for case in self.cases:
            parts = Path(case["location"]["file"]).parts
            self.assertEqual(parts[0], "tier1")
            self.assertEqual(parts[1], "python")


if __name__ == "__main__":
    unittest.main()


class Planes(unittest.TestCase):
    """The secret and SCA planes carry ground truth the vuln plane has no field
    for. A generator that can only emit `plane: vuln` cannot express them."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)

    def emit_one(self, **template_kwargs):
        base = replace(TEMPLATE, **template_kwargs)
        return emit(base, self.root)[0]

    def test_a_template_declares_its_plane(self):
        case = self.emit_one(plane="secret")

        self.assertEqual(case["plane"], "secret")

    def test_the_plane_defaults_to_vuln(self):
        self.assertEqual(emit(TEMPLATE, self.root)[0]["plane"], "vuln")

    def test_a_secret_case_carries_its_secret_block(self):
        case = self.emit_one(
            plane="secret",
            variants={"vulnerable": replace(
                TEMPLATE.variants["vulnerable"],
                extra_ground_truth={"kind": "aws-access-key", "live_validatable": False},
            )},
        )

        self.assertEqual(case["secret"]["kind"], "aws-access-key")

    def test_an_sca_case_carries_its_purl(self):
        case = self.emit_one(
            plane="sca",
            variants={"vulnerable": replace(
                TEMPLATE.variants["vulnerable"],
                extra_ground_truth={"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                                    "cve": "CVE-2021-44228", "scope": "runtime"},
            )},
        )

        self.assertEqual(case["sca"]["cve"], "CVE-2021-44228")

    def test_a_vuln_case_carries_no_plane_specific_block(self):
        case = emit(TEMPLATE, self.root)[0]

        self.assertNotIn("secret", case)
        self.assertNotIn("sca", case)
