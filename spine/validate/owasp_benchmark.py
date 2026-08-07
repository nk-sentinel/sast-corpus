#!/usr/bin/env python3
"""Validate `score.py` against OWASP BenchmarkJava.

Wave 0's exit criterion. Until the scorer reproduces a scorecard derived from
published ground truth, its numbers are self-consistent rather than correct.

The check is differential. `reference_score` re-implements the OWASP Benchmark
rule directly from its definition — a test case is one file with one intentional
CWE, detected when the tool reports that CWE anywhere in the file — without
reference to `score.py`. The same ground truth is then translated into this
corpus's answer-key format and run through `score.py`. The two must agree.

A bug shared by both would have to be invented twice, independently. Agreement
is therefore evidence; a single implementation passing its own tests is not.

    python3 spine/validate/owasp_benchmark.py \\
        --expected expectedresults-1.2.csv \\
        --source BenchmarkJava \\
        --results benchmark-semgrep.sarif
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from score.score import load_answer_key, match_findings, metrics, parse_sarif

TESTCODE_DIR = "src/main/java/org/owasp/benchmark/testcode"


@dataclass(frozen=True)
class TestCase:
    name: str
    category: str
    is_real: bool
    cwe: str


def parse_expected_results(text):
    """Read OWASP's `expectedresults-<version>.csv`.

    Columns: test name, category, real vulnerability, cwe. The first line is a
    comment carrying the benchmark version.
    """
    cases = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 4 or not parts[3].isdigit():
            continue
        cases.append(
            TestCase(
                name=parts[0],
                category=parts[1],
                is_real=parts[2].lower() == "true",
                cwe="CWE-{}".format(int(parts[3])),
            )
        )
    return cases


def reference_score(findings, cases):
    """The OWASP Benchmark rule, implemented from its definition.

    Deliberately independent of score.py: file-level granularity, exact CWE,
    each case counted once, findings outside a known test case ignored.
    """
    by_name = {case.name: case for case in cases}
    detected = set()

    for finding in findings:
        name = Path(finding.file).stem
        case = by_name.get(name)
        if case and case.cwe in finding.cwes:
            detected.add(name)

    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case in cases:
        hit = case.name in detected
        if case.is_real:
            counts["tp" if hit else "fn"] += 1
        else:
            counts["fp" if hit else "tn"] += 1

    return counts


def to_answer_key(cases, source_root, out_path, path_prefix=TESTCODE_DIR):
    """Translate OWASP ground truth into this corpus's answer-key format.

    Each test case becomes one case spanning its whole file, matching OWASP's
    file-level granularity. `acceptable_cwes` holds only the declared CWE:
    OWASP scores on an exact match, and widening it here would be comparing
    against a different rule.
    """
    source_root = Path(source_root)
    rows = []

    for case in cases:
        relative = "{}/{}.java".format(path_prefix, case.name)
        path = source_root / relative
        line_count = _count_lines(path) if path.is_file() else 1

        rows.append({
            "id": case.name,
            "label": "vulnerable" if case.is_real else "safe",
            "plane": "vuln",
            "tier": 1,
            "language": "java",
            "framework": "servlet",
            "primary_cwe": case.cwe,
            "acceptable_cwes": case.cwe,
            "owasp_2021": "",
            "severity": "high",
            "file": relative,
            "start_line": 1,
            "end_line": max(line_count, 1),
            "alt_locations": "",
            "flow": "intra-procedural",
            "sanitizer": "none" if case.is_real else "custom-effective",
            "obfuscation": "none",
            "build_required": "true",
        })

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    return out_path


def _count_lines(path):
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path, help="BenchmarkJava checkout")
    parser.add_argument("--results", required=True, type=Path, help="SARIF from the tool under test")
    parser.add_argument("--answer-key", type=Path, default=None)
    args = parser.parse_args(argv)

    cases = parse_expected_results(args.expected.read_text())
    findings = parse_sarif(json.loads(args.results.read_text()))

    print("ground truth   {} cases ({} real, {} fake)".format(
        len(cases), sum(c.is_real for c in cases), sum(not c.is_real for c in cases)))
    print("tool findings  {}".format(len(findings)))
    print()

    # Path A: independent implementation of the OWASP rule.
    reference = reference_score(findings, cases)

    # Path B: the corpus scorer, over the same ground truth translated into its
    # own format. Tolerance 0 — the range already spans the whole file, and any
    # padding would let a finding in one file claim a case in another.
    answer_key = args.answer_key or args.results.with_name("owasp-answer-key.csv")
    to_answer_key(cases, args.source, answer_key)
    report = match_findings(findings, load_answer_key(answer_key), tolerance=0)
    ours = report.counts()

    print("{:<12} {:>8} {:>8} {:>8} {:>8}".format("", "tp", "fp", "fn", "tn"))
    print("{:<12} {:>8} {:>8} {:>8} {:>8}".format("reference", *[reference[k] for k in ("tp", "fp", "fn", "tn")]))
    print("{:<12} {:>8} {:>8} {:>8} {:>8}".format("score.py", *[ours[k] for k in ("tp", "fp", "fn", "tn")]))
    print()

    agree = reference == ours
    conserved = sum(ours.values()) == len(cases)

    for label, value in (
        ("scorers agree", agree),
        ("every case counted exactly once", conserved),
    ):
        print("  [{}] {}".format("ok" if value else "FAIL", label))

    if not conserved:
        print("       {} cases counted, {} expected".format(sum(ours.values()), len(cases)))

    print()
    computed = metrics(ours)
    print("recall {:.4f}   precision {:.4f}   tpr {:.4f}   fpr {:.4f}   youden j {:.4f}".format(
        computed["recall"], computed["precision"], computed["tpr"], computed["fpr"], computed["youden_j"]))

    if not (agree and conserved):
        print("\nvalidation FAILED", file=sys.stderr)
        return 1

    print("\nvalidation passed: score.py reproduces an independently implemented "
          "OWASP Benchmark scorecard over {} published cases".format(len(cases)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
