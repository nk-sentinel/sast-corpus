#!/usr/bin/env python3
"""Generate docs/COVERAGE.md from the answer key.

The first question anyone asks of a corpus is whether it can evaluate a tool for
*their* stack. That answer has to come from the ground truth itself, because a
hand-maintained coverage table drifts the moment someone adds a case and forgets
the doc — and a stale coverage table is worse than none: it claims a language is
covered when nothing tests it, so a tool with no support for that language
sails through.

So this reads answers/expectedresults-<version>.csv and CI fails if the
committed doc differs from what the corpus currently contains.

The empty cells matter more than the full ones. A missing language is invisible
in a scorecard — it simply contributes no cases — and looks exactly like a tool
having nothing to find.
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

# Languages the schema admits. A language absent from the corpus is still listed,
# because "we cannot evaluate Swift" is the useful fact.
TARGET_LANGUAGES = [
    "java", "kotlin", "python", "javascript", "typescript", "go",
    "csharp", "c", "cpp", "swift", "php", "ruby", "rust",
]

# Weaknesses in scope, drawn from the OWASP Top 10 and the CWE Top 25 classes a
# static analyser can reasonably be expected to reach.
TARGET_CWES = [
    "CWE-89",   # SQL injection
    "CWE-78",   # OS command injection
    "CWE-79",   # cross-site scripting
    "CWE-22",   # path traversal
    "CWE-502",  # deserialisation of untrusted data
    "CWE-918",  # server-side request forgery
    "CWE-611",  # XML external entity
    "CWE-798",  # hard-coded credentials
    "CWE-327",  # broken or risky cryptographic algorithm
    "CWE-352",  # cross-site request forgery
]

CWE_NAMES = {
    "CWE-22": "path traversal",
    "CWE-78": "OS command injection",
    "CWE-79": "cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-327": "broken crypto",
    "CWE-352": "cross-site request forgery",
    "CWE-502": "unsafe deserialisation",
    "CWE-611": "XML external entity",
    "CWE-798": "hard-coded credentials",
    "CWE-918": "server-side request forgery",
    "CWE-94": "code injection",
}

OWASP_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


@dataclass(frozen=True)
class Cell:
    vulnerable: int = 0
    safe: int = 0

    @property
    def total(self):
        return self.vulnerable + self.safe


def load_rows(path):
    with Path(path).open(newline="") as handle:
        return list(csv.DictReader(handle))


def matrix(rows):
    """(language, cwe) -> Cell. Absent cells are absent, not zero."""
    counts = defaultdict(lambda: [0, 0])
    for row in rows:
        key = (row["language"], row["primary_cwe"])
        counts[key][0 if row["label"] == "vulnerable" else 1] += 1
    return {key: Cell(vulnerable=v, safe=s) for key, (v, s) in counts.items()}


def gaps(rows, languages, cwes):
    """Three distinct kinds of hole, because they need different fixes."""
    grid = matrix(rows)
    missing, untrapped, no_positive = [], [], []

    for language in languages:
        for cwe in cwes:
            cell = grid.get((language, cwe))
            if cell is None:
                missing.append((language, cwe))
            elif cell.safe == 0:
                untrapped.append((language, cwe))
            elif cell.vulnerable == 0:
                no_positive.append((language, cwe))

    return {"missing": missing, "untrapped": untrapped, "no_positive": no_positive}


def summarise(rows):
    return {
        "cases": len(rows),
        "traps": sum(1 for r in rows if r["label"] == "safe"),
        "languages": len({r["language"] for r in rows}),
        "cwes": len({r["primary_cwe"] for r in rows}),
        "build_required": sum(1 for r in rows if r["build_required"].strip().lower() == "true"),
        "by_flow": dict(Counter(r["flow"] for r in rows)),
        "by_sanitizer": dict(Counter(r["sanitizer"] for r in rows)),
        "by_tier": dict(Counter(r["tier"] for r in rows)),
        "by_plane": dict(Counter(r["plane"] for r in rows)),
        "by_language": dict(Counter(r["language"] for r in rows)),
        "by_owasp": dict(Counter(r["owasp_2021"] for r in rows if r["owasp_2021"])),
    }


def render(rows, languages=None, cwes=None):
    languages = languages or TARGET_LANGUAGES
    cwes = cwes or TARGET_CWES
    grid = matrix(rows)
    summary = summarise(rows)
    hole = gaps(rows, languages, cwes)

    present_languages = [lang for lang in languages if summary["by_language"].get(lang)]
    absent_languages = [lang for lang in languages if not summary["by_language"].get(lang)]
    extra_cwes = sorted(
        {row["primary_cwe"] for row in rows} - set(cwes),
        key=lambda c: int(c.split("-")[1]),
    )

    out = [
        "# Coverage",
        "",
        "Generated from `answers/expectedresults-1.0.csv` by "
        "`spine/report/coverage.py`. Do not edit by hand — CI regenerates it and "
        "fails if this file has drifted from the corpus.",
        "",
        "A cell reads `v/s`: vulnerable cases and safe siblings. A weakness with "
        "no safe sibling cannot measure a false-positive rate, and a language "
        "with no cases at all contributes nothing to a scorecard — which looks "
        "exactly like a tool having nothing to find. Both are listed below.",
        "",
        "## Totals",
        "",
        "| | |",
        "|---|---|",
        "| Cases | {} |".format(summary["cases"]),
        "| False-positive traps | {} ({:.0%}) |".format(
            summary["traps"], summary["traps"] / summary["cases"] if summary["cases"] else 0),
        "| Languages covered | {} of {} |".format(len(present_languages), len(languages)),
        "| Target weaknesses covered | {} of {} |".format(
            len({c for _, c in grid} & set(cwes)), len(cwes)),
        "| Visible to build-required engines | {} |".format(summary["build_required"]),
        "",
        "## Language × weakness",
        "",
    ]

    used_cwes = [c for c in cwes if any((lang, c) in grid for lang in languages)] + extra_cwes
    header = "| language | " + " | ".join(used_cwes) + " |"
    out.append(header)
    out.append("|" + "---|" * (len(used_cwes) + 1))

    for language in present_languages:
        cells = []
        for cwe in used_cwes:
            cell = grid.get((language, cwe))
            cells.append("{}/{}".format(cell.vulnerable, cell.safe) if cell else "·")
        out.append("| {} | {} |".format(language, " | ".join(cells)))

    out += ["", "Weakness codes:", ""]
    for cwe in used_cwes:
        out.append("- `{}` — {}".format(cwe, CWE_NAMES.get(cwe, "")))

    out += ["", "## Gaps", ""]

    if absent_languages:
        out += [
            "**No cases at all — these languages cannot be evaluated:** {}".format(
                ", ".join("`{}`".format(l) for l in absent_languages)),
            "",
        ]

    uncovered = [c for c in cwes if not any((lang, c) in grid for lang in languages)]
    if uncovered:
        out += [
            "**No cases in any language:** {}".format(
                ", ".join("`{}` ({})".format(c, CWE_NAMES.get(c, "")) for c in uncovered)),
            "",
        ]

    if hole["untrapped"]:
        out += [
            "**Covered but with no safe sibling** — a false-positive rate cannot "
            "be measured for these:",
            "",
        ]
        out += ["- {} / `{}`".format(lang, cwe) for lang, cwe in hole["untrapped"]]
        out.append("")

    if hole["no_positive"]:
        out += ["**Traps with no matching vulnerable case:**", ""]
        out += ["- {} / `{}`".format(lang, cwe) for lang, cwe in hole["no_positive"]]
        out.append("")

    if not (absent_languages or uncovered or hole["untrapped"] or hole["no_positive"]):
        out += ["None. Every target language and weakness has a vulnerable case "
                "and a safe sibling.", ""]

    out += ["## OWASP Top 10 (2021)", "", "| category | cases |", "|---|---|"]
    for code in sorted(OWASP_NAMES):
        count = summary["by_owasp"].get(code, 0)
        out.append("| {} {} | {} |".format(code, OWASP_NAMES[code], count or "·"))

    out += ["", "## Detection planes", "", "| plane | cases |", "|---|---|"]
    for plane in ("vuln", "secret", "sca", "crypto"):
        out.append("| {} | {} |".format(plane, summary["by_plane"].get(plane, 0) or "·"))
    out += [
        "",
        "`crypto` is delegated to the `CipherRadarTestProj` submodule and is not "
        "counted here.",
        "",
        "## Realism tiers",
        "",
        "| tier | cases |",
        "|---|---|",
    ]
    for tier, label in (("1", "synthetic fixtures"), ("2", "real applications"), ("3", "CVE reproductions")):
        out.append("| {} — {} | {} |".format(tier, label, summary["by_tier"].get(tier, 0) or "·"))

    out += ["", "## Difficulty", "", "| taint path | cases |", "|---|---|"]
    for flow in ("intra-procedural", "inter-procedural", "inter-file", "framework-mediated"):
        out.append("| {} | {} |".format(flow, summary["by_flow"].get(flow, 0) or "·"))

    out += ["", "| sanitizer | cases |", "|---|---|"]
    for sanitizer in ("none", "ineffective", "custom-effective", "framework-implicit"):
        out.append("| {} | {} |".format(sanitizer, summary["by_sanitizer"].get(sanitizer, 0) or "·"))

    out.append("")
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--answer-key", type=Path,
                        default=root / "answers" / "expectedresults-1.0.csv")
    parser.add_argument("--out", type=Path, default=root / "docs" / "COVERAGE.md")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if the committed doc has drifted from the corpus")
    args = parser.parse_args(argv)

    text = render(load_rows(args.answer_key))

    if args.check:
        current = args.out.read_text() if args.out.is_file() else ""
        if current != text:
            print("{} is stale; run spine/report/coverage.py".format(args.out), file=sys.stderr)
            return 1
        print("coverage doc is current")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text)
    print("wrote {}".format(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
