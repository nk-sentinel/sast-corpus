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
    "CWE-1395": "dependency on a vulnerable component",
    "CWE-20": "improper input validation",
    "CWE-77": "command injection",
    "CWE-117": "improper output neutralisation for logs",
    "CWE-120": "buffer copy without size check",
    "CWE-121": "stack-based buffer overflow",
    "CWE-122": "heap-based buffer overflow",
    "CWE-125": "out-of-bounds read",
    "CWE-134": "externally controlled format string",
    "CWE-190": "integer overflow or wraparound",
    "CWE-200": "exposure of sensitive information",
    "CWE-284": "improper access control",
    "CWE-306": "missing authentication for critical function",
    "CWE-416": "use after free",
    "CWE-434": "unrestricted upload of dangerous file type",
    "CWE-476": "NULL pointer dereference",
    "CWE-532": "sensitive information in a log file",
    "CWE-639": "authorisation bypass through user-controlled key",
    "CWE-770": "allocation without limits or throttling",
    "CWE-787": "out-of-bounds write",
    "CWE-862": "missing authorisation",
    "CWE-863": "incorrect authorisation",
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


CONTEXT_VARIANTS = frozenset({
    "in-markdown", "in-comment", "in-test-data", "in-vendored",
    "in-example-config", "in-changelog", "in-licence-header",
})


def variants_by_cwe(rows):
    """Which mechanisms each weakness is tested through.

    A cell holding one case only proves a tool knows the weakness class exists.
    A tool can catch concatenation into a Statement and miss every other route
    to the same CWE — a query concatenated before being prepared, an identifier
    that cannot be bound at all, an ORM raw fragment.
    """
    found = {}
    for row in rows:
        variant = (row.get("variant") or "").strip() or "(unlabelled)"
        found.setdefault(row["primary_cwe"], set()).add(variant)
    return found


def split_variants(variants):
    """Mechanisms and context traps, reported apart.

    They answer different questions. A mechanism asks whether the tool follows
    this route to the weakness; a context trap asks whether it can tell code
    from prose, test data or a vendored tree — which is where real scanners
    generate much of their noise.
    """
    mechanisms = sorted(v for v in variants if v not in CONTEXT_VARIANTS)
    contexts = sorted(v for v in variants if v in CONTEXT_VARIANTS)
    return mechanisms, contexts


def depth_by_language(rows):
    """Distinct weaknesses tested per language.

    A total across the whole corpus hides concentration. Thirty-three CWEs in
    three languages is a different corpus from thirty-three spread evenly, and
    only the second supports a claim about a polyglot estate — so the per
    language figure is the one that answers "can this evaluate a tool for my
    stack".
    """
    found = {}
    for row in rows:
        found.setdefault(row["language"], set()).add(row["primary_cwe"])
    return {language: len(cwes) for language, cwes in found.items()}


def density(rows):
    """Filled fraction of the language-by-weakness grid the corpus spans.

    Measured against the languages and weaknesses actually present, not against
    the target list, so it answers how evenly the existing material is spread
    rather than how much of the ambition is met.
    """
    languages = {row["language"] for row in rows}
    cwes = {row["primary_cwe"] for row in rows}
    if not languages or not cwes:
        return 0.0
    filled = {(row["language"], row["primary_cwe"]) for row in rows}
    return len(filled) / (len(languages) * len(cwes))


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

    # Ranked here rather than at the depth section below: the totals block
    # quotes the two ends of this list, and it must be the same ranking the
    # reader sees further down. Depth is a tier-1 measure — tier-3 rows come
    # from whatever CVEs the upstream dataset happens to contain, so counting
    # them would credit breadth nobody designed.
    tier1 = [r for r in rows if r.get("tier") == "1"]
    depth = sorted(depth_by_language(tier1 or rows).items(),
                   key=lambda kv: (-kv[1], kv[0]))

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
        "| Distinct weaknesses | {} |".format(len({c for _, c in grid})),
        # Stated as a range, never as an average. The mean would read as though
        # every language sat near it; the floor is what a thin row actually
        # rests on, and it is the figure a per-language score should be read
        # against.
        "| Weaknesses per language | {} thinnest ({}) → {} deepest ({}) |".format(
            depth[-1][1], depth[-1][0], depth[0][1], depth[0][0]),
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

    total_cells = len(languages) * len(cwes)
    if hole["missing"]:
        out += [
            "**{} of {} language-by-weakness cells are empty.** Full coverage of "
            "the grid is not the goal — CSRF has no meaning in a C program, and "
            "SQL injection none in a shell script — but an empty cell still means "
            "a tool is never tested on that combination, so it cannot pass or "
            "fail it. The languages carrying only one or two weaknesses are the "
            "ones where a result rests on the least evidence.".format(
                len(hole["missing"]), total_cells),
            "",
        ]
        thin = sorted(
            ((lang, len({c for l, c in grid if l == lang})) for lang in languages
             if summary["by_language"].get(lang)),
            key=lambda pair: pair[1],
        )
        out += ["Weaknesses covered per language, thinnest first:", ""]
        out += ["- `{}` — {}".format(lang, count) for lang, count in thin]
        out.append("")

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

    if not (absent_languages or uncovered or hole["missing"] or hole["untrapped"] or hole["no_positive"]):
        out += ["None. Every target language and weakness has a vulnerable case "
                "and a safe sibling.", ""]

    ranked = depth

    out += ["## Depth per language", "",
            "The distinct-CWE total for the corpus says nothing about spread. This is "
            "what each language is actually tested on, and it is heavily uneven — a "
            "result for a language near the bottom of this table rests on very little.",
            "",
            "| language | weaknesses | cases |", "|---|---|---|"]
    for language, count in ranked:
        cases = sum(1 for r in (tier1 or rows) if r["language"] == language)
        out.append("| `{}` | {} | {} |".format(language, count, cases))

    out += ["",
            "Grid density is **{:.0%}** — {} of the language-by-weakness cells the "
            "present material spans are filled. Full density is not the goal, since "
            "many combinations are meaningless, but the figure is the honest measure "
            "of how far the corpus generalises beyond its deepest languages."
            .format(density(tier1 or rows),
                    len({(r["language"], r["primary_cwe"]) for r in (tier1 or rows)})),
            ""]

    out += ["## Variants per weakness", "",
            "A cell in the matrix above holding one case proves only that the weakness "
            "class is represented. These are the distinct mechanisms each weakness is "
            "actually tested through, and the context traps that ask whether a tool can "
            "tell code from prose.", "",
            "| weakness | mechanisms | context traps |", "|---|---|---|"]

    by_variant = variants_by_cwe(rows)
    for cwe in sorted(by_variant, key=lambda c: int(c.split("-")[1])):
        mechanisms, contexts = split_variants(by_variant[cwe])
        out.append("| `{}` | {} | {} |".format(
            cwe,
            ", ".join("`{}`".format(m) for m in mechanisms) or "·",
            ", ".join("`{}`".format(c) for c in contexts) or "·"))

    unlabelled = sum(1 for r in rows if not (r.get("variant") or "").strip())
    unknown = sum(1 for r in rows if (r.get("variant") or "").strip() == "unknown")

    if unlabelled:
        out += ["",
                "**{} of {} cases carry no variant label** and are counted as "
                "`(unlabelled)`. Until they are named the mechanism coverage above "
                "understates what exists and cannot show what is missing."
                .format(unlabelled, len(rows))]

    if unknown:
        out += ["",
                "`unknown` is not the same gap. {} derived tier-3 cases carry it because "
                "the mechanism is not knowable from the CVE metadata — only from reading "
                "the code — and guessing would be indistinguishable from a finding in the "
                "table above.".format(unknown)]

    out += ["", "## OWASP Top 10 (2021)", "", "| category | cases |", "|---|---|"]
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
