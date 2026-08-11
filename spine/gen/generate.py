#!/usr/bin/env python3
"""Generate tier-1 fixtures and their ground truth from templates.

Two things make generation worth the machinery.

It is the only affordable way to reach breadth. Hand-authoring six weakness
classes across a dozen languages, each with a safe sibling, is hundreds of files
and hundreds of ground-truth entries kept in sync by hand.

And it makes anti-leakage structural rather than a rule people remember. A
generator emits exactly what its template contains: opaque directory names, no
comments, no identifier naming the weakness. Nothing leaks because nothing that
could leak is ever written.

What generation cannot do is produce the cases that separate tools — custom
sanitizers, aliasing, framework-mediated binding. Those are hand-authored, and
the two kinds are labelled so a scorecard can say how much of a result rests on
generated uniformity. See docs/THREATS-TO-VALIDITY.md.
"""

import argparse
import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@dataclass
class Variant:
    """One emitted case.

    `label` is what the answer key records, and it is not implied by the variant
    name. A sanitizer that looks effective and is not produces a case that is
    still `vulnerable`, and that case is the most realistic false-positive
    source there is — so it cannot live in the 'safe' slot.
    """

    files: dict
    sink_file: str
    sink_match: str
    sanitizer: str
    rationale: str
    label: str = "vulnerable"
    source_file: str = None
    source_match: str = None
    flow: str = None
    obfuscation: str = None
    variant: str = None
    # Plane-specific ground truth: the `secret` or `sca` block for this case.
    # The vuln plane needs none, and emitting an empty one would fail the schema.
    extra_ground_truth: dict = None


@dataclass
class Template:
    slug: str
    language: str
    extension: str
    primary_cwe: str
    acceptable_cwes: list
    owasp_2021: str
    severity: str
    flow: str
    obfuscation: str
    variants: dict
    variant_name: str = None
    plane: str = "vuln"
    framework: str = None
    build_required: bool = False
    build_recipe: str = None
    entry_file: str = field(default=None)


def case_id(slug, label):
    """Deterministic, opaque, and stable across regeneration.

    Stable because a random id would rewrite the entire answer key on every run,
    burying real changes. Opaque because an id that hinted at the language or
    the weakness would be one more thing for a model to read instead of the code.
    """
    digest = hashlib.sha256("{}::{}".format(slug, label).encode()).hexdigest()
    return "c-{}".format(digest[:8])


def locate(text, marker):
    """First and last line holding `marker`, 1-indexed.

    Raising on a missing marker is deliberate. Silently defaulting to line 1
    would produce ground truth pointing at an import statement, and every tool
    would fail a case none of them could pass.
    """
    lines = [number for number, line in enumerate(text.splitlines(), start=1) if marker in line]
    if not lines:
        raise ValueError("marker {!r} not found in generated file".format(marker))
    return lines[0], lines[-1]


def emit(template, root):
    """Write every variant and return their ground-truth cases."""
    return [
        _emit_variant(template, name, variant, Path(root))
        for name, variant in template.variants.items()
    ]


def _emit_variant(template, name, variant, root):
    identifier = case_id(template.slug, name)
    directory = "tier1/{}/{}".format(template.language, identifier[2:])
    target = root / directory
    target.mkdir(parents=True, exist_ok=True)

    for filename, content in variant.files.items():
        path = target / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    sink_text = variant.files[variant.sink_file]
    start, end = locate(sink_text, variant.sink_match)

    alt_locations = []
    if variant.source_file and variant.source_match:
        source_start, source_end = locate(variant.files[variant.source_file], variant.source_match)
        alt_locations.append({
            "file": "{}/{}".format(directory, variant.source_file),
            "start_line": source_start,
            "end_line": source_end,
        })

    case = {
        "id": identifier,
        "label": variant.label,
        "plane": template.plane,
        "tier": 1,
        "language": template.language,
        "framework": template.framework,
        "primary_cwe": template.primary_cwe,
        "variant": variant.variant or template.variant_name,
        "acceptable_cwes": list(template.acceptable_cwes),
        "owasp_2021": template.owasp_2021,
        "severity": template.severity,
        "location": {
            "file": "{}/{}".format(directory, variant.sink_file),
            "start_line": start,
            "end_line": end,
        },
        "alt_locations": alt_locations,
        "difficulty": {
            "flow": variant.flow or template.flow,
            "sanitizer": variant.sanitizer,
            "obfuscation": variant.obfuscation or template.obfuscation,
        },
        "evidence": {
            "source": "generated",
            "rationale": variant.rationale,
            "cve": None,
        },
        "build": {
            "required": template.build_required,
            "recipe": template.build_recipe,
        },
    }

    if variant.extra_ground_truth and template.plane in ("secret", "sca"):
        case[template.plane] = dict(variant.extra_ground_truth)

    return case


def write_case_files(cases, root):
    """Write each case as answers/cases/<id>.yml.

    Hand-rolled rather than via PyYAML so the generator stays dependency-free
    and the output formatting is fixed — a formatter change must not show up as
    a diff across every generated case.
    """
    written = []
    directory = Path(root) / "answers" / "cases"
    directory.mkdir(parents=True, exist_ok=True)

    for case in cases:
        path = directory / "{}.yml".format(case["id"])
        path.write_text(_render_yaml(case))
        written.append(path)

    return written


def _render_yaml(case):
    lines = [
        "id: {}".format(case["id"]),
        "label: {}".format(case["label"]),
        "plane: {}".format(case["plane"]),
        "tier: {}".format(case["tier"]),
        "language: {}".format(case["language"]),
        "framework: {}".format(case["framework"] if case["framework"] else "null"),
        "primary_cwe: {}".format(case["primary_cwe"]),
        "variant: {}".format(case.get("variant") or "null"),
        "acceptable_cwes: [{}]".format(", ".join(case["acceptable_cwes"])),
        "owasp_2021: {}".format(case["owasp_2021"] or "null"),
        "severity: {}".format(case["severity"]),
        "location:",
        "  file: {}".format(case["location"]["file"]),
        "  start_line: {}".format(case["location"]["start_line"]),
        "  end_line: {}".format(case["location"]["end_line"]),
    ]

    if case["alt_locations"]:
        lines.append("alt_locations:")
        for alt in case["alt_locations"]:
            lines.append("  - file: {}".format(alt["file"]))
            lines.append("    start_line: {}".format(alt["start_line"]))
            lines.append("    end_line: {}".format(alt["end_line"]))
    else:
        lines.append("alt_locations: []")

    lines += [
        "difficulty:",
        "  flow: {}".format(case["difficulty"]["flow"]),
        "  sanitizer: {}".format(case["difficulty"]["sanitizer"]),
        "  obfuscation: {}".format(case["difficulty"]["obfuscation"]),
        "evidence:",
        "  source: {}".format(case["evidence"]["source"]),
        "  rationale: >-",
        "    {}".format(case["evidence"]["rationale"]),
        "  cve: null",
    ]

    for plane in ("secret", "sca"):
        block = case.get(plane)
        if not block:
            continue
        lines.append("{}:".format(plane))
        for key, value in block.items():
            if value is None:
                rendered = "null"
            elif isinstance(value, bool):
                rendered = "true" if value else "false"
            else:
                rendered = str(value)
            lines.append("  {}: {}".format(key, rendered))

    lines += [
        "build:",
        "  required: {}".format("true" if case["build"]["required"] else "false"),
        "  recipe: {}".format(case["build"]["recipe"] or "null"),
    ]

    return "\n".join(lines) + "\n"


def main(argv=None):
    from gen import templates

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=Path(__file__).resolve().parents[2], type=Path)
    parser.add_argument("--language", default=None, help="generate only this language")
    parser.add_argument("--list", action="store_true", help="list templates and exit")
    args = parser.parse_args(argv)

    selected = [
        template for template in templates.ALL
        if not args.language or template.language == args.language
    ]

    if args.list:
        for template in selected:
            print("{:<28} {:<12} {}".format(template.slug, template.language, template.primary_cwe))
        print("\n{} templates, {} cases".format(len(selected), len(selected) * 2))
        return 0

    cases = []
    for template in selected:
        cases.extend(emit(template, args.root))

    write_case_files(cases, args.root)

    languages = sorted({case["language"] for case in cases})
    print("generated {} cases across {} languages: {}".format(
        len(cases), len(languages), ", ".join(languages)))
    print("traps: {} of {}".format(sum(c["label"] == "safe" for c in cases), len(cases)))
    print("\nnow run: compile_answers.py, then antileak.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
