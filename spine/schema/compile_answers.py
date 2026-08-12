"""Validate answers/cases/*.yml and compile them into the flat answer key.

The YAML cases are the authoring format: readable, commentable, reviewable in a
pull request. The CSV they compile to is the scoring format: one flat row per
case, consumable by `spine/score/score.py` with no dependencies at all.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

COLUMNS = [
    "id",
    "label",
    "plane",
    "tier",
    "language",
    "framework",
    "primary_cwe",
    "variant",
    "acceptable_cwes",
    "owasp_2021",
    "severity",
    "file",
    "start_line",
    "end_line",
    "alt_locations",
    "flow",
    "sanitizer",
    "obfuscation",
    "build_required",
    # Whether a case came from the generator, a person, or a CVE. Carried into
    # the key so a scorecard can split results by provenance: the
    # synthetic-versus-real gap is the largest caveat on any tier-1 number.
    "source",
]


def compile_answer_key(repo_root, schema_path, out_path):
    """Validate every case and write the answer key. Returns a list of errors.

    Nothing is written when any case fails. A partially-valid answer key is worse
    than none: it scores tools against ground truth nobody has checked.
    """
    import jsonschema
    import yaml

    repo_root = Path(repo_root)
    schema = json.loads(Path(schema_path).read_text())
    validator = jsonschema.Draft202012Validator(schema)

    cases = []
    errors = []

    for path in sorted((repo_root / "answers" / "cases").glob("*.yml")):
        case = yaml.safe_load(path.read_text())
        case_id = case.get("id", path.name) if isinstance(case, dict) else path.name

        schema_problems = [
            "{}: {}".format(case_id, problem.message)
            for problem in validator.iter_errors(case)
        ]
        if schema_problems:
            errors.extend(schema_problems)
            continue

        errors.extend(
            "{}: {}".format(case_id, problem)
            for problem in semantic_errors(case) + file_errors(case, repo_root)
        )
        cases.append(case)

    errors.extend(duplicate_id_errors(cases))

    if errors:
        return errors

    # Retired cases leave the answer key and keep their file. Deleting the YAML
    # would make an older scorecard unexplainable: the row would be gone with
    # nothing recording why.
    cases = [case for case in cases if "retired" not in case]
    cases.sort(key=lambda case: case["id"])
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for case in cases:
            writer.writerow(to_csv_row(case))

    return []


def compile_rows(repo_root, schema_path=None):
    """The rows an answer key would contain, raising rather than returning errors.

    Same pipeline as `compile_answers`, without writing anything — for callers
    that want the data rather than the file.
    """
    repo_root = Path(repo_root)
    schema_path = schema_path or Path(__file__).resolve().parent / "case.schema.json"
    out = repo_root / ".compile-rows.csv"
    errors = compile_answer_key(repo_root, schema_path, out)
    if errors:
        raise ValueError("; ".join(errors[:5]))
    try:
        with out.open() as handle:
            return list(csv.DictReader(handle))
    finally:
        out.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    here = Path(__file__).resolve()
    parser.add_argument("--repo-root", default=here.parents[2], type=Path)
    parser.add_argument("--schema", default=here.parent / "case.schema.json", type=Path)
    parser.add_argument("--version", default="1.0")
    parser.add_argument("--out", default=None, type=Path)
    args = parser.parse_args(argv)

    out = args.out or args.repo_root / "answers" / "expectedresults-{}.csv".format(args.version)
    errors = compile_answer_key(args.repo_root, args.schema, out)

    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print("\n{} error(s); answer key not written".format(len(errors)), file=sys.stderr)
        return 1

    print("answer key written to {}".format(out))
    return 0


def semantic_errors(case):
    """Cross-field rules the JSON Schema cannot express.

    Returns every problem found, not just the first — a contributor fixing one
    error at a time across a few hundred cases is a bad use of anyone's day.
    """
    errors = []

    if case["primary_cwe"] not in case["acceptable_cwes"]:
        errors.append(
            "primary_cwe {} is absent from acceptable_cwes; a tool reporting the "
            "most precise CWE would be scored as a miss".format(case["primary_cwe"])
        )

    location = case["location"]
    if location["start_line"] > location["end_line"]:
        errors.append(
            "location start_line {} is after end_line {}".format(
                location["start_line"], location["end_line"]
            )
        )

    for index, alt in enumerate(case.get("alt_locations") or []):
        if alt["start_line"] > alt["end_line"]:
            errors.append(
                "alt_locations[{}] start_line {} is after end_line {}".format(
                    index, alt["start_line"], alt["end_line"]
                )
            )

    if case["label"] == "safe" and case["evidence"].get("cve"):
        errors.append(
            "a safe case cannot cite cve {}; a CVE is evidence the code was "
            "genuinely vulnerable".format(case["evidence"]["cve"])
        )

    expected_prefix = "tier{}/".format(case["tier"])
    for path in _all_paths(case):
        if not path.startswith(expected_prefix):
            errors.append(
                "tier {} case points at {}, which is outside {}".format(
                    case["tier"], path, expected_prefix
                )
            )

    return errors


def file_errors(case, repo_root):
    """Check every referenced file exists and every line is inside it.

    Fixtures get refactored and lines shift. Without this the answer key keeps
    pointing at a line that no longer holds the flaw, and every tool starts
    failing a case none of them can pass.
    """
    errors = []
    repo_root = Path(repo_root)

    # Tier 1 is committed, so a missing file really is a broken answer key.
    # Tiers 2 and 3 point into checkouts fetched on demand and never committed;
    # their absence means "not fetched", and failing on it would make the answer
    # key uncompilable on any machine that had not cloned several gigabytes of
    # other people's repositories. A fetched file is still range-checked, so
    # absence is excused but being wrong is not.
    external = case["tier"] in (2, 3)

    for label, loc in _labelled_locations(case):
        path = repo_root / loc["file"]
        if not path.is_file():
            if not external:
                errors.append("{} references missing file {}".format(label, loc["file"]))
            continue

        line_count = _count_lines(path)
        if loc["end_line"] > line_count:
            errors.append(
                "{} references line {} but {} has only {} lines".format(
                    label, loc["end_line"], loc["file"], line_count
                )
            )

    return errors


def duplicate_id_errors(cases):
    """A reused id silently drops a case from the answer key."""
    seen = set()
    duplicated = []
    for case in cases:
        if case["id"] in seen and case["id"] not in duplicated:
            duplicated.append(case["id"])
        seen.add(case["id"])

    return ["duplicate case id {}".format(case_id) for case_id in duplicated]


def _count_lines(path):
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def _labelled_locations(case):
    yield "location", case["location"]
    for index, alt in enumerate(case.get("alt_locations") or []):
        yield "alt_locations[{}]".format(index), alt


def _all_paths(case):
    yield case["location"]["file"]
    for alt in case.get("alt_locations") or []:
        yield alt["file"]


def _encode_locations(locations):
    """file:start:end triples, semicolon-separated.

    Paths in this corpus never contain colons, so a colon split is unambiguous.
    """
    return ";".join(
        "{}:{}:{}".format(loc["file"], loc["start_line"], loc["end_line"])
        for loc in locations
    )


def to_csv_row(case):
    """Flatten one validated case into a single answer-key row.

    The rationale is deliberately dropped: the answer key travels with the corpus
    when a tool is scored, and prose describing the flaw is exactly the hint the
    corpus exists to withhold.
    """
    location = case["location"]
    difficulty = case["difficulty"]

    return {
        "id": case["id"],
        "label": case["label"],
        "plane": case["plane"],
        "tier": case["tier"],
        "language": case["language"],
        "framework": case.get("framework") or "",
        "primary_cwe": case["primary_cwe"],
        "variant": case.get("variant") or "",
        "acceptable_cwes": ";".join(case["acceptable_cwes"]),
        "owasp_2021": case.get("owasp_2021") or "",
        "severity": case["severity"],
        "file": location["file"],
        "start_line": location["start_line"],
        "end_line": location["end_line"],
        "alt_locations": _encode_locations(case.get("alt_locations") or []),
        "flow": difficulty["flow"],
        "sanitizer": difficulty["sanitizer"],
        "obfuscation": difficulty["obfuscation"],
        "source": (case.get("evidence") or {}).get("source"),
        "build_required": "true" if case["build"]["required"] else "false",
    }


if __name__ == "__main__":
    raise SystemExit(main())
