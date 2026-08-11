#!/usr/bin/env python3
"""Derive tier-3 ground truth from cwe-bench-java.

The dataset gives 120 manually vetted CVEs in real Java projects, every one of
which builds, with the fixing file, class and method recorded per CVE. That is
far more than any other source hands you, and it is why tier 3 is derivable at
all rather than being months of hand-labelling.

**The line numbers in `fix_info.csv` cannot be used directly.** They are
anchored to the *fixed* commit, and the commit that must be scanned is the
*buggy* one — otherwise there is nothing to find. The two differ, sometimes
enormously. In `alibaba/one-java-agent` the fixed `IOUtils.java` is 106 lines
and the buggy one is 162, and the fix removed the vulnerable `unzip` method
outright, so the fixed file contains no method range for it at all — which is
exactly why several rows have an empty `method_start`.

So the method is located **by name in the buggy checkout**. Every derived case
records which granularity that search achieved, because a whole-file span in a
sixteen-hundred-line class is a far weaker claim than a method span, and a
scorecard has to be able to say which it leaned on.

Nothing here is a substitute for reading the code. This produces candidate
cases; a human confirms them before they enter the answer key.
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Sibling weaknesses a tool could defensibly report instead. Getting this wrong
# reads as missing tool coverage — see the incident in docs/MATCH-POLICY.md.
SIBLINGS = {
    "CWE-22": ["CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-73"],
    "CWE-78": ["CWE-78", "CWE-77", "CWE-88", "CWE-94"],
    "CWE-79": ["CWE-79", "CWE-80", "CWE-83", "CWE-116"],
    "CWE-94": ["CWE-94", "CWE-95", "CWE-96", "CWE-78", "CWE-470"],
}

DECLARATION_KEYWORDS = ("public", "private", "protected", "static", "final",
                        "synchronized", "abstract", "native", "default")


def normalise_cwe(value):
    """`CWE-022` and `094` both become the form every SARIF producer emits."""
    digits = re.sub(r"[^0-9]", "", str(value))
    return "CWE-{}".format(int(digits)) if digits else ""


def acceptable_for(cwe):
    return list(SIBLINGS.get(cwe, [cwe]))


def _strip_literals(line):
    """Blank out string and character literals so their braces do not count."""
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', re.sub(r"'(?:\\.|[^'\\])'", "''", line))


def _span_from(lines, index):
    """Line span of the block opening at or after `index`, 1-indexed inclusive."""
    depth = 0
    started = False

    for offset in range(index, len(lines)):
        for char in _strip_literals(lines[offset]):
            if char == "{":
                depth += 1
                started = True
            elif char == "}":
                depth -= 1
                if started and depth == 0:
                    return index + 1, offset + 1
        if started and depth <= 0 and offset > index:
            break

    return None


def find_method(source, name):
    """Locate a method declaration by name and span its body.

    A call site is not a declaration: the line must carry a modifier or a return
    type before the name, which `write(target);` inside another method does not.
    """
    if not name:
        return None

    lines = source.splitlines()
    pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")

    for index, line in enumerate(lines):
        match = pattern.search(line)
        if not match:
            continue

        before = line[:match.start()].strip()
        if not before:
            continue
        # A declaration names a modifier, a return type, or both. A bare call is
        # preceded by nothing, an assignment, or a dot.
        if before.endswith((".", "=", "return", "new")):
            continue
        words = before.replace("<", " ").replace(">", " ").split()
        if not words:
            continue
        if not (words[0] in DECLARATION_KEYWORDS or len(words) >= 1 and words[-1][:1].isalpha()):
            continue

        span = _span_from(lines, index)
        if span:
            return span

    return None


def find_class(source, name):
    if not name:
        return None

    lines = source.splitlines()
    pattern = re.compile(r"\b(?:class|interface|enum|record)\s+" + re.escape(name) + r"\b")

    for index, line in enumerate(lines):
        if pattern.search(line):
            span = _span_from(lines, index)
            if span:
                return span

    return None


def resolve_location(source, class_name, method_name):
    """(start, end, granularity) — method, then class, then whole file."""
    span = find_method(source, method_name)
    if span:
        return span[0], span[1], "method"

    span = find_class(source, class_name)
    if span:
        return span[0], span[1], "class"

    return 1, max(len(source.splitlines()), 1), "file"


TEST_SEGMENTS = ("test", "tests", "testsuite", "src/test", "it", "integration-test")
TEST_SUFFIXES = ("Test.java", "TestCase.java", "Tests.java", "IT.java", "ITCase.java")


def is_test_path(path):
    """True for test code, which must never become ground truth.

    A fix commit routinely updates the test that proves it. Tools skip test
    directories by default, so an entry pointing at one charges every tool a
    false negative for behaving correctly.

    Matched on whole path segments, so `LatestBuild.java` is not mistaken for a
    test by containing the letters `test`.
    """
    segments = path.replace("\\", "/").split("/")
    if any(segment.lower() in TEST_SEGMENTS for segment in segments[:-1]):
        return True
    return segments[-1].endswith(TEST_SUFFIXES)


def _normalised(text):
    """Collapse whitespace so reindentation is not mistaken for a fix."""
    return " ".join(text.split())


def derive_trap(buggy_source, fixed_source, class_name, method_name):
    """The fixed version of a vulnerable method, as a false-positive trap.

    This is the strongest trap material available anywhere in this corpus.
    Upstream maintainers wrote it under real constraints against a real,
    published attack — it is not a plausible-looking sample we invented, it is
    the actual defence that shipped. A tool that still reports here is matching
    on shape rather than reasoning about dataflow.

    Returns None rather than guessing in two cases, each of which would
    otherwise corrupt the ground truth:

    - The fix **deleted** the method. `alibaba/one-java-agent` removed `unzip`
      outright, and there is no safe sibling to point at. Emitting one would be
      a fabricated trap.
    - The method is **unchanged**. If the fix did not touch it, the fixed copy is
      the same vulnerable code, and labelling it safe would invert the ground
      truth and charge a correct finding as a false positive.
    """
    # No class fallback here, unlike the vulnerable side. For a flaw, "somewhere
    # in this class" is a weak but honest claim. For a trap it is a much stronger
    # one — that the whole class is correctly defended — and when the method was
    # deleted there is nothing structurally comparable left to trap on at all.
    fixed_span = find_method(fixed_source, method_name)
    buggy_span = find_method(buggy_source, method_name)
    if not fixed_span or not buggy_span:
        return None

    fixed_lines = fixed_source.splitlines()[fixed_span[0] - 1:fixed_span[1]]
    buggy_lines = buggy_source.splitlines()[buggy_span[0] - 1:buggy_span[1]]

    if _normalised("\n".join(fixed_lines)) == _normalised("\n".join(buggy_lines)):
        return None

    return {
        "label": "safe",
        "start_line": fixed_span[0],
        "end_line": fixed_span[1],
        "sanitizer": "custom-effective",
    }


def derive(dataset_root, sources_root, slug_filter=None):
    """Build candidate cases from the dataset plus fetched buggy checkouts."""
    dataset_root = Path(dataset_root)
    sources_root = Path(sources_root)

    projects = {r["project_slug"]: r
                for r in csv.DictReader((dataset_root / "data" / "project_info.csv").open())}
    fixes = list(csv.DictReader((dataset_root / "data" / "fix_info.csv").open()))

    candidates, skipped = [], []

    for row in fixes:
        slug = row["project_slug"]
        if slug_filter and slug != slug_filter:
            continue

        project = projects.get(slug)
        if not project:
            skipped.append((slug, "no project_info row"))
            continue

        checkout = sources_root / slug
        if not checkout.is_dir():
            skipped.append((slug, "checkout absent"))
            continue

        if is_test_path(row["file"]):
            skipped.append((slug, "test code, not the flaw: {}".format(row["file"])))
            continue

        path = checkout / row["file"]
        if not path.is_file():
            skipped.append((slug, "file absent in buggy checkout: {}".format(row["file"])))
            continue

        source = path.read_text(errors="replace")
        start, end, granularity = resolve_location(source, row["class"], row["method"])
        cwe = normalise_cwe(project["cwe_id"])

        candidates.append({
            "slug": slug,
            "cve": project["cve_id"],
            "cwe": cwe,
            "acceptable_cwes": acceptable_for(cwe),
            "file": "tier3/project-sources/{}/{}".format(slug, row["file"]),
            "start_line": start,
            "end_line": end,
            "granularity": granularity,
            "class": row["class"],
            "method": row["method"],
            "signature": row["signature"],
            "buggy_commit": project["buggy_commit_id"],
            "fix_commit": row["commit"],
            "repo": project["github_url"],
        })

    return group_by_cve(candidates), skipped


def group_by_cve(rows):
    """One case per CVE, not one per touched method.

    A fix commit routinely touches more than the flaw — one CVE here spans
    seventeen methods, of which the vulnerability occupies one or two. Emitting
    all of them as ground truth would charge every tool fifteen false negatives
    for declining to flag refactored helpers.

    A CVE is one vulnerability, so it becomes one case: the first touched method
    is the primary location and the rest are alternatives. The match policy
    already credits a hit at any declared location, which is exactly the right
    reading — a tool that flags any affected method has found the CVE.

    Overloaded methods share a name, so every signature in the dataset resolves
    to the same span. Those collapse to one location rather than repeating.
    """
    # A located method makes a far stronger primary than a whole-class span, so
    # granularity is worth reordering for. Length is NOT: preferring the
    # narrowest method biases hard toward trivial accessors, because a fix that
    # adds a field also adds its getter, and a three-line `getPath()` is never
    # the vulnerability. Among rows of equal granularity the dataset's own
    # ordering stands, since it was manually vetted and length was not.
    precision = {"method": 0, "class": 1, "file": 2}
    rows = sorted(rows, key=lambda r: precision.get(r["granularity"], 3))

    grouped = {}
    seen = {}

    for row in rows:
        key = (row["slug"], row["cve"])
        span = (row["file"], row["start_line"], row["end_line"])

        if key not in grouped:
            grouped[key] = dict(row, alt_locations=[])
            seen[key] = {span}
            continue

        if span in seen[key]:
            continue
        seen[key].add(span)
        grouped[key]["alt_locations"].append({
            "file": row["file"],
            "start_line": row["start_line"],
            "end_line": row["end_line"],
            "method": row["method"],
            "granularity": row["granularity"],
        })

    return list(grouped.values())


def case_id(cve, slug):
    """Opaque and stable: derived from the CVE and project, so re-deriving
    produces the same id and the answer key diffs cleanly."""
    import hashlib
    digest = hashlib.sha256("{}::{}".format(cve, slug).encode()).hexdigest()
    return "c-{}".format(digest[:8])


def render_case(candidate):
    """Render a derived candidate as an answer-key case.

    Difficulty is recorded as `unknown` throughout. The taint path, the presence
    of a sanitizer and any aliasing are not knowable from the dataset — only from
    reading the code — and a guess would be indistinguishable from a finding in
    the difficulty breakdown. A reviewer fills them in when they confirm the case.

    There is no safe sibling, so tier 3 measures recall only. That is a real
    limitation of the tier, not an oversight: the dataset records where each CVE
    was fixed, and says nothing about which nearby code is correctly defended.
    """
    alts = candidate.get("alt_locations") or []
    spread = ("Ground truth spans the {} method(s) the fix touched, and a hit at "
              "any of them counts, because a fix commit routinely edits more than "
              "the flaw and a tool that flags any affected method has found this "
              "CVE.".format(len(alts) + 1))

    if candidate["granularity"] == "file":
        precision_note = (" The primary location is the whole file, because neither the "
                          "method nor the class could be located in the buggy checkout — "
                          "the weakest claim this corpus makes, and it should be narrowed "
                          "or dropped on review.")
    elif candidate["granularity"] == "class":
        precision_note = (" The primary location is the enclosing class rather than the "
                          "method, which the fix removed outright.")
    else:
        precision_note = ""

    rationale = (
        "{cve} in {repo}, at the buggy commit {commit}. The dataset records the fix "
        "as touching {cls}.{method}; that method was located by name in the buggy "
        "checkout rather than by the recorded line numbers, which belong to the fixed "
        "file and do not correspond. {spread}{note}"
    ).format(cve=candidate["cve"], repo=candidate["repo"].rsplit("/", 2)[-2] + "/" +
             candidate["repo"].rsplit("/", 1)[-1],
             commit=candidate["buggy_commit"], cls=candidate["class"],
             method=candidate["method"] or "(class-level change)",
             spread=spread, note=precision_note)

    lines = [
        "id: {}".format(case_id(candidate["cve"], candidate["slug"])),
        "label: vulnerable",
        "plane: vuln",
        "tier: 3",
        "language: java",
        "framework: null",
        "primary_cwe: {}".format(candidate["cwe"]),
        "variant: unknown",
        "acceptable_cwes: [{}]".format(", ".join(candidate["acceptable_cwes"])),
        "owasp_2021: null",
        "severity: high",
        "location:",
        "  file: {}".format(candidate["file"]),
        "  start_line: {}".format(candidate["start_line"]),
        "  end_line: {}".format(candidate["end_line"]),
    ]

    if alts:
        lines.append("alt_locations:")
        for alt in alts:
            lines += ["  - file: {}".format(alt["file"]),
                      "    start_line: {}".format(alt["start_line"]),
                      "    end_line: {}".format(alt["end_line"])]
    else:
        lines.append("alt_locations: []")

    lines += [
        "difficulty:",
        "  flow: unknown",
        "  sanitizer: unknown",
        "  obfuscation: unknown",
        "evidence:",
        "  source: cve",
        "  rationale: >-",
        "    {}".format(rationale),
        "  cve: {}".format(candidate["cve"]),
        "build:",
        "  required: true",
        "  recipe: tier3/cwe-bench-java/scripts/build_one.py",
    ]

    return "\n".join(lines) + "\n"


def fixed_source(checkout, fix_commit, relative_path):
    """Content of a file at the fix commit, without a second checkout.

    The buggy tree is already a git repository, so the fixed blob is one fetch
    and one `git show` away — far cheaper than cloning every project twice.
    """
    import subprocess

    fetched = subprocess.run(
        ["git", "-C", str(checkout), "fetch", "-q", "--depth", "1", "origin", fix_commit],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if fetched.returncode != 0:
        return None

    shown = subprocess.run(
        ["git", "-C", str(checkout), "show", "{}:{}".format(fix_commit, relative_path)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if shown.returncode != 0:
        return None

    return shown.stdout.decode("utf-8", errors="replace")


def render_trap(candidate, trap):
    """Render the fixed-commit trap as a `label: safe` answer-key case."""
    lines = [
        "id: {}".format(case_id(candidate["cve"] + "::fixed", candidate["slug"])),
        "label: safe",
        "plane: vuln",
        "tier: 3",
        "language: java",
        "framework: null",
        "primary_cwe: {}".format(candidate["cwe"]),
        "variant: unknown",
        "acceptable_cwes: [{}]".format(", ".join(candidate["acceptable_cwes"])),
        "owasp_2021: null",
        "severity: high",
        "location:",
        "  file: {}".format(trap["file"]),
        "  start_line: {}".format(trap["start_line"]),
        "  end_line: {}".format(trap["end_line"]),
        "alt_locations: []",
        "difficulty:",
        "  flow: unknown",
        "  sanitizer: {}".format(trap["sanitizer"]),
        "  obfuscation: unknown",
        "evidence:",
        "  source: cve",
        "  rationale: >-",
        "    The patched form of {method}, taken from the commit that fixed {cve} in "
        "{repo}. This is the defence upstream actually shipped against a real published "
        "attack, not a plausible-looking sample written to look safe, which makes it the "
        "strongest trap material in this corpus. The method is confirmed to differ from "
        "the buggy version by more than whitespace, so it is genuinely the fix and not an "
        "untouched copy. A tool reporting {cwe} here is matching on shape rather than "
        "reasoning about dataflow.".format(
            method=candidate["method"] or candidate["class"], cve=candidate["cve"],
            repo=candidate["repo"].rsplit("/", 1)[-1], cwe=candidate["cwe"]),
        "  cve: null",
        "build:",
        "  required: false",
        "  recipe: null",
    ]
    return "\n".join(lines) + "\n"


def fetch_project(project, sources_root):
    """Clone a project at its **buggy** commit — the fixed one has nothing to find."""
    import subprocess

    slug = project["project_slug"]
    destination = Path(sources_root) / slug
    if (destination / ".git").is_dir():
        return "present"

    destination.mkdir(parents=True, exist_ok=True)
    commit = project["buggy_commit_id"]
    steps = [
        ["git", "-C", str(destination), "init", "-q"],
        ["git", "-C", str(destination), "remote", "add", "origin", project["github_url"]],
        ["git", "-C", str(destination), "fetch", "-q", "--depth", "1", "origin", commit],
        ["git", "-C", str(destination), "checkout", "-q", "FETCH_HEAD"],
    ]
    for step in steps:
        if subprocess.run(step, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode != 0:
            return "failed"
    return "fetched"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--dataset", type=Path, default=root / "tier3" / "cwe-bench-java")
    parser.add_argument("--sources", type=Path, default=root / "tier3" / "project-sources")
    parser.add_argument("--slug", default=None, help="derive a single project")
    parser.add_argument("--out", type=Path, default=None, help="write candidates as JSON")
    parser.add_argument("--write-traps", action="store_true",
                        help="also derive false-positive traps from the fix commits")
    parser.add_argument("--write-cases", action="store_true",
                        help="write derived candidates into answers/cases/ for review")
    parser.add_argument("--fetch", type=int, default=0,
                        help="clone up to N projects at their buggy commit first")
    args = parser.parse_args(argv)

    if args.fetch:
        projects = list(csv.DictReader((args.dataset / "data" / "project_info.csv").open()))
        if args.slug:
            projects = [p for p in projects if p["project_slug"] == args.slug]
        for project in projects[:args.fetch]:
            state = fetch_project(project, args.sources)
            print("  {:<52} {}".format(project["project_slug"][:52], state))
        print()

    candidates, skipped = derive(args.dataset, args.sources, args.slug)

    by_granularity = {}
    for candidate in candidates:
        by_granularity[candidate["granularity"]] = by_granularity.get(candidate["granularity"], 0) + 1

    print("candidates {}   skipped {}".format(len(candidates), len(skipped)))
    for name in ("method", "class", "file"):
        if by_granularity.get(name):
            print("  {:<8} {}".format(name, by_granularity[name]))

    if by_granularity.get("file"):
        print("\n  whole-file spans are the weakest claim here; confirm each by hand "
              "or drop it before it enters the answer key")

    reasons = {}
    for _slug, reason in skipped:
        key = reason.split(":")[0]
        reasons[key] = reasons.get(key, 0) + 1
    for reason, count in sorted(reasons.items()):
        print("  skipped: {} ({})".format(reason, count))

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(candidates, indent=2))
        print("\nwrote {}".format(args.out))

    if args.write_traps:
        cases_dir = root / "answers" / "cases"
        cases_dir.mkdir(parents=True, exist_ok=True)
        fixed_root = root / "tier3" / "fixed-sources"
        made, deleted, unchanged, unreachable = 0, 0, 0, 0

        for candidate in candidates:
            checkout = args.sources / candidate["slug"]
            relative = candidate["file"].split("/", 3)[3]
            buggy_path = checkout / relative
            if not buggy_path.is_file():
                unreachable += 1
                continue

            fixed = fixed_source(checkout, candidate["fix_commit"], relative)
            if fixed is None:
                unreachable += 1
                continue

            trap = derive_trap(buggy_path.read_text(errors="replace"), fixed,
                               candidate["class"], candidate["method"])
            if trap is None:
                if not find_method(fixed, candidate["method"]):
                    deleted += 1
                else:
                    unchanged += 1
                continue

            out_path = fixed_root / candidate["slug"] / relative
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(fixed)
            trap["file"] = "tier3/fixed-sources/{}/{}".format(candidate["slug"], relative)

            identifier = case_id(candidate["cve"] + "::fixed", candidate["slug"])
            (cases_dir / "{}.yml".format(identifier)).write_text(render_trap(candidate, trap))
            made += 1

        print("\ntraps from fix commits: {} written".format(made))
        print("  {} skipped: the fix deleted the method, so no safe sibling exists".format(deleted))
        print("  {} skipped: method unchanged by the fix, so the 'fixed' copy is still "
              "the vulnerable code".format(unchanged))
        print("  {} skipped: fix commit or file unreachable".format(unreachable))

    if args.write_cases:
        cases_dir = root / "answers" / "cases"
        cases_dir.mkdir(parents=True, exist_ok=True)
        for candidate in candidates:
            identifier = case_id(candidate["cve"], candidate["slug"])
            (cases_dir / "{}.yml".format(identifier)).write_text(render_case(candidate))
        print("\nwrote {} case(s) to {}".format(len(candidates), cases_dir))
        print("these are CANDIDATES: each needs a human to confirm the flaw is real "
              "and the location is right before the numbers mean anything")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
