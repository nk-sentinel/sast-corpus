#!/usr/bin/env python3
"""Build the tier-3 projects, so build-required engines can be scored on them.

Fortify, Coverity and Veracode analyse compiled artifacts. A project that does
not build is invisible to them, and in a scorecard that is indistinguishable
from the tool finding nothing — so the tier that matters most to those engines
is unusable by them until this has run.

cwe-bench-java reports every one of its 120 projects builds. That is upstream's
claim about upstream's machine; what gets recorded here is what actually
happened on this one. If the rate is lower, saying so is the entire point of
running it.

**The JDKs are not the ones the dataset expects.** `setup_jdk.py` looks for
Oracle tarballs that have to be downloaded by hand behind a licence click, so it
silently skips and every build then fails with "should not happen!". Eclipse
Temurin is the same OpenJDK build without the click, unpacked under the
directory names the dataset's scripts look for. That substitution is recorded in
the output, because a build result is only reproducible if the toolchain that
produced it is known.
"""

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def buildable_slugs(sources_root, wanted=None):
    """Slugs with a checkout, optionally restricted to those carrying cases.

    Building all 120 costs hours for projects nothing scores against, so the
    default is to build only what the answer key actually references.
    """
    sources_root = Path(sources_root)
    if not sources_root.is_dir():
        return []

    found = sorted(p.name for p in sources_root.iterdir() if p.is_dir())
    if wanted is None:
        return found
    return [slug for slug in found if slug in wanted]


def summarise_builds(results):
    """Counts and the real rate. Zero of zero is not a perfect score."""
    counts = {}
    for status in results.values():
        counts[status] = counts.get(status, 0) + 1

    total = len(results)
    counts["rate"] = (counts.get("success", 0) / total) if total else None
    counts.setdefault("success", 0)
    counts.setdefault("failed", 0)
    return counts


def record_results(results, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "results": results,
        "summary": summarise_builds(results),
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "jdk_source": "eclipse-temurin (substituted for the Oracle tarballs the dataset expects)",
    }, indent=2) + "\n")
    return path


def slugs_with_cases(answer_key):
    """Project slugs referenced by tier-3 rows of the answer key."""
    import csv

    slugs = set()
    with Path(answer_key).open(newline="") as handle:
        for row in csv.DictReader(handle):
            if row["tier"] != "3":
                continue
            parts = row["file"].split("/")
            if len(parts) > 2 and parts[0] == "tier3":
                slugs.add(parts[2])
    return slugs


def build(slug, dataset_root, timeout):
    completed = subprocess.run(
        [sys.executable, "scripts/build_one.py", slug],
        cwd=str(dataset_root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout)
    output = completed.stdout.decode("utf-8", errors="replace")

    if completed.returncode != 0:
        return "failed", output
    if "Build succeeded" in output or "already built" in output:
        return "success", output
    return "failed", output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--dataset", type=Path, default=root / "tier3" / "cwe-bench-java")
    parser.add_argument("--sources", type=Path, default=root / "tier3" / "project-sources")
    parser.add_argument("--answer-key", type=Path,
                        default=root / "answers" / "expectedresults-1.0.csv")
    parser.add_argument("--all", action="store_true",
                        help="build every checkout, not only those carrying cases")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--out", type=Path, default=root / "tier3" / "build-status.json")
    args = parser.parse_args(argv)

    wanted = None if args.all else slugs_with_cases(args.answer_key)
    slugs = buildable_slugs(args.sources, wanted)

    print("building {} project(s)".format(len(slugs)))
    results = {}

    for slug in slugs:
        try:
            status, output = build(slug, args.dataset, args.timeout)
        except subprocess.TimeoutExpired:
            status, output = "timeout", ""
        results[slug] = status
        print("  {:<4} {}".format(status[:4], slug[:66]))
        if status != "success" and output:
            tail = [line for line in output.splitlines() if line.strip()][-2:]
            for line in tail:
                print("       {}".format(line[:100]))

    summary = summarise_builds(results)
    record_results(results, args.out)

    print("\n{} succeeded, {} failed{}".format(
        summary["success"], summary["failed"],
        ", rate {:.0%}".format(summary["rate"]) if summary["rate"] is not None else ""))
    print("recorded in {}".format(args.out))

    if summary["failed"]:
        print("\nProjects that do not build are invisible to Fortify, Coverity and "
              "Veracode. Their cases must be excluded from those tools' scorecards "
              "rather than counted as misses.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
