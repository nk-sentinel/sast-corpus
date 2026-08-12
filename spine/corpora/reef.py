#!/usr/bin/env python3
"""Derive C and C++ tier-3 cases using REEF as an index.

PatchEval covers Go, JavaScript and Python. C and C++ have no equivalent, and
REEF is the only broad source — but it is an index of fix commits rather than
scoring-ready ground truth, and it comes with two constraints that shape
everything here (see ../../docs/TIER3-DATASETS.md):

**REEF itself is never vendored or exported.** It ships 737 MB of copied source
from thousands of projects under no LICENSE file at all. It is read on this side
of the airgap to learn *which* commit fixed *which* CVE; the sources themselves
are fetched from their own upstream repositories, which carry real licences.

**Only unambiguous entries are derived.** REEF records the fixing commit and not
which file or which hunk held the flaw. 53% of its fixes touch more than one
file and 43% of its files carry more than one hunk, and picking the first of
either produces a confident wrong answer — one spike case derived to an include
block. Where a fix touches exactly one file with exactly one hunk there is
nothing left to guess, and that is the only shape accepted.

The vulnerable range comes from the `-` side of the hunk header, which describes
the file before the fix. That is the checkout being scanned; the `+` side
describes the fixed file and would point at the wrong lines.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

# A repository larger than this is not a scan target anyone wants in a corpus,
# and obtaining it costs more than the case is worth. torvalds/linux is in this
# dataset and accounts for a large share of its C entries.
# Two commits deep: the fix, and the parent that is the state being scanned.
#
# The first version used a blobless clone and then checked the tree out, which
# is the slowest possible way to obtain a large repository — the checkout
# fetches every blob in the tree in batches, and it spent minutes on one repo
# before this was noticed. The fix commit SHA from REEF is complete, unlike
# PatchEval's, so a shallow fetch reaches its parent directly.
FETCH_DEPTH = 2

from corpora.repos import (ALWAYS_SKIP, MAX_REPO_MB, is_permitted_repo,
                           repository_metadata, within_size_cap)


HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")

REACHABLE = {
    "CWE-787": ["CWE-787", "CWE-119", "CWE-120"],
    "CWE-125": ["CWE-125", "CWE-119", "CWE-126"],
    "CWE-416": ["CWE-416", "CWE-825"],
    "CWE-476": ["CWE-476", "CWE-395"],
    "CWE-120": ["CWE-120", "CWE-787", "CWE-121"],
    "CWE-121": ["CWE-121", "CWE-787", "CWE-120"],
    "CWE-122": ["CWE-122", "CWE-787", "CWE-120"],
    "CWE-134": ["CWE-134", "CWE-133"],
    "CWE-190": ["CWE-190", "CWE-680", "CWE-191"],
    "CWE-119": ["CWE-119", "CWE-787", "CWE-125"],
    "CWE-22": ["CWE-22", "CWE-23", "CWE-36"],
    "CWE-78": ["CWE-78", "CWE-77", "CWE-88"],
    "CWE-415": ["CWE-415", "CWE-416"],
    "CWE-401": ["CWE-401", "CWE-772"],
}


def parse_pre_fix_span(line):
    """Line range in the file as it was BEFORE the fix.

    A zero-length range is a pure insertion: nothing existed there to point at,
    so there is no location to record.
    """
    match = HUNK_HEADER.match(line)
    if not match:
        return None
    start = int(match.group(1))
    length = int(match.group(2)) if match.group(2) is not None else 1
    if length == 0:
        return None
    return start, start + length - 1


def is_unambiguous(entry):
    """One file, one hunk — the only shape where nothing has to be guessed."""
    details = entry.get("details") or []
    if len(details) != 1:
        return False
    headers = [l for l in (details[0].get("patch") or "").splitlines()
               if l.startswith("@@")]
    return len(headers) == 1


def path_from_raw_url(url, commit):
    marker = "/raw/{}/".format(commit)
    if marker not in url:
        return None
    return urllib.parse.unquote(url.split(marker, 1)[1])


def primary_cwe(entry):
    for cwe in entry.get("CWEs") or []:
        if cwe in REACHABLE:
            return cwe
    return None


def case_id(cve, path):
    digest = hashlib.sha256("reef::{}::{}".format(cve, path).encode()).hexdigest()
    return "c-{}".format(digest[:8])


def _run(command, cwd=None, timeout=1800):
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True,
                              text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


def slug_for(repo_url):
    parts = repo_url.rstrip("/").split("/")
    return "{}__{}".format(parts[-2], parts[-1])


def checkout_dir(slug, commit):
    """Keyed by commit as well as repository, for the same reason as PatchEval:
    two CVEs in one repository sit at different commits and cannot share a tree."""
    return "{}@{}".format(slug, str(commit)[:12])


def checkout_parent(repo, fix_commit, destination):
    """Check out the commit *before* the fix — the state being scanned.

    Shallow rather than blobless. The fix SHA is complete, so fetching two
    commits deep reaches its parent and brings that tree in one operation,
    instead of a blobless clone whose checkout then fetches every blob in
    batches.
    """
    destination = Path(destination)
    if (destination / ".git").is_dir():
        return "present"
    destination.mkdir(parents=True, exist_ok=True)
    if _run(["git", "init", "-q", str(destination)]).returncode != 0:
        return "clone-failed"
    _run(["git", "-C", str(destination), "remote", "add", "origin", repo])
    if _run(["git", "-C", str(destination), "fetch", "-q",
             "--depth", str(FETCH_DEPTH), "origin", fix_commit]).returncode != 0:
        return "fetch-failed"
    parent = _run(["git", "-C", str(destination), "rev-parse",
                   "FETCH_HEAD^"]).stdout.strip()
    if not parent:
        return "parent-missing"
    if _run(["git", "-C", str(destination), "checkout", "-q", parent]).returncode != 0:
        return "checkout-failed"
    return "fetched"


def render_case(candidate):
    """Difficulty stays unknown: nothing in the dataset says how the value
    reaches the flaw, and a guess would look like a measurement."""
    rationale = (
        "{cve} in {repo}, at the commit before {fix}. The fix touched exactly one "
        "file with exactly one hunk, which is the only shape this derivation "
        "accepts — REEF records which commit fixed a CVE and not which file or "
        "hunk held the flaw, so anything less certain would be a guess presented "
        "as ground truth. The range is the pre-fix side of the hunk header, which "
        "describes the file as it is in this checkout."
    ).format(cve=candidate["cve"],
             repo="/".join(candidate["repo"].rstrip("/").split("/")[-2:]),
             fix=candidate["fix_commit"][:12])

    return "\n".join([
        "id: {}".format(case_id(candidate["cve"], candidate["file"])),
        "label: vulnerable",
        "plane: vuln",
        "tier: 3",
        "language: {}".format(candidate["language"]),
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
        "alt_locations: []",
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
        "  required: false",
        "  recipe: null",
    ]) + "\n"


def select(rows, wanted=40, skip_repos=()):
    """Unambiguous entries with a weakness a scanner can match, deduplicated."""
    seen, chosen = set(), []
    for entry in rows:
        cve = entry.get("cve_id")
        if cve in seen or not is_unambiguous(entry):
            continue
        cwe = primary_cwe(entry)
        if not cwe:
            continue
        html = entry.get("html_url") or ""
        repo = "/".join(html.split("/")[:5])
        if not is_permitted_repo(repo) or any(s in repo for s in skip_repos):
            continue
        fix_commit = html.rstrip("/").split("/")[-1]
        detail = entry["details"][0]
        path = path_from_raw_url(detail.get("raw_url", ""), fix_commit)
        if not path:
            continue
        header = next((l for l in detail["patch"].splitlines() if l.startswith("@@")), "")
        span = parse_pre_fix_span(header)
        if span is None:
            continue
        seen.add(cve)
        chosen.append({"cve": cve, "repo": repo, "fix_commit": fix_commit,
                       "path": path, "span": span, "cwe": cwe,
                       "language": "cpp" if entry.get("language") == "C++" else "c",
                       "acceptable_cwes": REACHABLE[cwe]})
        if len(chosen) >= wanted:
            break
    return chosen


def derive(chosen, checkouts_root, progress=True):
    checkouts_root = Path(checkouts_root)
    candidates, skipped = [], []
    for item in chosen:
        slug = slug_for(item["repo"])
        directory = checkout_dir(slug, item["fix_commit"])
        destination = checkouts_root / directory
        if progress:
            print("  {} {}".format(item["cve"], directory), file=sys.stderr, flush=True)
        if not within_size_cap(repository_metadata(item["repo"])):
            skipped.append((item["cve"], "repository above the {} MB cap"
                            .format(MAX_REPO_MB)))
            continue

        state = checkout_parent(item["repo"], item["fix_commit"], destination)
        if state != "fetched" and state != "present":
            skipped.append((item["cve"], state))
            continue

        source = destination / item["path"]
        if not source.is_file():
            skipped.append((item["cve"], "file absent before the fix"))
            continue
        total = len(source.read_text(errors="replace").splitlines())
        start, end = item["span"]
        if end > total:
            skipped.append((item["cve"], "hunk range past end of file"))
            continue

        candidates.append({
            "cve": item["cve"], "repo": item["repo"], "fix_commit": item["fix_commit"],
            "language": item["language"], "cwe": item["cwe"],
            "acceptable_cwes": item["acceptable_cwes"],
            "file": "tier3/reef/{}/{}".format(directory, item["path"]),
            "start_line": start, "end_line": end,
        })
    return candidates, skipped


def main(argv=None):
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, required=True,
                        help="directory holding REEF query_*.jsonl")
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--wanted", type=int, default=40)
    parser.add_argument("--skip-repo", action="append", default=["torvalds/linux"])
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    rows = []
    for path in sorted(args.data.glob("query_C*.jsonl")):
        rows += [json.loads(line) for line in path.open()]

    chosen = select(rows, wanted=args.wanted, skip_repos=tuple(args.skip_repo))
    print("selected {} unambiguous entr(ies) from {} rows".format(len(chosen), len(rows)))

    candidates, skipped = derive(chosen, args.root / "tier3" / "reef")
    print("\nderived {}; {} skipped".format(len(candidates), len(skipped)))
    reasons = {}
    for _, reason in skipped:
        reasons[reason] = reasons.get(reason, 0) + 1
    for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print("  {:>4}  {}".format(count, reason))

    if args.write:
        cases = args.root / "answers" / "cases"
        cases.mkdir(parents=True, exist_ok=True)
        for candidate in candidates:
            name = case_id(candidate["cve"], candidate["file"])
            (cases / "{}.yml".format(name)).write_text(render_case(candidate))
        print("wrote {} case file(s)".format(len(candidates)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
