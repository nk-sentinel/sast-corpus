#!/usr/bin/env python3
"""Derive tier-3 cases from PatchEval — real CVEs in Go, JavaScript and Python.

Tier 3 was Java only, from cwe-bench-java. PatchEval covers the three languages
this corpus most needed real cases in, and unlike that dataset it records the
line numbers against the **buggy** commit rather than the fixed one, which was
verified by cloning all 230 repositories and comparing the recorded snippet to
the bytes at the recorded lines: 203 matched exactly.

Three rules came out of that verification, and skipping any of them loses cases
silently — see ../../docs/TIER3-DATASETS.md:

1. **Anchor to the commit each location names**, not to the fix commit's parent.
   They diverge on 5 of 230.
2. **Clone fully, not shallow.** The recorded commit is abbreviated and an
   abbreviated SHA cannot be fetched. A blobless clone gets the history cheaply
   and fills in file contents on checkout.
3. **Coerce the line numbers.** 6 of 296 locations record them as strings.

A location is used only when the recorded snippet is actually at the recorded
lines in the checkout. Anything else would point the answer key at code that is
not the flaw, which is worse than having no case at all.

These languages are scanned from source, so no build is required and the
per-CVE Docker images PatchEval ships are unnecessary here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

# Importable both as `corpora.<name>` (tests put spine/ on the path) and as a
# script run from the repository root, where sys.path[0] is spine/corpora.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from corpora.repos import worth_fetching

LANGUAGES = {"Go": "go", "JavaScript": "javascript", "Python": "python"}

# Two commits deep: the fix, and the parent that is almost always the commit the
# locations name. The recorded SHA is abbreviated and cannot be fetched
# directly, which is why the first version cloned whole histories — but the fix
# commit URL carries a complete one, and for 225 of 230 entries the recorded
# commit is simply its parent. The other 5 fall back to the full clone.
FETCH_DEPTH = 2

# The shortcut has to give up quickly. Fetching a specific SHA works only when
# the server will serve it, and where it will not the negotiation hangs rather
# than refusing — with the fallback's timeout, each such repository cost fifteen
# minutes and the run crawled at two CVEs an hour. The fallback is the slow path
# by definition and keeps its room.
FAST_FETCH_TIMEOUT = 120
FALLBACK_TIMEOUT = 1800

# Weaknesses a scanner can match on, in the order we prefer them. A CVE tagged
# both CWE-284 and CWE-22 is a path traversal; the class is the label a database
# reaches for when it wants a bucket, and the specific one is what a tool reports.
PREFERRED = [
    "CWE-89", "CWE-78", "CWE-77", "CWE-79", "CWE-22", "CWE-23", "CWE-73",
    "CWE-94", "CWE-95", "CWE-502", "CWE-611", "CWE-918", "CWE-798", "CWE-327",
    "CWE-601", "CWE-352", "CWE-434", "CWE-863", "CWE-862", "CWE-639", "CWE-306",
    "CWE-269", "CWE-250", "CWE-285", "CWE-284", "CWE-20", "CWE-400", "CWE-770",
]

ACCEPTABLE = {
    "CWE-89": ["CWE-89", "CWE-943", "CWE-564"],
    "CWE-78": ["CWE-78", "CWE-77", "CWE-88"],
    "CWE-77": ["CWE-77", "CWE-78", "CWE-88"],
    "CWE-79": ["CWE-79", "CWE-80", "CWE-83"],
    "CWE-22": ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
    "CWE-23": ["CWE-23", "CWE-22", "CWE-36"],
    "CWE-73": ["CWE-73", "CWE-22", "CWE-23"],
    "CWE-94": ["CWE-94", "CWE-95", "CWE-96"],
    "CWE-95": ["CWE-95", "CWE-94"],
    "CWE-502": ["CWE-502", "CWE-915"],
    "CWE-611": ["CWE-611", "CWE-827", "CWE-776"],
    "CWE-918": ["CWE-918", "CWE-441"],
    "CWE-601": ["CWE-601", "CWE-1022"],
    "CWE-862": ["CWE-862", "CWE-285", "CWE-863"],
    "CWE-863": ["CWE-863", "CWE-285", "CWE-862"],
}

CWE_SHAPE = re.compile(r"^CWE-\d+$")


def primary_cwe(cwe_info):
    """The weakness a scanner would actually report.

    NVD placeholders are not weaknesses. Where a CVE carries both a category and
    a specific weakness, the specific one wins — a database reaches for the
    category when it wants a bucket, and a tool reports the thing itself.
    """
    candidates = [c for c in (cwe_info or {}) if CWE_SHAPE.match(c)]
    if not candidates:
        return None
    for preferred in PREFERRED:
        if preferred in candidates:
            return preferred
    return sorted(candidates, key=lambda c: int(c.split("-")[1]))[0]


def acceptable_for(cwe):
    return ACCEPTABLE.get(cwe, [cwe])


def coerce_span(location):
    """The line range, whatever type the dataset used to record it."""
    try:
        start = int(location["start_line"])
        end = int(location["end_line"])
    except (KeyError, TypeError, ValueError):
        return None
    return (start, end) if start <= end else None


def _normalise(path):
    return str(path).lstrip("./")


def usable_locations(locations, sources):
    """Locations whose recorded snippet is genuinely at the recorded lines.

    `sources` maps a repository-relative path to its content at the buggy
    commit. A location that does not match is dropped rather than recorded with
    a caveat: an answer key pointing at code that is not the flaw scores every
    tool wrongly, in both directions.
    """
    kept = []
    for location in locations or []:
        span = coerce_span(location)
        if span is None:
            continue
        path = _normalise(location.get("file_path", ""))
        source = sources.get(path)
        if source is None:
            continue
        lines = source.splitlines()
        start, end = span
        if start < 1 or end > len(lines):
            continue
        actual = "\n".join(lines[start - 1:end])
        if actual.strip() != (location.get("snippet") or "").strip():
            continue
        kept.append({"path": path, "start_line": start, "end_line": end})
    return kept


def case_id(cve, path):
    """Opaque and stable, so re-deriving produces the same identifier and the
    answer key diffs cleanly."""
    digest = hashlib.sha256("patcheval::{}::{}".format(cve, path).encode()).hexdigest()
    return "c-{}".format(digest[:8])


def render_case(candidate):
    """Render a derived candidate as an answer-key case.

    Difficulty stays `unknown`. Whether the flow crosses a file, whether a
    sanitizer is present and whether anything is aliased are not knowable from
    the dataset — only from reading the code — and a guess would be
    indistinguishable from a measurement in the difficulty breakdown.

    There is no safe sibling, so tier 3 measures recall only. That is a property
    of the tier rather than an oversight: the dataset records where each CVE was
    fixed and says nothing about which nearby code is correctly defended.
    """
    alts = candidate.get("alt_locations") or []
    spread = ""
    if alts:
        spread = (" Ground truth spans the {} location(s) the fix touched, and a hit "
                  "at any of them counts, because a fix commit routinely edits more "
                  "than the flaw.".format(len(alts) + 1))

    rationale = (
        "{cve} in {repo}, at the buggy commit {commit}. The line range is the one "
        "PatchEval records for the vulnerable function, confirmed against the bytes "
        "in that checkout rather than trusted — the recorded snippet appears exactly "
        "at these lines.{spread}"
    ).format(cve=candidate["cve"],
             repo="/".join(candidate["repo"].rstrip("/").split("/")[-2:]),
             commit=candidate["commit"], spread=spread)

    lines = [
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
        "  required: false",
        "  recipe: null",
    ]
    return "\n".join(lines) + "\n"


# --- checkout ----------------------------------------------------------------


def _run(command, cwd=None, timeout=900):
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True,
                              text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


def fix_commit_of(entry):
    urls = entry.get("patch_url") or []
    if not urls:
        return None
    return urls[0].rstrip("/").split("/")[-1]


def is_recorded_commit(candidate, recorded):
    """Is this full SHA the commit the dataset named?

    The dataset abbreviates, so the comparison is a prefix. Empty on either side
    is not a match: nothing to compare against is not evidence of agreement.
    """
    if not candidate or not recorded:
        return False
    return candidate.startswith(recorded)


def checkout(repo, commit, destination, fix_commit=None):
    """Blobless full clone, then check out the commit the location names.

    Full rather than shallow because the recorded commit is abbreviated and an
    abbreviated SHA cannot be fetched directly. Blobless keeps that affordable:
    the history arrives, file contents follow only for what is checked out.
    """
    destination = Path(destination)
    if (destination / ".git").is_dir():
        if _run(["git", "-C", str(destination), "checkout", "-q", commit]).returncode == 0:
            return "present"
        return "wrong-revision"

    destination.parent.mkdir(parents=True, exist_ok=True)

    # Fast path: fetch two commits from the complete fix SHA and use its parent,
    # but only after confirming the parent really is the commit the locations
    # name. Where it is not, fall through to the full clone rather than scan the
    # wrong tree.
    if fix_commit:
        destination.mkdir(parents=True, exist_ok=True)
        _run(["git", "init", "-q", str(destination)])
        _run(["git", "-C", str(destination), "remote", "add", "origin", repo])
        fetched = _run(["git", "-C", str(destination), "fetch", "-q",
                        "--depth", str(FETCH_DEPTH), "origin", fix_commit],
                       timeout=FAST_FETCH_TIMEOUT)
        if fetched.returncode == 0:
            parent = _run(["git", "-C", str(destination), "rev-parse",
                           "FETCH_HEAD^"]).stdout.strip()
            if is_recorded_commit(parent, commit):
                if _run(["git", "-C", str(destination), "checkout", "-q",
                         parent]).returncode == 0:
                    return "fetched"
        import shutil
        shutil.rmtree(destination, ignore_errors=True)

    cloned = _run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout",
                   repo, str(destination)], timeout=FALLBACK_TIMEOUT)
    if cloned.returncode != 0:
        return "clone-failed"
    if _run(["git", "-C", str(destination), "checkout", "-q", commit],
            timeout=FALLBACK_TIMEOUT).returncode != 0:
        return "commit-missing"
    return "fetched"


def slug_for(repo):
    parts = repo.rstrip("/").replace(".git", "").split("/")
    return "{}__{}".format(parts[-2], parts[-1])


def checkout_dir(slug, commit):
    """Where a repository at a particular commit lives.

    Keyed by commit as well as repository. A repository can hold several CVEs at
    different commits — django has 12 in this dataset — and they cannot share a
    working tree: each derivation would move the tree away from the last, so
    every case but the final one would point at line numbers in a tree that had
    since changed. Two cases reached the answer key that way, both referencing
    lines past the end of their file.
    """
    return "{}@{}".format(slug, str(commit)[:12])


def read_sources(root, paths):
    sources = {}
    for path in paths:
        candidate = Path(root) / path
        if candidate.is_file():
            try:
                sources[path] = candidate.read_text(errors="replace")
            except OSError:
                continue
    return sources


def write_case(candidate, cases_root):
    """Write one derived case, returning where it landed.

    Written as each candidate is derived rather than collected and flushed at
    the end. Deriving 230 CVEs means cloning 230 repositories and takes hours,
    and a run that is interrupted — a timeout, a killed process, a full disk —
    otherwise produces nothing at all despite all of it.
    """
    cases_root = Path(cases_root)
    cases_root.mkdir(parents=True, exist_ok=True)
    path = cases_root / "{}.yml".format(case_id(candidate["cve"], candidate["file"]))
    path.write_text(render_case(candidate))
    return path


def derive(dataset, checkouts_root, only=None, progress=True, cases_root=None):
    """Walk the dataset and produce one candidate per usable CVE."""
    checkouts_root = Path(checkouts_root)
    candidates, skipped = [], []

    for entry in dataset:
        cve = entry.get("cve_id")
        if only and only != cve:
            continue
        language = LANGUAGES.get(entry.get("programming_language"))
        cwe = primary_cwe(entry.get("cwe_info"))
        locations = entry.get("vul_func") or []
        if not language or not cwe or not locations:
            skipped.append((cve, "no language, weakness or location"))
            continue

        if not worth_fetching(entry["repo"]):
            skipped.append((cve, "repository too large to be worth fetching"))
            continue

        commit = locations[0].get("commit")
        slug = slug_for(entry["repo"])
        directory = checkout_dir(slug, commit)
        destination = checkouts_root / directory
        if progress:
            print("  {} {}".format(cve, directory), file=sys.stderr, flush=True)

        state = checkout(entry["repo"], commit, destination,
                         fix_commit=fix_commit_of(entry))
        if state in ("clone-failed", "commit-missing", "wrong-revision"):
            skipped.append((cve, state))
            continue

        wanted = {_normalise(l.get("file_path", "")) for l in locations}
        usable = usable_locations(locations, read_sources(destination, wanted))
        if not usable:
            skipped.append((cve, "no location matched the checkout"))
            continue

        primary = usable[0]
        relative = "tier3/patcheval/{}".format(directory)
        candidate = {
            "cve": cve, "repo": entry["repo"], "commit": commit,
            "language": language, "cwe": cwe, "acceptable_cwes": acceptable_for(cwe),
            "slug": slug,
            "file": "{}/{}".format(relative, primary["path"]),
            "start_line": primary["start_line"], "end_line": primary["end_line"],
            "alt_locations": [
                {"file": "{}/{}".format(relative, other["path"]),
                 "start_line": other["start_line"], "end_line": other["end_line"]}
                for other in usable[1:]],
        }
        candidates.append(candidate)
        if cases_root:
            write_case(candidate, cases_root)

    return candidates, skipped


def main(argv=None):
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", type=Path, required=True,
                        help="patcheval_verified.json")
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--only", default=None, help="one CVE")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--write", action="store_true",
                        help="write case files into answers/cases/")
    args = parser.parse_args(argv)

    dataset = json.loads(args.dataset.read_text())
    if args.limit:
        dataset = dataset[:args.limit]

    candidates, skipped = derive(
        dataset, args.root / "tier3" / "patcheval", only=args.only,
        cases_root=(args.root / "answers" / "cases") if args.write else None)

    print("\nderived {} case(s); {} skipped".format(len(candidates), len(skipped)))
    reasons = {}
    for _, reason in skipped:
        reasons[reason] = reasons.get(reason, 0) + 1
    for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print("  {:>4}  {}".format(count, reason))

    if args.write:
        print("wrote {} case file(s) as they were derived".format(len(candidates)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
