#!/usr/bin/env python3
"""Fetch the external corpora — real applications, CVE reproductions, perf repos.

These are not vendored into this repository. WebGoat alone is larger than
everything here put together, and committing several such trees would make the
corpus expensive to clone for the sake of code we did not write and cannot edit.

Instead each corpus carries a manifest of upstream repositories pinned to a full
commit SHA, and this fetches them on demand. A run is reproducible because the
revision is fixed; the repository stays small because the code is not in it.

Pinning is enforced, not merely encouraged. A corpus fetched from a moving branch
is not a corpus: two runs a month apart would score different code, and nothing
in either scorecard would say so.

    python3 spine/corpora/fetch.py tier2
    python3 spine/corpora/fetch.py perf --check
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
REQUIRED = ("name", "repo", "sha", "license")


@dataclass
class Source:
    name: str
    repo: str
    sha: str
    license: str
    languages: list = field(default_factory=list)
    notes: str = ""
    approx_loc: int = None
    bucket: str = None


def load_manifest(path):
    data = json.loads(Path(path).read_text())
    return [
        Source(**{key: entry.get(key) for key in
                  ("name", "repo", "sha", "license", "languages", "notes",
                   "approx_loc", "bucket")})
        for entry in data.get("sources", [])
    ]


def manifest_errors(data):
    """Every problem at once, so a manifest is fixed in one pass."""
    errors = []
    seen = set()

    for entry in data.get("sources", []):
        name = entry.get("name", "<unnamed>")

        for key in REQUIRED:
            if not entry.get(key):
                errors.append("{}: missing {}".format(name, key))

        sha = entry.get("sha", "")
        if sha and not FULL_SHA.match(sha):
            errors.append(
                "{}: sha {!r} is not a full 40-character commit id; a branch or "
                "abbreviated revision makes the corpus unreproducible".format(name, sha))

        if name in seen:
            errors.append("{}: duplicate source name".format(name))
        seen.add(name)

    return errors


def target_path(root, corpus, source):
    """Where a source is checked out, refusing anything that escapes the corpus."""
    destination = (Path(root) / corpus / source.name).resolve()
    boundary = (Path(root) / corpus).resolve()

    if boundary != destination and boundary not in destination.parents:
        raise ValueError("source name {!r} escapes {}".format(source.name, corpus))

    return destination


def fetch(source, destination):
    """Clone at the pinned revision. Existing checkouts are left alone."""
    if (destination / ".git").is_dir():
        current = subprocess.run(["git", "-C", str(destination), "rev-parse", "HEAD"],
                                 stdout=subprocess.PIPE, text=True)
        if current.returncode == 0 and current.stdout.strip() == source.sha:
            return "present"
        return "wrong-revision"

    destination.mkdir(parents=True, exist_ok=True)
    steps = [
        ["git", "-C", str(destination), "init", "-q"],
        ["git", "-C", str(destination), "remote", "add", "origin", source.repo],
        ["git", "-C", str(destination), "fetch", "-q", "--depth", "1", "origin", source.sha],
        ["git", "-C", str(destination), "checkout", "-q", "FETCH_HEAD"],
    ]
    for step in steps:
        if subprocess.run(step, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE).returncode != 0:
            return "failed"

    return "fetched"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("corpus", choices=("tier2", "tier3", "perf"))
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--check", action="store_true",
                        help="validate the manifest and report status without cloning")
    parser.add_argument("--only", default=None, help="fetch a single source by name")
    args = parser.parse_args(argv)

    manifest_path = args.root / args.corpus / "sources.json"
    if not manifest_path.is_file():
        print("no manifest at {}".format(manifest_path), file=sys.stderr)
        return 2

    data = json.loads(manifest_path.read_text())
    errors = manifest_errors(data)
    for error in errors:
        print("error: {}".format(error), file=sys.stderr)
    if errors:
        return 1

    sources = load_manifest(manifest_path)
    if args.only:
        sources = [s for s in sources if s.name == args.only]

    print("{}: {} source(s)".format(args.corpus, len(sources)))
    failures = 0

    for source in sources:
        destination = target_path(args.root, args.corpus, source)
        if args.check:
            state = "present" if (destination / ".git").is_dir() else "absent"
            print("  {:<22} {:<10} {:<14} {}".format(
                source.name, state, source.license, source.sha[:12]))
            continue

        state = fetch(source, destination)
        print("  {:<22} {}".format(source.name, state))
        if state == "failed":
            failures += 1
        elif state == "wrong-revision":
            print("    checkout is not at the pinned revision; remove it and refetch",
                  file=sys.stderr)
            failures += 1

    if failures:
        print("\n{} source(s) unavailable".format(failures), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
