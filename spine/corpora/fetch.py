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
import os
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
    # Declared but not required. A source that produces no cases should not make
    # an offline check fail every time it runs — a check that always fails is one
    # people learn to ignore.
    optional: bool = False


FIELDS = ("name", "repo", "sha", "license", "languages", "notes",
          "approx_loc", "bucket", "optional")


def load_manifest_data(data):
    return [
        Source(**{key: entry[key] for key in FIELDS if key in entry})
        for entry in data.get("sources", [])
    ]


def load_manifest(path):
    return load_manifest_data(json.loads(Path(path).read_text()))


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


def _head(destination):
    current = subprocess.run(["git", "-C", str(destination), "rev-parse", "HEAD"],
                             stdout=subprocess.PIPE, text=True)
    return current.stdout.strip() if current.returncode == 0 else None


def checkout_state(destination, sha, head=None):
    """What is on disk, without assuming git history is there to ask.

    The export bundle drops `.git` on purpose — 602 MB of packfiles for code we
    did not write, replaced by the pinned SHA recorded in MANIFEST.json. Judging
    presence by the presence of `.git` would therefore call every restored tree
    *absent* and try to clone it, which is precisely what an airgapped
    environment cannot do. A populated directory without history is `restored`:
    usable, with its provenance in the manifest rather than in git.
    """
    destination = Path(destination)
    if not destination.is_dir():
        return "absent"
    if (destination / ".git").is_dir():
        current = (head or _head)(destination)
        return "present" if current == sha else "wrong-revision"
    return "restored" if any(destination.iterdir()) else "absent"


def offline_outcome(state, optional=False):
    """Whether a state is usable with no network, and what to do if not.

    `optional` sources are declared in a manifest but produce no cases, so their
    absence is reported and does not fail the run.
    """
    if state in ("present", "restored"):
        return "ok", ""
    if state == "wrong-revision":
        return "error", ("checkout is not at the pinned revision and cannot be "
                         "refetched offline; restore this source from the bundle")
    if optional:
        return "note", ("optional and not present; it contributes no cases, so "
                        "scoring is unaffected")
    return "error", ("not present and cannot be fetched offline; restore it from "
                     "the export bundle (see docs/AIRGAP-EXPORT.md)")


def offline_requested(argv_offline, environ):
    """An airgapped host should not depend on anyone remembering a flag."""
    if argv_offline:
        return True
    return str(environ.get("SAST_CORPUS_OFFLINE", "")).strip().lower() in ("1", "true", "yes")


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


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("corpus", choices=("tier2", "tier3", "perf"))
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--check", action="store_true",
                        help="validate the manifest and report status without cloning")
    parser.add_argument("--only", default=None, help="fetch a single source by name")
    parser.add_argument("--offline", action="store_true",
                        help="never reach the network; report what is present and "
                             "fail on anything that is not. Also set by "
                             "SAST_CORPUS_OFFLINE=1")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    offline = offline_requested(args.offline, os.environ)

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

    print("{}: {} source(s){}".format(
        args.corpus, len(sources), " [offline]" if offline else ""))
    failures = 0

    for source in sources:
        destination = target_path(args.root, args.corpus, source)
        if args.check:
            state = checkout_state(destination, source.sha)
            print("  {:<22} {:<12} {:<14} {}".format(
                source.name, state, source.license, source.sha[:12]))
            continue

        if offline:
            # Never touch the network. A clone attempt here does not fail fast:
            # it hangs against an unreachable host, which looks like the corpus
            # being broken rather than the environment being airgapped.
            state = checkout_state(destination, source.sha)
            status, advice = offline_outcome(state, source.optional)
            print("  {:<22} {}".format(source.name, state))
            if advice:
                stream = sys.stderr if status == "error" else sys.stdout
                print("    {}".format(advice), file=stream)
            if status == "error":
                failures += 1
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
