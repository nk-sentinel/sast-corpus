#!/usr/bin/env python3
"""Assert that an instrument run did not edit the corpus.

Scanners that drive a build mutate what they read. Building a CodeQL Go database
over `tier1/` ran the Go toolchain, which tidied two SCA manifests and deleted
`github.com/google/uuid v1.6.0` from them — the declared-but-never-imported
dependency those cases exist to state. `go mod tidy` removes exactly the line
the case is about, and nothing warned. It also wrote a `go.sum` in both, which
`git status` does not show without `-uall`.

Two kinds of path need two different checks, and conflating them is how the
first version of this script gave a false pass:

**Tier 1 is committed**, so git is the authority. Modified files and new
non-ignored files are both failures.

**Tiers 2 and 3 are fetched on demand and gitignored** (`/tier2/*/`,
`/tier3/*/`). git can see 3 files out of tens of thousands there, so a git-only
check reports "unchanged" while an extractor rewrites the whole tree. These need
a snapshot taken before the run:

    python3 spine/validate/corpus_unchanged.py --snapshot tier2 tier3
    ... run the scanner ...
    python3 spine/validate/corpus_unchanged.py tier2 tier3

Asked to verify an untracked tree with no snapshot, this **fails** rather than
passing. "We did not check" and "we checked and it was fine" must not look the
same — the whole point of the gate.

Better still, scan a copy and leave the corpus out of it entirely:

    cp -R tier1 tier2 /tmp/scan/ && codeql database create ... --source-root=/tmp/scan/tier1
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOTS = ROOT / "build-out" / "corpus-snapshots"

# Below this many tracked files, git is not a meaningful witness for the tree and
# a snapshot is required instead. Tier 1 has thousands; tiers 2 and 3 have three.
TRACKED_ENOUGH = 50


def resolve(target):
    """`target` as a path inside the repository, or None if it escapes.

    argv reaches a filesystem walk and a snapshot filename, so confine it before
    either. A caller pointing this at `/` would otherwise walk the disk.
    """
    path = (ROOT / target).resolve()
    if path != ROOT and ROOT not in path.parents:
        return None
    return path


def git(*args):
    done = subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False)
    return done.returncode, done.stdout


def tracked_count(target):
    _, out = git("ls-files", "--", target)
    return len(out.splitlines())


def manifest(path):
    """Every file under `path` as name -> (size, mtime).

    Size and mtime rather than content hashes: the tier-3 tree is 11 GB, and
    hashing it would take longer than the scan it is checking. A mutation that
    preserves both is not a failure mode any build tool has.
    """
    entries = {}
    for current, directories, files in os.walk(path):
        directories[:] = [d for d in directories if d != ".git"]
        for name in files:
            full = Path(current) / name
            try:
                info = full.stat()
            except OSError:
                continue
            entries[str(full.relative_to(ROOT))] = [info.st_size, int(info.st_mtime)]
    return entries


def snapshot_path(target):
    return SNAPSHOTS / "{}.json".format(str(target).strip("/").replace("/", "_"))


def take_snapshot(target, path):
    SNAPSHOTS.mkdir(parents=True, exist_ok=True)
    entries = manifest(path)
    snapshot_path(target).write_text(json.dumps(entries))
    print("  {}: {} file(s) recorded".format(target, len(entries)))
    return 0


def check_with_git(target):
    """Tier 1: modified tracked files, and new files git is not ignoring."""
    problems = []

    code, _ = git("diff", "--quiet", "--", target)
    if code != 0:
        _, stat = git("diff", "--stat", "--", target)
        problems.append(("MODIFIED", target, stat.rstrip()))

    _, untracked = git("ls-files", "--others", "--exclude-standard", "--", target)
    if untracked.strip():
        problems.append(("NEW FILES", target, untracked.rstrip()))

    return problems


def check_with_snapshot(target, path):
    """Tiers 2 and 3: compare against the manifest taken before the run."""
    stored = snapshot_path(target)
    if not stored.is_file():
        return [(
            "NOT VERIFIABLE", target,
            "git tracks too little of this tree to witness it, and no snapshot\n"
            "    was taken. Run with --snapshot before the scan, or scan a copy.",
        )]

    before = json.loads(stored.read_text())
    after = manifest(path)

    changed = sorted(k for k in before.keys() & after.keys() if before[k] != after[k])
    removed = sorted(before.keys() - after.keys())
    added = sorted(after.keys() - before.keys())

    problems = []
    for label, paths in (("MODIFIED", changed), ("REMOVED", removed), ("NEW FILES", added)):
        if paths:
            shown = "\n".join(paths[:10])
            if len(paths) > 10:
                shown += "\n... and {} more".format(len(paths) - 10)
            problems.append((label, "{} ({})".format(target, len(paths)), shown))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("targets", nargs="*", default=None,
                        help="paths to check (default: tier1)")
    parser.add_argument("--snapshot", action="store_true",
                        help="record the current state instead of checking it")
    args = parser.parse_args(argv)

    targets = args.targets or ["tier1"]
    status = 0

    if args.snapshot:
        print("recording corpus state:")
    for target in targets:
        path = resolve(target)
        if path is None or not path.exists():
            print("SKIP  {} is not a path inside the repository".format(target), file=sys.stderr)
            status = 1
            continue

        if args.snapshot:
            take_snapshot(target, path)
            continue

        if tracked_count(target) >= TRACKED_ENOUGH:
            problems = check_with_git(target)
        else:
            problems = check_with_snapshot(target, path)

        for label, where, detail in problems:
            print("{}  {}".format(label, where), file=sys.stderr)
            print("\n".join("    " + line for line in detail.splitlines()), file=sys.stderr)
            status = 1

    if args.snapshot:
        return 0

    if status:
        print(file=sys.stderr)
        print("The corpus changed during this run, or could not be verified.", file=sys.stderr)
        print("Ground truth may have been rewritten. Restore it — git checkout -- tier1,", file=sys.stderr)
        print("or re-fetch the vendored tiers — before scoring anything.", file=sys.stderr)
        return 1

    print("corpus unchanged: {}".format(" ".join(targets)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
