#!/usr/bin/env python3
"""Check tier-3 line ranges against the fix commits they were derived from.

Tier 3 is the one tier whose ranges were **derived** rather than read: nobody
chose them by looking at the code. 266 cases across 266 real project checkouts,
and if the derivation were systematically off by a few lines the whole tier
would be worthless with nothing to reveal it — every tool would miss every case
and it would read as the tools' failure.

A scanner is a poor instrument for this. CodeQL's recall on real CVEs is low, so
a hit confirms a range and a miss confirms nothing; and one database over all
266 checkouts put a single Python query at 62 minutes. The fix commit is a far
better witness and costs nothing: if the patch that fixed the CVE touched the
recorded lines, the recorded lines are where the flaw was.

Three groups, three kinds of evidence:

`patcheval` (217 cases)
    Verified by construction. `spine/corpora/patcheval.py` keeps a location only
    when the dataset's recorded snippet is byte-identical to the bytes at the
    recorded lines in the buggy checkout, and drops it otherwise. This script
    re-asserts it by counting what is present rather than trusting the claim.

`project-sources` (28 vulnerable cases)
    These name the buggy file, so their range must intersect the lines the fix
    commit **changed or removed** — in the buggy file's coordinates.

`fixed-sources` (21 traps)
    These name the patched file, so their range must intersect the lines the fix
    commit **wrote** — in the fixed file's coordinates. The distinction matters:
    a security fix is usually a pure insertion, and an insertion occupies no
    lines at all in the buggy file. Collecting changed lines in the wrong
    coordinate space makes every such case look like a miss, which is exactly
    the wrong answer the first version of this check produced.

    python3 spine/validate/tier3_ranges.py
"""

from __future__ import annotations

import argparse
import csv
import difflib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KEY = ROOT / "answers" / "expectedresults-1.0.csv"


def load(key):
    with Path(key).open(newline="") as handle:
        return [row for row in csv.DictReader(handle) if row["tier"] == "3"]


def twin(row):
    """The same file on the other side of the fix, or None if it is not fetched.

    `tier3/project-sources/<slug>/<path>` holds the buggy file and
    `tier3/fixed-sources/<slug>/<path>` the patched one, so the twin of either is
    the other with the second path segment swapped.
    """
    parts = row["file"].split("/")
    if len(parts) < 4:
        return None
    other = "fixed-sources" if parts[1] == "project-sources" else "project-sources"
    candidate = ROOT.joinpath("tier3", other, *parts[2:])
    return candidate if candidate.is_file() else None


def changed_lines(before, after, side):
    """Lines the patch touched, in the coordinates of `side`.

    `side` is "before" for a case naming the buggy file and "after" for one
    naming the patched file. A block that exists on only one side occupies no
    lines on the other, so the seam is marked instead — otherwise a pure
    insertion registers as no change at all.
    """
    changed = set()
    matcher = difflib.SequenceMatcher(None, before, after)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        start, end = (i1, i2) if side == "before" else (j1, j2)
        if start == end:
            changed.add(start + 1)
        else:
            changed.update(range(start + 1, end + 1))
    return changed


def check_against_patch(rows, side, subtree):
    """(covered, uncovered, unfetched) for cases under `subtree`."""
    covered, uncovered, unfetched = [], [], []
    for row in rows:
        if not row["file"].startswith("tier3/{}/".format(subtree)):
            continue
        own = ROOT / row["file"]
        other = twin(row)
        if other is None or not own.is_file():
            unfetched.append(row["id"])
            continue
        mine = own.read_text(errors="replace").splitlines()
        theirs = other.read_text(errors="replace").splitlines()
        before, after = (mine, theirs) if side == "before" else (theirs, mine)
        touched = changed_lines(before, after, side)
        span = set(range(int(row["start_line"]), int(row["end_line"]) + 1))
        (covered if touched & span else uncovered).append(
            (row["id"], row["file"].split("/")[-1], row["start_line"], row["end_line"]))
    return covered, uncovered, unfetched


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--key", type=Path, default=KEY)
    args = parser.parse_args(argv)

    rows = load(args.key)
    if not rows:
        print("no tier-3 cases in the key")
        return 0

    failures = []
    print("TIER-3 RANGES vs THE FIX COMMITS THEY CAME FROM")
    print("  {} cases".format(len(rows)))
    print()

    patcheval = [r for r in rows if r["file"].startswith("tier3/patcheval/")]
    present = [r for r in patcheval if (ROOT / r["file"]).is_file()]
    print("patcheval: {} case(s), {} with the checkout present".format(
        len(patcheval), len(present)))
    print("  ranges verified by construction — patcheval.py keeps a location only when")
    print("  the recorded snippet matches the bytes at those lines, and drops it otherwise")
    if len(present) < len(patcheval):
        print("  {} checkout(s) not fetched; run spine/corpora/fetch.py tier3".format(
            len(patcheval) - len(present)))

    for subtree, side, what in (
        ("project-sources", "before", "cover lines the fix changed or removed"),
        ("fixed-sources", "after", "cover lines the fix wrote"),
    ):
        covered, uncovered, unfetched = check_against_patch(rows, side, subtree)
        total = len(covered) + len(uncovered)
        print()
        print("{}: {} case(s) comparable against a fetched fix".format(subtree, total))
        if total:
            print("  {} of {} {}".format(len(covered), total, what))
        for identifier, name, start, end in uncovered:
            print("  MISS {} {}:{}-{} does not touch the patch".format(
                identifier, name, start, end))
        if uncovered:
            failures.append("{}: {} range(s) do not overlap their fix commit".format(
                subtree, len(uncovered)))
        if unfetched:
            print("  {} case(s) have no fetched twin, so this check cannot see them".format(
                len(unfetched)))

    print()
    if failures:
        print("FAILED")
        for failure in failures:
            print("  - {}".format(failure))
        return 1
    print("Every comparable tier-3 range lands on the lines its fix commit touched.")
    print("This says the ranges point at the flaw. It says nothing about whether any")
    print("tool can find it — see docs/VALIDATION.md for that.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
