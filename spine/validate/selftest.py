#!/usr/bin/env python3
"""Exercise the scoring pipeline end to end without any scanner.

Every other check in this corpus either reads the answer key (`compile_answers`,
`coverage`) or reads the fixtures (`antileak`, `build/verify.sh`). None of them
runs a finding through the matcher, so a defect in path resolution, line
matching, CWE matching or assignment would surface for the first time in a
scorecard — against a tool, where it reads as the tool's fault.

A scanner would catch it, but using one has a cost this corpus cannot pay
casually: the instrument shapes the ground truth, and
docs/THREATS-TO-VALIDITY.md forbids letting a tool under evaluation do that. So
this builds the findings itself, from the answer key:

  omniscient  one finding per vulnerable case, at its primary location, with its
              primary CWE                       -> every TP, no FP
  trap-only   one finding per safe case          -> no TP, every trap tripped
  silent      no findings at all                 -> no TP, no FP, all conserved

Each has an arithmetically certain outcome, so any deviation is a defect in the
scorer or the key rather than a judgement call. What it deliberately does *not*
establish is that a real tool can find anything — a case with no reachable sink
passes this check and is still undetectable. For that, run a scanner that is not
a candidate; see docs/THREATS-TO-VALIDITY.md.

    python3 spine/validate/selftest.py            # check, print, exit non-zero on failure
    python3 spine/validate/selftest.py --keep DIR # also leave the SARIF behind
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KEY = ROOT / "answers" / "expectedresults-1.0.csv"
SCORE = ROOT / "spine" / "score" / "score.py"


def load_rows(key):
    with Path(key).open() as handle:
        return list(csv.DictReader(handle))


def missing_files(rows):
    """Answer-key paths with nothing behind them.

    Tier 1 is committed, so a miss there is a broken key. Tiers 2 and 3 are
    fetched on demand, so a miss there means the corpus is not present - which
    the scorer cannot tell you, because it compares strings and never touches
    the filesystem.
    """
    return [r for r in rows if not (ROOT / r["file"]).is_file()]


def ranges_past_eof(rows):
    """Cases whose end_line is beyond the file, checked only where it exists."""
    out = []
    for row in rows:
        path = ROOT / row["file"]
        if not path.is_file():
            continue
        lines = len(path.read_text(errors="replace").splitlines())
        if int(row["end_line"]) > lines:
            out.append((row["id"], row["file"], int(row["end_line"]), lines))
    return out


def _sarif(rows, name):
    cwes = sorted({r["primary_cwe"] for r in rows})
    rule_of = {cwe: "rule-{}".format(i) for i, cwe in enumerate(cwes)}
    rules = [
        {"id": rule_of[cwe], "properties": {"tags": ["external/cwe/cwe-{}".format(cwe.split("-")[1])]}}
        for cwe in cwes
    ]
    results = [
        {
            "ruleId": rule_of[row["primary_cwe"]],
            "level": "error",
            "message": {"text": "synthetic self-test finding"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": row["file"]},
                    "region": {"startLine": int(row["start_line"]), "endLine": int(row["end_line"])},
                }
            }],
        }
        for row in rows
    ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": name, "version": "0.0.0", "rules": rules}}, "results": results}],
    }


def score(sarif_path, key):
    """Run the real scorer, so this tests what a scorecard runs, not a copy."""
    done = subprocess.run(
        [sys.executable, str(SCORE), str(sarif_path), str(key), "--json"],
        capture_output=True, text=True, check=False,
    )
    if done.returncode not in (0, 1):
        raise SystemExit("score.py failed ({}): {}".format(done.returncode, done.stderr.strip()[:400]))
    return json.loads(done.stdout)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--key", type=Path, default=KEY)
    parser.add_argument("--keep", type=Path, help="write the generated SARIF here instead of a temp dir")
    args = parser.parse_args(argv)

    rows = load_rows(args.key)
    vulnerable = [r for r in rows if r["label"] == "vulnerable"]
    safe = [r for r in rows if r["label"] == "safe"]
    failures = []

    print("ANSWER KEY")
    print("  {} cases: {} vulnerable, {} traps".format(len(rows), len(vulnerable), len(safe)))

    absent = missing_files(rows)
    by_tier = {}
    for row in absent:
        by_tier.setdefault(row["tier"], 0)
        by_tier[row["tier"]] += 1
    if absent:
        print("  {} case(s) point at files that are not present: {}".format(len(absent), by_tier))
        print("      tier 2 and 3 are fetched on demand — run spine/corpora/fetch.py")
        if any(r["tier"] == "1" for r in absent):
            failures.append("tier-1 cases reference missing files; tier 1 is committed, so the key is broken")
    else:
        print("  every referenced file is present")

    past = ranges_past_eof(rows)
    if past:
        failures.append("{} case(s) end past the end of their file".format(len(past)))
        for identifier, path, end, total in past[:5]:
            print("  RANGE {} {} ends at {} but the file has {} lines".format(identifier, path, end, total))
    else:
        print("  no case ends past the end of its file")

    holder = args.keep or Path(tempfile.mkdtemp(prefix="selftest-"))
    holder.mkdir(parents=True, exist_ok=True)
    expectations = [
        ("omniscient", vulnerable, len(vulnerable), 0),
        ("trap-only", safe, 0, len(safe)),
        ("silent", [], 0, 0),
    ]
    print("\nSYNTHETIC RUNS")
    for name, subset, want_tp, want_fp in expectations:
        path = holder / "selftest-{}.sarif".format(name)
        path.write_text(json.dumps(_sarif(subset or rows[:0], name)))
        overall = score(path, args.key)["overall"]
        got_tp, got_fp = overall["tp"], overall["fp"]
        ok = got_tp == want_tp and got_fp == want_fp
        print("  {:11s} tp={:4d} (want {:4d})   fp={:4d} (want {:4d})   {}".format(
            name, got_tp, want_tp, got_fp, want_fp, "ok" if ok else "FAILED"))
        if not ok:
            failures.append("{}: tp {} want {}, fp {} want {}".format(name, got_tp, want_tp, got_fp, want_fp))
        counted = got_tp + overall["fn"] + got_fp + overall["tn"]
        if counted != len(rows):
            failures.append("{}: {} cases accounted for, key has {}".format(name, counted, len(rows)))

    if args.keep:
        print("\nSARIF kept in {}".format(holder))

    print()
    if failures:
        print("FAILED")
        for failure in failures:
            print("  - {}".format(failure))
        return 1
    print("The matcher counts what the key says, and every case is accounted for.")
    print("This says nothing about whether a real tool can find these cases.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
