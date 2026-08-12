"""Prove, on the far side of an airgap, that this is the corpus that left.

A bundle that unpacks without error is not evidence. Files truncate in transit,
media go bad, and an archive extracted into the wrong tree looks perfectly
normal. What makes a scorecard produced in an airgapped environment comparable
to one produced here is that the corpus verified itself first — and that it
could do so without the network, without a package installation, and without
anything that might not have made the trip.

Every check runs against the standard library alone. That is the payoff of the
scorer having no dependencies: verification is available wherever the corpus is.

Two rules the report follows, both inherited from the syntax gate:

- **"Could not check" is not "checked and fine."** A gate that could not run is
  reported as skipped and fails the run, rather than quietly counting as a pass.
- **Nothing is asserted that was not measured.** An unlisted file is reported as
  unlisted, not as corruption.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

SUM_LINE = re.compile(r"^([0-9a-fA-F]{64})\s\s?\*?(.+)$")


def parse_sha256sums(text):
    """Read a `sha256sum` file.

    The digest and the path are separated by two spaces and the path may itself
    contain spaces, so splitting on whitespace truncates any path containing one
    and then reports a file that exists as missing. A line that is neither blank
    nor a valid entry raises rather than being dropped: a checksum file that is
    quietly half-read is worse than one that fails loudly.
    """
    entries = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        match = SUM_LINE.match(line)
        if not match:
            raise ValueError(f"not a sha256sum line: {line[:80]!r}")
        entries[match.group(2).strip()] = match.group(1).lower()
    return entries


@dataclass
class Integrity:
    checked: int = 0
    missing: list = field(default_factory=list)
    modified: list = field(default_factory=list)
    unlisted: list = field(default_factory=list)
    exposed_ground_truth: list = field(default_factory=list)


def _digest(path, chunk=1 << 20):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_checksums(root, entries, progress=None):
    root = Path(root)
    result = Integrity()

    for relative, expected in sorted(entries.items()):
        path = root / relative
        if not path.is_file():
            result.missing.append(relative)
            continue
        result.checked += 1
        if _digest(path) != expected:
            result.modified.append(relative)
        if progress and result.checked % 20000 == 0:
            progress(result.checked, len(entries))

    # An unlisted file matters only under a root the bundle actually covers.
    # A scan output written beside the corpus is not corruption; a stray file
    # inside tier1/ is, and extracting the answers archive over the corpus one
    # would show up here.
    covered = {Path(relative).parts[0] for relative in entries}
    for top in sorted(covered):
        directory = root / top
        if not directory.is_dir():
            continue
        for candidate in directory.rglob("*"):
            if not candidate.is_file() or candidate.is_symlink():
                continue
            relative = str(candidate.relative_to(root))
            if relative not in entries:
                result.unlisted.append(relative)
    result.unlisted.sort()
    result.exposed_ground_truth = ground_truth_exposed(root, entries)
    return result


def ground_truth_exposed(root, entries):
    """Is the answer key sitting in a tree that is meant to be scanned?

    Extracting the answers archive over the scannable one is the single mistake
    that quietly invalidates a bake-off: the scanner reads every CWE identifier
    and every rationale, and an LLM-based tool then scores on the answers rather
    than the code. The result still looks like a clean run.

    The generic unlisted-file walk cannot see it. That walk only inspects roots
    the checksum list already covers, and a corpus list contains no `answers/`
    entries, so the directory is never visited. Hence a check of its own.

    Verifying the answers archive itself is not exposure — there the answer key
    is exactly what is being checked.
    """
    if any(path.startswith("answers/") for path in entries):
        return []
    answers = Path(root) / "answers"
    if not answers.is_dir():
        return []
    found = [str(p.relative_to(root)) for p in sorted(answers.rglob("*"))
             if p.is_file() and p.suffix in (".yml", ".yaml", ".csv")]
    return found


def find_sum_files(root):
    """Checksum lists present in an extracted tree.

    Each archive ships its own, and the far side may legitimately have unpacked
    only one — the scannable archive and the answer key are meant to be kept
    apart. Verification runs against whichever are there. An older bundle with a
    single combined `SHA256SUMS` still works.
    """
    root = Path(root)
    per_archive = sorted(root.glob("SHA256SUMS.*"))
    if per_archive:
        return per_archive
    combined = root / "SHA256SUMS"
    return [combined] if combined.exists() else []


@dataclass
class GateResult:
    name: str
    status: str          # pass | fail | skipped
    detail: str = ""


def _run(command, cwd, timeout=1800):
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True,
                              text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def _last_meaningful_line(text):
    for line in reversed((text or "").strip().splitlines()):
        if line.strip():
            return line.strip()[:160]
    return ""


def run_gates(root, skip=()):
    """The checks already in the corpus, re-run where it landed."""
    root = Path(root)
    results = []

    def gate(name, command, needs=None):
        if name in skip:
            results.append(GateResult(name, "skipped", "excluded by request"))
            return
        if needs and not (root / needs).exists():
            results.append(GateResult(name, "skipped", f"{needs} not extracted"))
            return
        outcome = _run(command, root)
        if outcome.returncode == 127:
            results.append(GateResult(name, "skipped", _last_meaningful_line(outcome.stderr)))
        elif outcome.returncode == 0:
            results.append(GateResult(name, "pass",
                                      _last_meaningful_line(outcome.stdout)))
        else:
            results.append(GateResult(name, "fail",
                                      _last_meaningful_line(outcome.stderr)
                                      or _last_meaningful_line(outcome.stdout)))

    python = sys.executable or "python3"
    gate("answer key regenerates",
         [python, "spine/schema/compile_answers.py"], needs="answers")
    gate("no answer leakage", [python, "spine/lint/antileak.py"], needs="tier1")
    gate("fixtures parse", ["./build/syntax/check.sh"], needs="tier1")
    gate("unit tests",
         [python, "-m", "unittest", "discover", "-s", "spine/tests", "-t", "."])
    return results


def negative_control(root):
    """Score an empty result set. Every case must be accounted for and nothing
    may be credited — if a harness fabricates matches, it does it here."""
    root = Path(root)
    key = next(iter(sorted((root / "answers").glob("expectedresults-*.csv"))), None)
    if key is None:
        return GateResult("negative control", "skipped", "answer key not extracted")

    empty = root / ".verify-empty.sarif"
    empty.write_text(json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "none"}}, "results": []}],
    }))
    try:
        outcome = _run([sys.executable or "python3", "spine/score/score.py",
                        str(empty), str(key)], root)
    finally:
        empty.unlink(missing_ok=True)

    if outcome.returncode == 127:
        return GateResult("negative control", "skipped", _last_meaningful_line(outcome.stderr))
    text = outcome.stdout or ""
    found = re.search(r"(\d[\d,]*)\s+found", text)
    alarms = re.search(r"(\d[\d,]*)\s+false alarms", text)
    if not found:
        return GateResult("negative control", "fail",
                          "scorer produced no readable report")
    if found.group(1).replace(",", "") != "0":
        return GateResult("negative control", "fail",
                          f"empty input credited {found.group(1)} findings")
    if alarms and alarms.group(1).replace(",", "") != "0":
        return GateResult("negative control", "fail",
                          f"empty input raised {alarms.group(1)} false alarms")
    return GateResult("negative control", "pass",
                      "empty input scores 0 found, 0 false alarms")


def exit_code(integrity, gates):
    """Non-zero on anything that makes a scorecard untrustworthy.

    A skipped gate counts as a failure. The alternative is a run that reports
    green because nothing ran, which is the failure mode this whole file exists
    to prevent. An unlisted file is reported but does not fail: it is worth
    knowing about and is not evidence the corpus changed.
    """
    if integrity.missing or integrity.modified or integrity.exposed_ground_truth:
        return 1
    if any(gate.status != "pass" for gate in gates):
        return 1
    return 0


def render(integrity, gates, profile, version):
    lines = [
        f"ARRIVAL CHECK — sast-corpus {version}, profile {profile}",
        "",
        "INTEGRITY",
        f"  {integrity.checked:>7}  files checksummed",
        f"  {len(integrity.missing):>7}  missing",
        f"  {len(integrity.modified):>7}  modified — content differs from the manifest",
        f"  {len(integrity.unlisted):>7}  present but not in the manifest",
    ]
    for label, paths in (("missing", integrity.missing),
                         ("modified", integrity.modified)):
        for path in paths[:10]:
            lines.append(f"      {label}: {path}")
        if len(paths) > 10:
            lines.append(f"      ... and {len(paths) - 10} more")
    if integrity.exposed_ground_truth:
        lines += ["",
                  "  GROUND TRUTH IS IN THE SCAN TARGET",
                  f"  {len(integrity.exposed_ground_truth)} answer-key file(s) sit under "
                  "answers/ in a tree whose",
                  "  checksum list does not cover them — the answers archive was extracted",
                  "  over the scannable one. A scanner pointed here reads the CWE of every",
                  "  case, and an LLM-based tool will score on that rather than on the code.",
                  "  Remove answers/ before scanning, or extract the two archives apart."]
        for path in integrity.exposed_ground_truth[:3]:
            lines.append(f"      {path}")

    if integrity.unlisted:
        lines += ["",
                  "  Unlisted files are not corruption, but check whether the answers",
                  "  archive was extracted over the scannable one — that would put the",
                  "  ground truth where a scanner reads it."]
        for path in integrity.unlisted[:5]:
            lines.append(f"      {path}")

    if gates:
        lines += ["", "GATES"]
        for gate in gates:
            mark = {"pass": "ok  ", "fail": "FAIL", "skipped": "SKIP"}[gate.status]
            lines.append(f"  {mark}  {gate.name}" + (f" — {gate.detail}" if gate.detail else ""))

    skipped = [g for g in gates if g.status == "skipped"]
    failed = [g for g in gates if g.status == "fail"]
    lines.append("")
    if integrity.exposed_ground_truth:
        lines.append("Do not scan this tree until answers/ is removed from it.")
    elif integrity.missing or integrity.modified or failed:
        lines.append("This is NOT the corpus that left. Do not score against it.")
    elif skipped:
        lines.append(f"{len(skipped)} check(s) skipped — they could not run, so this corpus is")
        lines.append("unverified rather than verified-good. Resolve them before scoring.")
    else:
        lines.append("Verified: this is the same corpus that left, and a scorecard")
        lines.append("produced against it is comparable to one produced at origin.")
    return "\n".join(lines) + "\n"


def build_parser():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=root,
                        help="extracted corpus root")
    parser.add_argument("--sums", type=Path, default=None,
                        help="SHA256SUMS (default: <root>/SHA256SUMS)")
    parser.add_argument("--manifest", type=Path, default=None,
                        help="MANIFEST.json (default: <root>/MANIFEST.json)")
    parser.add_argument("--skip", action="append", default=[],
                        help="skip a gate by name; it is reported as skipped")
    parser.add_argument("--checksums-only", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    root = args.root
    sums = args.sums or root / "SHA256SUMS"
    manifest_path = args.manifest or root / "MANIFEST.json"

    profile, version = "unknown", "unknown"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        profile = manifest.get("profile", "unknown")
        version = manifest.get("corpus_version", "unknown")

    sum_files = [sums] if args.sums else find_sum_files(root)
    if not sum_files:
        print(f"no checksum list found under {root}; nothing can be verified",
              file=sys.stderr)
        return 2

    entries = {}
    for path in sum_files:
        print(f"reading {path.name}", file=sys.stderr, flush=True)
        entries.update(parse_sha256sums(path.read_text()))

    print(f"checking {len(entries)} files ...", file=sys.stderr, flush=True)
    integrity = verify_checksums(
        root, entries,
        progress=lambda done, total: print(f"  {done}/{total}", file=sys.stderr, flush=True))

    gates = []
    if not args.checksums_only:
        gates = run_gates(root, skip=set(args.skip))
        gates.append(negative_control(root))

    print(render(integrity, gates, profile, version), end="")
    return exit_code(integrity, gates)


if __name__ == "__main__":
    raise SystemExit(main())
