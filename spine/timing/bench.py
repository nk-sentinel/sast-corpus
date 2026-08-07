#!/usr/bin/env python3
"""Measure scan time reproducibly.

Accuracy and performance use different corpora. This harness runs against
`perf/`, whose repositories are sized to straddle the thresholds the SLAs care
about; timing the accuracy fixtures would measure a few thousand lines and say
nothing about a 200k-LOC repository.

Two rules drive the design:

  Phases are recorded separately. Provisioning, building, analysing and waiting
  in a hosted queue are different costs with different owners, and a hosted
  scanner's queue time is not scan speed.

  The line count is *scanned* LOC from codeprint — source only, excluding
  vendored, generated and binary files. Raw line counts flatter tools unevenly
  depending on how much of a repository each one chooses to skip.
"""

import argparse
import json
import math
import platform
import os
import resource
import shlex
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

STABILITY_THRESHOLD = 0.10
PHASE_NAMES = ("provision", "build", "analysis", "upload_wait")


@dataclass
class PhaseTimings:
    provision: float = 0.0
    build: float = 0.0
    analysis: float = 0.0
    upload_wait: float = 0.0

    @property
    def total(self):
        return self.provision + self.build + self.analysis + self.upload_wait


@dataclass
class RunResult:
    ok: bool
    phases: PhaseTimings
    peak_rss_bytes: int = 0
    exit_code: int = 0
    cpu_seconds: float = 0.0


def percentile(values, p):
    """Nearest-rank, so a reported p95 is a run that actually happened."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(p / 100 * len(ordered)))
    return ordered[rank - 1]


def seconds_per_1k_loc(seconds, scanned_loc):
    if not scanned_loc:
        return None
    return seconds / (scanned_loc / 1000)


def summarise(runs, scanned_loc):
    """Aggregate repeated runs into publishable figures.

    Failed runs are counted but excluded from every timing: a tool that crashes
    in 0.2 seconds must not look fast.
    """
    good = [run for run in runs if run.ok]
    totals = [run.phases.total for run in good]

    summary = {
        "runs": len(runs),
        "ok_runs": len(good),
        "failed_runs": len(runs) - len(good),
        "total": _distribution(totals),
        "phases": {
            name: _distribution([getattr(run.phases, name) for run in good])
            for name in PHASE_NAMES
        },
        "peak_rss_bytes": max((run.peak_rss_bytes for run in runs), default=0),
        "scanned_loc": scanned_loc,
    }

    median_total = summary["total"]["p50"]
    median_analysis = summary["phases"]["analysis"]["p50"]
    summary["seconds_per_1k_loc"] = {
        "total": seconds_per_1k_loc(median_total, scanned_loc) if median_total is not None else None,
        "analysis": seconds_per_1k_loc(median_analysis, scanned_loc) if median_analysis is not None else None,
    }

    summary["relative_stddev"] = _relative_stddev(totals)
    summary["stable"] = (
        len(good) > 1
        and summary["relative_stddev"] is not None
        and summary["relative_stddev"] <= STABILITY_THRESHOLD
    )

    return summary


def _distribution(values):
    if not values:
        return {"min": None, "mean": None, "p50": None, "p95": None, "max": None, "stddev": None}
    return {
        "min": min(values),
        "mean": statistics.fmean(values),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "max": max(values),
        "stddev": statistics.pstdev(values) if len(values) > 1 else 0.0,
    }


def _relative_stddev(values):
    if len(values) < 2:
        return None
    mean = statistics.fmean(values)
    if mean == 0:
        return None
    return statistics.pstdev(values) / mean


# --- execution -------------------------------------------------------------


def run_command(command, cwd=None, env=None):
    """Run one command, returning (seconds, exit_code, peak_rss_bytes, cpu_seconds).

    Peak RSS is read from the child's rusage rather than sampled, so a short
    memory spike is not missed.
    """
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    completed = subprocess.run(command, shell=isinstance(command, str), cwd=cwd, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    elapsed = time.monotonic() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)

    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    # ru_maxrss is kilobytes on Linux, bytes on macOS.
    scale = 1 if sys.platform == "darwin" else 1024
    return elapsed, completed.returncode, after.ru_maxrss * scale, cpu


def drop_caches():
    """Best-effort cold cache. Needs root; reports honestly when it cannot."""
    try:
        subprocess.run(["sync"], check=True)
        with open("/proc/sys/vm/drop_caches", "w") as handle:
            handle.write("3")
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def parse_codeprint_output(stdout):
    """Code lines from a codeprint fingerprint, or None if this is not one.

    `totals.code` excludes comments and blanks by design. Those belong to how a
    project is written, not to how much a scanner had to analyse, and including
    them would flatter tools unevenly since each skips a different share.
    """
    try:
        data = json.loads(stdout)
    except (TypeError, ValueError):
        return None

    totals = (data.get("fingerprint") or {}).get("totals") or {}
    code = totals.get("code")
    return int(code) if isinstance(code, int) else None


def scanned_loc(target, codeprint=None):
    """Scanned LOC from codeprint, falling back to a plain count.

    The fallback is recorded in the output so a number produced without
    codeprint is never mistaken for one produced with it.
    """
    codeprint = codeprint or os.environ.get("CODEPRINT_BIN", "codeprint")
    try:
        completed = subprocess.run([codeprint, "--format", "json", "--no-files", str(target)],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if completed.returncode == 0:
            code = parse_codeprint_output(completed.stdout)
            if code is not None:
                return code, "codeprint"
    except OSError:
        pass

    total = 0
    for path in Path(target).rglob("*"):
        if path.is_file():
            try:
                with path.open("rb") as handle:
                    chunk = handle.read(4096)
                    if b"\0" in chunk:
                        continue
                    handle.seek(0)
                    total += sum(1 for _ in handle)
            except OSError:
                continue
    return total, "fallback-line-count"


def benchmark(command, target, runs=5, warmup=1, cache="warm", build_command=None, cwd=None):
    results = []

    for index in range(warmup + runs):
        if cache == "cold":
            drop_caches()

        phases = PhaseTimings()
        ok = True
        exit_code = 0
        rss = 0
        cpu = 0.0

        if build_command:
            elapsed, code, peak, used = run_command(build_command, cwd=cwd)
            phases.build = elapsed
            rss = max(rss, peak)
            cpu += used
            if code != 0:
                ok, exit_code = False, code

        if ok:
            elapsed, code, peak, used = run_command(command, cwd=cwd)
            phases.analysis = elapsed
            rss = max(rss, peak)
            cpu += used
            if code != 0:
                ok, exit_code = False, code

        if index >= warmup:
            results.append(RunResult(ok=ok, phases=phases, peak_rss_bytes=rss,
                                     exit_code=exit_code, cpu_seconds=cpu))

    return results


def host_facts():
    """Recorded with every result: a timing without its host is not comparable."""
    return {
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Measure SAST scan time reproducibly.")
    parser.add_argument("--tool", required=True, help="name recorded in the output")
    parser.add_argument("--tool-version", default="", help="exact version under test")
    parser.add_argument("--command", required=True, help="the scan command")
    parser.add_argument("--build-command", default=None,
                        help="build step, timed separately; required for engines that analyse compiled artifacts")
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--cache", choices=("warm", "cold"), default="warm")
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.cache == "cold" and os.geteuid() != 0:
        print("warning: cold-cache runs need root to drop page cache; "
              "measuring warm and labelling it so", file=sys.stderr)
        args.cache = "warm-unprivileged"

    loc, loc_source = scanned_loc(args.target)
    results = benchmark(
        shlex.split(args.command) if " " in args.command else args.command,
        args.target,
        runs=args.runs,
        warmup=args.warmup,
        cache=args.cache,
        build_command=shlex.split(args.build_command) if args.build_command else None,
        cwd=args.cwd,
    )

    payload = {
        "tool": args.tool,
        "tool_version": args.tool_version,
        "target": str(args.target),
        "command": args.command,
        "build_command": args.build_command,
        "cache": args.cache,
        "warmup": args.warmup,
        "loc_source": loc_source,
        "host": host_facts(),
        "summary": summarise(results, loc),
        "runs_detail": [asdict(r) | {"phases": asdict(r.phases)} for r in results],
    }

    text = json.dumps(payload, indent=2, default=str)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)

    summary = payload["summary"]
    print("{} on {}".format(args.tool, args.target))
    print("  scanned loc   {} ({})".format(summary["scanned_loc"], loc_source))
    print("  total p50/p95 {}/{}".format(_fmt(summary["total"]["p50"]), _fmt(summary["total"]["p95"])))
    for name in PHASE_NAMES:
        value = summary["phases"][name]["p50"]
        if value:
            print("  {:<13} p50 {}".format(name, _fmt(value)))
    print("  sec / 1k loc  total {} · analysis {}".format(
        _fmt(summary["seconds_per_1k_loc"]["total"]),
        _fmt(summary["seconds_per_1k_loc"]["analysis"])))
    print("  peak rss      {:.1f} MiB".format(summary["peak_rss_bytes"] / (1024 * 1024)))

    if summary["failed_runs"]:
        print("  {} of {} runs failed and were excluded from the timings".format(
            summary["failed_runs"], summary["runs"]))
    if not summary["stable"]:
        print("  UNSTABLE: relative stddev {} exceeds {:.0%}; this host is too noisy to publish from".format(
            _fmt(summary["relative_stddev"]), STABILITY_THRESHOLD))

    return 0 if summary["ok_runs"] else 1


def _fmt(value):
    return "n/a" if value is None else "{:.3f}".format(value)


if __name__ == "__main__":
    raise SystemExit(main())
