"""Emit the artifact checklist an internal package repository has to satisfy.

An airgapped evaluation resolves dependencies from an internal repository rather
than from Maven Central. Whether that repository *has* what tier 3 needs is a
question to settle before the transfer, not during the evaluation — there is no
second attempt once the corpus is inside.

Two properties of this corpus make the answer non-obvious:

- The projects pin releases from 2014 to 2023, and the vulnerable dependency is
  frequently the point of the case. A repository that quarantines known-vulnerable
  versions blocks precisely what tier 3 is made of.
- Plugins are resolved separately from dependencies and are the half people
  forget. A missing plugin fails a build exactly as hard as a missing library,
  and this corpus has already lost a day to plugin version resolution once:
  Maven 3.8.7 defaults to compiler-plugin 3.1, which predates
  `maven.compiler.release` and silently falls back to source level 5.

Output is a deduplicated list of coordinates, which is what someone
administering the repository can actually act on.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Coordinate:
    group: str
    artifact: str
    version: str
    packaging: str = "jar"
    classifier: str | None = None
    scope: str | None = None

    def key(self):
        """What the repository has to serve. Scope is how a build consumed the
        file, not part of its identity — two projects wanting the same jar at
        compile and test scope are one row to check, not two."""
        return (self.group, self.artifact, self.version,
                self.packaging, self.classifier)

    def text(self):
        parts = [self.group, self.artifact, self.version]
        if self.classifier:
            parts.append(self.classifier)
        return ":".join(parts)


# One colon-joined token on an [INFO] line, with Maven 3.9 optionally appending
# ` -- module x`. Deliberately loose: the shape is validated by field count
# below, not by the regex, because the field count is what tells a classifier
# coordinate from a plain one.
MAVEN_LINE = re.compile(r"^\[INFO\]\s+(\S+)\s*(?:--\s.*)?$")

DEPENDENCY_HEADER = "files have been resolved"
PLUGIN_HEADER = "plugins have been resolved"


def _maven_coordinate(raw):
    """Maven prints five fields normally and six when a classifier is present.

    Reading the version by position gets the classifier on the six-field form
    and hands the repository a version that does not exist. Field *count* is the
    only thing that distinguishes them.
    """
    parts = raw.split(":")
    if parts and parts[-1] == "":
        # `dependency:resolve-plugins` ends every coordinate with a bare colon.
        parts = parts[:-1]
    if len(parts) == 4:                       # group:artifact:type:version
        group, artifact, packaging, version = parts
        classifier, scope = None, None
    elif len(parts) == 5:                     # ...:scope
        group, artifact, packaging, version, scope = parts
        classifier = None
    elif len(parts) == 6:                     # ...:classifier:version:scope
        group, artifact, packaging, classifier, version, scope = parts
    else:
        return None
    if not version or not re.match(r"^[\w.\-+]+$", version):
        return None
    return Coordinate(group, artifact, version, packaging, classifier or None,
                      scope or None)


def _parse_maven(text, header):
    """Lines belong to the most recent resolution header.

    `dependency:list` and `dependency:resolve-plugins` produce near-identical
    shapes, so output fed to the wrong parser would otherwise be reported as the
    wrong kind. Before any header appears the lines are taken at face value, so
    that a bare coordinate — a fragment, a hand-written fixture — still parses
    rather than silently yielding nothing.
    """
    coordinates, current = [], None
    for line in text.splitlines():
        if DEPENDENCY_HEADER in line:
            current = DEPENDENCY_HEADER
            continue
        if PLUGIN_HEADER in line:
            current = PLUGIN_HEADER
            continue
        if line.strip() in ("[INFO]", "") or "BUILD" in line:
            current = None if current == header else current
            continue
        if current is not None and current != header:
            continue
        match = MAVEN_LINE.match(line.rstrip())
        if not match:
            continue
        coordinate = _maven_coordinate(match.group(1))
        if coordinate:
            coordinates.append(coordinate)
    return coordinates


def parse_maven_list(text):
    """Coordinates from `mvn dependency:list`."""
    return _parse_maven(text, DEPENDENCY_HEADER)


def parse_maven_plugins(text):
    """Coordinates from `mvn dependency:resolve-plugins`."""
    return _parse_maven(text, PLUGIN_HEADER)


GRADLE_LINE = re.compile(r"^[|\s]*[+\\]---\s+(.*)$")


def parse_gradle_tree(text):
    """Coordinates from `gradle dependencies`.

    Gradle marks conflict resolution with `->`, and the version actually
    fetched is the one on the RIGHT. Taking the left asks the repository for a
    version the build never uses — which passes a coverage check and then fails
    the build.
    """
    coordinates = []
    for line in text.splitlines():
        match = GRADLE_LINE.match(line)
        if not match:
            continue
        entry = match.group(1).strip()
        for marker in (" (*)", " (c)", " (n)"):
            entry = entry.replace(marker, "")
        entry = entry.strip()
        if entry.startswith("project "):
            continue
        resolved = None
        if "->" in entry:
            entry, resolved = (part.strip() for part in entry.rsplit("->", 1))
        parts = entry.split(":")
        if len(parts) < 2:
            continue
        group, artifact = parts[0], parts[1]
        version = resolved or (parts[2] if len(parts) > 2 else None)
        if not version or not re.match(r"^[\w.\-+]+$", version):
            continue
        coordinates.append(Coordinate(group, artifact, version))
    return coordinates


def dedupe(coordinates):
    """One row per artifact the repository has to serve, ordered so the
    checklist diffs cleanly between corpus versions."""
    seen = {}
    for coordinate in coordinates:
        seen.setdefault(coordinate.key(), coordinate)
    return [seen[key] for key in sorted(seen)]


@dataclass
class Project:
    name: str
    tool: str
    jdk: str | None = None
    build_version: str | None = None
    coordinates: list = field(default_factory=list)
    error: str | None = None


def describe_failure(stages):
    """Name every stage that failed, or None if all of them worked.

    Dependencies and plugins come from two separate commands and one can fail
    while the other succeeds — `dependency:resolve-plugins` resolves plugins
    that are declared but never invoked, so it fails against a cache populated
    by an actual build. Recording only "some coordinates were found" would let a
    checklist missing every plugin look complete.
    """
    failed = [(name, reason) for name, (ok, reason) in sorted(stages.items()) if not ok]
    if not failed:
        return None
    return "; ".join(f"{name} failed: {reason.strip()[:160]}" for name, reason in failed)


def load_build_info(root):
    """Per-project toolchain. Forcing one Maven version on every project fails
    most of them — 3.9.x resolves plugin versions that a 3.5.0-era build never
    cached — so the toolchain travels with the checklist."""
    info = {}
    directory = Path(root) / "tier3" / "cwe-bench-java" / "build-info"
    for path in sorted(directory.glob("*.json")):
        data = json.loads(path.read_text())
        info[path.stem] = data
    return info


def _reason(result):
    """The first line that explains a failure, not the whole build log."""
    for stream in (result.stderr or "", result.stdout or ""):
        for line in stream.splitlines():
            if "ERROR" in line or "FAIL" in line:
                return line.split("] ", 1)[-1]
    return f"exit {result.returncode}"


def _run(command, cwd, timeout=900):
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True,
                              text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


def collect(root, only=None, offline=True, progress=True):
    """Walk the tier-3 projects and gather what each build resolves.

    Progress goes to stderr, unbuffered. Resolution runs a real build tool
    against 28 projects and takes tens of minutes; a harness that prints nothing
    until it finishes is indistinguishable from one that has hung.
    """
    root = Path(root)
    env = root / "tier3" / "cwe-bench-java" / "java-env"
    projects = []

    for name, info in load_build_info(root).items():
        if only and only != name:
            continue
        source = root / "tier3" / "project-sources" / name
        if not source.is_dir():
            continue
        started = time.monotonic()
        if progress:
            print(f"  resolving {name} ...", file=sys.stderr, flush=True)

        jdk = info.get("jdk")
        java_home = env / ("jdk-17" if jdk == "17" else "jdk1.8.0_202")
        environment = {"JAVA_HOME": str(java_home),
                       "PATH": f"{java_home}/bin:/usr/bin:/bin"}

        if info.get("mvn"):
            project = Project(name, "maven", jdk, info["mvn"])
            mvn = env / f"apache-maven-{info['mvn']}" / "bin" / "mvn"
            if not mvn.exists():
                project.error = f"maven {info['mvn']} not provisioned"
                projects.append(project)
                continue
            flags = ["-o"] if offline else []
            listing = _run([str(mvn), *flags, "-B", "dependency:list"], source)
            plugins = _run([str(mvn), *flags, "-B", "dependency:resolve-plugins"], source)
            project.coordinates = (parse_maven_list(listing.stdout)
                                   + parse_maven_plugins(plugins.stdout))
            project.error = describe_failure({
                "dependencies": (listing.returncode == 0, _reason(listing)),
                "plugins": (plugins.returncode == 0, _reason(plugins)),
            })
        elif info.get("gradle"):
            project = Project(name, "gradle", jdk, str(info.get("gradle")))
            wrapper = source / "gradlew"
            if not wrapper.exists():
                project.error = "no gradle wrapper; needs a provisioned gradle"
                projects.append(project)
                continue
            flags = ["--offline"] if offline else []
            listing = _run([str(wrapper), *flags, "-q", "dependencies"], source)
            project.coordinates = parse_gradle_tree(listing.stdout)
            project.error = describe_failure({
                "dependencies": (listing.returncode == 0, _reason(listing)),
            })
        else:
            project = Project(name, "unknown")
            project.error = "build-info declares neither mvn nor gradle"

        if progress:
            outcome = project.error or f"{len(project.coordinates)} coordinates"
            print(f"    {name}: {outcome} [{time.monotonic() - started:.0f}s]",
                  file=sys.stderr, flush=True)
        projects.append(project)
    return projects


def render_text(coordinates):
    return "\n".join(coordinate.text() for coordinate in coordinates) + "\n"


def render_report(projects, offline=False):
    """Human-readable summary. States what could NOT be collected as loudly as
    what could — a checklist that silently omits a project reads as complete."""
    every = dedupe([c for p in projects for c in p.coordinates])
    lines = [
        "ARTIFACT CHECKLIST",
        "",
        f"  {len(every)} distinct artifacts required by {len(projects)} project(s)",
        "",
    ]
    if offline:
        lines += ["  GENERATED OFFLINE — this list is incomplete. Plugins declared but",
                  "  never invoked are absent from any cache, so they are absent here.",
                  ""]
    failed = [p for p in projects if p.error]
    if failed:
        lines += [f"  {len(failed)} project(s) yielded nothing — their artifacts are NOT below:"]
        lines += [f"      {p.name}: {p.error}" for p in failed]
        lines += [""]
    by_tool = {}
    for project in projects:
        by_tool.setdefault(project.tool, []).append(project)
    for tool, group in sorted(by_tool.items()):
        lines.append(f"  {tool}: {len(group)} project(s), "
                     f"{len(dedupe([c for p in group for c in p.coordinates]))} artifacts")
    return "\n".join(lines) + "\n"


def build_parser():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--only", default=None, help="one project by name")
    # Online by default. The whole point of the checklist is to enumerate what
    # the FAR side needs, including artifacts this machine has never cached —
    # `dependency:resolve-plugins` resolves plugins that are declared but never
    # invoked, and those are absent from any cache a real build populated. Run
    # offline and the checklist silently omits them.
    parser.add_argument("--offline", action="store_true",
                        help="resolve without the network; the result will be "
                             "incomplete and is reported as such")
    parser.add_argument("--format", choices=("text", "json", "report"), default="report")
    parser.add_argument("--out", type=Path, default=None)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    projects = collect(args.root, only=args.only, offline=args.offline)
    every = dedupe([c for p in projects for c in p.coordinates])

    if args.format == "text":
        output = render_text(every)
    elif args.format == "json":
        output = json.dumps({
            "offline": args.offline,
            "artifacts": [c.__dict__ for c in every],
            "projects": [{"name": p.name, "tool": p.tool, "jdk": p.jdk,
                          "build_version": p.build_version,
                          "artifacts": len(p.coordinates), "error": p.error}
                         for p in projects],
        }, indent=2) + "\n"
    else:
        output = render_report(projects, offline=args.offline)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output)
        print(f"wrote {args.out}")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
