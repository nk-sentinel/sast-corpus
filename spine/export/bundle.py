"""Pack the corpus for transfer into an environment with no GitHub access.

The corpus normally fetches `tier2`, `tier3` and `perf` on demand, because those
trees are far larger than this repository and are code we did not write. Where
there is no network that model does not work and the corpus has to travel.

Three decisions shape what this produces, and each of them is a measurement
rather than a preference:

**Build output does not travel.** 17.6 of the 20 GB under `tier3` is `target/`,
regenerated on arrival by Maven in strict offline mode. Shipping it would
quadruple the transfer to save a step that works.

**Git history does not travel.** Another 602 MB is packfiles in trees we did not
write. Provenance moves into the manifest as a pinned commit SHA plus a
checksum, which is smaller and more directly verifiable. `--keep-git` restores
it for anyone doing incremental scanning, which is the one thing that needs it.

**Ground truth travels in its own archive.** Rule 1 of this corpus is that the
answer key lives outside the fixtures, and a single archive would undo it: a
scanner pointed at the extracted root reads every CWE identifier and every
rationale, and an LLM-based scanner then scores on the answers instead of the
code. Two archives keep the scan target and the answer key physically apart.

See ../../docs/AIRGAP-EXPORT.md for the surrounding argument.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Component:
    name: str
    paths: tuple
    archive: str = "corpus"
    note: str = ""


# The machinery and the fixtures: without these there is no corpus at all, so
# every profile carries them.
CORE = (
    Component("spine", (Path("spine"),), note="scorer, adapters, lint, generator"),
    Component("build", (Path("build"),), note="build and syntax recipes"),
    Component("docs", (Path("docs"), Path("README.md")), note="method and policy"),
    Component("tier1", (Path("tier1"),), note="synthetic fixtures"),
    Component("answers", (Path("answers"),), archive="answers",
              note="ground truth — kept out of the scannable archive on purpose"),
)

TIER3 = Component("tier3", (Path("tier3/project-sources"), Path("tier3/sources.json"),
                            Path("tier3/fixed-sources"), Path("tier3/build-status.json"),
                            Path("tier3/cwe-bench-java/build-info")),
                  note="real CVE reproductions, sources only")
PERF = Component("perf", (Path("perf"),), note="scan-time targets, never accuracy-scored")
JAVA_ENV = Component("java-env", (Path("tier3/cwe-bench-java/java-env"),),
                     note="JDKs and build tools — a package repository does not serve these")
CACHES = Component("caches", (Path("export/caches"),),
                   note="prefetched dependency caches; only needed if the internal "
                        "repository cannot serve the checklist")

PROFILES = {
    "scoring": CORE + (TIER3,),
    "perf": CORE + (TIER3, PERF),
    "build": CORE + (TIER3, JAVA_ENV),
    "full": CORE + (TIER3, PERF, JAVA_ENV, CACHES),
}


def components_for(profile):
    """Components in a profile. Unknown names raise rather than yielding an
    empty bundle that unpacks cleanly and scores nothing."""
    if profile not in PROFILES:
        raise KeyError(f"unknown profile {profile!r}; expected one of "
                       f"{', '.join(sorted(PROFILES))}")
    return list(PROFILES[profile])


# Directory names that never travel. Matched as whole path components, so
# `TargetHandler.java` is kept while `target/` is dropped.
EXCLUDED_DIRECTORIES = {"target", "__pycache__", "node_modules", ".gradle", ".mvn"}

# REEF ships 737 MB of copied source from thousands of projects under no LICENSE
# file at all. Cloning it here for analysis and copying it into another
# organisation are different propositions, and only one of them is ours to make.
NEVER_BUNDLED = {"reef"}


def should_exclude(relative, keep_git=False):
    parts = set(relative.parts)
    if parts & NEVER_BUNDLED:
        return True
    if parts & EXCLUDED_DIRECTORIES:
        return True
    if ".git" in parts and not keep_git:
        return True
    return False


def iter_files(root, paths, keep_git=False):
    """Every file under the given paths, excluded rules applied, stable order.

    A path that does not exist yields nothing rather than raising: `perf` is
    absent until fetched, and a bundle should report that rather than crash.
    """
    root = Path(root)
    found = []
    for path in paths:
        absolute = root / path
        if absolute.is_file():
            found.append(absolute)
            continue
        if not absolute.is_dir():
            continue
        for candidate in absolute.rglob("*"):
            if not candidate.is_file() or candidate.is_symlink():
                continue
            if should_exclude(candidate.relative_to(root), keep_git):
                continue
            found.append(candidate)
    return sorted(set(found))


def checksum(path, chunk=1 << 20):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def _pinned(root, corpora=None):
    """Upstream repository and commit for the vendored trees in this bundle, so
    provenance survives dropping `.git`.

    Scoped to what actually travelled. A manifest that pins `perf` in a bundle
    carrying no `perf` claims provenance for something not there, which is the
    same way a licence page listing absent corpora stops being evidence.
    """
    pinned = {}
    for corpus in (corpora if corpora is not None else ("tier2", "tier3", "perf")):
        manifest = Path(root) / corpus / "sources.json"
        if not manifest.exists():
            continue
        for source in json.loads(manifest.read_text()).get("sources", []):
            pinned[source["name"]] = {"repo": source.get("repo"),
                                      "sha": source.get("sha"),
                                      "license": source.get("license"),
                                      "corpus": corpus}
    return pinned


def render_checksums(root, files):
    """Per-file digests in `sha256sum` format.

    Not JSON: at 120k files the embedded form made MANIFEST.json 31 MB, and
    this format is verifiable on the far side with `sha256sum -c` alone. A
    verification step that needs our tooling to run is one more thing that can
    be missing when it matters.
    """
    root = Path(root)
    return "".join(f"{checksum(path)}  {path.relative_to(root)}\n"
                   for path in files)


def build_manifest(root, files, profile, keep_git=False, version=None, corpora=None):
    """Metadata only. Per-file digests live in SHA256SUMS beside it."""
    root = Path(root)
    total = sum(path.stat().st_size for path in files)
    return {
        "corpus_version": version or _version(root),
        "profile": profile,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "keep_git": keep_git,
        "file_count": len(files),
        "total_bytes": total,
        "pinned": _pinned(root, corpora),
    }


def _version(root):
    for candidate in sorted((Path(root) / "answers").glob("expectedresults-*.csv")):
        return candidate.stem.replace("expectedresults-", "")
    return "unknown"


def render_licenses(root, corpora):
    """A licence page for the trees actually inside the bundle.

    Only the corpora being shipped appear. Listing a licence for something that
    did not travel is how a manifest stops being evidence.
    """
    lines = ["# Licences of vendored corpora", "",
             "Third-party trees copied into this bundle, with the licence each",
             "declares upstream. Internal use is not distribution, but the",
             "question should be answerable here rather than re-derived.", ""]
    found = False
    for corpus in ("tier2", "tier3", "perf"):
        if corpus not in corpora:
            continue
        manifest = Path(root) / corpus / "sources.json"
        if not manifest.exists():
            continue
        sources = json.loads(manifest.read_text()).get("sources", [])
        if not sources:
            continue
        found = True
        lines += [f"## {corpus}", "", "| source | licence | upstream |", "|---|---|---|"]
        for source in sources:
            licence = source.get("license") or "UNDECLARED"
            lines.append(f"| {source['name']} | {licence} | {source.get('repo','')} |")
        lines.append("")
    unverified = [name for name, data in _pinned(root, corpora).items()
                  if (data["license"] or "").upper().startswith("VERIFY")]
    if unverified:
        lines += ["## Needs a decision before use", "",
                  "These declare no settled licence upstream:", ""]
        lines += [f"- **{name}**" for name in sorted(unverified)]
        lines.append("")
    if not found:
        lines += ["No vendored corpora in this bundle.", ""]
    return "\n".join(lines)


def split_plan(total_bytes, part_bytes):
    """How many parts an archive of this size needs."""
    if not part_bytes or total_bytes <= part_bytes:
        return 1
    return -(-total_bytes // part_bytes)


def _split_file(path, part_bytes):
    """Cut a finished archive into transfer-sized parts, checksumming each."""
    parts = []
    with path.open("rb") as handle:
        index = 0
        while True:
            chunk = handle.read(part_bytes)
            if not chunk:
                break
            index += 1
            part = path.with_suffix(path.suffix + f".part{index:03d}")
            part.write_bytes(chunk)
            parts.append({"name": part.name, "bytes": len(chunk),
                          "sha256": hashlib.sha256(chunk).hexdigest()})
    path.unlink()
    return parts


def write_archive(root, files, destination):
    root = Path(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w:gz") as archive:
        for path in files:
            archive.add(path, arcname=str(path.relative_to(root)))
    return destination


def bundle(root, profile, out, keep_git=False, part_bytes=None):
    root, out = Path(root), Path(out)
    components = components_for(profile)
    version = _version(root)

    grouped = {}
    for component in components:
        grouped.setdefault(component.archive, []).extend(component.paths)

    report = {"profile": profile, "version": version, "archives": [], "missing": []}
    every_file = []

    for archive_name, paths in sorted(grouped.items()):
        files = iter_files(root, paths, keep_git)
        every_file.extend(files)
        for path in paths:
            if not (root / path).exists():
                report["missing"].append(str(path))
        destination = out / f"sast-corpus-{version}-{profile}-{archive_name}.tar.gz"
        write_archive(root, files, destination)

        # One checksum list per archive. A single combined list would make a
        # correct extraction fail verification: the two archives are meant to be
        # unpacked separately, so checking the scannable tree against a list
        # that also covers the answer key reports every answer file as missing.
        sums_name = f"SHA256SUMS.{archive_name}"
        (out / sums_name).write_text(render_checksums(root, files))

        entry = {"archive": destination.name, "files": len(files),
                 "checksums": sums_name,
                 "bytes": destination.stat().st_size}
        if part_bytes:
            entry["parts"] = _split_file(destination, part_bytes)
        else:
            entry["sha256"] = checksum(destination)
        report["archives"].append(entry)

    corpora = [c for c in ("tier2", "tier3", "perf")
               if any(str(p).startswith(c) for comp in components for p in comp.paths)]

    manifest = build_manifest(root, every_file, profile, keep_git, version, corpora)
    manifest["archives"] = report["archives"]
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=1) + "\n")
    (out / "LICENSES.md").write_text(render_licenses(root, corpora))

    report["manifest"] = str(out / "MANIFEST.json")
    return report


def build_parser():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="scoring")
    parser.add_argument("--out", type=Path, default=root / "export" / "bundle")
    parser.add_argument("--keep-git", action="store_true",
                        help="keep vendored .git; needed only for incremental scanning")
    parser.add_argument("--split", type=str, default=None,
                        help="cut archives into parts of this size, e.g. 4G")
    return parser


def _parse_size(text):
    if not text:
        return None
    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
    if text[-1].upper() in units:
        return int(float(text[:-1]) * units[text[-1].upper()])
    return int(text)


def main(argv=None):
    args = build_parser().parse_args(argv)
    report = bundle(args.root, args.profile, args.out,
                    keep_git=args.keep_git, part_bytes=_parse_size(args.split))

    print(f"profile {report['profile']}, corpus {report['version']}")
    for entry in report["archives"]:
        size = entry.get("bytes", 0) / (1 << 20)
        print(f"  {entry['archive']}  {entry['files']} files  {size:.1f} MB"
              f"  ({entry['checksums']})")
        for part in entry.get("parts", []):
            print(f"      {part['name']}  {part['bytes'] / (1 << 20):.1f} MB")
    if report["missing"]:
        # Silence here would look like a complete bundle.
        print(f"  NOT PRESENT and therefore NOT bundled: {', '.join(report['missing'])}")
    print(f"  {report['manifest']}")
    print("\nThe answer key is in the -answers archive, deliberately apart from the")
    print("scannable one. Do not extract both into the same tree before scanning.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
