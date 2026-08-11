#!/usr/bin/env python3
"""Fail the build when a corpus fixture gives away its own answer.

A leaky corpus produces a meaningless ranking. Established suites encode the
weakness in the filename and the category in a comment, so a tool — or a large
language model — can classify a case without analysing a line of it. Everything
this lint forbids exists to keep that from happening here.

Tier 1 is ours, so a leak is fixable and therefore fatal. Tiers 2 and 3 are real
applications vendored unchanged; their hints cannot be edited away without
forking upstream, so they are reported and disclosed on the scorecard instead.
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

STRICT_TIERS = ("tier1",)
DISCLOSED_TIERS = ("tier2", "tier3")

CWE_PATTERN = re.compile(r"\bcwe[-_ ]?\d+\b", re.IGNORECASE)

# Matched anywhere, even inside a longer word: no innocent identifier contains
# these.
UNAMBIGUOUS_HINTS = (
    "vuln", "vulnerable", "insecure", "unsafe", "exploit", "malicious",
    "xss", "traversal", "benign", "goodcode", "badcode",
    "badsink", "goodsink", "badsource", "goodsource",
)

# Matched only as whole tokens, in content and in paths alike. `sqli` is a real
# giveaway but it is also a substring of `sqlite` and `mysqli`, and patching
# library names one at a time is whack-a-mole. Tokenising handles all of them at
# once: `mysqli_query` yields the token `mysqli`, while `runSqliCheck` yields
# `sqli`.
CONTENT_TOKEN_HINTS = frozenset({"sqli", "injection"})

# Additionally forbidden in paths. As identifiers these appear constantly in
# innocent code — DataSource, EventSink, sourceFile — so flagging them in
# content would train people to ignore the lint. In a filename they are always
# deliberate. `source` inside `resources` is Maven's standard layout, and a lint
# that rejects src/main/resources/ is a lint people turn off.
PATH_TOKEN_HINTS = CONTENT_TOKEN_HINTS | {
    "safe", "attack", "source", "sink", "taint", "payload",
}

UNAMBIGUOUS_PATTERN = re.compile("|".join(UNAMBIGUOUS_HINTS), re.IGNORECASE)
TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def _tokens(text):
    return {token.lower() for token in TOKEN_SPLIT.split(text) if token}


def path_hints(text):
    """Giveaway words in a path fragment, tokenising camelCase and separators."""
    if UNAMBIGUOUS_PATTERN.search(text):
        return True
    return bool(_tokens(text) & PATH_TOKEN_HINTS)


def content_hints(line):
    """Giveaway words in a line of source."""
    if UNAMBIGUOUS_PATTERN.search(line):
        return True
    return bool(_tokens(line) & CONTENT_TOKEN_HINTS)


RULE_ANNOTATION = re.compile(r"\b(?:todoruleid|todook|ruleid|ok)\s*:", re.IGNORECASE)
ANSWER_KEY_NAME = re.compile(r"expectedresults.*\.csv$|^c-[0-9a-f]{8}\.ya?ml$", re.IGNORECASE)

LINE_COMMENT_MARKERS = {
    ".java": ("//",), ".kt": ("//",), ".js": ("//",), ".ts": ("//",), ".go": ("//",),
    ".cs": ("//",), ".c": ("//",), ".h": ("//",), ".cpp": ("//",), ".hpp": ("//",),
    ".swift": ("//",), ".rs": ("//",), ".php": ("//", "#"),
    ".py": ("#",), ".rb": ("#",), ".sh": ("#",), ".yml": ("#",), ".yaml": ("#",),
}
BLOCK_COMMENT_MARKERS = {
    ".java": ("/*",), ".kt": ("/*",), ".js": ("/*",), ".ts": ("/*",), ".go": ("/*",),
    ".cs": ("/*",), ".c": ("/*",), ".h": ("/*",), ".cpp": ("/*",), ".hpp": ("/*",),
    ".swift": ("/*",), ".rs": ("/*",), ".php": ("/*",),
}


# Directories that appear under a tier but are not corpus content: toolchains we
# provisioned, build output, dependency caches, git internals. Fetching tier 3
# drops entire JDK and Maven distributions under it — 327,000 files, 544 MB —
# and walking them turned this gate from a second into minutes. CI runs it on
# every push, and a slow gate is one people route around.
NOT_CORPUS_CONTENT = frozenset({
    ".git", "java-env", "build-info", "target", "build", "out",
    "node_modules", ".gradle", ".m2", "__pycache__", ".venv", "venv",
})


@dataclass(frozen=True)
class Leak:
    path: str
    line: int
    kind: str
    detail: str

    def __str__(self):
        return "{}:{}: {}: {}".format(self.path, self.line, self.kind, self.detail)


# Variants whose whole point is the thing the lint forbids. A trap asserting
# that a weak algorithm named in a changelog is not a crypto finding has to name
# it in a changelog; one asserting that a comment is not code has to contain a
# comment. Without these, the corpus can only measure false positives in code —
# and prose, test data and vendored trees are where real scanners generate most
# of theirs.
CONTEXT_VARIANTS = frozenset({
    "in-markdown", "in-comment", "in-test-data", "in-vendored",
    "in-example-config", "in-changelog", "in-licence-header",
})


def waived_files(root):
    """Files the answer key marks as context traps.

    Read from the compiled answer key rather than from a marker beside the
    fixture. A marker beside the fixture would be ground truth living outside
    `answers/`, which is the single rule the rest of the corpus rests on — and it
    would tell a reader that this particular file is special, which is itself a
    hint.
    """
    import csv

    waived = set()
    answers = Path(root) / "answers"
    if not answers.is_dir():
        return waived

    for key in sorted(answers.glob("expectedresults-*.csv")):
        try:
            with key.open(newline="") as handle:
                for row in csv.DictReader(handle):
                    if (row.get("variant") or "") in CONTEXT_VARIANTS:
                        waived.add(row.get("file", ""))
        except (OSError, csv.Error):
            continue

    return waived


def scan_tree(root, disclose=False):
    """Returns (errors, warnings).

    Errors are leaks in tiers we author, and they are what the gate enforces.
    Warnings are leaks inherent to vendored third-party code, which the
    methodology discloses rather than pretends away.

    The two are separate jobs. Enforcement runs on every push and must be fast.
    Disclosure walks whole vendored repositories — 28 real Java projects here —
    and is only needed when producing a scorecard, so it is opt-in. Charging
    every push a minute for a report nobody is reading at that moment is how a
    gate ends up switched off.

    The error result is identical either way; only the warnings differ.
    """
    root = Path(root)
    errors, warnings = [], []
    waived = waived_files(root)

    for tier in STRICT_TIERS:
        errors.extend(_scan_tier(root, tier, strict=True, waived=waived))

    if disclose:
        for tier in DISCLOSED_TIERS:
            warnings.extend(_scan_tier(root, tier, strict=False, waived=waived))

    return errors, warnings


def _scan_tier(root, tier, strict, waived=frozenset()):
    leaks = []
    tier_root = root / tier
    if not tier_root.is_dir():
        return leaks

    for path in _corpus_files(tier_root):

        # A tier's own metadata — its source manifest, its README — describes
        # what the tier contains and so names weaknesses by design. Reporting it
        # would bury the genuine disclosed leaks from vendored code under noise
        # on every single run.
        if path.parent == tier_root:
            continue

        relative = path.relative_to(root).as_posix()

        if relative in waived:
            continue

        leaks.extend(_scan_path(relative, path.name))

        text = _read_text(path)
        if text is None:
            continue
        leaks.extend(_scan_content(relative, path.suffix.lower(), text, strict))

    return leaks


def _corpus_files(tier_root):
    """Walk a tier, pruning provisioned directories rather than filtering after.

    Pruning matters: rglob would still descend into a JDK to discard each file
    individually, which is the cost being avoided.
    """
    import os

    for directory, subdirectories, filenames in os.walk(tier_root):
        subdirectories[:] = sorted(d for d in subdirectories if d not in NOT_CORPUS_CONTENT)
        for filename in sorted(filenames):
            yield Path(directory) / filename


def _scan_path(relative, name):
    leaks = []
    directory = relative.rsplit("/", 1)[0] if "/" in relative else ""

    if ANSWER_KEY_NAME.search(name):
        leaks.append(Leak(relative, 0, "answer-key-in-tier",
                          "ground truth must live in answers/, never beside the fixture"))

    if CWE_PATTERN.search(relative):
        leaks.append(Leak(relative, 0, "cwe-in-path", "path names the weakness"))

    # The directory of a hand-authored case may carry a language name; only the
    # basename and any opaque id segment are checked for giveaway words.
    if path_hints(name) or path_hints(directory):
        leaks.append(Leak(relative, 0, "hint-in-path", "path names the answer"))

    return leaks


def _scan_content(relative, suffix, text, strict):
    leaks = []

    for number, line in enumerate(text.splitlines(), start=1):
        if CWE_PATTERN.search(line):
            leaks.append(Leak(relative, number, "cwe-in-content", line.strip()[:90]))

        if RULE_ANNOTATION.search(line):
            leaks.append(Leak(relative, number, "rule-annotation",
                              "rule unit-test annotations belong in the engine's own tests"))

        if content_hints(line):
            leaks.append(Leak(relative, number, "hint-in-content", line.strip()[:90]))

        if strict and _comment_start(line, suffix) is not None:
            leaks.append(Leak(relative, number, "comment",
                              "tier-1 fixtures carry no prose for a model to read"))

    return leaks


def _comment_start(line, suffix):
    """Index of a comment marker outside a string literal, or None.

    Deliberately simple: it must not flag `https://` or a `#rrggbb` colour, and
    beyond that a false positive costs one fixture edit, not a wrong result.
    """
    for marker in BLOCK_COMMENT_MARKERS.get(suffix, ()):
        index = line.find(marker)
        if index != -1 and not _inside_string(line, index):
            return index

    for marker in LINE_COMMENT_MARKERS.get(suffix, ()):
        start = 0
        while True:
            index = line.find(marker, start)
            if index == -1:
                break
            if marker == "//" and index > 0 and line[index - 1] == ":":
                start = index + 2
                continue
            if _inside_string(line, index):
                start = index + len(marker)
                continue
            return index

    return None


def _inside_string(line, index):
    single = double = False
    for position, char in enumerate(line[:index]):
        if char == "'" and not double:
            single = not single
        elif char == '"' and not single:
            double = not double
    return single or double


def _read_text(path):
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def summarise_warnings(warnings):
    """Reduce disclosed leaks to the statistic a scorecard needs.

    Vendored tiers hold whole real repositories, so listing every leaking line
    runs to five figures and buries the errors that matter. What a reader needs
    is the size of the effect, not its transcript.
    """
    by_kind, by_tier, files = {}, {}, set()

    for leak in warnings:
        by_kind[leak.kind] = by_kind.get(leak.kind, 0) + 1
        tier = leak.path.split("/", 1)[0]
        by_tier[tier] = by_tier.get(tier, 0) + 1
        files.add(leak.path)

    return {"total": len(warnings), "files": len(files),
            "by_kind": by_kind, "by_tier": by_tier}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=Path(__file__).resolve().parents[2], type=Path)
    parser.add_argument("--disclose", action="store_true",
                        help="also walk the vendored tiers and report their inherent "
                             "leakage — slow, and only needed when producing a scorecard")
    args = parser.parse_args(argv)

    errors, warnings = scan_tree(args.root, disclose=args.disclose)

    summary = summarise_warnings(warnings)
    for error in errors:
        print("error:   {}".format(error), file=sys.stderr)

    if summary["total"]:
        print("disclosed leakage in vendored tiers: {} occurrence(s) across {} file(s)".format(
            summary["total"], summary["files"]))
        for tier, count in sorted(summary["by_tier"].items()):
            print("  {:<8} {}".format(tier, count))
        for kind, count in sorted(summary["by_kind"].items(), key=lambda kv: -kv[1]):
            print("  {:<18} {}".format(kind, count))
        print("  These are real applications naming their own weaknesses; they cannot be")
        print("  edited away. The figure belongs in a scorecard's threats-to-validity")
        print("  section, because an LLM-based scanner can read them instead of the code.")
    if errors:
        print("\n{} leak(s) in authored fixtures; the corpus is not sound until "
              "they are fixed.".format(len(errors)), file=sys.stderr)
        return 1

    print("no leaks in authored fixtures")
    if not args.disclose:
        print("(vendored tiers not walked; run with --disclose for the "
              "scorecard's leakage figure)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
