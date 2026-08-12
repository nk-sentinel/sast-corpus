#!/usr/bin/env python3
"""Are the Python and JavaScript ineffective sanitizers actually ineffective?

Compiling or parsing a fixture proves it is well-formed, not that it is labelled
correctly. A pair marked `sanitizer: ineffective` whose sanitizer in fact works
puts a vulnerability in the answer key that does not exist, and every tool that
correctly reports nothing is then scored as having missed it.

The Java equivalent lives in SanitizerClaims.java. One of those was wrong when
first written, which is why these are executed rather than asserted.
"""

import html
import os
import re
import subprocess
import sys
import urllib.parse

FAILURES = []


def claim(name, defeated):
    print(("  defeated  " if defeated else "  HELD      ") + name)
    if not defeated:
        FAILURES.append(name)


def holds(name, effective):
    if not effective:
        print("  BROKEN    safe sibling: " + name)
        FAILURES.append("safe:" + name)


def main():
    print("python sanitizer claims:")

    # os.path.join discards everything before an absolute component
    name = "/etc/passwd"
    claim("join-absolute", ".." not in name
          and os.path.join("/srv/reports", name) == "/etc/passwd")

    # html.escape(quote=False) leaves quotes alone
    claim("escape-quotes", '"' in html.escape('x" onmouseover=y', quote=False))

    # search matches anywhere in the string
    url = "https://api.example.com@evil.test/x"
    claim("search-unanchored",
          bool(re.compile(r"api\.example\.com").search(url))
          and urllib.parse.urlparse(url).hostname != "api.example.com")

    # re.match anchors only at the start
    claim("match-prefix-only", bool(re.match(r"[a-z-]+", "report; id")))

    # validated value is derived, so the check always passes
    raw = "X' OR '1'='1"
    code = re.sub(r"[^A-Z0-9]", "", raw)
    claim("wrong-variable", bool(re.fullmatch(r"[A-Z0-9]{1,12}", code)) and "'" in raw)

    # replace returns a new string; the original is unchanged
    dirty = "../etc/passwd"
    dirty.replace("..", "")
    claim("discarded-result", ".." in dirty)

    # normpath after the prefix check
    target = "/srv/reports" + "/" + "../../etc/passwd"
    claim("normalise-after-check",
          target.startswith("/srv/reports")
          and not os.path.normpath(target).startswith("/srv/reports"))

    # safe siblings must actually work
    holds("basename", os.path.realpath(os.path.join(
        "/srv/reports", os.path.basename("../../etc/passwd"))).startswith("/srv/reports"))
    holds("escape-quotes", '"' not in html.escape('x"y', quote=True))
    holds("fullmatch", not re.fullmatch(r"[a-z-]{1,20}", "report; id"))
    holds("host-equality",
          urllib.parse.urlparse(url).hostname not in {"api.example.com"})
    holds("normpath-first",
          not os.path.normpath(os.path.join("/srv/reports", "../../etc/passwd"))
          .startswith("/srv/reports" + os.sep))

    node = _node_claims()
    if node is not None:
        print(node, end="")

    if FAILURES:
        print(f"{len(FAILURES)} claim(s) do not hold; the answer key labels a case wrongly")
        return 1
    print("  safe siblings hold")
    return 0


NODE_PROBE = r"""
const out = [];
let bad = 0;
const claim = (n, d) => { out.push((d ? "  defeated  " : "  HELD      ") + n); if (!d) bad++; };

// replace without /g hits only the first occurrence
claim("replace-first-only", "....//x".replace("../", "").includes("../"));

// encodeURIComponent is not an HTML encoder
claim("wrong-encoder", encodeURIComponent("<img src=x onerror=y>").includes("%3C") &&
      !encodeURIComponent("'").includes("&#"));

// unanchored test() succeeds anywhere
const url = "https://api.example.com@evil.test/x";
claim("unanchored-test", /api\.example\.com/.test(url) &&
      new URL(url).hostname !== "api.example.com");

// result of replace discarded
let dirty = "../etc/passwd";
dirty.replace("..", "");
claim("discarded-result", dirty.includes(".."));

const safeOk = !/^[a-z-]{1,20}$/.test("report; id") &&
               new URL(url).hostname !== "api.example.com";
out.push(safeOk ? "  safe siblings hold" : "  BROKEN    a safe sibling");
if (!safeOk) bad++;
console.log(out.join("\n"));
process.exit(bad > 0 ? 1 : 0);
"""


def _node_claims():
    if not any(os.access(os.path.join(p, "node"), os.X_OK)
               for p in os.environ.get("PATH", "").split(os.pathsep)):
        return "javascript sanitizer claims: node absent, not checked\n"
    result = subprocess.run([sys.executable and "node", "-e", NODE_PROBE],
                            capture_output=True, text=True)
    if result.returncode != 0 and "HELD" in result.stdout:
        FAILURES.append("javascript")
    return "javascript sanitizer claims:\n" + result.stdout


if __name__ == "__main__":
    raise SystemExit(main())
