"""Templates that vary analysis depth and sanitizer quality.

Two skews in the breadth slice made the corpus unable to say things it should.

Every case sat at `inter-file`, so a tool that only reasons within one procedure
scored the same as one that follows values across a codebase. The depth variants
here put the same weakness at three distances — inside one function, across two
functions in one file, and across files — so the difficulty breakdown separates
them.

And `sanitizer: ineffective` had no cases at all, despite being the most common
false-negative source in real code. A filter that looks like a defence and is
not is exactly what a tool must reason about: it has to decide whether the
sanitizer actually works, not merely that one is present. Those cases are
labelled **vulnerable** — the code really is exploitable — so a tool that treats
any nearby `replace` as proof of safety records a false negative.
"""

from gen.generate import Variant
from gen.templates import CMDI, PATHT, SQLI, XSS, template

# --- depth: the same weakness at three distances ---------------------------

PY_DEPTH = [
    template(
        "py-sqli-local", "python", "py", SQLI, "flask", "intra-procedural",
        {"view.py": (
            "import sqlite3\n\n\n"
            "def show(code):\n"
            "    cursor = sqlite3.connect(\"app.db\").cursor()\n"
            "    statement = \"SELECT status FROM orders WHERE code = '\" + code + \"'\"\n"
            "    return cursor.execute(statement).fetchone()\n")},
        "view.py", "cursor.execute(statement)",
        "source and sink sit in one function, so no dataflow analysis beyond the statement is needed",
        {"view.py": (
            "import sqlite3\n\n\n"
            "def show(code):\n"
            "    cursor = sqlite3.connect(\"app.db\").cursor()\n"
            "    statement = \"SELECT status FROM orders WHERE code = ?\"\n"
            "    return cursor.execute(statement, (code,)).fetchone()\n")},
        "view.py", "cursor.execute(statement", "framework-implicit",
        "the value is bound rather than concatenated, in the same single function",
        None, None,
    ),
    template(
        "py-sqli-crossfn", "python", "py", SQLI, "flask", "inter-procedural",
        {"view.py": (
            "import sqlite3\n\n\n"
            "def _run(statement):\n"
            "    cursor = sqlite3.connect(\"app.db\").cursor()\n"
            "    return cursor.execute(statement).fetchone()\n\n\n"
            "def show(code):\n"
            "    return _run(\"SELECT status FROM orders WHERE code = '\" + code + \"'\")\n")},
        "view.py", "cursor.execute(statement)",
        "the assembled text crosses a function boundary inside one file before reaching the sink",
        {"view.py": (
            "import sqlite3\n\n\n"
            "def _run(statement, code):\n"
            "    cursor = sqlite3.connect(\"app.db\").cursor()\n"
            "    return cursor.execute(statement, (code,)).fetchone()\n\n\n"
            "def show(code):\n"
            "    return _run(\"SELECT status FROM orders WHERE code = ?\", code)\n")},
        "view.py", "cursor.execute(statement", "framework-implicit",
        "the same call structure, but the value is bound instead of concatenated",
        "view.py", "def show",
    ),
]

# --- sanitizers that look like defences and are not ------------------------

WEAK = [
    template(
        "py-path-filter", "python", "py", PATHT, "flask", "inter-file",
        {"handler.py": "from reader import contents\n\n\ndef show(name):\n    return contents(name)\n",
         "reader.py": (
             "import os\n\n"
             "BASE = \"/srv/reports\"\n\n\n"
             "def contents(name):\n"
             "    cleaned = name.replace(\"../\", \"\")\n"
             "    with open(os.path.join(BASE, cleaned)) as handle:\n"
             "        return handle.read()\n")},
        "reader.py", "with open(os.path.join",
        "the filter runs once, so ....// collapses to ../ after the replacement and the read still escapes the base",
        {"handler.py": "from reader import contents\n\n\ndef show(name):\n    return contents(name)\n",
         "reader.py": (
             "import os\n\n"
             "BASE = \"/srv/reports\"\n\n\n"
             "def contents(name):\n"
             "    target = os.path.realpath(os.path.join(BASE, os.path.basename(name)))\n"
             "    if not target.startswith(BASE + os.sep):\n"
             "        raise ValueError(name)\n"
             "    with open(target) as handle:\n"
             "        return handle.read()\n")},
        "reader.py", "with open(target)", "custom-effective",
        "the directory part is discarded and the resolved path is checked to remain under the base",
        "handler.py", "def show",
        extra={
            "vulnerable-loop-filter": Variant(
                files={
                    "handler.py": "from reader import contents\n\n\ndef show(name):\n    return contents(name)\n",
                    "reader.py": (
                        "import os\n\n"
                        "BASE = \"/srv/reports\"\n\n\n"
                        "def contents(name):\n"
                        "    cleaned = name\n"
                        "    while \"../\" in cleaned:\n"
                        "        cleaned = cleaned.replace(\"../\", \"\")\n"
                        "    with open(os.path.join(BASE, cleaned)) as handle:\n"
                        "        return handle.read()\n"),
                },
                sink_file="reader.py", sink_match="with open(os.path.join",
                source_file="handler.py", source_match="def show",
                sanitizer="ineffective", label="vulnerable",
                rationale=(
                    "looping the replacement closes the ....// bypass but an absolute path is "
                    "untouched, and os.path.join discards the base entirely when handed one"),
            ),
        },
    ),
    template(
        "py-cmdi-filter", "python", "py", CMDI, "flask", "inter-file",
        {"handler.py": "from runner import archive\n\n\ndef show(name):\n    return archive(name)\n",
         "runner.py": (
             "import subprocess\n\n\n"
             "def archive(name):\n"
             "    cleaned = name.replace(\";\", \"\")\n"
             "    return subprocess.run(\"tar -cf backup.tar \" + cleaned, shell=True).returncode\n")},
        "runner.py", "subprocess.run(\"tar",
        "only the semicolon is removed, so a pipe, an ampersand pair, a backtick or $() still starts a second command",
        {"handler.py": "from runner import archive\n\n\ndef show(name):\n    return archive(name)\n",
         "runner.py": (
             "import subprocess\n\n\n"
             "def archive(name):\n"
             "    return subprocess.run([\"tar\", \"-cf\", \"backup.tar\", name], shell=False).returncode\n")},
        "runner.py", "subprocess.run([", "framework-implicit",
        "an argument vector with no shell means the value cannot become syntax at all",
        "handler.py", "def show",
    ),
]

# --- cross-site scripting ---------------------------------------------------

MARKUP = [
    template(
        "py-markup", "python", "py", XSS, "flask", "inter-file",
        {"handler.py": "from page import render_row\n\n\ndef show(name):\n    return render_row(name)\n",
         "page.py": (
             "def render_row(name):\n"
             "    return \"<div class='row'>\" + name + \"</div>\"\n")},
        "page.py", "return \"<div class='row'>\"",
        "the request value is placed straight into markup, so any tag it contains is parsed as markup by the browser",
        {"handler.py": "from page import render_row\n\n\ndef show(name):\n    return render_row(name)\n",
         "page.py": (
             "import html\n\n\n"
             "def render_row(name):\n"
             "    return \"<div class='row'>\" + html.escape(name, quote=True) + \"</div>\"\n")},
        "page.py", "return \"<div class='row'>\"", "custom-effective",
        "html.escape converts the characters that could open a tag or close the attribute",
        "handler.py", "def show",
        extra={
            "vulnerable-tag-filter": Variant(
                files={
                    "handler.py": "from page import render_row\n\n\ndef show(name):\n    return render_row(name)\n",
                    "page.py": (
                        "def render_row(name):\n"
                        "    cleaned = name.replace(\"<script>\", \"\")\n"
                        "    return \"<div class='row'>\" + cleaned + \"</div>\"\n"),
                },
                sink_file="page.py", sink_match="return \"<div class='row'>\"",
                source_file="handler.py", source_match="def show",
                sanitizer="ineffective", label="vulnerable",
                rationale=(
                    "removing one literal tag spelling leaves every event-handler attribute and "
                    "every other tag intact, and the filter itself is case-sensitive"),
            ),
        },
    ),
    template(
        "js-markup", "javascript", "js", XSS, "express", "inter-file",
        {"route.js": "const { renderRow } = require('./page');\n\nfunction show(req, res) {\n  return res.send(renderRow(req.query.name));\n}\n\nmodule.exports = { show };\n",
         "page.js": (
             "function renderRow(name) {\n"
             "  return \"<div class='row'>\" + name + \"</div>\";\n"
             "}\n\n"
             "module.exports = { renderRow };\n")},
        "page.js", "return \"<div class='row'>\"",
        "the query value is placed straight into markup, so any tag it contains is parsed as markup by the browser",
        {"route.js": "const { renderRow } = require('./page');\n\nfunction show(req, res) {\n  return res.send(renderRow(req.query.name));\n}\n\nmodule.exports = { show };\n",
         "page.js": (
             "const REPLACEMENTS = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' };\n\n"
             "function renderRow(name) {\n"
             "  const encoded = String(name).replace(/[&<>\"']/g, (c) => REPLACEMENTS[c]);\n"
             "  return \"<div class='row'>\" + encoded + \"</div>\";\n"
             "}\n\n"
             "module.exports = { renderRow };\n")},
        "page.js", "return \"<div class='row'>\"", "custom-effective",
        "every character that could open a tag or close the attribute is encoded before insertion",
        "route.js", "function show",
    ),
]

DEPTH_ALL = PY_DEPTH + WEAK + MARKUP
