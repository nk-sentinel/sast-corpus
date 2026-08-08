"""Fixture templates for the tier-1 breadth slice.

These measure **coverage**, not depth: does a tool recognise this weakness in
this language at all? So the sink stays locally visible — the concatenation and
the call sit in one function — and a miss means the tool does not cover the
language or the weakness, rather than that it declined to trace a value across
files. Depth is measured by the hand-authored cases, which deliberately split
those apart. See docs/METHODOLOGY.md.

Every template ships a vulnerable variant and a safe sibling with the same
shape, because a corpus without traps cannot measure a false-positive rate.

Nothing here may contain a comment or an identifier naming the weakness. The
generator emits exactly what these strings hold, so anti-leakage is structural.
"""

from gen.generate import Template, Variant

SQLI = ("CWE-89", ["CWE-89", "CWE-943", "CWE-564"], "A03")
CMDI = ("CWE-78", ["CWE-78", "CWE-77", "CWE-88", "CWE-94"], "A03")
PATHT = ("CWE-22", ["CWE-22", "CWE-23", "CWE-35", "CWE-36"], "A01")
SSRF = ("CWE-918", ["CWE-918"], "A10")
DESER = ("CWE-502", ["CWE-502"], "A08")
XSS = ("CWE-79", ["CWE-79", "CWE-80"], "A03")


def template(slug, language, extension, weakness, framework, flow,
             vuln_files, vuln_sink_file, vuln_sink, vuln_rationale,
             safe_files, safe_sink_file, safe_sink, safe_sanitizer, safe_rationale,
             entry_file, entry_match, obfuscation="none", severity="high",
             extra=None):
    """Build the standard vulnerable/safe pair, plus any extra variants.

    `extra` is a dict of variant name to Variant. Variant names feed the case
    id, so adding one never disturbs the ids already in the answer key.
    """
    primary, acceptable, owasp = weakness
    variants = {
        "vulnerable": Variant(
            files=vuln_files, sink_file=vuln_sink_file, sink_match=vuln_sink,
            source_file=entry_file, source_match=entry_match,
            sanitizer="none", rationale=vuln_rationale, label="vulnerable",
        ),
        "safe": Variant(
            files=safe_files, sink_file=safe_sink_file, sink_match=safe_sink,
            source_file=entry_file, source_match=entry_match,
            sanitizer=safe_sanitizer, rationale=safe_rationale, label="safe",
        ),
    }
    variants.update(extra or {})

    return Template(
        slug=slug,
        language=language,
        extension=extension,
        framework=framework,
        primary_cwe=primary,
        acceptable_cwes=acceptable,
        owasp_2021=owasp,
        severity=severity,
        flow=flow,
        obfuscation=obfuscation,
        variants=variants,
    )


def local(files, sink_file, sink_match, sanitizer, rationale, label="vulnerable", flow=None):
    """A variant with no separate entry point — source and sink in one function."""
    return Variant(
        files=files, sink_file=sink_file, sink_match=sink_match,
        sanitizer=sanitizer, rationale=rationale, label=label,
        flow=flow or "intra-procedural",
    )


# --- python ----------------------------------------------------------------

PY_ENTRY = "from store import lookup\n\n\ndef show(code):\n    return lookup(code)\n"

PYTHON = [
    template(
        "py-sqli", "python", "py", SQLI, "flask", "inter-file",
        {"handler.py": PY_ENTRY,
         "store.py": (
             "import sqlite3\n\n\n"
             "def lookup(code):\n"
             "    cursor = sqlite3.connect(\"app.db\").cursor()\n"
             "    statement = \"SELECT status FROM orders WHERE code = '\" + code + \"'\"\n"
             "    return cursor.execute(statement).fetchone()\n")},
        "store.py", "cursor.execute(statement)",
        "the request value is concatenated into the statement text, which sqlite3 then parses as code",
        {"handler.py": PY_ENTRY,
         "store.py": (
             "import sqlite3\n\n\n"
             "def lookup(code):\n"
             "    cursor = sqlite3.connect(\"app.db\").cursor()\n"
             "    statement = \"SELECT status FROM orders WHERE code = ?\"\n"
             "    return cursor.execute(statement, (code,)).fetchone()\n")},
        "store.py", "cursor.execute(statement", "framework-implicit",
        "the value travels as a bound parameter, so the statement text never contains it",
        "handler.py", "def show",
    ),
    template(
        "py-cmdi", "python", "py", CMDI, "flask", "inter-file",
        {"handler.py": "from runner import archive\n\n\ndef show(name):\n    return archive(name)\n",
         "runner.py": (
             "import subprocess\n\n\n"
             "def archive(name):\n"
             "    line = \"tar -cf backup.tar \" + name\n"
             "    return subprocess.run(line, shell=True, capture_output=True).stdout\n")},
        "runner.py", "subprocess.run(line",
        "the request value is spliced into a string handed to a shell, so a semicolon starts a second command",
        {"handler.py": "from runner import archive\n\n\ndef show(name):\n    return archive(name)\n",
         "runner.py": (
             "import subprocess\n\n\n"
             "def archive(name):\n"
             "    argv = [\"tar\", \"-cf\", \"backup.tar\", name]\n"
             "    return subprocess.run(argv, shell=False, capture_output=True).stdout\n")},
        "runner.py", "subprocess.run(argv", "framework-implicit",
        "the value is one element of an argument vector with no shell involved, so it cannot become syntax",
        "handler.py", "def show",
    ),
    template(
        "py-path", "python", "py", PATHT, "flask", "inter-file",
        {"handler.py": "from reader import contents\n\n\ndef show(name):\n    return contents(name)\n",
         "reader.py": (
             "import os\n\n"
             "BASE = \"/srv/reports\"\n\n\n"
             "def contents(name):\n"
             "    target = os.path.join(BASE, name)\n"
             "    with open(target) as handle:\n"
             "        return handle.read()\n")},
        "reader.py", "with open(target)",
        "os.path.join discards the base whenever the request value is absolute, and honours .. segments otherwise",
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
        "basename strips any directory part and the resolved path is checked to remain under the base",
        "handler.py", "def show",
    ),
    template(
        "py-ssrf", "python", "py", SSRF, "flask", "inter-file",
        {"handler.py": "from fetcher import body\n\n\ndef show(target):\n    return body(target)\n",
         "fetcher.py": (
             "import requests\n\n\n"
             "def body(target):\n"
             "    response = requests.get(target, timeout=5)\n"
             "    return response.text\n")},
        "fetcher.py", "requests.get(target",
        "the request value becomes the whole URL, so the server can be aimed at internal addresses",
        {"handler.py": "from fetcher import body\n\n\ndef show(target):\n    return body(target)\n",
         "fetcher.py": (
             "from urllib.parse import urlparse\n\n"
             "import requests\n\n"
             "PERMITTED = {\"api.example.com\", \"cdn.example.com\"}\n\n\n"
             "def body(target):\n"
             "    parsed = urlparse(target)\n"
             "    if parsed.scheme != \"https\" or parsed.hostname not in PERMITTED:\n"
             "        raise ValueError(target)\n"
             "    response = requests.get(target, timeout=5)\n"
             "    return response.text\n")},
        "fetcher.py", "requests.get(target", "custom-effective",
        "the scheme and host are checked against a fixed allowlist before the request is made",
        "handler.py", "def show",
    ),
    template(
        "py-deser", "python", "py", DESER, "flask", "inter-file",
        {"handler.py": "from loader import restore\n\n\ndef show(blob):\n    return restore(blob)\n",
         "loader.py": (
             "import pickle\n\n\n"
             "def restore(blob):\n"
             "    return pickle.loads(blob)\n")},
        "loader.py", "pickle.loads(blob)",
        "pickle reconstructs arbitrary objects and runs their reduce hooks, so decoding request bytes executes them",
        {"handler.py": "from loader import restore\n\n\ndef show(blob):\n    return restore(blob)\n",
         "loader.py": (
             "import json\n\n\n"
             "def restore(blob):\n"
             "    return json.loads(blob)\n")},
        "loader.py", "json.loads(blob)", "custom-effective",
        "json decodes to plain data only and has no mechanism for invoking code during parsing",
        "handler.py", "def show",
    ),
]

# --- javascript / typescript -----------------------------------------------

JS = [
    template(
        "js-sqli", "javascript", "js", SQLI, "express", "inter-file",
        {"route.js": "const { lookup } = require('./store');\n\nfunction show(req, res) {\n  return res.json(lookup(req.params.code));\n}\n\nmodule.exports = { show };\n",
         "store.js": (
             "const { pool } = require('./db');\n\n"
             "function lookup(code) {\n"
             "  const statement = \"SELECT status FROM orders WHERE code = '\" + code + \"'\";\n"
             "  return pool.query(statement);\n"
             "}\n\n"
             "module.exports = { lookup };\n"),
         "db.js": "const pool = { query: (text, values) => ({ text, values }) };\n\nmodule.exports = { pool };\n"},
        "store.js", "pool.query(statement)",
        "the route parameter is concatenated into the statement text, which the driver then parses as code",
        {"route.js": "const { lookup } = require('./store');\n\nfunction show(req, res) {\n  return res.json(lookup(req.params.code));\n}\n\nmodule.exports = { show };\n",
         "store.js": (
             "const { pool } = require('./db');\n\n"
             "function lookup(code) {\n"
             "  const statement = 'SELECT status FROM orders WHERE code = $1';\n"
             "  return pool.query(statement, [code]);\n"
             "}\n\n"
             "module.exports = { lookup };\n"),
         "db.js": "const pool = { query: (text, values) => ({ text, values }) };\n\nmodule.exports = { pool };\n"},
        "store.js", "pool.query(statement", "framework-implicit",
        "the value is passed in the parameter array, so the statement text never contains it",
        "route.js", "function show",
    ),
    template(
        "js-cmdi", "javascript", "js", CMDI, "express", "inter-file",
        {"route.js": "const { archive } = require('./runner');\n\nfunction show(req, res) {\n  return archive(req.params.name, res);\n}\n\nmodule.exports = { show };\n",
         "runner.js": (
             "const { exec } = require('child_process');\n\n"
             "function archive(name, res) {\n"
             "  const line = 'tar -cf backup.tar ' + name;\n"
             "  return exec(line, (err, out) => res.send(out));\n"
             "}\n\n"
             "module.exports = { archive };\n")},
        "runner.js", "exec(line",
        "exec hands the assembled string to a shell, so a semicolon in the route parameter starts a second command",
        {"route.js": "const { archive } = require('./runner');\n\nfunction show(req, res) {\n  return archive(req.params.name, res);\n}\n\nmodule.exports = { show };\n",
         "runner.js": (
             "const { execFile } = require('child_process');\n\n"
             "function archive(name, res) {\n"
             "  const argv = ['-cf', 'backup.tar', name];\n"
             "  return execFile('tar', argv, (err, out) => res.send(out));\n"
             "}\n\n"
             "module.exports = { archive };\n")},
        "runner.js", "execFile('tar'", "framework-implicit",
        "execFile spawns the binary directly with an argument vector and never involves a shell",
        "route.js", "function show",
    ),
    template(
        "js-path", "javascript", "js", PATHT, "express", "inter-file",
        {"route.js": "const { contents } = require('./reader');\n\nfunction show(req, res) {\n  return res.send(contents(req.params.name));\n}\n\nmodule.exports = { show };\n",
         "reader.js": (
             "const fs = require('fs');\n"
             "const path = require('path');\n\n"
             "const BASE = '/srv/reports';\n\n"
             "function contents(name) {\n"
             "  const target = path.join(BASE, name);\n"
             "  return fs.readFileSync(target, 'utf8');\n"
             "}\n\n"
             "module.exports = { contents };\n")},
        "reader.js", "fs.readFileSync(target",
        "path.join resolves .. segments in the route parameter, so the read escapes the base directory",
        {"route.js": "const { contents } = require('./reader');\n\nfunction show(req, res) {\n  return res.send(contents(req.params.name));\n}\n\nmodule.exports = { show };\n",
         "reader.js": (
             "const fs = require('fs');\n"
             "const path = require('path');\n\n"
             "const BASE = '/srv/reports';\n\n"
             "function contents(name) {\n"
             "  const target = path.resolve(BASE, path.basename(name));\n"
             "  if (!target.startsWith(BASE + path.sep)) {\n"
             "    throw new Error('rejected');\n"
             "  }\n"
             "  return fs.readFileSync(target, 'utf8');\n"
             "}\n\n"
             "module.exports = { contents };\n")},
        "reader.js", "fs.readFileSync(target", "custom-effective",
        "basename removes any directory part and the resolved path is confirmed to stay under the base",
        "route.js", "function show",
    ),
    template(
        "js-ssrf", "javascript", "js", SSRF, "express", "inter-file",
        {"route.js": "const { body } = require('./fetcher');\n\nfunction show(req, res) {\n  return body(req.query.target).then((t) => res.send(t));\n}\n\nmodule.exports = { show };\n",
         "fetcher.js": (
             "async function body(target) {\n"
             "  const response = await fetch(target);\n"
             "  return response.text();\n"
             "}\n\n"
             "module.exports = { body };\n")},
        "fetcher.js", "await fetch(target)",
        "the query parameter becomes the whole URL, so the server can be aimed at internal addresses",
        {"route.js": "const { body } = require('./fetcher');\n\nfunction show(req, res) {\n  return body(req.query.target).then((t) => res.send(t));\n}\n\nmodule.exports = { show };\n",
         "fetcher.js": (
             "const PERMITTED = new Set(['api.example.com', 'cdn.example.com']);\n\n"
             "async function body(target) {\n"
             "  const parsed = new URL(target);\n"
             "  if (parsed.protocol !== 'https:' || !PERMITTED.has(parsed.hostname)) {\n"
             "    throw new Error('rejected');\n"
             "  }\n"
             "  const response = await fetch(target);\n"
             "  return response.text();\n"
             "}\n\n"
             "module.exports = { body };\n")},
        "fetcher.js", "await fetch(target)", "custom-effective",
        "the parsed scheme and host are checked against a fixed allowlist before the request is issued",
        "route.js", "function show",
    ),
]

TYPESCRIPT = [
    template(
        "ts-sqli", "typescript", "ts", SQLI, "nestjs", "inter-file",
        {"route.ts": "import { lookup } from './store';\n\nexport function show(code: string): unknown {\n  return lookup(code);\n}\n",
         "store.ts": (
             "import { pool } from './db';\n\n"
             "export function lookup(code: string): unknown {\n"
             "  const statement = \"SELECT status FROM orders WHERE code = '\" + code + \"'\";\n"
             "  return pool.query(statement);\n"
             "}\n"),
         "db.ts": "export const pool = {\n  query(text: string, values?: unknown[]): unknown {\n    return { text, values };\n  },\n};\n"},
        "store.ts", "pool.query(statement)",
        "the handler argument is concatenated into the statement text, which the driver then parses as code",
        {"route.ts": "import { lookup } from './store';\n\nexport function show(code: string): unknown {\n  return lookup(code);\n}\n",
         "store.ts": (
             "import { pool } from './db';\n\n"
             "export function lookup(code: string): unknown {\n"
             "  const statement = 'SELECT status FROM orders WHERE code = $1';\n"
             "  return pool.query(statement, [code]);\n"
             "}\n"),
         "db.ts": "export const pool = {\n  query(text: string, values?: unknown[]): unknown {\n    return { text, values };\n  },\n};\n"},
        "store.ts", "pool.query(statement", "framework-implicit",
        "the value is passed in the parameter array, so the statement text never contains it",
        "route.ts", "export function show",
    ),
    template(
        "ts-cmdi", "typescript", "ts", CMDI, "nestjs", "inter-file",
        {"route.ts": "import { archive } from './runner';\n\nexport function show(name: string): unknown {\n  return archive(name);\n}\n",
         "runner.ts": (
             "import { execSync } from 'child_process';\n\n"
             "export function archive(name: string): Buffer {\n"
             "  const line = 'tar -cf backup.tar ' + name;\n"
             "  return execSync(line);\n"
             "}\n")},
        "runner.ts", "execSync(line)",
        "execSync hands the assembled string to a shell, so a semicolon in the argument starts a second command",
        {"route.ts": "import { archive } from './runner';\n\nexport function show(name: string): unknown {\n  return archive(name);\n}\n",
         "runner.ts": (
             "import { execFileSync } from 'child_process';\n\n"
             "export function archive(name: string): Buffer {\n"
             "  const argv = ['-cf', 'backup.tar', name];\n"
             "  return execFileSync('tar', argv);\n"
             "}\n")},
        "runner.ts", "execFileSync('tar'", "framework-implicit",
        "execFileSync spawns the binary directly with an argument vector and never involves a shell",
        "route.ts", "export function show",
    ),
]

ALL = PYTHON + JS + TYPESCRIPT


# --- go --------------------------------------------------------------------

GO_ENTRY = """package app

func Show(code string) (string, error) {
	return Lookup(code)
}
"""

GO = [
    template(
        "go-sqli", "go", "go", SQLI, "net/http", "inter-file",
        {"handler.go": GO_ENTRY,
         "store.go": (
             "package app\n\n"
             "import (\n\t\"database/sql\"\n\t\"fmt\"\n)\n\n"
             "var db *sql.DB\n\n"
             "func Lookup(code string) (string, error) {\n"
             "\tstatement := fmt.Sprintf(\"SELECT status FROM orders WHERE code = '%s'\", code)\n"
             "\tvar status string\n"
             "\terr := db.QueryRow(statement).Scan(&status)\n"
             "\treturn status, err\n}\n")},
        "store.go", "db.QueryRow(statement)",
        "the request value is formatted into the statement text, which the driver then parses as code",
        {"handler.go": GO_ENTRY,
         "store.go": (
             "package app\n\n"
             "import (\n\t\"database/sql\"\n)\n\n"
             "var db *sql.DB\n\n"
             "func Lookup(code string) (string, error) {\n"
             "\tstatement := \"SELECT status FROM orders WHERE code = $1\"\n"
             "\tvar status string\n"
             "\terr := db.QueryRow(statement, code).Scan(&status)\n"
             "\treturn status, err\n}\n")},
        "store.go", "db.QueryRow(statement", "framework-implicit",
        "the value travels as a bound argument, so the statement text never contains it",
        "handler.go", "func Show",
    ),
    template(
        "go-cmdi", "go", "go", CMDI, "net/http", "inter-file",
        {"handler.go": "package app\n\nfunc Show(name string) ([]byte, error) {\n\treturn Archive(name)\n}\n",
         "runner.go": (
             "package app\n\n"
             "import (\n\t\"os/exec\"\n)\n\n"
             "func Archive(name string) ([]byte, error) {\n"
             "\tline := \"tar -cf backup.tar \" + name\n"
             "\treturn exec.Command(\"sh\", \"-c\", line).Output()\n}\n")},
        "runner.go", "exec.Command(\"sh\"",
        "the assembled string is handed to a shell, so a semicolon in the request value starts a second command",
        {"handler.go": "package app\n\nfunc Show(name string) ([]byte, error) {\n\treturn Archive(name)\n}\n",
         "runner.go": (
             "package app\n\n"
             "import (\n\t\"os/exec\"\n)\n\n"
             "func Archive(name string) ([]byte, error) {\n"
             "\treturn exec.Command(\"tar\", \"-cf\", \"backup.tar\", name).Output()\n}\n")},
        "runner.go", "exec.Command(\"tar\"", "framework-implicit",
        "the binary is invoked directly with an argument vector, so no shell can reinterpret the value",
        "handler.go", "func Show",
    ),
    template(
        "go-path", "go", "go", PATHT, "net/http", "inter-file",
        {"handler.go": "package app\n\nfunc Show(name string) ([]byte, error) {\n\treturn Contents(name)\n}\n",
         "reader.go": (
             "package app\n\n"
             "import (\n\t\"os\"\n\t\"path/filepath\"\n)\n\n"
             "const base = \"/srv/reports\"\n\n"
             "func Contents(name string) ([]byte, error) {\n"
             "\ttarget := filepath.Join(base, name)\n"
             "\treturn os.ReadFile(target)\n}\n")},
        "reader.go", "os.ReadFile(target)",
        "filepath.Join resolves .. segments in the request value, so the read escapes the base directory",
        {"handler.go": "package app\n\nfunc Show(name string) ([]byte, error) {\n\treturn Contents(name)\n}\n",
         "reader.go": (
             "package app\n\n"
             "import (\n\t\"errors\"\n\t\"os\"\n\t\"path/filepath\"\n\t\"strings\"\n)\n\n"
             "const base = \"/srv/reports\"\n\n"
             "func Contents(name string) ([]byte, error) {\n"
             "\ttarget := filepath.Join(base, filepath.Base(name))\n"
             "\tif !strings.HasPrefix(target, base+string(filepath.Separator)) {\n"
             "\t\treturn nil, errors.New(\"rejected\")\n\t}\n"
             "\treturn os.ReadFile(target)\n}\n")},
        "reader.go", "os.ReadFile(target)", "custom-effective",
        "filepath.Base strips any directory part and the joined path is checked to remain under the base",
        "handler.go", "func Show",
    ),
]

# --- c# --------------------------------------------------------------------

CSHARP = [
    template(
        "cs-sqli", "csharp", "cs", SQLI, "aspnet", "inter-file",
        {"Controller.cs": "namespace App;\n\npublic class Controller\n{\n    public object Show(string code) => Store.Lookup(code);\n}\n",
         "Store.cs": (
             "using Microsoft.Data.SqlClient;\n\n"
             "namespace App;\n\n"
             "public static class Store\n{\n"
             "    public static object Lookup(string code)\n    {\n"
             "        var statement = \"SELECT status FROM orders WHERE code = '\" + code + \"'\";\n"
             "        using var command = new SqlCommand(statement);\n"
             "        return command.ExecuteScalar();\n    }\n}\n")},
        "Store.cs", "command.ExecuteScalar()",
        "the request value is concatenated into the command text, which the server then parses as code",
        {"Controller.cs": "namespace App;\n\npublic class Controller\n{\n    public object Show(string code) => Store.Lookup(code);\n}\n",
         "Store.cs": (
             "using Microsoft.Data.SqlClient;\n\n"
             "namespace App;\n\n"
             "public static class Store\n{\n"
             "    public static object Lookup(string code)\n    {\n"
             "        var statement = \"SELECT status FROM orders WHERE code = @code\";\n"
             "        using var command = new SqlCommand(statement);\n"
             "        command.Parameters.AddWithValue(\"@code\", code);\n"
             "        return command.ExecuteScalar();\n    }\n}\n")},
        "Store.cs", "command.ExecuteScalar()", "framework-implicit",
        "the value is added as a command parameter, so the command text never contains it",
        "Controller.cs", "public object Show",
    ),
    template(
        "cs-cmdi", "csharp", "cs", CMDI, "aspnet", "inter-file",
        {"Controller.cs": "namespace App;\n\npublic class Controller\n{\n    public void Show(string name) => Runner.Archive(name);\n}\n",
         "Runner.cs": (
             "using System.Diagnostics;\n\n"
             "namespace App;\n\n"
             "public static class Runner\n{\n"
             "    public static void Archive(string name)\n    {\n"
             "        var line = \"-c \\\"tar -cf backup.tar \" + name + \"\\\"\";\n"
             "        Process.Start(\"/bin/sh\", line);\n    }\n}\n")},
        "Runner.cs", "Process.Start(\"/bin/sh\"",
        "the assembled argument string is handed to a shell, so a semicolon in the request value starts a second command",
        {"Controller.cs": "namespace App;\n\npublic class Controller\n{\n    public void Show(string name) => Runner.Archive(name);\n}\n",
         "Runner.cs": (
             "using System.Diagnostics;\n\n"
             "namespace App;\n\n"
             "public static class Runner\n{\n"
             "    public static void Archive(string name)\n    {\n"
             "        var info = new ProcessStartInfo(\"tar\");\n"
             "        info.ArgumentList.Add(\"-cf\");\n"
             "        info.ArgumentList.Add(\"backup.tar\");\n"
             "        info.ArgumentList.Add(name);\n"
             "        Process.Start(info);\n    }\n}\n")},
        "Runner.cs", "Process.Start(info)", "framework-implicit",
        "ArgumentList passes each argument separately to the binary with no shell in the path",
        "Controller.cs", "public void Show",
    ),
]

# --- php -------------------------------------------------------------------

PHP = [
    template(
        "php-sqli", "php", "php", SQLI, "laravel", "inter-file",
        {"handler.php": "<?php\n\nrequire_once __DIR__ . '/store.php';\n\nfunction show($code) {\n    return lookup($code);\n}\n",
         "store.php": (
             "<?php\n\n"
             "function lookup($code) {\n"
             "    $link = mysqli_connect('localhost', 'app', '', 'orders');\n"
             "    $statement = \"SELECT status FROM orders WHERE code = '\" . $code . \"'\";\n"
             "    return mysqli_query($link, $statement);\n}\n")},
        "store.php", "mysqli_query($link, $statement)",
        "the request value is concatenated into the statement text, which the server then parses as code",
        {"handler.php": "<?php\n\nrequire_once __DIR__ . '/store.php';\n\nfunction show($code) {\n    return lookup($code);\n}\n",
         "store.php": (
             "<?php\n\n"
             "function lookup($code) {\n"
             "    $link = mysqli_connect('localhost', 'app', '', 'orders');\n"
             "    $statement = mysqli_prepare($link, 'SELECT status FROM orders WHERE code = ?');\n"
             "    mysqli_stmt_bind_param($statement, 's', $code);\n"
             "    mysqli_stmt_execute($statement);\n"
             "    return mysqli_stmt_get_result($statement);\n}\n")},
        "store.php", "mysqli_stmt_execute($statement)", "framework-implicit",
        "the value is bound to a prepared statement, so the statement text never contains it",
        "handler.php", "function show",
    ),
    template(
        "php-cmdi", "php", "php", CMDI, "laravel", "inter-file",
        {"handler.php": "<?php\n\nrequire_once __DIR__ . '/runner.php';\n\nfunction show($name) {\n    return archive($name);\n}\n",
         "runner.php": (
             "<?php\n\n"
             "function archive($name) {\n"
             "    $line = 'tar -cf backup.tar ' . $name;\n"
             "    return shell_exec($line);\n}\n")},
        "runner.php", "shell_exec($line)",
        "the assembled string is handed to a shell, so a semicolon in the request value starts a second command",
        {"handler.php": "<?php\n\nrequire_once __DIR__ . '/runner.php';\n\nfunction show($name) {\n    return archive($name);\n}\n",
         "runner.php": (
             "<?php\n\n"
             "function archive($name) {\n"
             "    $line = 'tar -cf backup.tar ' . escapeshellarg($name);\n"
             "    return shell_exec($line);\n}\n")},
        "runner.php", "shell_exec($line)", "custom-effective",
        "escapeshellarg quotes the value so the shell treats it as a single literal argument",
        "handler.php", "function show",
    ),
]

# --- ruby ------------------------------------------------------------------

RUBY = [
    template(
        "rb-sqli", "ruby", "rb", SQLI, "rails", "inter-file",
        {"handler.rb": "require_relative 'store'\n\ndef show(code)\n  lookup(code)\nend\n",
         "store.rb": (
             "require 'sqlite3'\n\n"
             "def lookup(code)\n"
             "  db = SQLite3::Database.new('app.db')\n"
             "  statement = \"SELECT status FROM orders WHERE code = '\" + code + \"'\"\n"
             "  db.execute(statement)\nend\n")},
        "store.rb", "db.execute(statement)",
        "the request value is concatenated into the statement text, which the engine then parses as code",
        {"handler.rb": "require_relative 'store'\n\ndef show(code)\n  lookup(code)\nend\n",
         "store.rb": (
             "require 'sqlite3'\n\n"
             "def lookup(code)\n"
             "  db = SQLite3::Database.new('app.db')\n"
             "  statement = 'SELECT status FROM orders WHERE code = ?'\n"
             "  db.execute(statement, [code])\nend\n")},
        "store.rb", "db.execute(statement", "framework-implicit",
        "the value is passed as a bound parameter, so the statement text never contains it",
        "handler.rb", "def show",
    ),
    template(
        "rb-cmdi", "ruby", "rb", CMDI, "rails", "inter-file",
        {"handler.rb": "require_relative 'runner'\n\ndef show(name)\n  archive(name)\nend\n",
         "runner.rb": (
             "def archive(name)\n"
             "  line = 'tar -cf backup.tar ' + name\n"
             "  system(line)\nend\n")},
        "runner.rb", "system(line)",
        "a single string argument makes Kernel#system route through a shell, so a semicolon starts a second command",
        {"handler.rb": "require_relative 'runner'\n\ndef show(name)\n  archive(name)\nend\n",
         "runner.rb": (
             "def archive(name)\n"
             "  system('tar', '-cf', 'backup.tar', name)\nend\n")},
        "runner.rb", "system('tar'", "framework-implicit",
        "the multi-argument form invokes the binary directly and never involves a shell",
        "handler.rb", "def show",
    ),
]

ALL = ALL + GO + CSHARP + PHP + RUBY

from gen.templates_depth import DEPTH_ALL  # noqa: E402
from gen.templates_more import MORE_ALL  # noqa: E402
from gen.templates_planes import PLANES_ALL  # noqa: E402

ALL = ALL + DEPTH_ALL + MORE_ALL + PLANES_ALL
