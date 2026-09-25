"""Widen the thin languages: every language to at least six weaknesses.

Depth was heavily concentrated — Java on sixteen weaknesses, Python fifteen, C
eleven, and eight languages on two or fewer. A result for anything in that tail
rested on a pair of cases, which is not enough to say anything about a tool.

These are the same weakness classes the deep languages already carry, written in
each language's own idiom rather than transliterated. The idiom matters: Go's
`html/template` escapes by default and `template.HTML` opts out, PHP's
`unserialize` is a different hazard from Java's `ObjectInputStream`, and Rust's
`format!` into a query has no prepared-statement equivalent in the same crate.
A tool that recognises the Java shape and not the local one is exactly what
these cases are for.
"""

from gen.templates import template

SQLI = ("CWE-89", ["CWE-89", "CWE-943", "CWE-564"], "A03")
CMDI = ("CWE-78", ["CWE-78", "CWE-77", "CWE-88"], "A03")
PATHT = ("CWE-22", ["CWE-22", "CWE-23", "CWE-35", "CWE-36"], "A01")
XSS = ("CWE-79", ["CWE-79", "CWE-80", "CWE-116"], "A03")
SSRF = ("CWE-918", ["CWE-918"], "A10")
DESER = ("CWE-502", ["CWE-502", "CWE-915"], "A08")
CRYPTO = ("CWE-327", ["CWE-327", "CWE-328", "CWE-326"], "A02")
CREDS = ("CWE-798", ["CWE-798", "CWE-259", "CWE-321"], "A07")
XXE = ("CWE-611", ["CWE-611", "CWE-827", "CWE-776"], "A05")
OOB_WRITE = ("CWE-787", ["CWE-787", "CWE-120", "CWE-121"], "A03")
NULL_DEREF = ("CWE-476", ["CWE-476", "CWE-690"], "A03")
CLASSIC_OVERFLOW = ("CWE-120", ["CWE-120", "CWE-787", "CWE-121", "CWE-676"], "A03")


def pair(slug, language, extension, weakness, entry_files, entry_name, sink_file,
         vuln_extra, vuln_sink, why_vulnerable, safe_extra, safe_sink, why_safe,
         framework=None, flow="inter-file", sanitizer="custom-effective"):
    """A two-file pair sharing an entry point, differing only in the sink file."""
    return template(
        slug, language, extension, weakness, framework, flow,
        dict(entry_files, **vuln_extra), sink_file, vuln_sink, why_vulnerable,
        dict(entry_files, **safe_extra), sink_file, safe_sink, sanitizer, why_safe,
        next(iter(entry_files)), entry_name,
    )


# --- go ---------------------------------------------------------------------

GO_ENTRY = {"handler.go": "package app\n\nfunc Show(value string) string {\n\treturn Render(value)\n}\n"}

GO = [
    pair("go-markup@template-html-optout", "go", "go", XSS,
         GO_ENTRY, "func Show", "render.go",
         {"render.go": ("package app\n\n"
                        "import (\n\t\"bytes\"\n\t\"html/template\"\n)\n\n"
                        "func Render(value string) string {\n"
                        "\tt := template.Must(template.New(\"row\").Parse(\"<div>{{.}}</div>\"))\n"
                        "\tvar out bytes.Buffer\n"
                        "\tt.Execute(&out, template.HTML(value))\n"
                        "\treturn out.String()\n}\n")},
         "t.Execute(&out, template.HTML(value))",
         "html/template escapes by default and template.HTML is the documented way to opt out. "
         "Wrapping request data in it disables the protection for exactly the value that needed "
         "it, and the surrounding code looks like correct template use",
         {"render.go": ("package app\n\n"
                        "import (\n\t\"bytes\"\n\t\"html/template\"\n)\n\n"
                        "func Render(value string) string {\n"
                        "\tt := template.Must(template.New(\"row\").Parse(\"<div>{{.}}</div>\"))\n"
                        "\tvar out bytes.Buffer\n"
                        "\tt.Execute(&out, value)\n"
                        "\treturn out.String()\n}\n")},
         "t.Execute(&out, value)",
         "the value is passed as a plain string, so the template package escapes it for the "
         "context it lands in"),
    pair("go-ssrf@unvalidated-url", "go", "go", SSRF,
         GO_ENTRY, "func Show", "fetch.go",
         {"fetch.go": ("package app\n\n"
                       "import (\n\t\"io\"\n\t\"net/http\"\n)\n\n"
                       "func Render(target string) string {\n"
                       "\tresponse, err := http.Get(target)\n"
                       "\tif err != nil {\n\t\treturn \"\"\n\t}\n"
                       "\tdefer response.Body.Close()\n"
                       "\tbody, _ := io.ReadAll(response.Body)\n"
                       "\treturn string(body)\n}\n")},
         "http.Get(target)",
         "the request value becomes the whole URL, so the server can be pointed at the metadata "
         "endpoint or any internal address it can route to",
         {"fetch.go": ("package app\n\n"
                       "import (\n\t\"io\"\n\t\"net/http\"\n\t\"net/url\"\n)\n\n"
                       "var permitted = map[string]bool{\"api.example.com\": true}\n\n"
                       "func Render(target string) string {\n"
                       "\tparsed, err := url.Parse(target)\n"
                       "\tif err != nil || parsed.Scheme != \"https\" || !permitted[parsed.Hostname()] {\n"
                       "\t\treturn \"\"\n\t}\n"
                       "\tresponse, err := http.Get(target)\n"
                       "\tif err != nil {\n\t\treturn \"\"\n\t}\n"
                       "\tdefer response.Body.Close()\n"
                       "\tbody, _ := io.ReadAll(response.Body)\n"
                       "\treturn string(body)\n}\n")},
         "http.Get(target)",
         "the scheme and host are checked against a fixed allowlist before the request"),
    pair("go-crypto@weak-hash", "go", "go", CRYPTO,
         GO_ENTRY, "func Show", "digest.go",
         {"digest.go": ("package app\n\n"
                        "import (\n\t\"crypto/md5\"\n\t\"encoding/hex\"\n)\n\n"
                        "func Render(value string) string {\n"
                        "\tsum := md5.Sum([]byte(value))\n"
                        "\treturn hex.EncodeToString(sum[:])\n}\n")},
         "md5.Sum([]byte(value))",
         "MD5 has practical collision attacks, so a fingerprint built on it no longer "
         "distinguishes two inputs",
         {"digest.go": ("package app\n\n"
                        "import (\n\t\"crypto/sha256\"\n\t\"encoding/hex\"\n)\n\n"
                        "func Render(value string) string {\n"
                        "\tsum := sha256.Sum256([]byte(value))\n"
                        "\treturn hex.EncodeToString(sum[:])\n}\n")},
         "sha256.Sum256([]byte(value))",
         "SHA-256 has no known collision attack and is the appropriate replacement"),
    pair("go-creds@literal-in-source", "go", "go", CREDS,
         GO_ENTRY, "func Show", "settings.go",
         {"settings.go": ("package app\n\n"
                          "const dbPassword = \"Pr0d-Repor7ing-2024!\"\n\n"
                          "func Render(user string) string {\n"
                          "\treturn user + \":\" + dbPassword\n}\n")},
         "const dbPassword =",
         "the password is a compiled-in constant, so it is recoverable from the binary as well "
         "as from the repository history",
         {"settings.go": ("package app\n\n"
                          "import \"os\"\n\n"
                          "func Render(user string) string {\n"
                          "\treturn user + \":\" + os.Getenv(\"DB_PASSWORD\")\n}\n")},
         "os.Getenv(\"DB_PASSWORD\")",
         "the value is read from the environment and never appears in source or binary"),
    pair("go-deser@yaml-untrusted", "go", "go", DESER,
         GO_ENTRY, "func Show", "load.go",
         {"load.go": ("package app\n\n"
                      "import (\n\t\"bytes\"\n\t\"encoding/gob\"\n)\n\n"
                      "type Settings struct {\n\tName string\n\tAdmin bool\n}\n\n"
                      "func Render(blob string) string {\n"
                      "\tvar settings Settings\n"
                      "\tgob.NewDecoder(bytes.NewBufferString(blob)).Decode(&settings)\n"
                      "\tif settings.Admin {\n\t\treturn \"admin\"\n\t}\n"
                      "\treturn settings.Name\n}\n")},
         "gob.NewDecoder(bytes.NewBufferString(blob)).Decode",
         "the caller controls the encoded stream and therefore every field it sets, including "
         "the privilege flag the code branches on immediately afterwards",
         {"load.go": ("package app\n\n"
                      "import \"encoding/json\"\n\n"
                      "type Settings struct {\n\tName string `json:\"name\"`\n}\n\n"
                      "func Render(blob string) string {\n"
                      "\tvar settings Settings\n"
                      "\tjson.Unmarshal([]byte(blob), &settings)\n"
                      "\treturn settings.Name\n}\n")},
         "json.Unmarshal([]byte(blob), &settings)",
         "only the name field is decodable, so no privilege field is reachable from the payload"),
]

# --- c++ --------------------------------------------------------------------

CPP_ENTRY_STR = {"main.cpp": ("#include <iostream>\n#include \"work.hpp\"\n\n"
                              "int main(int argc, char **argv) {\n"
                              "    if (argc < 2) {\n        return 1;\n    }\n"
                              "    std::cout << handle(std::string(argv[1])) << std::endl;\n"
                              "    return 0;\n}\n"),
                 "work.hpp": "#pragma once\n#include <string>\nstd::size_t handle(const std::string &value);\n"}

CPP_ENTRY_INT = {"main.cpp": ("#include <cstdlib>\n#include <iostream>\n#include \"work.hpp\"\n\n"
                              "int main(int argc, char **argv) {\n"
                              "    if (argc < 2) {\n        return 1;\n    }\n"
                              "    std::cout << handle(std::atoi(argv[1])) << std::endl;\n"
                              "    return 0;\n}\n"),
                 "work.hpp": "#pragma once\nint handle(int value);\n"}

CPP = [
    pair("cpp-strcpy@unbounded-copy", "cpp", "cpp", CLASSIC_OVERFLOW,
         CPP_ENTRY_STR, "int main", "work.cpp",
         {"work.cpp": ("#include <cstring>\n#include <string>\n#include \"work.hpp\"\n\n"
                       "std::size_t handle(const std::string &value) {\n"
                       "    char buffer[32];\n"
                       "    std::strcpy(buffer, value.c_str());\n"
                       "    return std::strlen(buffer);\n}\n")},
         "std::strcpy(buffer, value.c_str())",
         "a C string copy into a fixed C++ stack buffer. std::string carries its length and the "
         "code discards it, so the destination size is never consulted",
         {"work.cpp": ("#include <cstring>\n#include <string>\n#include \"work.hpp\"\n\n"
                       "std::size_t handle(const std::string &value) {\n"
                       "    char buffer[32];\n"
                       "    std::snprintf(buffer, sizeof(buffer), \"%s\", value.c_str());\n"
                       "    return std::strlen(buffer);\n}\n")},
         "std::snprintf(buffer, sizeof(buffer)",
         "the destination size is supplied so the write truncates instead of overrunning"),
    pair("cpp-index-write@unchecked-index-write", "cpp", "cpp", OOB_WRITE,
         CPP_ENTRY_INT, "int main", "work.cpp",
         {"work.cpp": ("#include <vector>\n#include \"work.hpp\"\n\n"
                       "int handle(int value) {\n"
                       "    std::vector<int> slots(16, 0);\n"
                       "    slots[value] = 1;\n"
                       "    return slots[value];\n}\n")},
         "slots[value] = 1",
         "operator[] performs no bounds check on write any more than on read, so an out-of-range "
         "index corrupts whatever follows the vector's buffer",
         {"work.cpp": ("#include <vector>\n#include \"work.hpp\"\n\n"
                       "int handle(int value) {\n"
                       "    std::vector<int> slots(16, 0);\n"
                       "    if (value < 0 || static_cast<std::size_t>(value) >= slots.size()) {\n"
                       "        return -1;\n    }\n"
                       "    slots[value] = 1;\n"
                       "    return slots[value];\n}\n")},
         "slots[value] = 1",
         "both ends of the range are checked against the container's own size before the write"),
    pair("cpp-nullderef@unchecked-allocation", "cpp", "cpp", NULL_DEREF,
         CPP_ENTRY_STR, "int main", "work.cpp",
         {"work.cpp": ("#include <cstdlib>\n#include <cstring>\n#include <string>\n#include \"work.hpp\"\n\n"
                       "std::size_t handle(const std::string &value) {\n"
                       "    char *copy = static_cast<char *>(std::malloc(value.size() + 1));\n"
                       "    std::strcpy(copy, value.c_str());\n"
                       "    std::size_t length = std::strlen(copy);\n"
                       "    std::free(copy);\n"
                       "    return length;\n}\n")},
         "std::strcpy(copy, value.c_str())",
         "malloc is used rather than new, so allocation failure returns null instead of throwing, "
         "and the very next statement writes through it without a test",
         {"work.cpp": ("#include <cstdlib>\n#include <cstring>\n#include <string>\n#include \"work.hpp\"\n\n"
                       "std::size_t handle(const std::string &value) {\n"
                       "    char *copy = static_cast<char *>(std::malloc(value.size() + 1));\n"
                       "    if (copy == nullptr) {\n        return 0;\n    }\n"
                       "    std::strcpy(copy, value.c_str());\n"
                       "    std::size_t length = std::strlen(copy);\n"
                       "    std::free(copy);\n"
                       "    return length;\n}\n")},
         "if (copy == nullptr)",
         "the result is tested before any use"),
    pair("cpp-path@unvalidated-concat", "cpp", "cpp", PATHT,
         CPP_ENTRY_STR, "int main", "work.cpp",
         {"work.cpp": ("#include <fstream>\n#include <string>\n#include \"work.hpp\"\n\n"
                       "std::size_t handle(const std::string &value) {\n"
                       "    std::string target = \"/srv/reports/\" + value;\n"
                       "    std::ifstream stream(target);\n"
                       "    return stream.good() ? target.size() : 0;\n}\n")},
         "std::ifstream stream(target)",
         "the value is pasted after the base directory, so dot-dot segments walk out of it",
         {"work.cpp": ("#include <filesystem>\n#include <fstream>\n#include <string>\n#include \"work.hpp\"\n\n"
                       "std::size_t handle(const std::string &value) {\n"
                       "    std::filesystem::path base = \"/srv/reports\";\n"
                       "    std::filesystem::path target = base / std::filesystem::path(value).filename();\n"
                       "    std::ifstream stream(target);\n"
                       "    return stream.good() ? target.string().size() : 0;\n}\n")},
         "std::ifstream stream(target)",
         "filename() discards every directory component, so only a leaf name reaches the join"),
]

TAIL_COMPILED = GO + CPP


# --- rust -------------------------------------------------------------------

RS_ENTRY = {"main.rs": ("mod work;\n\nfn main() {\n"
                        "    let value = std::env::args().nth(1).unwrap_or_default();\n"
                        "    println!(\"{}\", work::handle(&value));\n}\n")}

RUST = [
    pair("rs-sqli@format-string", "rust", "rs", SQLI,
         RS_ENTRY, "fn main", "work.rs",
         {"work.rs": ("pub fn handle(code: &str) -> String {\n"
                      "    let statement = format!(\"SELECT status FROM orders WHERE code = '{}'\", code);\n"
                      "    run(&statement)\n}\n\n"
                      "fn run(statement: &str) -> String {\n"
                      "    statement.to_string()\n}\n")},
         "let statement = format!(",
         "format! interpolates the argument into the statement text, which the driver then "
         "parses as code. Rust's type system has nothing to say about a string that is valid "
         "UTF-8 and invalid SQL",
         {"work.rs": ("pub fn handle(code: &str) -> String {\n"
                      "    let statement = \"SELECT status FROM orders WHERE code = $1\";\n"
                      "    run(statement, code)\n}\n\n"
                      "fn run(statement: &str, code: &str) -> String {\n"
                      "    format!(\"{}|{}\", statement, code)\n}\n")},
         "let statement = \"SELECT status FROM orders WHERE code = $1\"",
         "the statement carries a placeholder and the value travels beside it as a bound "
         "parameter"),
    pair("rs-ssrf@unvalidated-url", "rust", "rs", SSRF,
         RS_ENTRY, "fn main", "work.rs",
         {"work.rs": ("pub fn handle(target: &str) -> String {\n"
                      "    fetch(target)\n}\n\n"
                      "fn fetch(target: &str) -> String {\n"
                      "    format!(\"GET {}\", target)\n}\n")},
         "fn fetch(target: &str)",
         "the request value becomes the whole URL with no scheme or host restriction, so the "
         "process can be aimed at any address it can route to",
         {"work.rs": ("const PERMITTED: [&str; 1] = [\"api.example.com\"];\n\n"
                      "pub fn handle(target: &str) -> String {\n"
                      "    if !target.starts_with(\"https://\") {\n"
                      "        return String::new();\n    }\n"
                      "    let host = target.trim_start_matches(\"https://\").split('/').next().unwrap_or(\"\");\n"
                      "    if !PERMITTED.contains(&host) {\n"
                      "        return String::new();\n    }\n"
                      "    fetch(target)\n}\n\n"
                      "fn fetch(target: &str) -> String {\n"
                      "    format!(\"GET {}\", target)\n}\n")},
         "fn fetch(target: &str)",
         "the scheme and host are checked against a fixed list before the request is made"),
    pair("rs-creds@literal-in-source", "rust", "rs", CREDS,
         RS_ENTRY, "fn main", "work.rs",
         {"work.rs": ("const DB_PASSWORD: &str = \"Pr0d-Repor7ing-2024!\";\n\n"
                      "pub fn handle(user: &str) -> String {\n"
                      "    format!(\"{}:{}\", user, DB_PASSWORD)\n}\n")},
         "const DB_PASSWORD",
         "the password is a compiled-in constant and survives in the binary as well as the "
         "repository",
         {"work.rs": ("pub fn handle(user: &str) -> String {\n"
                      "    let password = std::env::var(\"DB_PASSWORD\").unwrap_or_default();\n"
                      "    format!(\"{}:{}\", user, password)\n}\n")},
         "std::env::var(\"DB_PASSWORD\")",
         "the value comes from the environment at runtime"),
    pair("rs-crypto@weak-hash", "rust", "rs", CRYPTO,
         RS_ENTRY, "fn main", "work.rs",
         {"work.rs": ("pub fn handle(value: &str) -> String {\n"
                      "    md5_hex(value)\n}\n\n"
                      "fn md5_hex(value: &str) -> String {\n"
                      "    format!(\"md5:{}\", value.len())\n}\n")},
         "fn md5_hex(value: &str)",
         "MD5 is used for a fingerprint. Practical collisions mean two different inputs can "
         "produce the same digest, so it no longer distinguishes them",
         {"work.rs": ("pub fn handle(value: &str) -> String {\n"
                      "    sha256_hex(value)\n}\n\n"
                      "fn sha256_hex(value: &str) -> String {\n"
                      "    format!(\"sha256:{}\", value.len())\n}\n")},
         "fn sha256_hex(value: &str)",
         "SHA-256 has no known collision attack"),
]

# --- typescript -------------------------------------------------------------

TS_ENTRY = {"route.ts": "import { render } from './work';\n\nexport function show(value: string): string {\n  return render(value);\n}\n"}

TYPESCRIPT = [
    pair("ts-path@unvalidated-join", "typescript", "ts", PATHT,
         TS_ENTRY, "export function show", "work.ts",
         {"work.ts": ("import * as fs from 'fs';\nimport * as path from 'path';\n\n"
                      "const BASE = '/srv/reports';\n\n"
                      "export function render(name: string): string {\n"
                      "  return fs.readFileSync(path.join(BASE, name), 'utf8');\n}\n")},
         "fs.readFileSync(path.join(BASE, name)",
         "path.join resolves dot-dot segments, so the read escapes the base directory",
         {"work.ts": ("import * as fs from 'fs';\nimport * as path from 'path';\n\n"
                      "const BASE = '/srv/reports';\n\n"
                      "export function render(name: string): string {\n"
                      "  const target = path.resolve(BASE, path.basename(name));\n"
                      "  if (!target.startsWith(BASE + path.sep)) {\n"
                      "    throw new Error('rejected');\n  }\n"
                      "  return fs.readFileSync(target, 'utf8');\n}\n")},
         "fs.readFileSync(target, 'utf8')",
         "basename strips the directory part and the resolved path is confirmed under the base"),
    pair("ts-markup@unescaped-output", "typescript", "ts", XSS,
         TS_ENTRY, "export function show", "work.ts",
         {"work.ts": ("export function render(name: string): string {\n"
                      "  return \"<div class='row'>\" + name + '</div>';\n}\n")},
         "return \"<div class='row'>\"",
         "the value is placed straight into markup, so a tag inside it is parsed as markup. "
         "TypeScript's types describe the shape of the string and say nothing about its context",
         {"work.ts": ("const REPLACEMENTS: Record<string, string> = {\n"
                      "  '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;',\n};\n\n"
                      "export function render(name: string): string {\n"
                      "  const encoded = String(name).replace(/[&<>\"']/g, (c) => REPLACEMENTS[c]);\n"
                      "  return \"<div class='row'>\" + encoded + '</div>';\n}\n")},
         "return \"<div class='row'>\"",
         "every character that could open a tag or close the attribute is encoded first"),
    pair("ts-ssrf@unvalidated-url", "typescript", "ts", SSRF,
         TS_ENTRY, "export function show", "work.ts",
         {"work.ts": ("export function render(target: string): string {\n"
                      "  return `GET ${target}`;\n}\n")},
         "return `GET ${target}`",
         "the value becomes the whole URL with no restriction on scheme or host",
         {"work.ts": ("const PERMITTED = new Set(['api.example.com']);\n\n"
                      "export function render(target: string): string {\n"
                      "  const parsed = new URL(target);\n"
                      "  if (parsed.protocol !== 'https:' || !PERMITTED.has(parsed.hostname)) {\n"
                      "    throw new Error('rejected');\n  }\n"
                      "  return `GET ${target}`;\n}\n")},
         "return `GET ${target}`",
         "the parsed scheme and host are checked against an allowlist before use"),
    pair("ts-creds@literal-in-source", "typescript", "ts", CREDS,
         TS_ENTRY, "export function show", "work.ts",
         {"work.ts": ("const DB_PASSWORD = 'Pr0d-Repor7ing-2024!';\n\n"
                      "export function render(user: string): string {\n"
                      "  return `${user}:${DB_PASSWORD}`;\n}\n")},
         "const DB_PASSWORD =",
         "the password is committed in source and ships in every bundle built from it",
         {"work.ts": ("export function render(user: string): string {\n"
                      "  return `${user}:${process.env.DB_PASSWORD ?? ''}`;\n}\n")},
         "process.env.DB_PASSWORD",
         "the value is read from the environment"),
    pair("ts-deser@prototype-pollution", "typescript", "ts", DESER,
         TS_ENTRY, "export function show", "work.ts",
         {"work.ts": ("export function render(blob: string): string {\n"
                      "  const target: Record<string, unknown> = {};\n"
                      "  const source = JSON.parse(blob);\n"
                      "  for (const key of Object.keys(source)) {\n"
                      "    (target as any)[key] = source[key];\n  }\n"
                      "  return String(Object.keys(target).length);\n}\n")},
         "(target as any)[key] = source[key]",
         "keys are copied from parsed input with no filtering, so __proto__ and constructor "
         "reach the assignment and change behaviour for objects the caller never touched. "
         "JSON.parse itself is safe; the merge that follows is not",
         {"work.ts": ("const REFUSED = new Set(['__proto__', 'constructor', 'prototype']);\n\n"
                      "export function render(blob: string): string {\n"
                      "  const target: Record<string, unknown> = Object.create(null);\n"
                      "  const source = JSON.parse(blob);\n"
                      "  for (const key of Object.keys(source)) {\n"
                      "    if (REFUSED.has(key)) {\n      continue;\n    }\n"
                      "    target[key] = source[key];\n  }\n"
                      "  return String(Object.keys(target).length);\n}\n")},
         "target[key] = source[key]",
         "the prototype keys are refused and the target has no prototype to pollute"),
]

TAIL_COMPILED = TAIL_COMPILED + RUST + TYPESCRIPT


# --- c# ---------------------------------------------------------------------

CS_ENTRY = {"Controller.cs": "namespace App;\n\npublic class Controller\n{\n    public object Show(string value) => Work.Render(value);\n}\n"}

CSHARP = [
    pair("cs-path@unvalidated-join", "csharp", "cs", PATHT,
         CS_ENTRY, "public object Show", "Work.cs",
         {"Work.cs": ("using System.IO;\n\nnamespace App;\n\n"
                      "public static class Work\n{\n"
                      "    private const string Base = \"/srv/reports\";\n\n"
                      "    public static object Render(string name)\n    {\n"
                      "        return File.ReadAllText(Path.Combine(Base, name));\n    }\n}\n")},
         "File.ReadAllText(Path.Combine(Base, name))",
         "Path.Combine discards the base entirely when the second argument is rooted, so an "
         "absolute path reads anywhere the process can reach, and dot-dot walks out otherwise",
         {"Work.cs": ("using System.IO;\n\nnamespace App;\n\n"
                      "public static class Work\n{\n"
                      "    private const string Base = \"/srv/reports\";\n\n"
                      "    public static object Render(string name)\n    {\n"
                      "        var target = Path.GetFullPath(Path.Combine(Base, Path.GetFileName(name)));\n"
                      "        if (!target.StartsWith(Base + Path.DirectorySeparatorChar))\n        {\n"
                      "            throw new IOException(name);\n        }\n"
                      "        return File.ReadAllText(target);\n    }\n}\n")},
         "return File.ReadAllText(target)",
         "GetFileName strips the directory part and the resolved path is checked to stay under "
         "the base"),
    pair("cs-deser@binaryformatter", "csharp", "cs", DESER,
         CS_ENTRY, "public object Show", "Work.cs",
         {"Work.cs": ("using System;\nusing System.IO;\n"
                      "using System.Runtime.Serialization.Formatters.Binary;\n\nnamespace App;\n\n"
                      "public static class Work\n{\n"
                      "    public static object Render(string blob)\n    {\n"
                      "        var raw = Convert.FromBase64String(blob);\n"
                      "        var formatter = new BinaryFormatter();\n"
                      "        return formatter.Deserialize(new MemoryStream(raw));\n    }\n}\n")},
         "formatter.Deserialize(new MemoryStream(raw))",
         "BinaryFormatter reconstructs whatever types the payload names and runs their "
         "deserialisation callbacks. Microsoft marks it obsolete and dangerous precisely because "
         "no configuration makes it safe on untrusted input",
         {"Work.cs": ("using System.Text.Json;\n\nnamespace App;\n\n"
                      "public sealed record Settings(string Name);\n\n"
                      "public static class Work\n{\n"
                      "    public static object Render(string blob)\n    {\n"
                      "        return JsonSerializer.Deserialize<Settings>(blob) ?? new Settings(string.Empty);\n"
                      "    }\n}\n")},
         "JsonSerializer.Deserialize<Settings>(blob)",
         "the payload can only populate a declared record with one string field, so no type in "
         "the process is reachable from it"),
    pair("cs-xxe@default-resolver", "csharp", "cs", XXE,
         CS_ENTRY, "public object Show", "Work.cs",
         {"Work.cs": ("using System.IO;\nusing System.Xml;\n\nnamespace App;\n\n"
                      "public static class Work\n{\n"
                      "    public static object Render(string document)\n    {\n"
                      "        var settings = new XmlReaderSettings();\n"
                      "        settings.DtdProcessing = DtdProcessing.Parse;\n"
                      "        settings.XmlResolver = new XmlUrlResolver();\n"
                      "        using var reader = XmlReader.Create(new StringReader(document), settings);\n"
                      "        while (reader.Read()) { }\n"
                      "        return true;\n    }\n}\n")},
         "XmlReader.Create(new StringReader(document), settings)",
         "DTD processing is enabled and a resolver that fetches external references is attached, "
         "so a declared entity reads local files or reaches the network",
         {"Work.cs": ("using System.IO;\nusing System.Xml;\n\nnamespace App;\n\n"
                      "public static class Work\n{\n"
                      "    public static object Render(string document)\n    {\n"
                      "        var settings = new XmlReaderSettings();\n"
                      "        settings.DtdProcessing = DtdProcessing.Prohibit;\n"
                      "        settings.XmlResolver = null;\n"
                      "        using var reader = XmlReader.Create(new StringReader(document), settings);\n"
                      "        while (reader.Read()) { }\n"
                      "        return true;\n    }\n}\n")},
         "XmlReader.Create(new StringReader(document), settings)",
         "the DOCTYPE is prohibited and no resolver is attached"),
    pair("cs-crypto@weak-hash", "csharp", "cs", CRYPTO,
         CS_ENTRY, "public object Show", "Work.cs",
         {"Work.cs": ("using System.Security.Cryptography;\nusing System.Text;\n\nnamespace App;\n\n"
                      "public static class Work\n{\n"
                      "    public static object Render(string value)\n    {\n"
                      "        using var algorithm = MD5.Create();\n"
                      "        return algorithm.ComputeHash(Encoding.UTF8.GetBytes(value));\n    }\n}\n")},
         "MD5.Create()",
         "MD5 has practical collisions, so a digest built on it no longer distinguishes inputs",
         {"Work.cs": ("using System.Security.Cryptography;\nusing System.Text;\n\nnamespace App;\n\n"
                      "public static class Work\n{\n"
                      "    public static object Render(string value)\n    {\n"
                      "        using var algorithm = SHA256.Create();\n"
                      "        return algorithm.ComputeHash(Encoding.UTF8.GetBytes(value));\n    }\n}\n")},
         "SHA256.Create()",
         "SHA-256 has no known collision attack"),
    pair("cs-creds@literal-in-source", "csharp", "cs", CREDS,
         CS_ENTRY, "public object Show", "Work.cs",
         {"Work.cs": ("namespace App;\n\npublic static class Work\n{\n"
                      "    private const string DbPassword = \"Pr0d-Repor7ing-2024!\";\n\n"
                      "    public static object Render(string user) => user + \":\" + DbPassword;\n}\n")},
         "private const string DbPassword",
         "a const string is embedded in the assembly and recoverable from it, not only from the "
         "repository",
         {"Work.cs": ("using System;\n\nnamespace App;\n\npublic static class Work\n{\n"
                      "    public static object Render(string user) =>\n"
                      "        user + \":\" + Environment.GetEnvironmentVariable(\"DB_PASSWORD\");\n}\n")},
         "Environment.GetEnvironmentVariable(\"DB_PASSWORD\")",
         "the value is read from the environment at runtime"),
]

# --- kotlin -----------------------------------------------------------------

KT_ENTRY = {"Cli.kt": "package app\n\nfun main(args: Array<String>) {\n    println(render(args[0]))\n}\n"}

KOTLIN = [
    pair("kt-path@unvalidated-join", "kotlin", "kt", PATHT,
         KT_ENTRY, "fun main", "Work.kt",
         {"Work.kt": ("package app\n\nimport java.io.File\n\n"
                      "private const val BASE = \"/srv/reports\"\n\n"
                      "fun render(name: String): String {\n"
                      "    return File(BASE, name).readText()\n}\n")},
         "File(BASE, name).readText()",
         "the two-argument File constructor honours dot-dot segments and is replaced entirely by "
         "an absolute second argument",
         {"Work.kt": ("package app\n\nimport java.io.File\n\n"
                      "private const val BASE = \"/srv/reports\"\n\n"
                      "fun render(name: String): String {\n"
                      "    val target = File(BASE, File(name).name).canonicalFile\n"
                      "    if (!target.path.startsWith(\"$BASE/\")) {\n"
                      "        throw IllegalArgumentException(name)\n    }\n"
                      "    return target.readText()\n}\n")},
         "return target.readText()",
         "only the leaf name is used and the canonical path is checked to remain under the base"),
    pair("kt-crypto@weak-hash", "kotlin", "kt", CRYPTO,
         KT_ENTRY, "fun main", "Work.kt",
         {"Work.kt": ("package app\n\nimport java.security.MessageDigest\n\n"
                      "fun render(value: String): String {\n"
                      "    val digest = MessageDigest.getInstance(\"MD5\")\n"
                      "    return digest.digest(value.toByteArray()).joinToString(\"\") { \"%02x\".format(it) }\n}\n")},
         "MessageDigest.getInstance(\"MD5\")",
         "MD5 has practical collisions and no longer distinguishes two inputs",
         {"Work.kt": ("package app\n\nimport java.security.MessageDigest\n\n"
                      "fun render(value: String): String {\n"
                      "    val digest = MessageDigest.getInstance(\"SHA-256\")\n"
                      "    return digest.digest(value.toByteArray()).joinToString(\"\") { \"%02x\".format(it) }\n}\n")},
         "MessageDigest.getInstance(\"SHA-256\")",
         "SHA-256 has no known collision attack"),
    pair("kt-creds@literal-in-source", "kotlin", "kt", CREDS,
         KT_ENTRY, "fun main", "Work.kt",
         {"Work.kt": ("package app\n\n"
                      "private const val DB_PASSWORD = \"Pr0d-Repor7ing-2024!\"\n\n"
                      "fun render(user: String): String = \"$user:$DB_PASSWORD\"\n")},
         "private const val DB_PASSWORD",
         "a const val is inlined into the bytecode and recoverable from the artifact",
         {"Work.kt": ("package app\n\n"
                      "fun render(user: String): String = \"$user:\" + (System.getenv(\"DB_PASSWORD\") ?: \"\")\n")},
         "System.getenv(\"DB_PASSWORD\")",
         "the value comes from the environment"),
    pair("kt-ssrf@unvalidated-url", "kotlin", "kt", SSRF,
         KT_ENTRY, "fun main", "Work.kt",
         {"Work.kt": ("package app\n\nimport java.net.URL\n\n"
                      "fun render(target: String): String {\n"
                      "    return URL(target).readText()\n}\n")},
         "URL(target).readText()",
         "the value becomes the whole URL, so the process fetches whatever address it names",
         {"Work.kt": ("package app\n\nimport java.net.URL\n\n"
                      "private val PERMITTED = setOf(\"api.example.com\")\n\n"
                      "fun render(target: String): String {\n"
                      "    val parsed = URL(target)\n"
                      "    if (parsed.protocol != \"https\" || parsed.host !in PERMITTED) {\n"
                      "        throw IllegalArgumentException(target)\n    }\n"
                      "    return parsed.readText()\n}\n")},
         "return parsed.readText()",
         "the scheme and host are checked against an allowlist first"),
    pair("kt-deser@objectinputstream", "kotlin", "kt", DESER,
         KT_ENTRY, "fun main", "Work.kt",
         {"Work.kt": ("package app\n\n"
                      "import java.io.ByteArrayInputStream\nimport java.io.ObjectInputStream\n"
                      "import java.util.Base64\n\n"
                      "fun render(blob: String): String {\n"
                      "    val raw = Base64.getDecoder().decode(blob)\n"
                      "    val stream = ObjectInputStream(ByteArrayInputStream(raw))\n"
                      "    return stream.readObject().toString()\n}\n")},
         "stream.readObject()",
         "readObject reconstructs whatever classes the stream names and runs their hooks while "
         "doing it, regardless of the declared return type",
         {"Work.kt": ("package app\n\nimport java.util.Base64\n\n"
                      "fun render(blob: String): String {\n"
                      "    val raw = Base64.getDecoder().decode(blob)\n"
                      "    return String(raw).trim()\n}\n")},
         "String(raw).trim()",
         "the bytes are treated as text and no object graph is reconstructed"),
]

TAIL_COMPILED = TAIL_COMPILED + CSHARP + KOTLIN


# --- php --------------------------------------------------------------------

PHP_ENTRY = {"handler.php": "<?php\n\nrequire_once __DIR__ . '/work.php';\n\nfunction show($value) {\n    return render($value);\n}\n"}

PHP = [
    pair("php-path@unvalidated-concat", "php", "php", PATHT,
         PHP_ENTRY, "function show", "work.php",
         {"work.php": ("<?php\n\n"
                       "function render($name) {\n"
                       "    return file_get_contents('/srv/reports/' . $name);\n}\n")},
         "file_get_contents('/srv/reports/'",
         "the value is pasted after the base directory, so dot-dot walks out of it and a wrapper "
         "prefix such as php:// or data:// changes the stream entirely",
         {"work.php": ("<?php\n\n"
                       "function render($name) {\n"
                       "    $target = realpath('/srv/reports/' . basename($name));\n"
                       "    if ($target === false || strpos($target, '/srv/reports/') !== 0) {\n"
                       "        throw new InvalidArgumentException($name);\n    }\n"
                       "    return file_get_contents($target);\n}\n")},
         "return file_get_contents($target)",
         "basename discards the directory part and the resolved path is checked to stay under "
         "the base"),
    pair("php-markup@unescaped-output", "php", "php", XSS,
         PHP_ENTRY, "function show", "work.php",
         {"work.php": ("<?php\n\n"
                       "function render($name) {\n"
                       "    return \"<div class='row'>\" . $name . \"</div>\";\n}\n")},
         "return \"<div class='row'>\"",
         "the value goes straight into markup with no encoding, so a tag inside it is parsed as "
         "markup by the browser",
         {"work.php": ("<?php\n\n"
                       "function render($name) {\n"
                       "    $encoded = htmlspecialchars($name, ENT_QUOTES | ENT_HTML5, 'UTF-8');\n"
                       "    return \"<div class='row'>\" . $encoded . \"</div>\";\n}\n")},
         "return \"<div class='row'>\"",
         "htmlspecialchars with ENT_QUOTES encodes both quote styles as well as the angle "
         "brackets, which the single-quoted attribute here requires"),
    pair("php-deser@unserialize-untrusted", "php", "php", DESER,
         PHP_ENTRY, "function show", "work.php",
         {"work.php": ("<?php\n\n"
                       "function render($blob) {\n"
                       "    return unserialize($blob);\n}\n")},
         "unserialize($blob)",
         "unserialize instantiates whatever classes the payload names and triggers their magic "
         "methods, so a gadget chain present anywhere in the loaded code becomes reachable "
         "without any of it being called explicitly",
         {"work.php": ("<?php\n\n"
                       "function render($blob) {\n"
                       "    return json_decode($blob, true);\n}\n")},
         "json_decode($blob, true)",
         "json_decode with the associative flag produces arrays and scalars only, and "
         "instantiates nothing"),
    pair("php-crypto@weak-hash", "php", "php", CRYPTO,
         PHP_ENTRY, "function show", "work.php",
         {"work.php": ("<?php\n\n"
                       "function render($value) {\n"
                       "    return md5($value);\n}\n")},
         "return md5($value)",
         "MD5 has practical collisions, so the digest no longer distinguishes two inputs",
         {"work.php": ("<?php\n\n"
                       "function render($value) {\n"
                       "    return hash('sha256', $value);\n}\n")},
         "hash('sha256', $value)",
         "SHA-256 has no known collision attack"),
    pair("php-creds@literal-in-source", "php", "php", CREDS,
         PHP_ENTRY, "function show", "work.php",
         {"work.php": ("<?php\n\n"
                       "define('DB_PASSWORD', 'Pr0d-Repor7ing-2024!');\n\n"
                       "function render($user) {\n"
                       "    return $user . ':' . DB_PASSWORD;\n}\n")},
         "define('DB_PASSWORD'",
         "the password is committed in source and served by any misconfiguration that exposes "
         "the file rather than executing it",
         {"work.php": ("<?php\n\n"
                       "function render($user) {\n"
                       "    return $user . ':' . getenv('DB_PASSWORD');\n}\n")},
         "getenv('DB_PASSWORD')",
         "the value is read from the environment"),
]

# --- ruby -------------------------------------------------------------------

RB_ENTRY = {"handler.rb": "require_relative 'work'\n\ndef show(value)\n  render(value)\nend\n"}

RUBY = [
    pair("rb-path@unvalidated-join", "ruby", "rb", PATHT,
         RB_ENTRY, "def show", "work.rb",
         {"work.rb": ("BASE = '/srv/reports'.freeze\n\n"
                      "def render(name)\n"
                      "  File.read(File.join(BASE, name))\nend\n")},
         "File.read(File.join(BASE, name))",
         "File.join honours dot-dot segments, so the read escapes the base directory",
         {"work.rb": ("BASE = '/srv/reports'.freeze\n\n"
                      "def render(name)\n"
                      "  target = File.expand_path(File.join(BASE, File.basename(name)))\n"
                      "  raise ArgumentError, name unless target.start_with?(BASE + '/')\n\n"
                      "  File.read(target)\nend\n")},
         "File.read(target)",
         "basename removes the directory part and the expanded path is checked to remain under "
         "the base"),
    pair("rb-deser@marshal-untrusted", "ruby", "rb", DESER,
         RB_ENTRY, "def show", "work.rb",
         {"work.rb": ("def render(blob)\n"
                      "  Marshal.load(blob)\nend\n")},
         "Marshal.load(blob)",
         "Marshal.load reconstructs arbitrary objects and invokes their initialisation hooks, so "
         "a gadget available in the loaded gems becomes reachable from the payload",
         {"work.rb": ("require 'json'\n\n"
                      "def render(blob)\n"
                      "  JSON.parse(blob)\nend\n")},
         "JSON.parse(blob)",
         "JSON.parse produces hashes, arrays and scalars, and instantiates nothing"),
    pair("rb-markup@unescaped-output", "ruby", "rb", XSS,
         RB_ENTRY, "def show", "work.rb",
         {"work.rb": ("def render(name)\n"
                      "  \"<div class='row'>\" + name + '</div>'\nend\n")},
         "\"<div class='row'>\" + name",
         "the value is concatenated into markup without encoding, so a tag inside it is parsed "
         "as markup",
         {"work.rb": ("require 'cgi'\n\n"
                      "def render(name)\n"
                      "  \"<div class='row'>\" + CGI.escapeHTML(name) + '</div>'\nend\n")},
         "CGI.escapeHTML(name)",
         "escapeHTML encodes the angle brackets and both quote styles before insertion"),
    pair("rb-crypto@weak-hash", "ruby", "rb", CRYPTO,
         RB_ENTRY, "def show", "work.rb",
         {"work.rb": ("require 'digest'\n\n"
                      "def render(value)\n"
                      "  Digest::MD5.hexdigest(value)\nend\n")},
         "Digest::MD5.hexdigest(value)",
         "MD5 has practical collisions and no longer distinguishes two inputs",
         {"work.rb": ("require 'digest'\n\n"
                      "def render(value)\n"
                      "  Digest::SHA256.hexdigest(value)\nend\n")},
         "Digest::SHA256.hexdigest(value)",
         "SHA-256 has no known collision attack"),
    pair("rb-creds@literal-in-source", "ruby", "rb", CREDS,
         RB_ENTRY, "def show", "work.rb",
         {"work.rb": ("DB_PASSWORD = 'Pr0d-Repor7ing-2024!'.freeze\n\n"
                      "def render(user)\n"
                      "  \"#{user}:#{DB_PASSWORD}\"\nend\n")},
         "DB_PASSWORD = ",
         "the password is committed in source and lives in every clone and every history",
         {"work.rb": ("def render(user)\n"
                      "  \"#{user}:#{ENV.fetch('DB_PASSWORD', '')}\"\nend\n")},
         "ENV.fetch('DB_PASSWORD'",
         "the value is read from the environment"),
]

# --- swift ------------------------------------------------------------------

SW_ENTRY = {"main.swift": ("import Foundation\n\n"
                           "let value = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : \"\"\n"
                           "print(render(value))\n")}

SWIFT = [
    pair("sw-sqli@concat-statement", "swift", "swift", SQLI,
         SW_ENTRY, "print(render(value))", "Work.swift",
         {"Work.swift": ("import Foundation\n\n"
                         "func render(_ code: String) -> String {\n"
                         "    let statement = \"SELECT status FROM orders WHERE code = '\" + code + \"'\"\n"
                         "    return execute(statement)\n}\n\n"
                         "func execute(_ statement: String) -> String {\n"
                         "    return statement\n}\n")},
         "let statement = \"SELECT status FROM orders WHERE code = '\"",
         "the value is concatenated into the statement text, which the driver parses as code",
         {"Work.swift": ("import Foundation\n\n"
                         "func render(_ code: String) -> String {\n"
                         "    let statement = \"SELECT status FROM orders WHERE code = ?\"\n"
                         "    return execute(statement, code)\n}\n\n"
                         "func execute(_ statement: String, _ value: String) -> String {\n"
                         "    return statement + \"|\" + value\n}\n")},
         "let statement = \"SELECT status FROM orders WHERE code = ?\"",
         "the statement carries a placeholder and the value is bound beside it"),
    pair("sw-path@unvalidated-join", "swift", "swift", PATHT,
         SW_ENTRY, "print(render(value))", "Work.swift",
         {"Work.swift": ("import Foundation\n\n"
                         "let base = \"/srv/reports\"\n\n"
                         "func render(_ name: String) -> String {\n"
                         "    let target = base + \"/\" + name\n"
                         "    return (try? String(contentsOfFile: target, encoding: .utf8)) ?? \"\"\n}\n")},
         "String(contentsOfFile: target",
         "the value is pasted after the base directory, so dot-dot segments walk out of it",
         {"Work.swift": ("import Foundation\n\n"
                         "let base = \"/srv/reports\"\n\n"
                         "func render(_ name: String) -> String {\n"
                         "    let leaf = (name as NSString).lastPathComponent\n"
                         "    let target = (base as NSString).appendingPathComponent(leaf)\n"
                         "    guard target.hasPrefix(base + \"/\") else { return \"\" }\n"
                         "    return (try? String(contentsOfFile: target, encoding: .utf8)) ?? \"\"\n}\n")},
         "String(contentsOfFile: target",
         "lastPathComponent discards every directory component and the result is confirmed under "
         "the base"),
    pair("sw-creds@literal-in-source", "swift", "swift", CREDS,
         SW_ENTRY, "print(render(value))", "Work.swift",
         {"Work.swift": ("import Foundation\n\n"
                         "let dbPassword = \"Pr0d-Repor7ing-2024!\"\n\n"
                         "func render(_ user: String) -> String {\n"
                         "    return user + \":\" + dbPassword\n}\n")},
         "let dbPassword = ",
         "the password is embedded in the binary as well as the repository, and strings on the "
         "shipped app recovers it",
         {"Work.swift": ("import Foundation\n\n"
                         "func render(_ user: String) -> String {\n"
                         "    let password = ProcessInfo.processInfo.environment[\"DB_PASSWORD\"] ?? \"\"\n"
                         "    return user + \":\" + password\n}\n")},
         "ProcessInfo.processInfo.environment[\"DB_PASSWORD\"]",
         "the value is read from the environment at runtime"),
    pair("sw-crypto@weak-hash", "swift", "swift", CRYPTO,
         SW_ENTRY, "print(render(value))", "Work.swift",
         {"Work.swift": ("import CryptoKit\nimport Foundation\n\n"
                         "func render(_ value: String) -> String {\n"
                         "    let digest = Insecure.MD5.hash(data: Data(value.utf8))\n"
                         "    return digest.map { String(format: \"%02x\", $0) }.joined()\n}\n")},
         "Insecure.MD5.hash(data:",
         "CryptoKit places MD5 under an enum literally named Insecure, and the code reaches into "
         "it anyway. Practical collisions mean the digest no longer distinguishes two inputs",
         {"Work.swift": ("import CryptoKit\nimport Foundation\n\n"
                         "func render(_ value: String) -> String {\n"
                         "    let digest = SHA256.hash(data: Data(value.utf8))\n"
                         "    return digest.map { String(format: \"%02x\", $0) }.joined()\n}\n")},
         "SHA256.hash(data:",
         "SHA-256 has no known collision attack"),
    pair("sw-ssrf@unvalidated-url", "swift", "swift", SSRF,
         SW_ENTRY, "print(render(value))", "Work.swift",
         {"Work.swift": ("import Foundation\n\n"
                         "func render(_ target: String) -> String {\n"
                         "    guard let url = URL(string: target) else { return \"\" }\n"
                         "    return (try? String(contentsOf: url, encoding: .utf8)) ?? \"\"\n}\n")},
         "String(contentsOf: url",
         "the value becomes the whole URL, so the process fetches whatever address it names, "
         "including loopback and link-local metadata endpoints",
         {"Work.swift": ("import Foundation\n\n"
                         "let permitted: Set<String> = [\"api.example.com\"]\n\n"
                         "func render(_ target: String) -> String {\n"
                         "    guard let url = URL(string: target), url.scheme == \"https\",\n"
                         "          let host = url.host, permitted.contains(host) else { return \"\" }\n"
                         "    return (try? String(contentsOf: url, encoding: .utf8)) ?? \"\"\n}\n")},
         "String(contentsOf: url",
         "the scheme and host are checked against an allowlist before the fetch"),
]

TAIL_COMPILED = TAIL_COMPILED + PHP + RUBY + SWIFT
