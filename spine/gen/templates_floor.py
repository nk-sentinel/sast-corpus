"""Raising the per-language floor from six weaknesses to ten.

Chosen against `spine/report/applicability.json` rather than by what was easy to
write, so every new cell is one the map already says can exist. Nothing here
claims XXE in Rust or a buffer overflow in Ruby.

The weaknesses that fill the gap are the ones that were only ever tested in the
deepest languages: logging, sensitive-data exposure, missing authorisation,
integer overflow and code injection. That they are cheap to write is not the
reason they are here — it is that a Swift or Kotlin scorecard row resting on six
weaknesses says less than one resting on ten, and these are the ten the map
permits.
"""

from gen.templates_tail import pair

LOG = ("CWE-117", ["CWE-117", "CWE-93", "CWE-116"], "A09")
EXPOSE = ("CWE-200", ["CWE-200", "CWE-209", "CWE-532"], "A01")
AUTHZ = ("CWE-862", ["CWE-862", "CWE-285", "CWE-863"], "A01")
OVERFLOW = ("CWE-190", ["CWE-190", "CWE-680", "CWE-191"], "A03")
CODEI = ("CWE-94", ["CWE-94", "CWE-95", "CWE-96"], "A03")
VALID = ("CWE-20", ["CWE-20", "CWE-1284"], "A03")


def _log(slug, language, extension, entry, entry_name, sink_file,
         vuln_files, vuln_sink, safe_files, safe_sink, writer):
    return pair(slug, language, extension, LOG, entry, entry_name, sink_file,
                vuln_files, vuln_sink,
                "a newline inside the value starts a second line in the log, so the "
                "caller writes entries the application never emitted. Anything reading "
                "those records afterwards — an analyst, an alerting rule, a correlation "
                "engine — treats attacker-authored lines as system output",
                safe_files, safe_sink,
                "line breaks are removed before the value is written, so one call can "
                "only ever produce one record")


TEMPLATES = [
    # --- swift: 6 -> 10 -------------------------------------------------------
    pair("sw-log@unsanitised-entry", "swift", "swift", LOG,
         {"main.swift": ("import Foundation\n\n"
                         "let value = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : \"\"\n"
                         "print(render(value))\n")},
         "print(render(value))", "Work.swift",
         {"Work.swift": ("import Foundation\n\n"
                         "func render(_ user: String) -> String {\n"
                         "    return \"level=info action=login user=\" + user\n}\n")},
         "return \"level=info action=login user=\"",
         "a newline inside the value starts a second log line, so the caller writes "
         "records the application never emitted",
         {"Work.swift": ("import Foundation\n\n"
                         "func render(_ user: String) -> String {\n"
                         "    let flat = user.replacingOccurrences(of: \"\\n\", with: \"\")\n"
                         "        .replacingOccurrences(of: \"\\r\", with: \"\")\n"
                         "    return \"level=info action=login user=\" + flat\n}\n")},
         "return \"level=info action=login user=\"",
         "both line-break characters are removed before the value is written"),

    pair("sw-expose@error-detail-returned", "swift", "swift", EXPOSE,
         {"main.swift": ("import Foundation\n\n"
                         "let value = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : \"\"\n"
                         "print(render(value))\n")},
         "print(render(value))", "Work.swift",
         {"Work.swift": ("import Foundation\n\n"
                         "enum StoreError: Error { case failed(String) }\n\n"
                         "func render(_ key: String) -> String {\n"
                         "    do {\n        return try load(key)\n"
                         "    } catch {\n        return \"lookup failed: \\(error)\"\n    }\n}\n\n"
                         "func load(_ key: String) throws -> String {\n"
                         "    throw StoreError.failed(\"connect to db.internal:5432 as reporting failed\")\n}\n")},
         "return \"lookup failed: \\(error)\"",
         "the internal error is returned to the caller verbatim, handing over hostnames, "
         "ports and account names that the caller had no way to learn otherwise",
         {"Work.swift": ("import Foundation\n\n"
                         "enum StoreError: Error { case failed(String) }\n\n"
                         "func render(_ key: String) -> String {\n"
                         "    do {\n        return try load(key)\n"
                         "    } catch {\n        return \"lookup failed\"\n    }\n}\n\n"
                         "func load(_ key: String) throws -> String {\n"
                         "    throw StoreError.failed(\"connect to db.internal:5432 as reporting failed\")\n}\n")},
         "return \"lookup failed\"",
         "the caller is told the operation failed and nothing about why"),

    pair("sw-authz@no-ownership-check", "swift", "swift", AUTHZ,
         {"main.swift": ("import Foundation\n\n"
                         "let value = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : \"\"\n"
                         "print(render(value))\n")},
         "print(render(value))", "Work.swift",
         {"Work.swift": ("import Foundation\n\n"
                         "let currentUser = \"alice\"\n\n"
                         "func render(_ orderID: String) -> String {\n"
                         "    return fetch(orderID)\n}\n\n"
                         "func fetch(_ orderID: String) -> String {\n"
                         "    return \"order \\(orderID) contents\"\n}\n")},
         "return fetch(orderID)",
         "the identifier is taken from the caller and used to fetch a record with no "
         "check that the caller owns it, so incrementing it walks the whole table",
         {"Work.swift": ("import Foundation\n\n"
                         "let currentUser = \"alice\"\nlet owners = [\"A-1001\": \"alice\", \"A-1002\": \"bob\"]\n\n"
                         "func render(_ orderID: String) -> String {\n"
                         "    guard owners[orderID] == currentUser else { return \"\" }\n"
                         "    return fetch(orderID)\n}\n\n"
                         "func fetch(_ orderID: String) -> String {\n"
                         "    return \"order \\(orderID) contents\"\n}\n")},
         "return fetch(orderID)",
         "ownership is confirmed against the acting user before the record is read"),

    pair("sw-overflow@unchecked-arithmetic", "swift", "swift", OVERFLOW,
         {"main.swift": ("import Foundation\n\n"
                         "let value = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : \"0\"\n"
                         "print(render(value))\n")},
         "print(render(value))", "Work.swift",
         {"Work.swift": ("import Foundation\n\n"
                         "func render(_ raw: String) -> String {\n"
                         "    let count = Int32(raw) ?? 0\n"
                         "    let total = count &* 4096\n"
                         "    return \"allocating \\(total)\"\n}\n")},
         "let total = count &* 4096",
         "the masking multiply wraps silently instead of trapping, so a large count "
         "produces a small or negative total and the allocation that follows is sized "
         "from a number that bears no relation to the request",
         {"Work.swift": ("import Foundation\n\n"
                         "func render(_ raw: String) -> String {\n"
                         "    let count = Int32(raw) ?? 0\n"
                         "    let (total, overflowed) = count.multipliedReportingOverflow(by: 4096)\n"
                         "    if overflowed || total < 0 { return \"rejected\" }\n"
                         "    return \"allocating \\(total)\"\n}\n")},
         "count.multipliedReportingOverflow(by: 4096)",
         "the multiply reports whether it wrapped and the result is rejected when it did"),

    # --- javascript / typescript: 7 -> 10 -------------------------------------
    pair("js-codeinj@dynamic-evaluation", "javascript", "js", CODEI,
         {"cli.js": "const { render } = require('./work');\n\nconsole.log(render(process.argv[2] || ''));\n"},
         "console.log(render(", "work.js",
         {"work.js": ("function render(expression) {\n"
                      "  return eval('(' + expression + ')');\n}\n\n"
                      "module.exports = { render };\n")},
         "return eval('(' + expression + ')')",
         "the value is evaluated as source, so it runs with the full authority of the "
         "process rather than being read as data",
         {"work.js": ("function render(expression) {\n"
                      "  try {\n    return JSON.parse(expression);\n"
                      "  } catch (e) {\n    return null;\n  }\n}\n\n"
                      "module.exports = { render };\n")},
         "return JSON.parse(expression)",
         "the value is parsed as data, which produces objects and scalars and executes "
         "nothing"),

    pair("js-log@unsanitised-entry", "javascript", "js", LOG,
         {"cli.js": "const { render } = require('./work');\n\nconsole.log(render(process.argv[2] || ''));\n"},
         "console.log(render(", "work.js",
         {"work.js": ("function render(user) {\n"
                      "  return 'level=info action=login user=' + user;\n}\n\n"
                      "module.exports = { render };\n")},
         "return 'level=info action=login user=' + user",
         "a newline inside the value starts a second log line, so the caller writes "
         "records the application never emitted",
         {"work.js": ("function render(user) {\n"
                      "  const flat = String(user).replace(/[\\r\\n]/g, '');\n"
                      "  return 'level=info action=login user=' + flat;\n}\n\n"
                      "module.exports = { render };\n")},
         "return 'level=info action=login user=' + flat",
         "both line-break characters are removed before the value is written"),

    pair("js-expose@stack-returned", "javascript", "js", EXPOSE,
         {"cli.js": "const { render } = require('./work');\n\nconsole.log(render(process.argv[2] || ''));\n"},
         "console.log(render(", "work.js",
         {"work.js": ("function render(key) {\n"
                      "  try {\n    return load(key);\n"
                      "  } catch (e) {\n    return 'lookup failed: ' + e.stack;\n  }\n}\n\n"
                      "function load(key) {\n"
                      "  throw new Error('connect to db.internal:5432 as reporting failed');\n}\n\n"
                      "module.exports = { render };\n")},
         "return 'lookup failed: ' + e.stack",
         "the stack trace is returned to the caller, handing over file paths, internal "
         "hostnames and the shape of the code that produced the failure",
         {"work.js": ("function render(key) {\n"
                      "  try {\n    return load(key);\n"
                      "  } catch (e) {\n    return 'lookup failed';\n  }\n}\n\n"
                      "function load(key) {\n"
                      "  throw new Error('connect to db.internal:5432 as reporting failed');\n}\n\n"
                      "module.exports = { render };\n")},
         "return 'lookup failed'",
         "the caller is told the operation failed and nothing about why"),
]

FLOOR_ALL = TEMPLATES


# --- typescript, kotlin, csharp, php, ruby, rust, cpp -------------------------

TS_ENTRY = {"cli.ts": ("import { render } from './work';\n\n"
                       "console.log(render(process.argv[2] ?? ''));\n")}
KT_ENTRY = {"Cli.kt": ("fun main(args: Array<String>) {\n"
                       "    println(render(if (args.isNotEmpty()) args[0] else \"\"))\n}\n")}
CS_ENTRY = {"Cli.cs": ("using System;\n\npublic static class Cli\n{\n"
                       "    public static void Main(string[] args)\n    {\n"
                       "        Console.WriteLine(Work.Render(args.Length > 0 ? args[0] : \"\"));\n"
                       "    }\n}\n")}
PHP_ENTRY = {"handler.php": "<?php\n\nrequire_once __DIR__ . '/work.php';\n\nfunction show($value) {\n    return render($value);\n}\n"}
RB_ENTRY = {"handler.rb": "require_relative 'work'\n\ndef show(value)\n  render(value)\nend\n"}
RS_ENTRY = {"src/main.rs": ("mod work;\n\nfn main() {\n"
                            "    let value = std::env::args().nth(1).unwrap_or_default();\n"
                            "    println!(\"{}\", work::render(&value));\n}\n")}
CPP_ENTRY = {"main.cpp": ("#include <iostream>\n#include <string>\n\n"
                          "std::string render(const std::string& value);\n\n"
                          "int main(int argc, char** argv) {\n"
                          "    std::cout << render(argc > 1 ? argv[1] : \"\") << std::endl;\n"
                          "    return 0;\n}\n")}

LOG_WHY_V = ("a newline inside the value starts a second line in the log, so the caller "
             "writes records the application never emitted and anything reading them "
             "afterwards treats attacker-authored lines as system output")
LOG_WHY_S = "both line-break characters are removed before the value is written"
EXPOSE_WHY_V = ("the internal failure detail is handed back to the caller, giving away "
                "hostnames, ports and account names they had no other way to learn")
EXPOSE_WHY_S = "the caller is told the operation failed and nothing about why"
AUTHZ_WHY_V = ("the identifier comes from the caller and the record is fetched with no "
               "check that they own it, so changing the number walks the whole table")
AUTHZ_WHY_S = "ownership is confirmed against the acting user before the record is read"

TEMPLATES += [
    pair("ts-log@unsanitised-entry", "typescript", "ts", LOG, TS_ENTRY,
         "console.log(render(", "work.ts",
         {"work.ts": ("export function render(user: string): string {\n"
                      "  return 'level=info action=login user=' + user;\n}\n")},
         "return 'level=info action=login user=' + user", LOG_WHY_V,
         {"work.ts": ("export function render(user: string): string {\n"
                      "  const flat = user.replace(/[\\r\\n]/g, '');\n"
                      "  return 'level=info action=login user=' + flat;\n}\n")},
         "return 'level=info action=login user=' + flat", LOG_WHY_S),

    pair("ts-expose@stack-returned", "typescript", "ts", EXPOSE, TS_ENTRY,
         "console.log(render(", "work.ts",
         {"work.ts": ("export function render(key: string): string {\n"
                      "  try {\n    return load(key);\n"
                      "  } catch (e) {\n    return 'lookup failed: ' + (e as Error).stack;\n  }\n}\n\n"
                      "function load(key: string): string {\n"
                      "  throw new Error('connect to db.internal:5432 as reporting failed');\n}\n")},
         "return 'lookup failed: ' + (e as Error).stack", EXPOSE_WHY_V,
         {"work.ts": ("export function render(key: string): string {\n"
                      "  try {\n    return load(key);\n"
                      "  } catch (e) {\n    return 'lookup failed';\n  }\n}\n\n"
                      "function load(key: string): string {\n"
                      "  throw new Error('connect to db.internal:5432 as reporting failed');\n}\n")},
         "return 'lookup failed'", EXPOSE_WHY_S),

    pair("ts-authz@no-ownership-check", "typescript", "ts", AUTHZ, TS_ENTRY,
         "console.log(render(", "work.ts",
         {"work.ts": ("const CURRENT_USER = 'alice';\n\n"
                      "export function render(orderId: string): string {\n"
                      "  return fetchOrder(orderId);\n}\n\n"
                      "function fetchOrder(orderId: string): string {\n"
                      "  return `order ${orderId} contents`;\n}\n")},
         "return fetchOrder(orderId)", AUTHZ_WHY_V,
         {"work.ts": ("const CURRENT_USER = 'alice';\n"
                      "const OWNERS: Record<string, string> = { 'A-1001': 'alice', 'A-1002': 'bob' };\n\n"
                      "export function render(orderId: string): string {\n"
                      "  if (OWNERS[orderId] !== CURRENT_USER) {\n    return '';\n  }\n"
                      "  return fetchOrder(orderId);\n}\n\n"
                      "function fetchOrder(orderId: string): string {\n"
                      "  return `order ${orderId} contents`;\n}\n")},
         "return fetchOrder(orderId)", AUTHZ_WHY_S),

    pair("kt-log@unsanitised-entry", "kotlin", "kt", LOG, KT_ENTRY,
         "println(render(", "Work.kt",
         {"Work.kt": ("fun render(user: String): String {\n"
                      "    return \"level=info action=login user=\" + user\n}\n")},
         "return \"level=info action=login user=\" + user", LOG_WHY_V,
         {"Work.kt": ("fun render(user: String): String {\n"
                      "    val flat = user.replace(\"\\n\", \"\").replace(\"\\r\", \"\")\n"
                      "    return \"level=info action=login user=\" + flat\n}\n")},
         "return \"level=info action=login user=\" + flat", LOG_WHY_S),

    pair("kt-expose@error-detail-returned", "kotlin", "kt", EXPOSE, KT_ENTRY,
         "println(render(", "Work.kt",
         {"Work.kt": ("fun render(key: String): String {\n"
                      "    return try {\n        load(key)\n"
                      "    } catch (e: Exception) {\n        \"lookup failed: \" + e.message\n    }\n}\n\n"
                      "fun load(key: String): String {\n"
                      "    throw IllegalStateException(\"connect to db.internal:5432 as reporting failed\")\n}\n")},
         "\"lookup failed: \" + e.message", EXPOSE_WHY_V,
         {"Work.kt": ("fun render(key: String): String {\n"
                      "    return try {\n        load(key)\n"
                      "    } catch (e: Exception) {\n        \"lookup failed\"\n    }\n}\n\n"
                      "fun load(key: String): String {\n"
                      "    throw IllegalStateException(\"connect to db.internal:5432 as reporting failed\")\n}\n")},
         "\"lookup failed\"", EXPOSE_WHY_S),

    pair("kt-authz@no-ownership-check", "kotlin", "kt", AUTHZ, KT_ENTRY,
         "println(render(", "Work.kt",
         {"Work.kt": ("const val CURRENT_USER = \"alice\"\n\n"
                      "fun render(orderId: String): String {\n"
                      "    return fetchOrder(orderId)\n}\n\n"
                      "fun fetchOrder(orderId: String): String = \"order $orderId contents\"\n")},
         "return fetchOrder(orderId)", AUTHZ_WHY_V,
         {"Work.kt": ("const val CURRENT_USER = \"alice\"\n"
                      "val OWNERS = mapOf(\"A-1001\" to \"alice\", \"A-1002\" to \"bob\")\n\n"
                      "fun render(orderId: String): String {\n"
                      "    if (OWNERS[orderId] != CURRENT_USER) return \"\"\n"
                      "    return fetchOrder(orderId)\n}\n\n"
                      "fun fetchOrder(orderId: String): String = \"order $orderId contents\"\n")},
         "return fetchOrder(orderId)", AUTHZ_WHY_S),

    pair("cs-log@unsanitised-entry", "csharp", "cs", LOG, CS_ENTRY,
         "Console.WriteLine(Work.Render(", "Work.cs",
         {"Work.cs": ("public static class Work\n{\n"
                      "    public static string Render(string user) =>\n"
                      "        \"level=info action=login user=\" + user;\n}\n")},
         "\"level=info action=login user=\" + user", LOG_WHY_V,
         {"Work.cs": ("public static class Work\n{\n"
                      "    public static string Render(string user)\n    {\n"
                      "        var flat = user.Replace(\"\\n\", \"\").Replace(\"\\r\", \"\");\n"
                      "        return \"level=info action=login user=\" + flat;\n    }\n}\n")},
         "\"level=info action=login user=\" + flat", LOG_WHY_S),

    pair("cs-expose@error-detail-returned", "csharp", "cs", EXPOSE, CS_ENTRY,
         "Console.WriteLine(Work.Render(", "Work.cs",
         {"Work.cs": ("using System;\n\npublic static class Work\n{\n"
                      "    public static string Render(string key)\n    {\n"
                      "        try {\n            return Load(key);\n"
                      "        } catch (Exception e) {\n"
                      "            return \"lookup failed: \" + e.ToString();\n        }\n    }\n\n"
                      "    private static string Load(string key) =>\n"
                      "        throw new InvalidOperationException(\n"
                      "            \"connect to db.internal:5432 as reporting failed\");\n}\n")},
         "return \"lookup failed: \" + e.ToString()", EXPOSE_WHY_V,
         {"Work.cs": ("using System;\n\npublic static class Work\n{\n"
                      "    public static string Render(string key)\n    {\n"
                      "        try {\n            return Load(key);\n"
                      "        } catch (Exception) {\n"
                      "            return \"lookup failed\";\n        }\n    }\n\n"
                      "    private static string Load(string key) =>\n"
                      "        throw new InvalidOperationException(\n"
                      "            \"connect to db.internal:5432 as reporting failed\");\n}\n")},
         "return \"lookup failed\"", EXPOSE_WHY_S),

    pair("php-log@unsanitised-entry", "php", "php", LOG, PHP_ENTRY,
         "function show", "work.php",
         {"work.php": "<?php\n\nfunction render($user) {\n    return 'level=info action=login user=' . $user;\n}\n"},
         "return 'level=info action=login user=' . $user", LOG_WHY_V,
         {"work.php": ("<?php\n\nfunction render($user) {\n"
                       "    $flat = str_replace([\"\\r\", \"\\n\"], '', $user);\n"
                       "    return 'level=info action=login user=' . $flat;\n}\n")},
         "return 'level=info action=login user=' . $flat", LOG_WHY_S),

    pair("php-authz@no-ownership-check", "php", "php", AUTHZ, PHP_ENTRY,
         "function show", "work.php",
         {"work.php": ("<?php\n\ndefine('CURRENT_USER', 'alice');\n\n"
                       "function render($orderId) {\n    return fetchOrder($orderId);\n}\n\n"
                       "function fetchOrder($orderId) {\n    return \"order $orderId contents\";\n}\n")},
         "return fetchOrder($orderId)", AUTHZ_WHY_V,
         {"work.php": ("<?php\n\ndefine('CURRENT_USER', 'alice');\n"
                       "$OWNERS = ['A-1001' => 'alice', 'A-1002' => 'bob'];\n\n"
                       "function render($orderId) {\n    global $OWNERS;\n"
                       "    if (($OWNERS[$orderId] ?? null) !== CURRENT_USER) {\n        return '';\n    }\n"
                       "    return fetchOrder($orderId);\n}\n\n"
                       "function fetchOrder($orderId) {\n    return \"order $orderId contents\";\n}\n")},
         "return fetchOrder($orderId)", AUTHZ_WHY_S),

    pair("rb-log@unsanitised-entry", "ruby", "rb", LOG, RB_ENTRY,
         "def show", "work.rb",
         {"work.rb": "def render(user)\n  \"level=info action=login user=#{user}\"\nend\n"},
         "\"level=info action=login user=", LOG_WHY_V,
         {"work.rb": ("def render(user)\n  flat = user.delete(\"\\r\\n\")\n"
                      "  \"level=info action=login user=#{flat}\"\nend\n")},
         "\"level=info action=login user=", LOG_WHY_S),

    pair("rb-authz@no-ownership-check", "ruby", "rb", AUTHZ, RB_ENTRY,
         "def show", "work.rb",
         {"work.rb": ("CURRENT_USER = \"alice\".freeze\n\n"
                      "def render(order_id)\n  fetch_order(order_id)\nend\n\n"
                      "def fetch_order(order_id)\n  \"order #{order_id} contents\"\nend\n")},
         "fetch_order(order_id)", AUTHZ_WHY_V,
         {"work.rb": ("CURRENT_USER = \"alice\".freeze\n"
                      "OWNERS = { \"A-1001\" => \"alice\", \"A-1002\" => \"bob\" }.freeze\n\n"
                      "def render(order_id)\n"
                      "  return \"\" unless OWNERS[order_id] == CURRENT_USER\n\n"
                      "  fetch_order(order_id)\nend\n\n"
                      "def fetch_order(order_id)\n  \"order #{order_id} contents\"\nend\n")},
         "fetch_order(order_id)", AUTHZ_WHY_S),

    pair("rs-log@unsanitised-entry", "rust", "rs", LOG, RS_ENTRY,
         "work::render(&value)", "src/work.rs",
         {"src/work.rs": ("pub fn render(user: &str) -> String {\n"
                          "    format!(\"level=info action=login user={}\", user)\n}\n")},
         "format!(\"level=info action=login user={}\", user)", LOG_WHY_V,
         {"src/work.rs": ("pub fn render(user: &str) -> String {\n"
                          "    let flat: String = user.chars().filter(|c| *c != '\\n' && *c != '\\r').collect();\n"
                          "    format!(\"level=info action=login user={}\", flat)\n}\n")},
         "format!(\"level=info action=login user={}\", flat)", LOG_WHY_S),

    pair("rs-authz@no-ownership-check", "rust", "rs", AUTHZ, RS_ENTRY,
         "work::render(&value)", "src/work.rs",
         {"src/work.rs": ("const CURRENT_USER: &str = \"alice\";\n\n"
                          "pub fn render(order_id: &str) -> String {\n"
                          "    fetch_order(order_id)\n}\n\n"
                          "fn fetch_order(order_id: &str) -> String {\n"
                          "    format!(\"order {} contents\", order_id)\n}\n")},
         "fetch_order(order_id)", AUTHZ_WHY_V,
         {"src/work.rs": ("const CURRENT_USER: &str = \"alice\";\n\n"
                          "fn owner_of(order_id: &str) -> Option<&'static str> {\n"
                          "    match order_id {\n"
                          "        \"A-1001\" => Some(\"alice\"),\n"
                          "        \"A-1002\" => Some(\"bob\"),\n"
                          "        _ => None,\n    }\n}\n\n"
                          "pub fn render(order_id: &str) -> String {\n"
                          "    if owner_of(order_id) != Some(CURRENT_USER) {\n"
                          "        return String::new();\n    }\n"
                          "    fetch_order(order_id)\n}\n\n"
                          "fn fetch_order(order_id: &str) -> String {\n"
                          "    format!(\"order {} contents\", order_id)\n}\n")},
         "fetch_order(order_id)", AUTHZ_WHY_S),

    pair("cpp-log@unsanitised-entry", "cpp", "cpp", LOG, CPP_ENTRY,
         "render(argc > 1 ? argv[1]", "work.cpp",
         {"work.cpp": ("#include <string>\n\n"
                       "std::string render(const std::string& user) {\n"
                       "    return \"level=info action=login user=\" + user;\n}\n")},
         "return \"level=info action=login user=\" + user", LOG_WHY_V,
         {"work.cpp": ("#include <algorithm>\n#include <string>\n\n"
                       "std::string render(const std::string& user) {\n"
                       "    std::string flat = user;\n"
                       "    flat.erase(std::remove_if(flat.begin(), flat.end(),\n"
                       "        [](char c) { return c == '\\n' || c == '\\r'; }), flat.end());\n"
                       "    return \"level=info action=login user=\" + flat;\n}\n")},
         "return \"level=info action=login user=\" + flat", LOG_WHY_S),
]

FLOOR_ALL = TEMPLATES


# cpp needs two more and rust one; both taken from what the map permits rather
# than from what is convenient. cpp gets a stack overflow and a format string;
# rust gets an out-of-bounds read, which safe Rust prevents and `unsafe` does not.

TEMPLATES += [
    pair("cpp-stackoverflow@unbounded-copy", "cpp", "cpp",
         ("CWE-121", ["CWE-121", "CWE-787", "CWE-120"], "A03"), CPP_ENTRY,
         "render(argc > 1 ? argv[1]", "work.cpp",
         {"work.cpp": ("#include <cstring>\n#include <string>\n\n"
                       "std::string render(const std::string& value) {\n"
                       "    char buffer[32];\n"
                       "    std::strcpy(buffer, value.c_str());\n"
                       "    return std::string(buffer);\n}\n")},
         "std::strcpy(buffer, value.c_str())",
         "the copy is bounded by where the source happens to end rather than by the "
         "size of the destination, so anything past thirty-one characters writes over "
         "whatever the stack frame holds next — saved registers and the return address "
         "among them",
         {"work.cpp": ("#include <string>\n\n"
                       "std::string render(const std::string& value) {\n"
                       "    char buffer[32];\n"
                       "    const std::size_t length = value.size() < sizeof(buffer) - 1\n"
                       "        ? value.size() : sizeof(buffer) - 1;\n"
                       "    value.copy(buffer, length);\n"
                       "    buffer[length] = '\\0';\n"
                       "    return std::string(buffer);\n}\n")},
         "value.copy(buffer, length)",
         "the length is clamped to the destination before the copy and the result is "
         "terminated explicitly"),

    pair("cpp-format@caller-controls-the-template", "cpp", "cpp",
         ("CWE-134", ["CWE-134", "CWE-133"], "A03"), CPP_ENTRY,
         "render(argc > 1 ? argv[1]", "work.cpp",
         {"work.cpp": ("#include <cstdio>\n#include <string>\n\n"
                       "std::string render(const std::string& value) {\n"
                       "    char out[256];\n"
                       "    std::snprintf(out, sizeof(out), value.c_str());\n"
                       "    return std::string(out);\n}\n")},
         "std::snprintf(out, sizeof(out), value.c_str())",
         "the caller supplies the format template itself, so conversion specifiers in "
         "it are honoured against arguments that were never passed — reading whatever "
         "the calling convention puts where the arguments should be, and with %n "
         "writing there too",
         {"work.cpp": ("#include <cstdio>\n#include <string>\n\n"
                       "std::string render(const std::string& value) {\n"
                       "    char out[256];\n"
                       "    std::snprintf(out, sizeof(out), \"%s\", value.c_str());\n"
                       "    return std::string(out);\n}\n")},
         "std::snprintf(out, sizeof(out), \"%s\", value.c_str())",
         "the template is a literal and the caller's value is one of its arguments, "
         "where any specifier it contains is data"),

    pair("rs-oob@unchecked-index-in-unsafe", "rust", "rs",
         ("CWE-125", ["CWE-125", "CWE-129", "CWE-787"], "A03"), RS_ENTRY,
         "work::render(&value)", "src/work.rs",
         {"src/work.rs": ("pub fn render(raw: &str) -> String {\n"
                          "    let table = [10u8, 20, 30, 40];\n"
                          "    let index: usize = raw.parse().unwrap_or(0);\n"
                          "    let value = unsafe { *table.get_unchecked(index) };\n"
                          "    format!(\"{}\", value)\n}\n")},
         "*table.get_unchecked(index)",
         "get_unchecked skips the bounds check that makes indexing safe, and the index "
         "comes straight from the caller. Past the end of the array it reads whatever "
         "lies beyond it — the one way safe Rust's guarantee is given up, and it is "
         "given up explicitly here",
         {"src/work.rs": ("pub fn render(raw: &str) -> String {\n"
                          "    let table = [10u8, 20, 30, 40];\n"
                          "    let index: usize = raw.parse().unwrap_or(0);\n"
                          "    match table.get(index) {\n"
                          "        Some(value) => format!(\"{}\", value),\n"
                          "        None => String::new(),\n    }\n}\n")},
         "match table.get(index)",
         "get returns an option rather than a value, so an index past the end is a case "
         "to handle instead of a read"),
]

FLOOR_ALL = TEMPLATES
