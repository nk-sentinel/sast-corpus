"""Sanitizers that are present and do not work.

The corpus already asks whether a tool finds an unsanitised flow. These ask the
harder question: whether it can tell a sanitizer that works from one that only
looks like it does. That is where tools disagree most, and where the most common
real-world false negative lives — *a sanitizer appears on the path, therefore
suppress the finding*.

Every pair here has a sanitizer call in **both** halves. The vulnerable one is
defeated; the safe one is not. A tool matching on the presence of a call scores
the vulnerable half as safe, and nothing about the shape of the code tells it
apart from the sibling.

Two of the ten are worth singling out because they are the ones real code gets
wrong most often, and neither involves a subtle encoding question:

- **`wrong-variable`** validates one value and uses another. The validation is
  correct, complete, and applied to something that never reaches the sink.
- **`discarded-result`** calls the validator and ignores what it returns. The
  check runs, passes or fails, and nothing acts on it.

Both are false-negative tests. A sanitizer is right there on the path in each,
and it has no effect whatsoever on what reaches the sink.
"""

from gen.generate import Template, Variant

SQLI = ("CWE-89", ["CWE-89", "CWE-943", "CWE-564"], "A03")
CMDI = ("CWE-78", ["CWE-78", "CWE-77", "CWE-88"], "A03")
PATHT = ("CWE-22", ["CWE-22", "CWE-23", "CWE-36"], "A01")
XSS = ("CWE-79", ["CWE-79", "CWE-80", "CWE-83"], "A03")
SSRF = ("CWE-918", ["CWE-918", "CWE-441"], "A10")


def defeated(slug, language, extension, weakness, flow,
             vulnerable_files, sink_file, sink_match, why_vulnerable,
             safe_files, safe_sink_file, safe_sink_match, why_safe,
             entry_file=None, source_file=None, source_match=None,
             severity="high"):
    """A defeated sanitizer and the same sanitizer done right.

    The vulnerable half is labelled `ineffective` rather than `none`: there is a
    sanitizer on the path and it does not work, which is a different fact from
    there being no sanitizer at all, and a scorecard that cannot separate them
    cannot say whether a tool understands sanitisation or merely detects it.
    """
    cwe, acceptable, owasp = weakness
    return Template(
        slug=slug, language=language, extension=extension,
        primary_cwe=cwe, acceptable_cwes=acceptable, owasp_2021=owasp,
        severity=severity, flow=flow, obfuscation="none",
        entry_file=entry_file, source="hand-authored",
        variants={
            "vulnerable": Variant(
                label="vulnerable", files=vulnerable_files,
                sink_file=sink_file, sink_match=sink_match,
                sanitizer="ineffective",
                source_file=source_file, source_match=source_match,
                rationale=why_vulnerable),
            "safe": Variant(
                label="safe", files=safe_files,
                sink_file=safe_sink_file, sink_match=safe_sink_match,
                sanitizer="custom-effective", rationale=why_safe),
        },
    )


JAVA_ENTRY = {"Cli.java": (
    "public final class Cli {\n"
    "    public static void main(String[] args) {\n"
    "        System.out.println(Handler.handle(args.length > 0 ? args[0] : \"\"));\n"
    "    }\n}\n")}


def _java(slug, weakness, vulnerable_body, sink_match, why_vulnerable,
          safe_body, safe_sink_match, why_safe):
    return defeated(
        slug, "java", "java", weakness, "inter-file",
        dict(JAVA_ENTRY, **{"Handler.java": vulnerable_body}),
        "Handler.java", sink_match, why_vulnerable,
        dict(JAVA_ENTRY, **{"Handler.java": safe_body}),
        "Handler.java", safe_sink_match, why_safe,
        entry_file="Cli.java", source_file="Cli.java", source_match="args[0]")


JAVA = [
    _java("jv-blacklist@misses-a-variant", XSS,
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        String cleaned = name.replace(\"<script>\", \"\").replace(\"</script>\", \"\");\n"
          "        return \"<div>\" + cleaned + \"</div>\";\n    }\n}\n",
          "return \"<div>\" + cleaned",
          "the filter removes one tag and nothing else, so an image element carrying an "
          "error handler passes through untouched and still runs script. Enumerating "
          "what is forbidden means the list is only ever as good as its author's "
          "imagination",
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        StringBuilder encoded = new StringBuilder();\n"
          "        for (char c : name.toCharArray()) {\n"
          "            switch (c) {\n"
          "                case '<': encoded.append(\"&lt;\"); break;\n"
          "                case '>': encoded.append(\"&gt;\"); break;\n"
          "                case '&': encoded.append(\"&amp;\"); break;\n"
          "                case '\"': encoded.append(\"&quot;\"); break;\n"
          "                case '\\'': encoded.append(\"&#x27;\"); break;\n"
          "                default: encoded.append(c);\n            }\n        }\n"
          "        return \"<div>\" + encoded + \"</div>\";\n    }\n}\n",
          "return \"<div>\" + encoded",
          "every character with meaning in markup is encoded, so nothing the caller "
          "sends can close the element or open a new one"),

    _java("jv-singlepass@nesting-restores-it", PATHT,
          "import java.io.IOException;\nimport java.nio.file.Files;\n"
          "import java.nio.file.Paths;\n\n"
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        String cleaned = name.replace(\"../\", \"\");\n"
          "        try {\n"
          "            return new String(Files.readAllBytes(\n"
          "                Paths.get(\"/srv/reports/\" + cleaned)));\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "    }\n}\n",
          "Files.readAllBytes(",
          "the removal runs once over the input, so a nested sequence reassembles itself "
          "as the pass consumes the middle of it and closes the gap. One pass cannot fix "
          "what the pass itself creates",
          "import java.io.IOException;\nimport java.nio.file.Files;\n"
          "import java.nio.file.Path;\nimport java.nio.file.Paths;\n\n"
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        try {\n"
          "            Path base = Paths.get(\"/srv/reports\").toRealPath();\n"
          "            Path target = base.resolve(Paths.get(name).getFileName()).normalize();\n"
          "            if (!target.startsWith(base)) {\n                return \"\";\n            }\n"
          "            return new String(Files.readAllBytes(target));\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "    }\n}\n",
          "return new String(Files.readAllBytes(target))",
          "the value is reduced to a bare filename and the resolved path is checked to "
          "remain under the base, so no amount of nesting changes where the read lands"),

    _java("jv-wrongcontext@encoder-for-another-place", XSS,
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        String encoded = name.replace(\"<\", \"&lt;\").replace(\">\", \"&gt;\");\n"
          "        return \"<script>var user = '\" + encoded + \"';</script>\";\n    }\n}\n",
          "return \"<script>var user = '\"",
          "the encoding is correct for markup and the value lands inside a script "
          "string, where angle brackets were never the danger. A quote closes the "
          "literal and the rest is executed as code — the right encoder applied to the "
          "wrong context does nothing at all",
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        StringBuilder encoded = new StringBuilder();\n"
          "        for (char c : name.toCharArray()) {\n"
          "            if (c < 0x20 || c == '\\'' || c == '\"' || c == '\\\\'\n"
          "                || c == '<' || c == '>' || c == '&') {\n"
          "                encoded.append(String.format(\"\\\\u%04x\", (int) c));\n"
          "            } else {\n                encoded.append(c);\n            }\n        }\n"
          "        return \"<script>var user = '\" + encoded + \"';</script>\";\n    }\n}\n",
          "return \"<script>var user = '\"",
          "the value is escaped for the context it actually lands in: quotes, "
          "backslashes and anything that could end the script element become unicode "
          "escapes"),

    _java("jv-decodeafter@check-then-undo-it", PATHT,
          "import java.io.IOException;\nimport java.net.URLDecoder;\n"
          "import java.nio.charset.StandardCharsets;\nimport java.nio.file.Files;\n"
          "import java.nio.file.Paths;\n\n"
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        if (name.contains(\"..\") || name.contains(\"/\")) {\n"
          "            return \"\";\n        }\n"
          "        String target = URLDecoder.decode(name, StandardCharsets.UTF_8);\n"
          "        try {\n"
          "            return new String(Files.readAllBytes(\n"
          "                Paths.get(\"/srv/reports/\" + target)));\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "    }\n}\n",
          "Files.readAllBytes(",
          "the check is thorough and runs against the encoded form, then the value is "
          "decoded afterwards and the decoding puts back exactly what the check "
          "rejected. Validating one representation and using another is the whole bug",
          "import java.io.IOException;\nimport java.net.URLDecoder;\n"
          "import java.nio.charset.StandardCharsets;\nimport java.nio.file.Files;\n"
          "import java.nio.file.Paths;\n\n"
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        String target = URLDecoder.decode(name, StandardCharsets.UTF_8);\n"
          "        if (target.contains(\"..\") || target.contains(\"/\")) {\n"
          "            return \"\";\n        }\n"
          "        try {\n"
          "            return new String(Files.readAllBytes(\n"
          "                Paths.get(\"/srv/reports/\" + target)));\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "    }\n}\n",
          "Files.readAllBytes(",
          "the value is decoded first and the check runs on the same representation that "
          "reaches the path"),

    _java("jv-wrongvariable@validated-one-used-another", SQLI,
          "public final class Handler {\n"
          "    public static String handle(String raw) {\n"
          "        String code = raw.replaceAll(\"[^A-Z0-9]\", \"\");\n"
          "        if (!code.matches(\"^[A-Z0-9]{1,12}$\")) {\n"
          "            return \"\";\n        }\n"
          "        return run(\"SELECT status FROM orders WHERE code = '\" + raw + \"'\");\n"
          "    }\n\n"
          "    private static String run(String statement) {\n        return statement;\n    }\n}\n",
          "return run(\"SELECT status FROM orders WHERE code = '\"",
          "the pattern is correct, anchored, and applied to a value that never reaches "
          "the statement. `raw` is what gets concatenated, and nothing was ever checked "
          "about it. A tool that sees a validator on the path and stops looking scores "
          "this as safe",
          "public final class Handler {\n"
          "    public static String handle(String raw) {\n"
          "        String code = raw.replaceAll(\"[^A-Z0-9]\", \"\");\n"
          "        if (!code.matches(\"^[A-Z0-9]{1,12}$\")) {\n"
          "            return \"\";\n        }\n"
          "        return run(\"SELECT status FROM orders WHERE code = '\" + code + \"'\");\n"
          "    }\n\n"
          "    private static String run(String statement) {\n        return statement;\n    }\n}\n",
          "return run(\"SELECT status FROM orders WHERE code = '\"",
          "the value that was validated is the value that reaches the statement, and the "
          "anchored pattern admits nothing that could close the quote"),

    _java("jv-discarded@check-runs-nothing-acts", CMDI,
          "import java.io.IOException;\n\n"
          "public final class Handler {\n"
          "    private static boolean permitted(String name) {\n"
          "        return name.matches(\"^[a-z-]{1,20}$\");\n    }\n\n"
          "    public static String handle(String name) {\n"
          "        permitted(name);\n"
          "        try {\n"
          "            Runtime.getRuntime().exec(new String[] {\"/bin/sh\", \"-c\",\n"
          "                \"/usr/bin/report \" + name});\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "        return name;\n    }\n}\n",
          "Runtime.getRuntime().exec(",
          "the validator is written correctly and called on the right value, and its "
          "answer is thrown away. Nothing branches on it, so every input reaches the "
          "shell exactly as if the call were not there",
          "import java.io.IOException;\n\n"
          "public final class Handler {\n"
          "    private static boolean permitted(String name) {\n"
          "        return name.matches(\"^[a-z-]{1,20}$\");\n    }\n\n"
          "    public static String handle(String name) {\n"
          "        if (!permitted(name)) {\n            return \"\";\n        }\n"
          "        try {\n"
          "            Runtime.getRuntime().exec(new String[] {\"/usr/bin/report\", name});\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "        return name;\n    }\n}\n",
          "Runtime.getRuntime().exec(",
          "the result of the check decides whether execution continues, and the command "
          "is run as an argument vector rather than through a shell"),

    _java("jv-ordering@sanitised-then-appended", SQLI,
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        String[] parts = name.split(\",\", 2);\n"
          "        String code = parts[0].replace(\"'\", \"''\");\n"
          "        String order = parts.length > 1 ? parts[1] : \"code\";\n"
          "        return run(\"SELECT status FROM orders WHERE code = '\" + code\n"
          "                   + \"' ORDER BY \" + order);\n    }\n\n"
          "    private static String run(String statement) {\n        return statement;\n    }\n}\n",
          "return run(\"SELECT status FROM orders WHERE code = '\"",
          "the first fragment is escaped properly and the second is concatenated raw "
          "afterwards. Sanitising part of a statement is not sanitising the statement, "
          "and the ORDER BY clause takes an identifier that cannot be bound anyway",
          "import java.util.Arrays;\nimport java.util.List;\n\n"
          "public final class Handler {\n"
          "    private static final List<String> COLUMNS = Arrays.asList(\"code\", \"status\");\n\n"
          "    public static String handle(String name) {\n"
          "        String[] parts = name.split(\",\", 2);\n"
          "        String order = parts.length > 1 ? parts[1] : \"code\";\n"
          "        if (!COLUMNS.contains(order)) {\n            return \"\";\n        }\n"
          "        return run(\"SELECT status FROM orders WHERE code = ? ORDER BY \" + order,\n"
          "                   parts[0]);\n    }\n\n"
          "    private static String run(String statement, String value) {\n"
          "        return statement + \"|\" + value;\n    }\n}\n",
          "return run(\"SELECT status FROM orders WHERE code = ? ORDER BY \" + order",
          "the value is bound as a parameter and the column name — which cannot be bound "
          "— is checked against a fixed list of real columns"),

    _java("jv-unanchored@pattern-matches-anywhere", SSRF,
          "import java.net.URI;\nimport java.util.regex.Pattern;\n\n"
          "public final class Handler {\n"
          "    private static final Pattern HOST = Pattern.compile(\"api.example.com\");\n\n"
          "    public static String handle(String target) {\n"
          "        if (!HOST.matcher(target).find()) {\n            return \"\";\n        }\n"
          "        return fetch(URI.create(target));\n    }\n\n"
          "    private static String fetch(URI uri) {\n        return uri.toString();\n    }\n}\n",
          "return fetch(URI.create(target))",
          "the pattern is unanchored and searched rather than matched, so it succeeds "
          "anywhere in the string — including in a userinfo section or a query "
          "parameter of an address that resolves somewhere else entirely. The "
          "unescaped dots match any character as a further courtesy",
          "import java.net.URI;\nimport java.util.Arrays;\nimport java.util.List;\n\n"
          "public final class Handler {\n"
          "    private static final List<String> ALLOWED = Arrays.asList(\"api.example.com\");\n\n"
          "    public static String handle(String target) {\n"
          "        URI uri = URI.create(target);\n"
          "        if (!\"https\".equals(uri.getScheme()) || uri.getHost() == null\n"
          "            || !ALLOWED.contains(uri.getHost())) {\n            return \"\";\n        }\n"
          "        return fetch(uri);\n    }\n\n"
          "    private static String fetch(URI uri) {\n        return uri.toString();\n    }\n}\n",
          "return fetch(uri)",
          "the address is parsed first and the host compared for equality against an "
          "allowlist, so nothing about the surrounding string can influence the result"),

    _java("jv-discardedreturn@result-not-assigned", PATHT,
          "import java.io.IOException;\nimport java.nio.file.Files;\n"
          "import java.nio.file.Paths;\n\n"
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        name.replace(\"..\", \"\");\n"
          "        try {\n"
          "            return new String(Files.readAllBytes(\n"
          "                Paths.get(\"/srv/reports/\" + name)));\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "    }\n}\n",
          "Files.readAllBytes(",
          "strings are immutable, so the replacement returns a new value and changes "
          "nothing about the one that is used. The call is on the right variable with "
          "the right argument and its result is dropped on the floor",
          "import java.io.IOException;\nimport java.nio.file.Files;\n"
          "import java.nio.file.Paths;\n\n"
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        String cleaned = Paths.get(name).getFileName().toString();\n"
          "        try {\n"
          "            return new String(Files.readAllBytes(\n"
          "                Paths.get(\"/srv/reports/\" + cleaned)));\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "    }\n}\n",
          "Files.readAllBytes(",
          "the reduced value is assigned and it is the assigned value that reaches the "
          "path"),

    _java("jv-toctou@canonicalise-after-check", PATHT,
          "import java.io.IOException;\nimport java.nio.file.Files;\n"
          "import java.nio.file.Path;\nimport java.nio.file.Paths;\n\n"
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        try {\n"
          "            Path target = Paths.get(\"/srv/reports/\" + name);\n"
          "            if (!target.startsWith(\"/srv/reports\")) {\n"
          "                return \"\";\n            }\n"
          "            return new String(Files.readAllBytes(target.toRealPath()));\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "    }\n}\n",
          "Files.readAllBytes(target.toRealPath())",
          "the prefix is checked against the unresolved path, which still contains its "
          "dot-dot segments and passes, and the resolution that removes them happens "
          "afterwards on the way to the read. Checking one form and opening another is "
          "the same error as decoding after validating",
          "import java.io.IOException;\nimport java.nio.file.Files;\n"
          "import java.nio.file.Path;\nimport java.nio.file.Paths;\n\n"
          "public final class Handler {\n"
          "    public static String handle(String name) {\n"
          "        try {\n"
          "            Path base = Paths.get(\"/srv/reports\").toRealPath();\n"
          "            Path target = base.resolve(name).normalize();\n"
          "            if (!target.startsWith(base)) {\n"
          "                return \"\";\n            }\n"
          "            return new String(Files.readAllBytes(target));\n"
          "        } catch (IOException e) {\n            return \"\";\n        }\n"
          "    }\n}\n",
          "return new String(Files.readAllBytes(target))",
          "the path is resolved before the check and the checked path is the one that is "
          "opened"),
]

SANITIZER_ALL = JAVA


PY_ENTRY = {"cli.py": ("import sys\n\nfrom handler import handle\n\n\n"
                       "def main():\n"
                       "    print(handle(sys.argv[1] if len(sys.argv) > 1 else \"\"))\n")}


def _python(slug, weakness, vulnerable_body, sink_match, why_vulnerable,
            safe_body, safe_sink_match, why_safe):
    return defeated(
        slug, "python", "py", weakness, "inter-file",
        dict(PY_ENTRY, **{"handler.py": vulnerable_body}),
        "handler.py", sink_match, why_vulnerable,
        dict(PY_ENTRY, **{"handler.py": safe_body}),
        "handler.py", safe_sink_match, why_safe,
        entry_file="cli.py", source_file="cli.py", source_match="sys.argv[1]")


PYTHON = [
    _python("py-joinabsolute@base-silently-dropped", PATHT,
            "import os\n\n\nBASE = \"/srv/reports\"\n\n\n"
            "def handle(name):\n"
            "    if \"..\" in name:\n        return \"\"\n"
            "    target = os.path.join(BASE, name)\n"
            "    with open(target) as handle_:\n        return handle_.read()\n",
            "with open(target) as handle_",
            "the dot-dot check is correct and irrelevant. os.path.join discards every "
            "component before an absolute one, so a leading slash replaces the base "
            "directory outright and no traversal sequence is needed to leave it",
            "import os\n\n\nBASE = \"/srv/reports\"\n\n\n"
            "def handle(name):\n"
            "    target = os.path.realpath(os.path.join(BASE, os.path.basename(name)))\n"
            "    if not target.startswith(BASE + os.sep):\n        return \"\"\n"
            "    with open(target) as handle_:\n        return handle_.read()\n",
            "with open(target) as handle_",
            "basename reduces the value to a single component, so nothing absolute "
            "survives, and the resolved path is confirmed to stay under the base"),

    _python("py-escapequotes@attribute-context", XSS,
            "import html\n\n\n"
            "def handle(name):\n"
            "    encoded = html.escape(name, quote=False)\n"
            "    return \"<div title=\" + encoded + \">report</div>\"\n",
            "return \"<div title=\"",
            "quote=False leaves both quote characters alone, and the value lands in an "
            "unquoted attribute where whitespace alone ends it. Angle brackets are "
            "encoded and are not what was needed here",
            "import html\n\n\n"
            "def handle(name):\n"
            "    encoded = html.escape(name, quote=True)\n"
            "    return \"<div title=\\\"\" + encoded + \"\\\">report</div>\"\n",
            "return \"<div title=\\\"\"",
            "the attribute is quoted and the encoder is told to encode quotes, so the "
            "value cannot end the attribute or introduce another"),

    _python("py-searchunanchored@matches-anywhere", SSRF,
            "import re\nimport urllib.request\n\n\n"
            "ALLOWED = re.compile(r\"api\\.example\\.com\")\n\n\n"
            "def handle(target):\n"
            "    if not ALLOWED.search(target):\n        return \"\"\n"
            "    with urllib.request.urlopen(target) as response:\n"
            "        return response.read().decode(\"utf-8\", \"replace\")\n",
            "urllib.request.urlopen(target)",
            "search succeeds anywhere in the string, so putting the permitted name in "
            "the userinfo section of an address satisfies it while the request goes "
            "somewhere else entirely",
            "import urllib.parse\nimport urllib.request\n\n\n"
            "ALLOWED = {\"api.example.com\"}\n\n\n"
            "def handle(target):\n"
            "    parsed = urllib.parse.urlparse(target)\n"
            "    if parsed.scheme != \"https\" or parsed.hostname not in ALLOWED:\n"
            "        return \"\"\n"
            "    with urllib.request.urlopen(target) as response:\n"
            "        return response.read().decode(\"utf-8\", \"replace\")\n",
            "urllib.request.urlopen(target)",
            "the address is parsed and the host compared for equality, so nothing "
            "elsewhere in the string can satisfy the check"),

    _python("py-matchprefix@anchored-only-at-the-start", CMDI,
            "import re\nimport subprocess\n\n\n"
            "def handle(name):\n"
            "    if not re.match(r\"[a-z-]+\", name):\n        return \"\"\n"
            "    subprocess.run(\"/usr/bin/report \" + name, shell=True, check=False)\n"
            "    return name\n",
            "subprocess.run(\"/usr/bin/report \"",
            "re.match anchors at the beginning and says nothing about the end, so a "
            "permitted prefix followed by a shell separator passes. re.fullmatch is the "
            "function that means what this check was written to mean",
            "import re\nimport subprocess\n\n\n"
            "def handle(name):\n"
            "    if not re.fullmatch(r\"[a-z-]{1,20}\", name):\n        return \"\"\n"
            "    subprocess.run([\"/usr/bin/report\", name], check=False)\n"
            "    return name\n",
            "subprocess.run([\"/usr/bin/report\", name]",
            "fullmatch requires the whole value to match, and the command is run as an "
            "argument vector rather than through a shell"),

    _python("py-wrongvariable@validated-one-used-another", SQLI,
            "import re\n\n\n"
            "def handle(raw):\n"
            "    code = re.sub(r\"[^A-Z0-9]\", \"\", raw)\n"
            "    if not re.fullmatch(r\"[A-Z0-9]{1,12}\", code):\n        return \"\"\n"
            "    return run(\"SELECT status FROM orders WHERE code = '\" + raw + \"'\")\n\n\n"
            "def run(statement):\n    return statement\n",
            "return run(\"SELECT status FROM orders WHERE code = '\"",
            "the pattern is anchored and correct and is applied to a value that never "
            "reaches the statement. Stripping the input to build the value that gets "
            "checked guarantees the check passes, and the original goes to the sink",
            "import re\n\n\n"
            "def handle(raw):\n"
            "    code = re.sub(r\"[^A-Z0-9]\", \"\", raw)\n"
            "    if not re.fullmatch(r\"[A-Z0-9]{1,12}\", code):\n        return \"\"\n"
            "    return run(\"SELECT status FROM orders WHERE code = %s\", (code,))\n\n\n"
            "def run(statement, params):\n    return statement + \"|\" + str(params)\n",
            "return run(\"SELECT status FROM orders WHERE code = %s\"",
            "the checked value is the one that travels, and it travels as a bound "
            "parameter rather than inside the statement text"),

    _python("py-discarded@result-not-assigned", PATHT,
            "def handle(name):\n"
            "    name.replace(\"..\", \"\")\n"
            "    with open(\"/srv/reports/\" + name) as handle_:\n"
            "        return handle_.read()\n",
            "with open(\"/srv/reports/\"",
            "strings are immutable, so the replacement builds a new value and discards "
            "it. The call names the right variable and the right argument and has no "
            "effect on what is opened",
            "import os\n\n\n"
            "def handle(name):\n"
            "    cleaned = os.path.basename(name)\n"
            "    with open(\"/srv/reports/\" + cleaned) as handle_:\n"
            "        return handle_.read()\n",
            "with open(\"/srv/reports/\"",
            "the reduced value is assigned and the assigned value is what is opened"),

    _python("py-checkignored@validator-return-dropped", CMDI,
            "import re\nimport subprocess\n\n\n"
            "def permitted(name):\n"
            "    return bool(re.fullmatch(r\"[a-z-]{1,20}\", name))\n\n\n"
            "def handle(name):\n"
            "    permitted(name)\n"
            "    subprocess.run(\"/usr/bin/report \" + name, shell=True, check=False)\n"
            "    return name\n",
            "subprocess.run(\"/usr/bin/report \"",
            "the validator is correct and is called on the right value, and its answer "
            "is discarded. Nothing branches on it, so every input reaches the shell",
            "import re\nimport subprocess\n\n\n"
            "def permitted(name):\n"
            "    return bool(re.fullmatch(r\"[a-z-]{1,20}\", name))\n\n\n"
            "def handle(name):\n"
            "    if not permitted(name):\n        return \"\"\n"
            "    subprocess.run([\"/usr/bin/report\", name], check=False)\n"
            "    return name\n",
            "subprocess.run([\"/usr/bin/report\", name]",
            "the validator's answer decides whether execution continues"),

    _python("py-normafter@check-before-resolving", PATHT,
            "import os\n\n\nBASE = \"/srv/reports\"\n\n\n"
            "def handle(name):\n"
            "    target = BASE + \"/\" + name\n"
            "    if not target.startswith(BASE):\n        return \"\"\n"
            "    with open(os.path.normpath(target)) as handle_:\n"
            "        return handle_.read()\n",
            "with open(os.path.normpath(target))",
            "the prefix is checked against the unresolved string, which still carries "
            "its dot-dot segments and therefore starts with the base. Normalisation "
            "happens afterwards, on the way to the open, and removes them",
            "import os\n\n\nBASE = \"/srv/reports\"\n\n\n"
            "def handle(name):\n"
            "    target = os.path.normpath(os.path.join(BASE, name))\n"
            "    if not target.startswith(BASE + os.sep):\n        return \"\"\n"
            "    with open(target) as handle_:\n        return handle_.read()\n",
            "with open(target) as handle_",
            "the path is normalised first and the checked path is the one that is "
            "opened"),
]

SANITIZER_ALL = SANITIZER_ALL + PYTHON


JS_ENTRY = {"cli.js": ("const { handle } = require('./handler');\n\n"
                       "console.log(handle(process.argv[2] || ''));\n")}


def _javascript(slug, weakness, vulnerable_body, sink_match, why_vulnerable,
                safe_body, safe_sink_match, why_safe):
    return defeated(
        slug, "javascript", "js", weakness, "inter-file",
        dict(JS_ENTRY, **{"handler.js": vulnerable_body}),
        "handler.js", sink_match, why_vulnerable,
        dict(JS_ENTRY, **{"handler.js": safe_body}),
        "handler.js", safe_sink_match, why_safe,
        entry_file="cli.js", source_file="cli.js", source_match="process.argv[2]")


JAVASCRIPT = [
    _javascript("js-replacefirst@only-one-occurrence", PATHT,
                "const fs = require('fs');\n\n"
                "function handle(name) {\n"
                "  const cleaned = name.replace('../', '');\n"
                "  return fs.readFileSync('/srv/reports/' + cleaned, 'utf8');\n}\n\n"
                "module.exports = { handle };\n",
                "fs.readFileSync('/srv/reports/'",
                "a string argument to replace substitutes the first occurrence only — "
                "the global flag is what makes it replace all of them. A second "
                "sequence survives untouched, and a nested one is reassembled by the "
                "single pass that removes its middle",
                "const fs = require('fs');\nconst path = require('path');\n\n"
                "const BASE = '/srv/reports';\n\n"
                "function handle(name) {\n"
                "  const target = path.resolve(BASE, path.basename(name));\n"
                "  if (!target.startsWith(BASE + path.sep)) {\n    return '';\n  }\n"
                "  return fs.readFileSync(target, 'utf8');\n}\n\n"
                "module.exports = { handle };\n",
                "fs.readFileSync(target, 'utf8')",
                "the value is reduced to a single component and the resolved path is "
                "confirmed to stay under the base, so no repetition changes the result"),

    _javascript("js-wrongencoder@url-escaping-for-markup", XSS,
                "function handle(name) {\n"
                "  const encoded = encodeURIComponent(name);\n"
                "  return '<div onclick=\"show(\\'' + encoded + '\\')\">report</div>';\n}\n\n"
                "module.exports = { handle };\n",
                "return '<div onclick=",
                "percent-encoding is for URL components and the value lands inside an "
                "event handler attribute, which the browser decodes as markup before "
                "running it as script. The encoder is real, applied correctly, and "
                "aimed at the wrong grammar",
                "function handle(name) {\n"
                "  const encoded = String(name).replace(/[&<>\"'/]/g,\n"
                "    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;',\n"
                "              '\"': '&quot;', \"'\": '&#x27;', '/': '&#x2F;' })[c]);\n"
                "  return '<div title=\"' + encoded + '\">report</div>';\n}\n\n"
                "module.exports = { handle };\n",
                "return '<div title=\"'",
                "the value is encoded for markup, lands in a quoted plain attribute "
                "rather than an event handler, and cannot close it"),

    _javascript("js-unanchored@pattern-tests-anywhere", SSRF,
                "const https = require('https');\n\n"
                "const ALLOWED = /api\\.example\\.com/;\n\n"
                "function handle(target) {\n"
                "  if (!ALLOWED.test(target)) {\n    return '';\n  }\n"
                "  return fetchIt(target);\n}\n\n"
                "function fetchIt(target) {\n  return String(target);\n}\n\n"
                "module.exports = { handle };\n",
                "return fetchIt(target)",
                "the pattern is unanchored, so it succeeds anywhere in the string. "
                "Placing the permitted name in the userinfo section satisfies it while "
                "the request resolves to a different host entirely",
                "const ALLOWED = new Set(['api.example.com']);\n\n"
                "function handle(target) {\n"
                "  let parsed;\n"
                "  try {\n    parsed = new URL(target);\n  } catch (e) {\n    return '';\n  }\n"
                "  if (parsed.protocol !== 'https:' || !ALLOWED.has(parsed.hostname)) {\n"
                "    return '';\n  }\n"
                "  return fetchIt(parsed.toString());\n}\n\n"
                "function fetchIt(target) {\n  return String(target);\n}\n\n"
                "module.exports = { handle };\n",
                "return fetchIt(parsed.toString())",
                "the address is parsed and the hostname compared for equality, so "
                "nothing elsewhere in the string can satisfy the check"),

    _javascript("js-discarded@result-not-assigned", PATHT,
                "const fs = require('fs');\n\n"
                "function handle(name) {\n"
                "  name.replace(/\\.\\./g, '');\n"
                "  return fs.readFileSync('/srv/reports/' + name, 'utf8');\n}\n\n"
                "module.exports = { handle };\n",
                "fs.readFileSync('/srv/reports/'",
                "the pattern is right, the global flag is right, and the result is "
                "thrown away. Strings are immutable, so the value that reaches the read "
                "is the one that arrived",
                "const fs = require('fs');\nconst path = require('path');\n\n"
                "function handle(name) {\n"
                "  const cleaned = path.basename(name);\n"
                "  return fs.readFileSync('/srv/reports/' + cleaned, 'utf8');\n}\n\n"
                "module.exports = { handle };\n",
                "fs.readFileSync('/srv/reports/'",
                "the reduced value is assigned and the assigned value is what is read"),

    _javascript("js-wrongvariable@validated-one-used-another", SQLI,
                "function handle(raw) {\n"
                "  const code = raw.replace(/[^A-Z0-9]/g, '');\n"
                "  if (!/^[A-Z0-9]{1,12}$/.test(code)) {\n    return '';\n  }\n"
                "  return run(\"SELECT status FROM orders WHERE code = '\" + raw + \"'\");\n}\n\n"
                "function run(statement) {\n  return statement;\n}\n\n"
                "module.exports = { handle };\n",
                "return run(\"SELECT status FROM orders WHERE code = '\"",
                "the pattern is anchored and correct and checks a value built by "
                "stripping the input, which guarantees it passes. The original string "
                "is what reaches the statement",
                "function handle(raw) {\n"
                "  const code = raw.replace(/[^A-Z0-9]/g, '');\n"
                "  if (!/^[A-Z0-9]{1,12}$/.test(code)) {\n    return '';\n  }\n"
                "  return run('SELECT status FROM orders WHERE code = ?', [code]);\n}\n\n"
                "function run(statement, params) {\n  return statement + '|' + params.join();\n}\n\n"
                "module.exports = { handle };\n",
                "return run('SELECT status FROM orders WHERE code = ?'",
                "the checked value is the one that travels, and it travels as a bound "
                "parameter"),

    _javascript("js-checkignored@validator-return-dropped", CMDI,
                "const { execSync } = require('child_process');\n\n"
                "function permitted(name) {\n  return /^[a-z-]{1,20}$/.test(name);\n}\n\n"
                "function handle(name) {\n"
                "  permitted(name);\n"
                "  execSync('/usr/bin/report ' + name);\n"
                "  return name;\n}\n\n"
                "module.exports = { handle };\n",
                "execSync('/usr/bin/report '",
                "the validator is correct and called on the right value, and its answer "
                "is discarded. Nothing branches on it, so every input reaches the shell",
                "const { execFileSync } = require('child_process');\n\n"
                "function permitted(name) {\n  return /^[a-z-]{1,20}$/.test(name);\n}\n\n"
                "function handle(name) {\n"
                "  if (!permitted(name)) {\n    return '';\n  }\n"
                "  execFileSync('/usr/bin/report', [name]);\n"
                "  return name;\n}\n\n"
                "module.exports = { handle };\n",
                "execFileSync('/usr/bin/report', [name])",
                "the validator's answer decides whether execution continues, and the "
                "command is run as an argument vector"),
]

SANITIZER_ALL = SANITIZER_ALL + JAVASCRIPT
