"""Hard cases: flows that are not a straight line from source to sink.

Every tier-1 case before these was a direct flow with a clean sibling. A regular
expression scores well on that shape and so does a commercial dataflow engine,
which means the corpus could not tell them apart — and telling them apart is the
whole point of a bake-off.

Six mechanisms, each the thing that actually separates tools:

| mechanism | what it asks | direction |
|---|---|---|
| `aliasing` | is the second reference to an object the same object? | FN |
| `collection` | does taint survive a round trip through a container? | FN |
| `container-field` | does taint survive being parked in a field? | FN |
| `callback` | does taint cross a lambda boundary? | FN |
| `reflection` | is the sink recognised when it is named at runtime? | FN |
| `strong-update` | is the overwrite noticed? | **FP trap** |

`strong-update` runs the other way on purpose. The tainted value is replaced by
a safe one before the sink, so there is nothing to report; a tool that tracks
assignment without modelling overwriting reports a vulnerability that does not
exist. It is the only mechanism here where the *vulnerable-looking* member of
the pair is the safe one, and it catches over-approximation the same way the
others catch under-approximation.

These are hand-authored. Their whole value is that the code shape differs from
the generator's, so they are recorded as `hand-authored` rather than inheriting
the generated provenance — the monoculture ratio is meaningless otherwise.

Precedent: Securibench Micro organises its 122 servlets by exactly these
categories, and DroidBench states the criterion plainly — "aliases must be
computed precisely or a false positive will be found".
"""

from gen.generate import Template, Variant

SQLI = ("CWE-89", ["CWE-89", "CWE-943", "CWE-564"], "A03")
CMDI = ("CWE-78", ["CWE-78", "CWE-77", "CWE-88"], "A03")
PATHT = ("CWE-22", ["CWE-22", "CWE-23", "CWE-36"], "A01")


def hard(slug, language, extension, weakness, obfuscation, flow,
         vulnerable_files, sink_file, sink_match, why_vulnerable,
         safe_files, safe_sink_file, safe_sink_match, why_safe,
         entry_file=None, source_file=None, source_match=None,
         severity="high", safe_obfuscation=None):
    """One hard case and its sibling.

    `safe_obfuscation` exists for `strong-update`, where the interesting member
    of the pair is the *safe* one — the label has to sit on whichever side
    carries the mechanism.
    """
    cwe, acceptable, owasp = weakness
    return Template(
        slug=slug, language=language, extension=extension,
        primary_cwe=cwe, acceptable_cwes=acceptable, owasp_2021=owasp,
        severity=severity, flow=flow, obfuscation=obfuscation,
        entry_file=entry_file,
        source="hand-authored",
        variants={
            "vulnerable": Variant(
                label="vulnerable", files=vulnerable_files,
                sink_file=sink_file, sink_match=sink_match, sanitizer="none",
                source_file=source_file, source_match=source_match,
                rationale=why_vulnerable, obfuscation=obfuscation),
            "safe": Variant(
                label="safe", files=safe_files,
                sink_file=safe_sink_file, sink_match=safe_sink_match,
                sanitizer="custom-effective", rationale=why_safe,
                obfuscation=safe_obfuscation or obfuscation),
        },
    )


# --- java ---------------------------------------------------------------------

JAVA_ENTRY = {"Cli.java": (
    "public final class Cli {\n"
    "    public static void main(String[] args) {\n"
    "        System.out.println(Report.build(args.length > 0 ? args[0] : \"\"));\n"
    "    }\n}\n")}

JAVA = [
    hard("jv-alias@second-reference", "java", "java", SQLI, "aliasing", "inter-file",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.util.ArrayList;\nimport java.util.List;\n\n"
             "public final class Report {\n"
             "    public static String build(String code) {\n"
             "        List<String> holder = new ArrayList<>();\n"
             "        List<String> same = holder;\n"
             "        holder.add(code);\n"
             "        return run(\"SELECT status FROM orders WHERE code = '\"\n"
             "                   + same.get(0) + \"'\");\n    }\n\n"
             "    private static String run(String statement) {\n"
             "        return statement;\n    }\n}\n")}),
         "Report.java", "return run(\"SELECT status FROM orders WHERE code = '\"",
         "the value is added through one reference and read back through another that "
         "points at the same list. A tool that does not resolve the two names to one "
         "object sees a list that was never written to, and reports nothing",
         dict(JAVA_ENTRY, **{"Report.java": (
             "public final class Report {\n"
             "    public static String build(String code) {\n"
             "        return run(\"SELECT status FROM orders WHERE code = ?\", code);\n"
             "    }\n\n"
             "    private static String run(String statement, String value) {\n"
             "        return statement + \"|\" + value;\n    }\n}\n")}),
         "Report.java", "return run(\"SELECT status FROM orders WHERE code = ?\"",
         "the statement carries a placeholder and the value is bound beside it, so "
         "aliasing changes nothing",
         entry_file="Cli.java", source_file="Cli.java", source_match="args[0]"),

    hard("jv-collection@map-round-trip", "java", "java", CMDI, "collection", "inter-file",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.io.IOException;\nimport java.util.HashMap;\n"
             "import java.util.Map;\n\n"
             "public final class Report {\n"
             "    public static String build(String name) {\n"
             "        Map<String, String> params = new HashMap<>();\n"
             "        params.put(\"target\", name);\n"
             "        params.put(\"mode\", \"summary\");\n"
             "        return run(params.get(\"target\"));\n    }\n\n"
             "    private static String run(String target) {\n"
             "        try {\n"
             "            Runtime.getRuntime().exec(\"/usr/bin/report \" + target);\n"
             "        } catch (IOException e) {\n            return \"\";\n        }\n"
             "        return target;\n    }\n}\n")}),
         "Report.java", "Runtime.getRuntime().exec(",
         "the value goes into a map under one key and comes back out under the same "
         "key. Tracking it requires modelling map contents per key rather than treating "
         "the map as one opaque tainted blob — and a tool that does the latter also "
         "reports the untainted 'mode' entry",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.io.IOException;\nimport java.util.HashMap;\n"
             "import java.util.Map;\n\n"
             "public final class Report {\n"
             "    private static final Map<String, String> ALLOWED = new HashMap<>();\n"
             "    static {\n        ALLOWED.put(\"daily\", \"daily\");\n"
             "        ALLOWED.put(\"weekly\", \"weekly\");\n    }\n\n"
             "    public static String build(String name) {\n"
             "        String target = ALLOWED.get(name);\n"
             "        if (target == null) {\n            return \"\";\n        }\n"
             "        return run(target);\n    }\n\n"
             "    private static String run(String target) {\n"
             "        try {\n"
             "            Runtime.getRuntime().exec(\"/usr/bin/report \" + target);\n"
             "        } catch (IOException e) {\n            return \"\";\n        }\n"
             "        return target;\n    }\n}\n")}),
         "Report.java", "Runtime.getRuntime().exec(",
         "the map is a fixed allowlist and the caller's value is only ever a key into "
         "it, so what reaches the sink is one of two constants",
         entry_file="Cli.java", source_file="Cli.java", source_match="args[0]"),

    hard("jv-field@object-carried", "java", "java", PATHT, "container-field", "inter-file",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.io.IOException;\nimport java.nio.file.Files;\n"
             "import java.nio.file.Paths;\n\n"
             "public final class Report {\n"
             "    private static final class Request {\n"
             "        private String name;\n"
             "        void setName(String value) {\n            this.name = value;\n        }\n"
             "        String getName() {\n            return this.name;\n        }\n    }\n\n"
             "    public static String build(String name) {\n"
             "        Request request = new Request();\n"
             "        request.setName(name);\n"
             "        return read(request);\n    }\n\n"
             "    private static String read(Request request) {\n"
             "        try {\n"
             "            return new String(Files.readAllBytes(\n"
             "                Paths.get(\"/srv/reports/\" + request.getName())));\n"
             "        } catch (IOException e) {\n            return \"\";\n        }\n"
             "    }\n}\n")}),
         "Report.java", "Files.readAllBytes(",
         "the value is parked in a field and the object travels to the sink instead of "
         "the value. Following it means tracking taint through object state across a "
         "call boundary, not through an argument",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.io.IOException;\nimport java.nio.file.Path;\n"
             "import java.nio.file.Files;\nimport java.nio.file.Paths;\n\n"
             "public final class Report {\n"
             "    private static final class Request {\n"
             "        private String name;\n"
             "        void setName(String value) {\n"
             "            this.name = Paths.get(value).getFileName().toString();\n        }\n"
             "        String getName() {\n            return this.name;\n        }\n    }\n\n"
             "    public static String build(String name) {\n"
             "        Request request = new Request();\n"
             "        request.setName(name);\n"
             "        return read(request);\n    }\n\n"
             "    private static String read(Request request) {\n"
             "        try {\n"
             "            Path base = Paths.get(\"/srv/reports\").toRealPath();\n"
             "            Path target = base.resolve(request.getName()).normalize();\n"
             "            if (!target.startsWith(base)) {\n                return \"\";\n            }\n"
             "            return new String(Files.readAllBytes(target));\n"
             "        } catch (IOException e) {\n            return \"\";\n        }\n"
             "    }\n}\n")}),
         "Report.java", "Files.readAllBytes(",
         "the setter reduces the value to a bare filename, and the read confirms the "
         "resolved path stays under the base directory",
         entry_file="Cli.java", source_file="Cli.java", source_match="args[0]"),

    hard("jv-callback@lambda-boundary", "java", "java", SQLI, "callback", "inter-file",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.util.function.Function;\n\n"
             "public final class Report {\n"
             "    public static String build(String code) {\n"
             "        Function<String, String> compose =\n"
             "            value -> \"SELECT status FROM orders WHERE code = '\" + value + \"'\";\n"
             "        return apply(compose, code);\n    }\n\n"
             "    private static String apply(Function<String, String> step, String value) {\n"
             "        return run(step.apply(value));\n    }\n\n"
             "    private static String run(String statement) {\n"
             "        return statement;\n    }\n}\n")}),
         "Report.java", "return run(step.apply(value))",
         "the concatenation happens inside a lambda that is passed to another method "
         "and invoked there. The sink never names the caller's value directly, and "
         "resolving it means following a function object across a call",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.util.function.Function;\n\n"
             "public final class Report {\n"
             "    public static String build(String code) {\n"
             "        Function<String, String> compose =\n"
             "            value -> \"SELECT status FROM orders WHERE code = ?\";\n"
             "        return apply(compose, code);\n    }\n\n"
             "    private static String apply(Function<String, String> step, String value) {\n"
             "        return run(step.apply(value), value);\n    }\n\n"
             "    private static String run(String statement, String value) {\n"
             "        return statement + \"|\" + value;\n    }\n}\n")}),
         "Report.java", "return run(step.apply(value), value)",
         "the lambda ignores its argument and returns a fixed parameterised statement; "
         "the value is bound separately",
         entry_file="Cli.java", source_file="Cli.java", source_match="args[0]"),

    hard("jv-reflect@runtime-named-sink", "java", "java", CMDI, "reflection", "inter-file",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.lang.reflect.Method;\n\n"
             "public final class Report {\n"
             "    public static String build(String name) {\n"
             "        try {\n"
             "            Class<?> runtime = Class.forName(\"java.lang.Runtime\");\n"
             "            Method current = runtime.getMethod(\"getRuntime\");\n"
             "            Method run = runtime.getMethod(\"exec\", String.class);\n"
             "            run.invoke(current.invoke(null), \"/usr/bin/report \" + name);\n"
             "        } catch (ReflectiveOperationException e) {\n"
             "            return \"\";\n        }\n"
             "        return name;\n    }\n}\n")}),
         "Report.java", "run.invoke(current.invoke(null)",
         "the sink is named by a string at runtime, so `Runtime.exec` never appears as "
         "a call the analyser can match. Reaching it requires resolving the reflective "
         "target, and a tool matching on call syntax alone sees nothing dangerous here",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.lang.reflect.Method;\n\n"
             "public final class Report {\n"
             "    public static String build(String name) {\n"
             "        try {\n"
             "            Class<?> strings = Class.forName(\"java.lang.String\");\n"
             "            Method upper = strings.getMethod(\"toUpperCase\");\n"
             "            return (String) upper.invoke(name);\n"
             "        } catch (ReflectiveOperationException e) {\n"
             "            return \"\";\n        }\n"
             "    }\n}\n")}),
         "Report.java", "return (String) upper.invoke(name)",
         "reflection is used just as heavily, and the resolved target is a string "
         "method that starts no process. A tool that flags reflection itself rather "
         "than what it resolves to reports this one",
         entry_file="Cli.java", source_file="Cli.java", source_match="args[0]"),

    hard("jv-strongupdate@overwritten-before-sink", "java", "java", PATHT,
         "none", "inter-file",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.io.IOException;\nimport java.nio.file.Files;\n"
             "import java.nio.file.Paths;\n\n"
             "public final class Report {\n"
             "    public static String build(String name) {\n"
             "        String target = name;\n"
             "        try {\n"
             "            return new String(Files.readAllBytes(\n"
             "                Paths.get(\"/srv/reports/\" + target)));\n"
             "        } catch (IOException e) {\n            return \"\";\n        }\n"
             "    }\n}\n")}),
         "Report.java", "Files.readAllBytes(",
         "the value reaches the path unchanged, so dot-dot segments walk out of the "
         "base directory. This is the direct half of the pair; the interesting half is "
         "its sibling",
         dict(JAVA_ENTRY, **{"Report.java": (
             "import java.io.IOException;\nimport java.nio.file.Files;\n"
             "import java.nio.file.Paths;\n\n"
             "public final class Report {\n"
             "    public static String build(String name) {\n"
             "        String target = name;\n"
             "        target = \"daily-summary.txt\";\n"
             "        try {\n"
             "            return new String(Files.readAllBytes(\n"
             "                Paths.get(\"/srv/reports/\" + target)));\n"
             "        } catch (IOException e) {\n            return \"\";\n        }\n"
             "    }\n}\n")}),
         "Report.java", "Files.readAllBytes(",
         "the caller's value is assigned and then overwritten with a constant before "
         "the read, so nothing of it reaches the path. A tool that records the first "
         "assignment without modelling the overwrite reports a traversal that cannot "
         "happen. This half tests over-approximation rather than detection",
         entry_file="Cli.java", source_file="Cli.java", source_match="args[0]",
         safe_obfuscation="strong-update"),
]

OBFUSCATION_ALL = JAVA


# --- python -------------------------------------------------------------------

PY_ENTRY = {"cli.py": ("import sys\n\nfrom work import build\n\n\n"
                       "def main():\n"
                       "    print(build(sys.argv[1] if len(sys.argv) > 1 else \"\"))\n")}

PYTHON = [
    hard("py-alias@second-reference", "python", "py", SQLI, "aliasing", "inter-file",
         dict(PY_ENTRY, **{"work.py": (
             "def build(code):\n"
             "    holder = []\n"
             "    same = holder\n"
             "    holder.append(code)\n"
             "    return run(\"SELECT status FROM orders WHERE code = '\" + same[0] + \"'\")\n\n\n"
             "def run(statement):\n    return statement\n")}),
         "work.py", "return run(\"SELECT status FROM orders WHERE code = '\"",
         "the value is appended through one name and read back through another bound to "
         "the same list. Python rebinding makes the two names indistinguishable at "
         "runtime, and a tool that treats them as separate objects sees an empty list",
         dict(PY_ENTRY, **{"work.py": (
             "def build(code):\n"
             "    return run(\"SELECT status FROM orders WHERE code = %s\", (code,))\n\n\n"
             "def run(statement, params):\n    return statement + \"|\" + str(params)\n")}),
         "work.py", "return run(\"SELECT status FROM orders WHERE code = %s\"",
         "the statement carries a placeholder and the value travels as a bound "
         "parameter, so aliasing changes nothing",
         entry_file="cli.py", source_file="cli.py", source_match="sys.argv[1]"),

    hard("py-collection@dict-round-trip", "python", "py", CMDI, "collection", "inter-file",
         dict(PY_ENTRY, **{"work.py": (
             "import subprocess\n\n\n"
             "def build(name):\n"
             "    params = {\"target\": name, \"mode\": \"summary\"}\n"
             "    return run(params[\"target\"])\n\n\n"
             "def run(target):\n"
             "    subprocess.run(\"/usr/bin/report \" + target, shell=True, check=False)\n"
             "    return target\n")}),
         "work.py", "subprocess.run(\"/usr/bin/report \"",
         "the value enters a dict under one key and leaves under the same key. Following "
         "it needs per-key modelling; a tool that taints the whole dict also reports the "
         "constant 'mode' entry, and one that gives up at the boundary reports nothing",
         dict(PY_ENTRY, **{"work.py": (
             "import subprocess\n\n\n"
             "ALLOWED = {\"daily\": \"daily\", \"weekly\": \"weekly\"}\n\n\n"
             "def build(name):\n"
             "    target = ALLOWED.get(name)\n"
             "    if target is None:\n        return \"\"\n"
             "    return run(target)\n\n\n"
             "def run(target):\n"
             "    subprocess.run([\"/usr/bin/report\", target], check=False)\n"
             "    return target\n")}),
         "work.py", "subprocess.run([\"/usr/bin/report\", target]",
         "the dict is a fixed allowlist the caller can only index into, and the call "
         "passes an argument vector rather than a shell string",
         entry_file="cli.py", source_file="cli.py", source_match="sys.argv[1]"),

    hard("py-field@object-carried", "python", "py", PATHT, "container-field", "inter-file",
         dict(PY_ENTRY, **{"work.py": (
             "class Request:\n"
             "    def __init__(self):\n        self.name = None\n\n\n"
             "def build(name):\n"
             "    request = Request()\n"
             "    request.name = name\n"
             "    return read(request)\n\n\n"
             "def read(request):\n"
             "    with open(\"/srv/reports/\" + request.name) as handle:\n"
             "        return handle.read()\n")}),
         "work.py", "with open(\"/srv/reports/\"",
         "the value is stored on an attribute and the object is what crosses into the "
         "reader. Tracking it means following taint through object state rather than "
         "through an argument",
         dict(PY_ENTRY, **{"work.py": (
             "import os\n\n\n"
             "BASE = \"/srv/reports\"\n\n\n"
             "class Request:\n"
             "    def __init__(self):\n        self.name = None\n\n\n"
             "def build(name):\n"
             "    request = Request()\n"
             "    request.name = os.path.basename(name)\n"
             "    return read(request)\n\n\n"
             "def read(request):\n"
             "    target = os.path.realpath(os.path.join(BASE, request.name))\n"
             "    if not target.startswith(BASE + os.sep):\n        return \"\"\n"
             "    with open(target) as handle:\n        return handle.read()\n")}),
         "work.py", "with open(target) as handle",
         "the attribute is set to a bare filename and the resolved path is confirmed to "
         "stay under the base directory",
         entry_file="cli.py", source_file="cli.py", source_match="sys.argv[1]"),

    hard("py-callback@lambda-boundary", "python", "py", SQLI, "callback", "inter-file",
         dict(PY_ENTRY, **{"work.py": (
             "def build(code):\n"
             "    compose = lambda value: \"SELECT status FROM orders WHERE code = '\" + value + \"'\"\n"
             "    return apply(compose, code)\n\n\n"
             "def apply(step, value):\n"
             "    return run(step(value))\n\n\n"
             "def run(statement):\n    return statement\n")}),
         "work.py", "return run(step(value))",
         "the concatenation happens inside a lambda handed to another function and "
         "called there. The sink never names the caller's value, so reaching it means "
         "following a function object across a call",
         dict(PY_ENTRY, **{"work.py": (
             "def build(code):\n"
             "    compose = lambda value: \"SELECT status FROM orders WHERE code = %s\"\n"
             "    return apply(compose, code)\n\n\n"
             "def apply(step, value):\n"
             "    return run(step(value), (value,))\n\n\n"
             "def run(statement, params):\n    return statement + \"|\" + str(params)\n")}),
         "work.py", "return run(step(value), (value,))",
         "the lambda ignores its argument and yields a parameterised statement; the "
         "value is bound separately",
         entry_file="cli.py", source_file="cli.py", source_match="sys.argv[1]"),

    hard("py-reflect@runtime-named-sink", "python", "py", CMDI, "reflection", "inter-file",
         dict(PY_ENTRY, **{"work.py": (
             "import importlib\n\n\n"
             "def build(name):\n"
             "    module = importlib.import_module(\"subprocess\")\n"
             "    call = getattr(module, \"run\")\n"
             "    call(\"/usr/bin/report \" + name, shell=True, check=False)\n"
             "    return name\n")}),
         "work.py", "call(\"/usr/bin/report \" + name",
         "the module and the function are both named by strings, so `subprocess.run` "
         "never appears as a call. A tool matching on call syntax sees `call(...)` and "
         "has no reason to treat it as a process launch",
         dict(PY_ENTRY, **{"work.py": (
             "import importlib\n\n\n"
             "def build(name):\n"
             "    module = importlib.import_module(\"html\")\n"
             "    call = getattr(module, \"escape\")\n"
             "    return call(name)\n")}),
         "work.py", "return call(name)",
         "the same dynamic lookup resolves to an HTML escaper, which starts no process. "
         "A tool that flags dynamic dispatch rather than what it resolves to reports "
         "this one",
         entry_file="cli.py", source_file="cli.py", source_match="sys.argv[1]"),

    hard("py-strongupdate@overwritten-before-sink", "python", "py", PATHT,
         "none", "inter-file",
         dict(PY_ENTRY, **{"work.py": (
             "def build(name):\n"
             "    target = name\n"
             "    with open(\"/srv/reports/\" + target) as handle:\n"
             "        return handle.read()\n")}),
         "work.py", "with open(\"/srv/reports/\"",
         "the value reaches the path unchanged, so dot-dot segments walk out of the base "
         "directory. This is the direct half of the pair",
         dict(PY_ENTRY, **{"work.py": (
             "def build(name):\n"
             "    target = name\n"
             "    target = \"daily-summary.txt\"\n"
             "    with open(\"/srv/reports/\" + target) as handle:\n"
             "        return handle.read()\n")}),
         "work.py", "with open(\"/srv/reports/\"",
         "the caller's value is bound and then rebound to a constant before the open, so "
         "none of it reaches the path. A tool that records the first binding without "
         "modelling the rebind reports a traversal that cannot happen",
         entry_file="cli.py", source_file="cli.py", source_match="sys.argv[1]",
         safe_obfuscation="strong-update"),
]

OBFUSCATION_ALL = OBFUSCATION_ALL + PYTHON


# --- go -----------------------------------------------------------------------

GO_ENTRY = {"main.go": (
    "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\n"
    "func main() {\n\tvalue := \"\"\n\tif len(os.Args) > 1 {\n\t\tvalue = os.Args[1]\n\t}\n"
    "\tfmt.Println(build(value))\n}\n")}

GO = [
    hard("go-alias@second-reference", "go", "go", SQLI, "aliasing", "inter-file",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\n"
             "func build(code string) string {\n"
             "\tholder := []string{}\n"
             "\tsame := &holder\n"
             "\tholder = append(holder, code)\n"
             "\treturn run(\"SELECT status FROM orders WHERE code = '\" + (*same)[0] + \"'\")\n}\n\n"
             "func run(statement string) string {\n\treturn statement\n}\n")}),
         "work.go", "return run(\"SELECT status FROM orders WHERE code = '\"",
         "the slice is written through the value and read back through a pointer to it. "
         "Resolving that the two reach the same backing array is pointer analysis, not "
         "name matching",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\n"
             "func build(code string) string {\n"
             "\treturn run(\"SELECT status FROM orders WHERE code = $1\", code)\n}\n\n"
             "func run(statement string, value string) string {\n"
             "\treturn statement + \"|\" + value\n}\n")}),
         "work.go", "return run(\"SELECT status FROM orders WHERE code = $1\"",
         "the statement carries a placeholder and the value is passed beside it",
         entry_file="main.go", source_file="main.go", source_match="os.Args[1]"),

    hard("go-collection@map-round-trip", "go", "go", CMDI, "collection", "inter-file",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\nimport \"os/exec\"\n\n"
             "func build(name string) string {\n"
             "\tparams := map[string]string{\"target\": name, \"mode\": \"summary\"}\n"
             "\treturn run(params[\"target\"])\n}\n\n"
             "func run(target string) string {\n"
             "\t_ = exec.Command(\"sh\", \"-c\", \"/usr/bin/report \"+target).Run()\n"
             "\treturn target\n}\n")}),
         "work.go", "exec.Command(\"sh\", \"-c\"",
         "the value enters a map under one key and leaves under the same key, and the "
         "result is handed to a shell. Following it needs per-key modelling of map "
         "contents",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\nimport \"os/exec\"\n\n"
             "var allowed = map[string]string{\"daily\": \"daily\", \"weekly\": \"weekly\"}\n\n"
             "func build(name string) string {\n"
             "\ttarget, ok := allowed[name]\n"
             "\tif !ok {\n\t\treturn \"\"\n\t}\n"
             "\treturn run(target)\n}\n\n"
             "func run(target string) string {\n"
             "\t_ = exec.Command(\"/usr/bin/report\", target).Run()\n"
             "\treturn target\n}\n")}),
         "work.go", "exec.Command(\"/usr/bin/report\", target)",
         "the map is a fixed allowlist the caller can only look up in, and the command "
         "is executed directly rather than through a shell",
         entry_file="main.go", source_file="main.go", source_match="os.Args[1]"),

    hard("go-field@struct-carried", "go", "go", PATHT, "container-field", "inter-file",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\nimport \"os\"\n\n"
             "type request struct {\n\tname string\n}\n\n"
             "func build(name string) string {\n"
             "\tr := &request{}\n\tr.name = name\n"
             "\treturn read(r)\n}\n\n"
             "func read(r *request) string {\n"
             "\tdata, err := os.ReadFile(\"/srv/reports/\" + r.name)\n"
             "\tif err != nil {\n\t\treturn \"\"\n\t}\n"
             "\treturn string(data)\n}\n")}),
         "work.go", "os.ReadFile(\"/srv/reports/\"",
         "the value is stored in a struct field and the pointer travels to the reader, "
         "so the taint crosses the call as object state rather than as an argument",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\nimport (\n\t\"os\"\n\t\"path/filepath\"\n\t\"strings\"\n)\n\n"
             "const base = \"/srv/reports\"\n\n"
             "type request struct {\n\tname string\n}\n\n"
             "func build(name string) string {\n"
             "\tr := &request{}\n\tr.name = filepath.Base(name)\n"
             "\treturn read(r)\n}\n\n"
             "func read(r *request) string {\n"
             "\ttarget := filepath.Clean(filepath.Join(base, r.name))\n"
             "\tif !strings.HasPrefix(target, base+string(os.PathSeparator)) {\n"
             "\t\treturn \"\"\n\t}\n"
             "\tdata, err := os.ReadFile(target)\n"
             "\tif err != nil {\n\t\treturn \"\"\n\t}\n"
             "\treturn string(data)\n}\n")}),
         "work.go", "os.ReadFile(target)",
         "the field holds a bare filename and the cleaned path is confirmed to stay "
         "under the base directory",
         entry_file="main.go", source_file="main.go", source_match="os.Args[1]"),

    hard("go-callback@closure-boundary", "go", "go", SQLI, "callback", "inter-file",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\n"
             "func build(code string) string {\n"
             "\tcompose := func(value string) string {\n"
             "\t\treturn \"SELECT status FROM orders WHERE code = '\" + value + \"'\"\n\t}\n"
             "\treturn apply(compose, code)\n}\n\n"
             "func apply(step func(string) string, value string) string {\n"
             "\treturn run(step(value))\n}\n\n"
             "func run(statement string) string {\n\treturn statement\n}\n")}),
         "work.go", "return run(step(value))",
         "the concatenation lives in a closure passed to another function and invoked "
         "there, so the sink never names the caller's value directly",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\n"
             "func build(code string) string {\n"
             "\tcompose := func(value string) string {\n"
             "\t\treturn \"SELECT status FROM orders WHERE code = $1\"\n\t}\n"
             "\treturn apply(compose, code)\n}\n\n"
             "func apply(step func(string) string, value string) string {\n"
             "\treturn run(step(value), value)\n}\n\n"
             "func run(statement string, value string) string {\n"
             "\treturn statement + \"|\" + value\n}\n")}),
         "work.go", "return run(step(value), value)",
         "the closure ignores its argument and returns a parameterised statement; the "
         "value travels separately",
         entry_file="main.go", source_file="main.go", source_match="os.Args[1]"),

    hard("go-strongupdate@overwritten-before-sink", "go", "go", PATHT,
         "none", "inter-file",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\nimport \"os\"\n\n"
             "func build(name string) string {\n"
             "\ttarget := name\n"
             "\tdata, err := os.ReadFile(\"/srv/reports/\" + target)\n"
             "\tif err != nil {\n\t\treturn \"\"\n\t}\n"
             "\treturn string(data)\n}\n")}),
         "work.go", "os.ReadFile(\"/srv/reports/\"",
         "the value reaches the path unchanged, so dot-dot segments walk out of the base "
         "directory. This is the direct half of the pair",
         dict(GO_ENTRY, **{"work.go": (
             "package main\n\nimport \"os\"\n\n"
             "func build(name string) string {\n"
             "\ttarget := name\n"
             "\ttarget = \"daily-summary.txt\"\n"
             "\tdata, err := os.ReadFile(\"/srv/reports/\" + target)\n"
             "\tif err != nil {\n\t\treturn \"\"\n\t}\n"
             "\treturn string(data)\n}\n")}),
         "work.go", "os.ReadFile(\"/srv/reports/\"",
         "the caller's value is assigned and then overwritten with a constant before the "
         "read, so none of it reaches the path. A tool that records the first assignment "
         "without modelling the overwrite reports a traversal that cannot happen",
         entry_file="main.go", source_file="main.go", source_match="os.Args[1]",
         safe_obfuscation="strong-update"),
]

OBFUSCATION_ALL = OBFUSCATION_ALL + GO
