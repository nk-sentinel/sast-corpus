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
