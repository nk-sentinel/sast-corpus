"""Templates for the languages the breadth slice was missing.

Java had only SQL injection despite being the primary language of the platform
this corpus was built to evaluate. Kotlin, Rust, C, C++ and Swift had nothing at
all, which is the worst kind of gap: a language with no cases contributes
nothing to a scorecard, so a tool with no support for it scores exactly like a
tool that found everything.

Java fixtures here compile with the JDK alone and are marked build-required, so
engines that analyse compiled artifacts — Fortify, Coverity, Veracode — can
actually see them. Previously only six cases in the whole corpus were visible to
those tools.
"""

from gen.generate import Variant
from gen.templates import CMDI, DESER, PATHT, SQLI, template

JAVAC = "build/java/javac.sh"


def _java(slug, weakness, vuln, safe, sink, safe_sink, safe_sanitizer,
          vuln_rationale, safe_rationale, extra=None):
    built = template(
        slug, "java", "java", weakness, None, "inter-file",
        vuln, "Runner.java", sink, vuln_rationale,
        safe, "Runner.java", safe_sink, safe_sanitizer, safe_rationale,
        "Cli.java", "static void main", extra=extra,
    )
    built.build_required = True
    built.build_recipe = JAVAC
    return built


JAVA_CLI = (
    "package app;\n\n"
    "public class Cli {\n"
    "    public static void main(String[] args) throws Exception {\n"
    "        System.out.println(Runner.handle(args[0]));\n"
    "    }\n"
    "}\n"
)

JAVA = [
    _java(
        "java-cmdi@shell-string", CMDI,
        {"Cli.java": JAVA_CLI,
         "Runner.java": (
             "package app;\n\n"
             "import java.io.InputStream;\n\n"
             "public class Runner {\n"
             "    static String handle(String name) throws Exception {\n"
             "        String line = \"tar -cf backup.tar \" + name;\n"
             "        Process process = Runtime.getRuntime().exec(new String[] {\"sh\", \"-c\", line});\n"
             "        InputStream stream = process.getInputStream();\n"
             "        return new String(stream.readAllBytes());\n"
             "    }\n"
             "}\n")},
        {"Cli.java": JAVA_CLI,
         "Runner.java": (
             "package app;\n\n"
             "import java.io.InputStream;\n"
             "import java.util.List;\n\n"
             "public class Runner {\n"
             "    static String handle(String name) throws Exception {\n"
             "        ProcessBuilder builder = new ProcessBuilder(List.of(\"tar\", \"-cf\", \"backup.tar\", name));\n"
             "        Process process = builder.start();\n"
             "        InputStream stream = process.getInputStream();\n"
             "        return new String(stream.readAllBytes());\n"
             "    }\n"
             "}\n")},
        "Runtime.getRuntime().exec", "ProcessBuilder builder", "framework-implicit",
        "the assembled string is handed to a shell, so a semicolon in the argument starts a second command",
        "an argument list is passed straight to the binary with no shell able to reinterpret it",
    ),
    _java(
        "java-path@unvalidated-join", PATHT,
        {"Cli.java": JAVA_CLI,
         "Runner.java": (
             "package app;\n\n"
             "import java.nio.file.Files;\n"
             "import java.nio.file.Path;\n\n"
             "public class Runner {\n"
             "    private static final String BASE = \"/srv/reports\";\n\n"
             "    static String handle(String name) throws Exception {\n"
             "        Path target = Path.of(BASE, name);\n"
             "        return new String(Files.readAllBytes(target));\n"
             "    }\n"
             "}\n")},
        {"Cli.java": JAVA_CLI,
         "Runner.java": (
             "package app;\n\n"
             "import java.nio.file.Files;\n"
             "import java.nio.file.Path;\n"
             "import java.nio.file.Paths;\n\n"
             "public class Runner {\n"
             "    private static final Path BASE = Paths.get(\"/srv/reports\").toAbsolutePath().normalize();\n\n"
             "    static String handle(String name) throws Exception {\n"
             "        Path target = BASE.resolve(Paths.get(name).getFileName()).normalize();\n"
             "        if (!target.startsWith(BASE)) {\n"
             "            throw new IllegalArgumentException(name);\n"
             "        }\n"
             "        return new String(Files.readAllBytes(target));\n"
             "    }\n"
             "}\n")},
        "Files.readAllBytes(target)", "Files.readAllBytes(target)", "custom-effective",
        "Path.of keeps .. segments and returns the argument outright when it is absolute, so the read leaves the base",
        "only the final name component is kept and the normalised result is checked to remain under the base",
    ),
    _java(
        "java-deser@objectinputstream", DESER,
        {"Cli.java": JAVA_CLI,
         "Runner.java": (
             "package app;\n\n"
             "import java.io.ByteArrayInputStream;\n"
             "import java.io.ObjectInputStream;\n"
             "import java.util.Base64;\n\n"
             "public class Runner {\n"
             "    static String handle(String blob) throws Exception {\n"
             "        byte[] raw = Base64.getDecoder().decode(blob);\n"
             "        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(raw));\n"
             "        return String.valueOf(stream.readObject());\n"
             "    }\n"
             "}\n")},
        {"Cli.java": JAVA_CLI,
         "Runner.java": (
             "package app;\n\n"
             "import java.util.Base64;\n\n"
             "public class Runner {\n"
             "    static String handle(String blob) throws Exception {\n"
             "        byte[] raw = Base64.getDecoder().decode(blob);\n"
             "        return new String(raw).trim();\n"
             "    }\n"
             "}\n")},
        "stream.readObject()", "new String(raw).trim()", "custom-effective",
        "readObject reconstructs whatever classes the stream names and runs their readObject hooks while doing it",
        "the bytes are treated as text and no object graph is reconstructed at all",
    ),
]

# --- rust -------------------------------------------------------------------

RUST = [
    template(
        "rs-cmdi@shell-string", "rust", "rs", CMDI, None, "inter-file",
        {"main.rs": "mod runner;\n\nfn main() {\n    let name = std::env::args().nth(1).unwrap_or_default();\n    println!(\"{}\", runner::archive(&name));\n}\n",
         "runner.rs": (
             "use std::process::Command;\n\n"
             "pub fn archive(name: &str) -> String {\n"
             "    let line = format!(\"tar -cf backup.tar {}\", name);\n"
             "    let out = Command::new(\"sh\").arg(\"-c\").arg(line).output().unwrap();\n"
             "    String::from_utf8_lossy(&out.stdout).to_string()\n"
             "}\n")},
        "runner.rs", "Command::new(\"sh\")",
        "the formatted string is handed to a shell, so a semicolon in the argument starts a second command",
        {"main.rs": "mod runner;\n\nfn main() {\n    let name = std::env::args().nth(1).unwrap_or_default();\n    println!(\"{}\", runner::archive(&name));\n}\n",
         "runner.rs": (
             "use std::process::Command;\n\n"
             "pub fn archive(name: &str) -> String {\n"
             "    let out = Command::new(\"tar\").args([\"-cf\", \"backup.tar\", name]).output().unwrap();\n"
             "    String::from_utf8_lossy(&out.stdout).to_string()\n"
             "}\n")},
        "runner.rs", "Command::new(\"tar\")", "framework-implicit",
        "the binary is invoked directly with separate arguments and no shell is involved",
        "main.rs", "fn main",
    ),
    template(
        "rs-path@unvalidated-join", "rust", "rs", PATHT, None, "inter-file",
        {"main.rs": "mod reader;\n\nfn main() {\n    let name = std::env::args().nth(1).unwrap_or_default();\n    println!(\"{}\", reader::contents(&name));\n}\n",
         "reader.rs": (
             "use std::fs;\n"
             "use std::path::Path;\n\n"
             "const BASE: &str = \"/srv/reports\";\n\n"
             "pub fn contents(name: &str) -> String {\n"
             "    let target = Path::new(BASE).join(name);\n"
             "    fs::read_to_string(target).unwrap_or_default()\n"
             "}\n")},
        "reader.rs", "fs::read_to_string(target)",
        "join keeps .. segments and replaces the base outright when the argument is absolute",
        {"main.rs": "mod reader;\n\nfn main() {\n    let name = std::env::args().nth(1).unwrap_or_default();\n    println!(\"{}\", reader::contents(&name));\n}\n",
         "reader.rs": (
             "use std::fs;\n"
             "use std::path::Path;\n\n"
             "const BASE: &str = \"/srv/reports\";\n\n"
             "pub fn contents(name: &str) -> String {\n"
             "    let leaf = match Path::new(name).file_name() {\n"
             "        Some(value) => value.to_owned(),\n"
             "        None => return String::new(),\n"
             "    };\n"
             "    let target = Path::new(BASE).join(leaf);\n"
             "    fs::read_to_string(target).unwrap_or_default()\n"
             "}\n")},
        "reader.rs", "fs::read_to_string(target)", "custom-effective",
        "file_name discards every directory component, so nothing but a leaf name reaches the join",
        "main.rs", "fn main",
    ),
]

# --- c and c++ --------------------------------------------------------------

C = [
    template(
        "c-cmdi@system-call", "c", "c", CMDI, None, "inter-file",
        {"main.c": "#include \"runner.h\"\n\nint main(int argc, char **argv) {\n    if (argc < 2) {\n        return 1;\n    }\n    return archive(argv[1]);\n}\n",
         "runner.h": "#ifndef RUNNER_H\n#define RUNNER_H\nint archive(const char *name);\n#endif\n",
         "runner.c": (
             "#include <stdio.h>\n"
             "#include <stdlib.h>\n"
             "#include \"runner.h\"\n\n"
             "int archive(const char *name) {\n"
             "    char line[512];\n"
             "    snprintf(line, sizeof(line), \"tar -cf backup.tar %s\", name);\n"
             "    return system(line);\n"
             "}\n")},
        "runner.c", "return system(line)",
        "system passes the assembled string to a shell, so a semicolon in the argument starts a second command",
        {"main.c": "#include \"runner.h\"\n\nint main(int argc, char **argv) {\n    if (argc < 2) {\n        return 1;\n    }\n    return archive(argv[1]);\n}\n",
         "runner.h": "#ifndef RUNNER_H\n#define RUNNER_H\nint archive(const char *name);\n#endif\n",
         "runner.c": (
             "#include <stdio.h>\n"
             "#include <unistd.h>\n"
             "#include <sys/wait.h>\n"
             "#include \"runner.h\"\n\n"
             "int archive(const char *name) {\n"
             "    pid_t pid = fork();\n"
             "    if (pid == 0) {\n"
             "        char *const argv[] = {\"tar\", \"-cf\", \"backup.tar\", (char *) name, NULL};\n"
             "        execvp(\"tar\", argv);\n"
             "        _exit(127);\n"
             "    }\n"
             "    int status = 0;\n"
             "    waitpid(pid, &status, 0);\n"
             "    return status;\n"
             "}\n")},
        "runner.c", "execvp(\"tar\", argv)", "framework-implicit",
        "execvp replaces the process image with the named binary and never consults a shell",
        "main.c", "int main",
    ),
    template(
        "c-path@unvalidated-concat", "c", "c", PATHT, None, "inter-file",
        {"main.c": "#include \"reader.h\"\n\nint main(int argc, char **argv) {\n    if (argc < 2) {\n        return 1;\n    }\n    return contents(argv[1]);\n}\n",
         "reader.h": "#ifndef READER_H\n#define READER_H\nint contents(const char *name);\n#endif\n",
         "reader.c": (
             "#include <stdio.h>\n"
             "#include \"reader.h\"\n\n"
             "int contents(const char *name) {\n"
             "    char target[512];\n"
             "    snprintf(target, sizeof(target), \"/srv/reports/%s\", name);\n"
             "    FILE *handle = fopen(target, \"r\");\n"
             "    if (handle == NULL) {\n"
             "        return 1;\n"
             "    }\n"
             "    fclose(handle);\n"
             "    return 0;\n"
             "}\n")},
        "reader.c", "fopen(target, \"r\")",
        "the argument is pasted after the base directory, so .. segments walk out of it",
        {"main.c": "#include \"reader.h\"\n\nint main(int argc, char **argv) {\n    if (argc < 2) {\n        return 1;\n    }\n    return contents(argv[1]);\n}\n",
         "reader.h": "#ifndef READER_H\n#define READER_H\nint contents(const char *name);\n#endif\n",
         "reader.c": (
             "#include <stdio.h>\n"
             "#include <string.h>\n"
             "#include \"reader.h\"\n\n"
             "int contents(const char *name) {\n"
             "    const char *leaf = strrchr(name, '/');\n"
             "    leaf = (leaf == NULL) ? name : leaf + 1;\n"
             "    if (strstr(leaf, \"..\") != NULL) {\n"
             "        return 1;\n"
             "    }\n"
             "    char target[512];\n"
             "    snprintf(target, sizeof(target), \"/srv/reports/%s\", leaf);\n"
             "    FILE *handle = fopen(target, \"r\");\n"
             "    if (handle == NULL) {\n"
             "        return 1;\n"
             "    }\n"
             "    fclose(handle);\n"
             "    return 0;\n"
             "}\n")},
        "reader.c", "fopen(target, \"r\")", "custom-effective",
        "everything up to the last separator is dropped and a remaining dot-dot is rejected outright",
        "main.c", "int main",
    ),
]

CPP = [
    template(
        "cpp-cmdi@system-call", "cpp", "cpp", CMDI, None, "inter-file",
        {"main.cpp": "#include <string>\n#include \"runner.hpp\"\n\nint main(int argc, char **argv) {\n    if (argc < 2) {\n        return 1;\n    }\n    return archive(std::string(argv[1]));\n}\n",
         "runner.hpp": "#pragma once\n#include <string>\nint archive(const std::string &name);\n",
         "runner.cpp": (
             "#include <cstdlib>\n"
             "#include <string>\n"
             "#include \"runner.hpp\"\n\n"
             "int archive(const std::string &name) {\n"
             "    std::string line = \"tar -cf backup.tar \" + name;\n"
             "    return std::system(line.c_str());\n"
             "}\n")},
        "runner.cpp", "std::system(line.c_str())",
        "std::system passes the assembled string to a shell, so a semicolon in the argument starts a second command",
        {"main.cpp": "#include <string>\n#include \"runner.hpp\"\n\nint main(int argc, char **argv) {\n    if (argc < 2) {\n        return 1;\n    }\n    return archive(std::string(argv[1]));\n}\n",
         "runner.hpp": "#pragma once\n#include <string>\nint archive(const std::string &name);\n",
         "runner.cpp": (
             "#include <string>\n"
             "#include <unistd.h>\n"
             "#include <sys/wait.h>\n"
             "#include \"runner.hpp\"\n\n"
             "int archive(const std::string &name) {\n"
             "    pid_t pid = fork();\n"
             "    if (pid == 0) {\n"
             "        char *const argv[] = {const_cast<char *>(\"tar\"), const_cast<char *>(\"-cf\"),\n"
             "                              const_cast<char *>(\"backup.tar\"),\n"
             "                              const_cast<char *>(name.c_str()), nullptr};\n"
             "        execvp(\"tar\", argv);\n"
             "        _exit(127);\n"
             "    }\n"
             "    int status = 0;\n"
             "    waitpid(pid, &status, 0);\n"
             "    return status;\n"
             "}\n")},
        "runner.cpp", "execvp(\"tar\", argv)", "framework-implicit",
        "execvp replaces the process image with the named binary and never consults a shell",
        "main.cpp", "int main",
    ),
]

# --- kotlin and swift (no toolchain here, so source-only) -------------------

KOTLIN = [
    template(
        "kt-sqli@concat-statement", "kotlin", "kt", SQLI, None, "inter-file",
        {"Cli.kt": "package app\n\nfun main(args: Array<String>) {\n    println(lookup(args[0]))\n}\n",
         "Store.kt": (
             "package app\n\n"
             "import java.sql.DriverManager\n\n"
             "fun lookup(code: String): String {\n"
             "    val connection = DriverManager.getConnection(\"jdbc:h2:mem:app\")\n"
             "    val statement = connection.createStatement()\n"
             "    val results = statement.executeQuery(\"SELECT status FROM orders WHERE code = '\" + code + \"'\")\n"
             "    return if (results.next()) results.getString(1) else \"\"\n"
             "}\n")},
        "Store.kt", "statement.executeQuery",
        "the argument is concatenated into the statement text, which the driver then parses as code",
        {"Cli.kt": "package app\n\nfun main(args: Array<String>) {\n    println(lookup(args[0]))\n}\n",
         "Store.kt": (
             "package app\n\n"
             "import java.sql.DriverManager\n\n"
             "fun lookup(code: String): String {\n"
             "    val connection = DriverManager.getConnection(\"jdbc:h2:mem:app\")\n"
             "    val statement = connection.prepareStatement(\"SELECT status FROM orders WHERE code = ?\")\n"
             "    statement.setString(1, code)\n"
             "    val results = statement.executeQuery()\n"
             "    return if (results.next()) results.getString(1) else \"\"\n"
             "}\n")},
        "Store.kt", "statement.executeQuery()", "framework-implicit",
        "the value is bound to a prepared statement, so the statement text never contains it",
        "Cli.kt", "fun main",
    ),
    template(
        "kt-cmdi@shell-string", "kotlin", "kt", CMDI, None, "inter-file",
        {"Cli.kt": "package app\n\nfun main(args: Array<String>) {\n    println(archive(args[0]))\n}\n",
         "Runner.kt": (
             "package app\n\n"
             "fun archive(name: String): String {\n"
             "    val line = \"tar -cf backup.tar \" + name\n"
             "    val process = ProcessBuilder(\"sh\", \"-c\", line).start()\n"
             "    return process.inputStream.readBytes().decodeToString()\n"
             "}\n")},
        "Runner.kt", "ProcessBuilder(\"sh\"",
        "the assembled string is handed to a shell, so a semicolon in the argument starts a second command",
        {"Cli.kt": "package app\n\nfun main(args: Array<String>) {\n    println(archive(args[0]))\n}\n",
         "Runner.kt": (
             "package app\n\n"
             "fun archive(name: String): String {\n"
             "    val process = ProcessBuilder(listOf(\"tar\", \"-cf\", \"backup.tar\", name)).start()\n"
             "    return process.inputStream.readBytes().decodeToString()\n"
             "}\n")},
        "Runner.kt", "ProcessBuilder(listOf(", "framework-implicit",
        "an argument list goes straight to the binary with no shell able to reinterpret it",
        "Cli.kt", "fun main",
    ),
]

SWIFT = [
    template(
        "sw-cmdi@shell-string", "swift", "swift", CMDI, None, "inter-file",
        {"main.swift": "import Foundation\n\nlet name = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : \"\"\nprint(archive(name))\n",
         "Runner.swift": (
             "import Foundation\n\n"
             "func archive(_ name: String) -> String {\n"
             "    let line = \"tar -cf backup.tar \" + name\n"
             "    let task = Process()\n"
             "    task.executableURL = URL(fileURLWithPath: \"/bin/sh\")\n"
             "    task.arguments = [\"-c\", line]\n"
             "    try? task.run()\n"
             "    return line\n"
             "}\n")},
        "Runner.swift", "task.arguments = [\"-c\", line]",
        "the assembled string is handed to a shell, so a semicolon in the argument starts a second command",
        {"main.swift": "import Foundation\n\nlet name = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : \"\"\nprint(archive(name))\n",
         "Runner.swift": (
             "import Foundation\n\n"
             "func archive(_ name: String) -> String {\n"
             "    let task = Process()\n"
             "    task.executableURL = URL(fileURLWithPath: \"/usr/bin/tar\")\n"
             "    task.arguments = [\"-cf\", \"backup.tar\", name]\n"
             "    try? task.run()\n"
             "    return name\n"
             "}\n")},
        "Runner.swift", "task.arguments = [\"-cf\"", "framework-implicit",
        "the binary is named directly and the value is one separate argument, with no shell involved",
        "main.swift", "print(archive(name))",
    ),
]

MORE_ALL = JAVA + RUST + C + CPP + KOTLIN + SWIFT
