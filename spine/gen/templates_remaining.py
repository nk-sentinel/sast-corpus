"""The last five CWE Top 25 classes: upload, input validation, access control,
argument injection and resource exhaustion.

Two of these needed care to be distinct from cases already in the corpus.

**CWE-77 is not CWE-78 again.** The corpus already pairs a shell string against
an argument vector, and every one of those safe siblings says "no shell, so the
value cannot become syntax". That is true of *shell* syntax and false in
general: `git clone <url>` with no shell at all will execute a program if the
URL begins with `--upload-pack=`, because the value became an option rather than
an operand. Argument injection is the case that shows an argument vector is a
defence against one thing and not against everything, and a tool keyed on
"vectored call means safe" reports nothing.

**CWE-284 is not CWE-862 again.** Missing authorization is an absent check.
Improper access control here is a check that reads its input from somewhere the
caller controls — a role taken off a request header — so the check runs, passes,
and decides nothing.
"""

from gen.templates import template

FILE_UPLOAD = ("CWE-434", ["CWE-434", "CWE-646", "CWE-73"], "A04")
INPUT_VALIDATION = ("CWE-20", ["CWE-20", "CWE-1284", "CWE-129"], "A04")
ACCESS_CONTROL = ("CWE-284", ["CWE-284", "CWE-862", "CWE-863", "CWE-807"], "A01")
COMMAND_INJECTION = ("CWE-77", ["CWE-77", "CWE-88", "CWE-78"], "A03")
RESOURCE_LIMIT = ("CWE-770", ["CWE-770", "CWE-400", "CWE-789"], "A04")

REMAINING = [
    template(
        "go-arginject@argument-injection", "go", "go", COMMAND_INJECTION, None, "inter-file",
        {"handler.go": "package app\n\nfunc Show(source string) ([]byte, error) {\n\treturn Mirror(source)\n}\n",
         "runner.go": (
             "package app\n\n"
             "import (\n\t\"os/exec\"\n)\n\n"
             "func Mirror(source string) ([]byte, error) {\n"
             "\treturn exec.Command(\"git\", \"clone\", source, \"/tmp/mirror\").Output()\n}\n")},
        "runner.go", "exec.Command(\"git\", \"clone\", source",
        "no shell is involved and the value is a separate argument, which is the defence every "
        "command-injection safe sibling in this corpus relies on. It does not hold here: a value "
        "beginning with --upload-pack= is read by git as an option rather than a repository, and "
        "runs the program it names. The vector protects against shell syntax and not against "
        "the callee's own option parsing",
        {"handler.go": "package app\n\nfunc Show(source string) ([]byte, error) {\n\treturn Mirror(source)\n}\n",
         "runner.go": (
             "package app\n\n"
             "import (\n\t\"errors\"\n\t\"os/exec\"\n\t\"strings\"\n)\n\n"
             "func Mirror(source string) ([]byte, error) {\n"
             "\tif strings.HasPrefix(source, \"-\") {\n"
             "\t\treturn nil, errors.New(\"rejected\")\n\t}\n"
             "\treturn exec.Command(\"git\", \"clone\", \"--\", source, \"/tmp/mirror\").Output()\n}\n")},
        "runner.go", "exec.Command(\"git\", \"clone\", \"--\"", "custom-effective",
        "the leading dash is rejected and a -- separator ends option parsing, so the value can "
        "only be read as an operand",
        "handler.go", "func Show",
    ),
    template(
        "java-arginject@argument-injection", "java", "java", COMMAND_INJECTION, None, "inter-file",
        {"Cli.java": ("package app;\n\npublic class Cli {\n"
                      "    public static void main(String[] args) throws Exception {\n"
                      "        System.out.println(Runner.handle(args[0]));\n    }\n}\n"),
         "Runner.java": (
             "package app;\n\n"
             "import java.io.InputStream;\n"
             "import java.util.List;\n\n"
             "public class Runner {\n"
             "    static String handle(String source) throws Exception {\n"
             "        ProcessBuilder builder = new ProcessBuilder(List.of(\"git\", \"clone\", source));\n"
             "        Process process = builder.start();\n"
             "        InputStream stream = process.getInputStream();\n"
             "        return new String(stream.readAllBytes());\n    }\n}\n")},
        "Runner.java", "new ProcessBuilder(List.of(\"git\"",
        "a ProcessBuilder with an argument list, which is the canonical fix for command "
        "injection and is applied correctly here. The value still reaches git's option parser, "
        "so --upload-pack= executes a program without any shell being involved",
        {"Cli.java": ("package app;\n\npublic class Cli {\n"
                      "    public static void main(String[] args) throws Exception {\n"
                      "        System.out.println(Runner.handle(args[0]));\n    }\n}\n"),
         "Runner.java": (
             "package app;\n\n"
             "import java.io.InputStream;\n"
             "import java.util.List;\n\n"
             "public class Runner {\n"
             "    static String handle(String source) throws Exception {\n"
             "        if (source.startsWith(\"-\")) {\n"
             "            throw new IllegalArgumentException(source);\n        }\n"
             "        ProcessBuilder builder = new ProcessBuilder(\n"
             "                List.of(\"git\", \"clone\", \"--\", source));\n"
             "        Process process = builder.start();\n"
             "        InputStream stream = process.getInputStream();\n"
             "        return new String(stream.readAllBytes());\n    }\n}\n")},
        "Runner.java", "List.of(\"git\", \"clone\", \"--\"", "custom-effective",
        "the value cannot begin with a dash and the separator closes option parsing",
        "Cli.java", "static void main",
    ),
    template(
        "py-upload@unchecked-upload", "python", "py", FILE_UPLOAD, "flask", "inter-file",
        {"handler.py": "from storage import save\n\n\ndef show(filename, payload):\n    return save(filename, payload)\n",
         "storage.py": (
             "import os\n\n"
             "UPLOADS = \"/srv/uploads\"\n\n\n"
             "def save(filename, payload):\n"
             "    target = os.path.join(UPLOADS, filename)\n"
             "    with open(target, \"wb\") as handle:\n"
             "        handle.write(payload)\n"
             "    return target\n")},
        "storage.py", "with open(target, \"wb\")",
        "the client chooses both the name and the extension, so a .jsp or .php lands in a "
        "directory the server may execute from, and the name may traverse out of it as well",
        {"handler.py": "from storage import save\n\n\ndef show(filename, payload):\n    return save(filename, payload)\n",
         "storage.py": (
             "import os\n"
             "import uuid\n\n"
             "UPLOADS = \"/srv/uploads\"\n"
             "PERMITTED = {\".png\", \".jpg\", \".pdf\"}\n\n\n"
             "def save(filename, payload):\n"
             "    extension = os.path.splitext(filename)[1].lower()\n"
             "    if extension not in PERMITTED:\n"
             "        raise ValueError(filename)\n"
             "    target = os.path.join(UPLOADS, uuid.uuid4().hex + extension)\n"
             "    with open(target, \"wb\") as handle:\n"
             "        handle.write(payload)\n"
             "    return target\n")},
        "storage.py", "with open(target, \"wb\")", "custom-effective",
        "the extension is checked against an allowlist and the stored name is generated, so "
        "neither the type nor the path comes from the client",
        "handler.py", "def show",
        extra=None,
    ),
    template(
        "py-upload-blocklist@blocklist-extension", "python", "py", FILE_UPLOAD, "flask",
        "inter-file",
        {"handler.py": "from storage import save\n\n\ndef show(filename, payload):\n    return save(filename, payload)\n",
         "storage.py": (
             "import os\n\n"
             "UPLOADS = \"/srv/uploads\"\n"
             "REFUSED = {\".php\", \".jsp\", \".exe\"}\n\n\n"
             "def save(filename, payload):\n"
             "    extension = os.path.splitext(filename)[1].lower()\n"
             "    if extension in REFUSED:\n"
             "        raise ValueError(filename)\n"
             "    target = os.path.join(UPLOADS, filename)\n"
             "    with open(target, \"wb\") as handle:\n"
             "        handle.write(payload)\n"
             "    return target\n")},
        "storage.py", "with open(target, \"wb\")",
        "a blocklist of three extensions. It misses .phtml, .php5, .jspx, .aspx, a trailing dot "
        "or space on some filesystems, and every extension nobody thought of — and the stored "
        "name is still the client's, so the path is not constrained either",
        {"handler.py": "from storage import save\n\n\ndef show(filename, payload):\n    return save(filename, payload)\n",
         "storage.py": (
             "import os\n"
             "import uuid\n\n"
             "UPLOADS = \"/srv/uploads\"\n"
             "PERMITTED = {\".png\", \".jpg\", \".pdf\"}\n\n\n"
             "def save(filename, payload):\n"
             "    extension = os.path.splitext(filename)[1].lower()\n"
             "    if extension not in PERMITTED:\n"
             "        raise ValueError(filename)\n"
             "    target = os.path.join(UPLOADS, uuid.uuid4().hex + extension)\n"
             "    with open(target, \"wb\") as handle:\n"
             "        handle.write(payload)\n"
             "    return target\n")},
        "storage.py", "with open(target, \"wb\")", "custom-effective",
        "an allowlist decides what is permitted rather than a list of what is not",
        "handler.py", "def show",
    ),
    template(
        "java-clientrole@client-controlled-role", "java", "java", ACCESS_CONTROL, None,
        "inter-file",
        {"Cli.java": ("package app;\n\npublic class Cli {\n"
                      "    public static void main(String[] args) {\n"
                      "        System.out.println(Gate.handle(args[0], args[1]));\n    }\n}\n"),
         "Gate.java": (
             "package app;\n\n"
             "public class Gate {\n"
             "    static String handle(String headerRole, String tenant) {\n"
             "        if (\"admin\".equals(headerRole)) {\n"
             "            return \"keys-\" + tenant;\n        }\n"
             "        return \"denied\";\n    }\n}\n")},
        "Gate.java", "if (\"admin\".equals(headerRole))",
        "the check runs, compares correctly and passes only for the admin value — and decides "
        "nothing, because the role it reads arrives in a request header the caller sets. An "
        "analysis looking for a missing check finds a present one",
        {"Cli.java": ("package app;\n\npublic class Cli {\n"
                      "    public static void main(String[] args) {\n"
                      "        System.out.println(Gate.handle(Session.roleOf(args[0]), args[1]));\n    }\n}\n"),
         "Gate.java": (
             "package app;\n\n"
             "public class Gate {\n"
             "    static String handle(String sessionRole, String tenant) {\n"
             "        if (\"admin\".equals(sessionRole)) {\n"
             "            return \"keys-\" + tenant;\n        }\n"
             "        return \"denied\";\n    }\n}\n"),
         "Session.java": (
             "package app;\n\n"
             "import java.util.Map;\n\n"
             "public final class Session {\n"
             "    private static final Map<String, String> ROLES = Map.of(\"s-1\", \"admin\");\n\n"
             "    private Session() {\n    }\n\n"
             "    static String roleOf(String sessionId) {\n"
             "        return ROLES.getOrDefault(sessionId, \"guest\");\n    }\n}\n")},
        "Gate.java", "if (\"admin\".equals(sessionRole))", "custom-effective",
        "the identical comparison, against a role resolved server-side from the session rather "
        "than read from the request",
        "Cli.java", "static void main",
    ),
    template(
        "py-quantity@unvalidated-numeric-range", "python", "py", INPUT_VALIDATION, "flask",
        "inter-file",
        {"handler.py": "from ledger import total\n\n\ndef show(quantity):\n    return total(int(quantity))\n",
         "ledger.py": (
             "UNIT_PRICE = 1250\n\n\n"
             "def total(quantity):\n"
             "    return UNIT_PRICE * quantity\n")},
        "ledger.py", "return UNIT_PRICE * quantity",
        "the quantity is parsed and used with no range check. A negative value produces a "
        "negative total, which downstream becomes a credit rather than a charge — the parse "
        "succeeded, the arithmetic is correct, and nothing in either file is malformed",
        {"handler.py": "from ledger import total\n\n\ndef show(quantity):\n    return total(int(quantity))\n",
         "ledger.py": (
             "UNIT_PRICE = 1250\n"
             "MAX_QUANTITY = 100\n\n\n"
             "def total(quantity):\n"
             "    if quantity < 1 or quantity > MAX_QUANTITY:\n"
             "        raise ValueError(quantity)\n"
             "    return UNIT_PRICE * quantity\n")},
        "ledger.py", "return UNIT_PRICE * quantity", "custom-effective",
        "both ends of the range are enforced before the value is used",
        "handler.py", "def show",
    ),
    template(
        "py-unbounded-read@unbounded-allocation", "python", "py", RESOURCE_LIMIT, "flask",
        "inter-file",
        {"handler.py": "from intake import receive\n\n\ndef show(stream):\n    return receive(stream)\n",
         "intake.py": (
             "def receive(stream):\n"
             "    payload = stream.read()\n"
             "    return len(payload)\n")},
        "intake.py", "payload = stream.read()",
        "the whole request body is read into memory with no cap, so the peak allocation is "
        "whatever the caller chooses to send and a handful of concurrent requests exhausts the "
        "process",
        {"handler.py": "from intake import receive\n\n\ndef show(stream):\n    return receive(stream)\n",
         "intake.py": (
             "MAX_BYTES = 1048576\n\n\n"
             "def receive(stream):\n"
             "    payload = stream.read(MAX_BYTES + 1)\n"
             "    if len(payload) > MAX_BYTES:\n"
             "        raise ValueError(\"too large\")\n"
             "    return len(payload)\n")},
        "intake.py", "payload = stream.read(MAX_BYTES + 1)", "custom-effective",
        "the read is capped one byte above the limit so the overflow is detectable, and the "
        "request is rejected rather than buffered",
        "handler.py", "def show",
    ),
    template(
        "java-unbounded-read@unbounded-allocation", "java", "java", RESOURCE_LIMIT, None,
        "inter-file",
        {"Cli.java": ("package app;\n\npublic class Cli {\n"
                      "    public static void main(String[] args) throws Exception {\n"
                      "        System.out.println(Intake.handle(System.in));\n    }\n}\n"),
         "Intake.java": (
             "package app;\n\n"
             "import java.io.InputStream;\n\n"
             "public class Intake {\n"
             "    static int handle(InputStream stream) throws Exception {\n"
             "        byte[] payload = stream.readAllBytes();\n"
             "        return payload.length;\n    }\n}\n")},
        "Intake.java", "stream.readAllBytes()",
        "readAllBytes buffers the entire stream regardless of size, so the allocation is under "
        "the caller's control",
        {"Cli.java": ("package app;\n\npublic class Cli {\n"
                      "    public static void main(String[] args) throws Exception {\n"
                      "        System.out.println(Intake.handle(System.in));\n    }\n}\n"),
         "Intake.java": (
             "package app;\n\n"
             "import java.io.IOException;\n"
             "import java.io.InputStream;\n\n"
             "public class Intake {\n"
             "    private static final int MAX_BYTES = 1048576;\n\n"
             "    static int handle(InputStream stream) throws Exception {\n"
             "        byte[] payload = stream.readNBytes(MAX_BYTES + 1);\n"
             "        if (payload.length > MAX_BYTES) {\n"
             "            throw new IOException(\"too large\");\n        }\n"
             "        return payload.length;\n    }\n}\n")},
        "Intake.java", "stream.readNBytes(MAX_BYTES + 1)", "custom-effective",
        "readNBytes bounds the allocation and one extra byte makes an oversized body detectable",
        "Cli.java", "static void main",
    ),
]

REMAINING_ALL = REMAINING


LOG_EXPOSURE = ("CWE-532", ["CWE-532", "CWE-200", "CWE-215"], "A09")
LOG_INJECTION = ("CWE-117", ["CWE-117", "CWE-93", "CWE-116"], "A09")

LOGGING = [
    template(
        "py-log-secrets@credentials-in-log", "python", "py", LOG_EXPOSURE, None, "inter-file",
        {"handler.py": "from audit import record\n\n\ndef show(user, password):\n    return record(user, password)\n",
         "audit.py": (
             "import logging\n\n"
             "logger = logging.getLogger(__name__)\n\n\n"
             "def record(user, password):\n"
             "    logger.info(\"sign-in user=%s password=%s\", user, password)\n"
             "    return True\n")},
        "audit.py", "logger.info(\"sign-in user=%s password=%s\"",
        "the credential is written to the log, where it outlives the request, travels to "
        "whatever aggregator ships the logs, and is readable by everyone with operational "
        "access rather than only by the authentication path",
        {"handler.py": "from audit import record\n\n\ndef show(user, password):\n    return record(user, password)\n",
         "audit.py": (
             "import logging\n\n"
             "logger = logging.getLogger(__name__)\n\n\n"
             "def record(user, password):\n"
             "    logger.info(\"sign-in user=%s\", user)\n"
             "    return True\n")},
        "audit.py", "logger.info(\"sign-in user=%s\"", "custom-effective",
        "the identity is logged and the credential is not, which is the whole of the fix",
        "handler.py", "def show",
    ),
    template(
        "java-log-injection@unsanitised-log-entry", "java", "java", LOG_INJECTION, None,
        "inter-file",
        {"Cli.java": ("package app;\n\npublic class Cli {\n"
                      "    public static void main(String[] args) {\n"
                      "        Audit.handle(args[0]);\n    }\n}\n"),
         "Audit.java": (
             "package app;\n\n"
             "import java.util.logging.Logger;\n\n"
             "public class Audit {\n"
             "    private static final Logger LOGGER = Logger.getLogger(\"audit\");\n\n"
             "    static void handle(String user) {\n"
             "        LOGGER.info(\"sign-in attempt for \" + user);\n    }\n}\n")},
        "Audit.java", "LOGGER.info(\"sign-in attempt for \"",
        "a newline inside the value starts a second log line, so the caller writes entries the "
        "application never emitted. Anything reading those logs afterwards — an analyst, an "
        "alerting rule, a SIEM correlation — is reading attacker-authored records as though the "
        "system had produced them",
        {"Cli.java": ("package app;\n\npublic class Cli {\n"
                      "    public static void main(String[] args) {\n"
                      "        Audit.handle(args[0]);\n    }\n}\n"),
         "Audit.java": (
             "package app;\n\n"
             "import java.util.logging.Logger;\n\n"
             "public class Audit {\n"
             "    private static final Logger LOGGER = Logger.getLogger(\"audit\");\n\n"
             "    static void handle(String user) {\n"
             "        String flattened = user.replace('\\n', '_').replace('\\r', '_');\n"
             "        LOGGER.info(\"sign-in attempt for \" + flattened);\n    }\n}\n")},
        "Audit.java", "LOGGER.info(\"sign-in attempt for \"", "custom-effective",
        "both line terminators are replaced before the value reaches the log, so it cannot "
        "become more than one record",
        "Cli.java", "static void main",
    ),
]

REMAINING_ALL = REMAINING_ALL + LOGGING
