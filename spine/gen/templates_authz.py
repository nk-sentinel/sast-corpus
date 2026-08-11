"""Authorization and authentication templates.

Five of the 2025 CWE Top 25 are access-control weaknesses — missing
authorization, incorrect authorization, improper access control, missing
authentication for a critical function, and authorization bypass through a
user-controlled key — and the corpus covered none of them.

**These are included knowing that static analysis is weak here, and that is
deliberate.** A missing authorization check has no syntactic surface on the
vulnerable side: the code is a perfectly ordinary handler, and what makes it a
defect is an intent the source never states. A tool that finds it has done
something genuinely difficult. A tool that misses it has done what the
literature predicts. Either way the corpus should be able to say which, and it
could not before.

Two of these are within reach and worth separating from the rest. CWE-639, the
IDOR shape, is a dataflow question — a request-supplied identifier reaching a
lookup with no ownership comparison — and taint-aware tools are positioned to
catch it. A handler missing an annotation its siblings all carry is a
consistency question, which is also tractable.

The traps matter as much here as anywhere: an endpoint that is *meant* to be
public is not a finding, and a tool that flags every unannotated handler will
bury a team in noise on exactly the routes that should be open.
"""

from gen.templates import template

MISSING_AUTHZ = ("CWE-862", ["CWE-862", "CWE-284", "CWE-285", "CWE-863"], "A01")
INCORRECT_AUTHZ = ("CWE-863", ["CWE-863", "CWE-862", "CWE-285", "CWE-284"], "A01")
IDOR = ("CWE-639", ["CWE-639", "CWE-862", "CWE-285", "CWE-284", "CWE-566"], "A01")
MISSING_AUTHN = ("CWE-306", ["CWE-306", "CWE-287", "CWE-862"], "A07")
INFO_EXPOSURE = ("CWE-200", ["CWE-200", "CWE-209", "CWE-532"], "A01")

SPRING_IMPORTS = (
    "import org.springframework.web.bind.annotation.GetMapping;\n"
    "import org.springframework.web.bind.annotation.PathVariable;\n"
    "import org.springframework.web.bind.annotation.RestController;\n"
)

SPRING_POM = (
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n"
    "  <modelVersion>4.0.0</modelVersion>\n"
    "  <groupId>org.sastcorpus</groupId>\n"
    "  <artifactId>portal</artifactId>\n"
    "  <version>1.0.0</version>\n"
    "  <properties>\n"
    "    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>\n"
    "  </properties>\n"
    "  <dependencies>\n"
    "    <dependency>\n"
    "      <groupId>org.springframework</groupId>\n"
    "      <artifactId>spring-web</artifactId>\n"
    "      <version>6.2.1</version>\n"
    "    </dependency>\n"
    "    <dependency>\n"
    "      <groupId>org.springframework.security</groupId>\n"
    "      <artifactId>spring-security-core</artifactId>\n"
    "      <version>6.4.2</version>\n"
    "    </dependency>\n"
    "  </dependencies>\n"
    "  <build>\n"
    "    <sourceDirectory>${project.basedir}</sourceDirectory>\n"
    "    <plugins><plugin>\n"
    "      <groupId>org.apache.maven.plugins</groupId>\n"
    "      <artifactId>maven-compiler-plugin</artifactId>\n"
    "      <version>3.13.0</version>\n"
    "      <configuration><release>21</release></configuration>\n"
    "    </plugin></plugins>\n"
    "  </build>\n"
    "</project>\n"
)


AUTHZ = [
    template(
        "java-idor@user-controlled-key", "java", "java", IDOR, "spring-mvc", "inter-file",
        {"pom.xml": SPRING_POM, "InvoiceController.java": (
            "package portal;\n\n" + SPRING_IMPORTS + "\n"
            "@RestController\npublic class InvoiceController {\n\n"
            "    private final InvoiceStore store;\n\n"
            "    public InvoiceController(InvoiceStore store) {\n"
            "        this.store = store;\n    }\n\n"
            "    @GetMapping(\"/invoices/{id}\")\n"
            "    public String show(@PathVariable long id, Principal caller) {\n"
            "        return store.byId(id);\n    }\n}\n"),
         "InvoiceStore.java": (
            "package portal;\n\n"
            "public class InvoiceStore {\n\n"
            "    public String byId(long id) {\n"
            "        return \"invoice-\" + id;\n    }\n\n"
            "    public String byIdForOwner(long id, String owner) {\n"
            "        return \"invoice-\" + id + \"-\" + owner;\n    }\n}\n"),
         "Principal.java": "package portal;\n\npublic interface Principal {\n    String name();\n}\n"},
        "InvoiceController.java", "return store.byId(id)",
        "the identifier comes straight from the URL and selects the record with no comparison "
        "against the caller. Changing the number in the path returns another tenant's invoice. "
        "The store already offers byIdForOwner, so the ownership-aware call exists and is simply "
        "not the one used — which is the shape a dataflow tool can actually reach",
        {"pom.xml": SPRING_POM, "InvoiceController.java": (
            "package portal;\n\n" + SPRING_IMPORTS + "\n"
            "@RestController\npublic class InvoiceController {\n\n"
            "    private final InvoiceStore store;\n\n"
            "    public InvoiceController(InvoiceStore store) {\n"
            "        this.store = store;\n    }\n\n"
            "    @GetMapping(\"/invoices/{id}\")\n"
            "    public String show(@PathVariable long id, Principal caller) {\n"
            "        return store.byIdForOwner(id, caller.name());\n    }\n}\n"),
         "InvoiceStore.java": (
            "package portal;\n\n"
            "public class InvoiceStore {\n\n"
            "    public String byId(long id) {\n"
            "        return \"invoice-\" + id;\n    }\n\n"
            "    public String byIdForOwner(long id, String owner) {\n"
            "        return \"invoice-\" + id + \"-\" + owner;\n    }\n}\n"),
         "Principal.java": "package portal;\n\npublic interface Principal {\n    String name();\n}\n"},
        "InvoiceController.java", "return store.byIdForOwner(", "custom-effective",
        "the same identifier is scoped to the caller, so a record belonging to someone else "
        "cannot be selected however the path is manipulated",
        "InvoiceController.java", "public String show",
    ),
    template(
        "java-missing-authz@missing-annotation", "java", "java", MISSING_AUTHZ, "spring-security",
        "framework-mediated",
        {"pom.xml": SPRING_POM, "AdminController.java": (
            "package portal;\n\n"
            "import org.springframework.security.access.prepost.PreAuthorize;\n"
            + SPRING_IMPORTS + "\n"
            "@RestController\npublic class AdminController {\n\n"
            "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
            "    @GetMapping(\"/admin/tenants\")\n"
            "    public String tenants() {\n"
            "        return \"tenants\";\n    }\n\n"
            "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
            "    @GetMapping(\"/admin/audit\")\n"
            "    public String audit() {\n"
            "        return \"audit\";\n    }\n\n"
            "    @GetMapping(\"/admin/keys/{tenant}\")\n"
            "    public String keys(@PathVariable String tenant) {\n"
            "        return \"keys-\" + tenant;\n    }\n}\n")},
        "AdminController.java", "public String keys(",
        "one handler in an admin controller carries no authorization annotation while every "
        "sibling does. Nothing in the method is wrong; the defect is the absence, and it is "
        "visible only against the pattern its neighbours establish. This is the class the "
        "literature says static analysis struggles with, included so the corpus can record "
        "which tools manage it",
        {"pom.xml": SPRING_POM, "AdminController.java": (
            "package portal;\n\n"
            "import org.springframework.security.access.prepost.PreAuthorize;\n"
            + SPRING_IMPORTS + "\n"
            "@RestController\npublic class AdminController {\n\n"
            "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
            "    @GetMapping(\"/admin/tenants\")\n"
            "    public String tenants() {\n"
            "        return \"tenants\";\n    }\n\n"
            "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
            "    @GetMapping(\"/admin/audit\")\n"
            "    public String audit() {\n"
            "        return \"audit\";\n    }\n\n"
            "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
            "    @GetMapping(\"/admin/keys/{tenant}\")\n"
            "    public String keys(@PathVariable String tenant) {\n"
            "        return \"keys-\" + tenant;\n    }\n}\n")},
        "AdminController.java", "public String keys(", "framework-implicit",
        "every handler in the controller carries the same role requirement",
        "AdminController.java", "public String tenants",
    ),
    template(
        "java-public-endpoint@intentionally-public", "java", "java", MISSING_AUTHZ, "spring-security",
        "framework-mediated",
        {"pom.xml": SPRING_POM, "StatusController.java": (
            "package portal;\n\n"
            "import org.springframework.security.access.prepost.PreAuthorize;\n"
            + SPRING_IMPORTS + "\n"
            "@RestController\npublic class StatusController {\n\n"
            "    @GetMapping(\"/internal/tenants/{tenant}/secrets\")\n"
            "    public String secrets(@PathVariable String tenant) {\n"
            "        return \"secrets-\" + tenant;\n    }\n\n"
            "    @PreAuthorize(\"permitAll()\")\n"
            "    @GetMapping(\"/health\")\n"
            "    public String health() {\n"
            "        return \"ok\";\n    }\n}\n")},
        "StatusController.java", "public String secrets(",
        "an unannotated handler returning per-tenant secrets sits beside one that is explicitly "
        "marked public. The explicit marking on the neighbour removes the excuse that this "
        "controller simply does not use annotations",
        {"pom.xml": SPRING_POM, "StatusController.java": (
            "package portal;\n\n"
            "import org.springframework.security.access.prepost.PreAuthorize;\n"
            + SPRING_IMPORTS + "\n"
            "@RestController\npublic class StatusController {\n\n"
            "    @PreAuthorize(\"permitAll()\")\n"
            "    @GetMapping(\"/health\")\n"
            "    public String health() {\n"
            "        return \"ok\";\n    }\n\n"
            "    @PreAuthorize(\"permitAll()\")\n"
            "    @GetMapping(\"/version\")\n"
            "    public String version() {\n"
            "        return \"2.1.0\";\n    }\n}\n"),
         },
        "StatusController.java", "public String health()", "framework-implicit",
        "a health check and a version endpoint, both explicitly marked public. These are meant "
        "to be unauthenticated, and a tool that flags every endpoint without a role requirement "
        "reports them — which is how an access-control rule becomes noise on exactly the routes "
        "that should be open",
        "StatusController.java", "public String health",
    ),
    template(
        "java-incorrect-authz@wrong-role-checked", "java", "java", INCORRECT_AUTHZ,
        "spring-security", "framework-mediated",
        {"pom.xml": SPRING_POM, "BillingController.java": (
            "package portal;\n\n"
            "import org.springframework.security.access.prepost.PreAuthorize;\n"
            + SPRING_IMPORTS + "\n"
            "@RestController\npublic class BillingController {\n\n"
            "    @PreAuthorize(\"isAuthenticated()\")\n"
            "    @GetMapping(\"/billing/{tenant}/refund\")\n"
            "    public String refund(@PathVariable String tenant) {\n"
            "        return \"refunded-\" + tenant;\n    }\n}\n")},
        "BillingController.java", "public String refund(",
        "the check is present and passes for any logged-in user, while the operation moves money "
        "for a named tenant. An authorization control exists, so a tool looking for the absence "
        "of one finds nothing; the defect is that the control asserts authentication where it "
        "needed authorization",
        {"pom.xml": SPRING_POM, "BillingController.java": (
            "package portal;\n\n"
            "import org.springframework.security.access.prepost.PreAuthorize;\n"
            + SPRING_IMPORTS + "\n"
            "@RestController\npublic class BillingController {\n\n"
            "    @PreAuthorize(\"hasRole('BILLING') and #tenant == authentication.name\")\n"
            "    @GetMapping(\"/billing/{tenant}/refund\")\n"
            "    public String refund(@PathVariable String tenant) {\n"
            "        return \"refunded-\" + tenant;\n    }\n}\n")},
        "BillingController.java", "public String refund(", "framework-implicit",
        "the expression requires the role and binds the path variable to the caller's identity, "
        "so the operation is scoped to the tenant that owns it",
        "BillingController.java", "public String refund",
    ),
    template(
        "py-missing-authn@no-authentication", "python", "py", MISSING_AUTHN, "flask",
        "framework-mediated",
        {"routes.py": (
            "from flask import Flask\n\n"
            "from auth import login_required\n\n"
            "app = Flask(__name__)\n\n\n"
            "@app.route(\"/reports\")\n"
            "@login_required\n"
            "def reports():\n"
            "    return \"reports\"\n\n\n"
            "@app.route(\"/config/rotate-keys\", methods=[\"POST\"])\n"
            "def rotate_keys():\n"
            "    return \"rotated\"\n"),
         "auth.py": (
            "def login_required(view):\n"
            "    def wrapped(*args, **kwargs):\n"
            "        return view(*args, **kwargs)\n"
            "    wrapped.__name__ = view.__name__\n"
            "    return wrapped\n")},
        "routes.py", "def rotate_keys()",
        "a state-changing endpoint that rotates keys is registered with no authentication "
        "decorator, while a read-only report endpoint beside it has one. The asymmetry runs the "
        "wrong way: the dangerous route is the unprotected one",
        {"routes.py": (
            "from flask import Flask\n\n"
            "from auth import login_required\n\n"
            "app = Flask(__name__)\n\n\n"
            "@app.route(\"/reports\")\n"
            "@login_required\n"
            "def reports():\n"
            "    return \"reports\"\n\n\n"
            "@app.route(\"/config/rotate-keys\", methods=[\"POST\"])\n"
            "@login_required\n"
            "def rotate_keys():\n"
            "    return \"rotated\"\n"),
         "auth.py": (
            "def login_required(view):\n"
            "    def wrapped(*args, **kwargs):\n"
            "        return view(*args, **kwargs)\n"
            "    wrapped.__name__ = view.__name__\n"
            "    return wrapped\n")},
        "routes.py", "def rotate_keys()", "framework-implicit",
        "both routes carry the decorator",
        "routes.py", "def reports()",
    ),
    template(
        "py-info-exposure@stack-trace-to-client", "python", "py", INFO_EXPOSURE, "flask",
        "inter-file",
        {"handler.py": (
            "import traceback\n\n"
            "from store import lookup\n\n\n"
            "def show(code):\n"
            "    try:\n"
            "        return lookup(code)\n"
            "    except Exception:\n"
            "        return traceback.format_exc()\n"),
         "store.py": (
            "def lookup(code):\n"
            "    raise RuntimeError(\"no route to db.internal:5432 for \" + code)\n")},
        "handler.py", "return traceback.format_exc()",
        "the formatted traceback is returned to the caller. It carries file paths, the internal "
        "hostname and port from the exception message, and the shape of the call stack — a map "
        "of the deployment handed to whoever triggered the error",
        {"handler.py": (
            "import logging\n\n"
            "from store import lookup\n\n"
            "logger = logging.getLogger(__name__)\n\n\n"
            "def show(code):\n"
            "    try:\n"
            "        return lookup(code)\n"
            "    except Exception:\n"
            "        logger.exception(\"lookup failed\")\n"
            "        return \"lookup failed\"\n"),
         "store.py": (
            "def lookup(code):\n"
            "    raise RuntimeError(\"no route to db.internal:5432 for \" + code)\n")},
        "handler.py", "return \"lookup failed\"", "custom-effective",
        "the detail goes to the log where operators can reach it and the caller receives a "
        "constant string",
        "handler.py", "def show",
    ),
]

AUTHZ_ALL = AUTHZ
