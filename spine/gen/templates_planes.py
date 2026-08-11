"""The last four target weaknesses, plus the secret and SCA detection planes.

Every credential here is synthetic. The AWS values are the example key pair
AWS itself publishes in its documentation, which exists precisely so that
detector tests need not use a live one. Nothing in this file grants access to
anything.

The traps on the secret plane matter more than the positives. Real repositories
are full of long high-entropy strings that are not credentials — UUIDs, content
hashes, base64 assets, placeholder values in example configuration — and a
scanner that reports entropy rather than secrets drowns a team in noise. Those
strings are the cases that tell the two apart.
"""

from gen.generate import Variant
from gen.templates import template

XXE = ("CWE-611", ["CWE-611", "CWE-827", "CWE-776"], "A05")
CREDS = ("CWE-798", ["CWE-798", "CWE-259", "CWE-321"], "A07")
CRYPTO = ("CWE-327", ["CWE-327", "CWE-328", "CWE-326"], "A02")
CSRF = ("CWE-352", ["CWE-352"], "A01")
SCA_CWE = ("CWE-1395", ["CWE-1395", "CWE-937", "CWE-1104"], "A06")


def _plain(slug, language, extension, weakness, framework, files_v, sink_v, files_s, sink_s,
           sanitizer_s, why_v, why_s, entry=None, entry_match=None, flow="intra-procedural",
           plane="vuln", extra_v=None, extra_s=None, severity="high"):
    """A pair whose whole story lives in one file — configuration and credential
    weaknesses have no taint path to follow."""
    sink_file = next(iter(files_v))
    safe_sink_file = next(iter(files_s))
    built = template(
        slug, language, extension, weakness, framework, flow,
        files_v, sink_file, sink_v, why_v,
        files_s, safe_sink_file, sink_s, sanitizer_s, why_s,
        entry, entry_match, severity=severity,
    )
    built.plane = plane
    if extra_v:
        built.variants["vulnerable"].extra_ground_truth = extra_v
    if extra_s:
        built.variants["safe"].extra_ground_truth = extra_s
    return built


# --- XML external entities --------------------------------------------------

XXE_T = [
    _plain(
        "py-xxe@entities-enabled", "python", "py", XXE, None,
        {"parser.py": (
            "from lxml import etree\n\n\n"
            "def parse(document):\n"
            "    config = etree.XMLParser(resolve_entities=True, no_network=False)\n"
            "    return etree.fromstring(document, parser=config)\n")},
        "etree.fromstring(document",
        {"parser.py": (
            "from lxml import etree\n\n\n"
            "def parse(document):\n"
            "    config = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)\n"
            "    return etree.fromstring(document, parser=config)\n")},
        "etree.fromstring(document", "custom-effective",
        "entity resolution and network access are both left on, so a declared entity can read local files",
        "entity resolution, DTD loading and network access are all disabled before parsing",
    ),
    _plain(
        "java-xxe@default-factory", "java", "java", XXE, None,
        {"Parser.java": (
            "package app;\n\n"
            "import java.io.ByteArrayInputStream;\n"
            "import javax.xml.parsers.DocumentBuilderFactory;\n"
            "import org.w3c.dom.Document;\n\n"
            "public class Parser {\n"
            "    static Document parse(byte[] document) throws Exception {\n"
            "        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n"
            "        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(document));\n"
            "    }\n"
            "}\n")},
        "factory.newDocumentBuilder().parse",
        {"Parser.java": (
            "package app;\n\n"
            "import java.io.ByteArrayInputStream;\n"
            "import javax.xml.XMLConstants;\n"
            "import javax.xml.parsers.DocumentBuilderFactory;\n"
            "import org.w3c.dom.Document;\n\n"
            "public class Parser {\n"
            "    static Document parse(byte[] document) throws Exception {\n"
            "        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n"
            "        factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
            "        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\");\n"
            "        factory.setXIncludeAware(false);\n"
            "        factory.setExpandEntityReferences(false);\n"
            "        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(document));\n"
            "    }\n"
            "}\n")},
        "factory.newDocumentBuilder().parse", "custom-effective",
        "the factory keeps its permissive defaults, so a DOCTYPE in the document can pull in an external entity",
        "the DOCTYPE declaration is refused outright and external DTD access is blanked",
    ),
]

# --- hard-coded credentials -------------------------------------------------

CREDS_T = [
    _plain(
        "py-creds@literal-in-source", "python", "py", CREDS, None,
        {"settings.py": (
            "import psycopg2\n\n"
            "DB_USER = \"reporting\"\n"
            "DB_PASSWORD = \"Pr0d-Repor7ing-2024!\"\n\n\n"
            "def connect():\n"
            "    return psycopg2.connect(user=DB_USER, password=DB_PASSWORD, host=\"db.internal\")\n")},
        "DB_PASSWORD = ",
        {"settings.py": (
            "import os\n\n"
            "import psycopg2\n\n"
            "DB_USER = os.environ[\"DB_USER\"]\n"
            "DB_PASSWORD = os.environ[\"DB_PASSWORD\"]\n\n\n"
            "def connect():\n"
            "    return psycopg2.connect(user=DB_USER, password=DB_PASSWORD, host=\"db.internal\")\n")},
        "DB_PASSWORD = ", "custom-effective",
        "the password is committed in source, so it lives in history and in every clone forever",
        "the value is read from the environment and never appears in the repository",
    ),
    _plain(
        "java-creds@literal-in-source", "java", "java", CREDS, None,
        {"Settings.java": (
            "package app;\n\n"
            "public final class Settings {\n"
            "    static final String DB_USER = \"reporting\";\n"
            "    static final String DB_PASSWORD = \"Pr0d-Repor7ing-2024!\";\n\n"
            "    private Settings() {\n"
            "    }\n"
            "}\n")},
        "DB_PASSWORD = ",
        {"Settings.java": (
            "package app;\n\n"
            "public final class Settings {\n"
            "    static final String DB_USER = System.getenv(\"DB_USER\");\n"
            "    static final String DB_PASSWORD = System.getenv(\"DB_PASSWORD\");\n\n"
            "    private Settings() {\n"
            "    }\n"
            "}\n")},
        "DB_PASSWORD = ", "custom-effective",
        "the password is a compiled-in constant, so it is recoverable from the artifact as well as the repository",
        "the value is read from the environment at runtime and never appears in source or bytecode",
    ),
]

# --- broken cryptography ----------------------------------------------------

CRYPTO_T = [
    _plain(
        "py-digest@weak-hash", "python", "py", CRYPTO, None,
        {"tokens.py": (
            "import hashlib\n\n\n"
            "def fingerprint(value):\n"
            "    return hashlib.md5(value.encode()).hexdigest()\n")},
        "hashlib.md5(",
        {"tokens.py": (
            "import hashlib\n\n\n"
            "def fingerprint(value):\n"
            "    return hashlib.sha256(value.encode()).hexdigest()\n")},
        "hashlib.sha256(", "custom-effective",
        "MD5 has practical collision attacks, so a fingerprint built on it no longer distinguishes two inputs",
        "SHA-256 has no known collision attack and is the appropriate replacement here",
    ),
    _plain(
        "java-cipher@weak-cipher-mode", "java", "java", CRYPTO, None,
        {"Sealer.java": (
            "package app;\n\n"
            "import javax.crypto.Cipher;\n"
            "import javax.crypto.spec.SecretKeySpec;\n\n"
            "public class Sealer {\n"
            "    static byte[] seal(byte[] key, byte[] value) throws Exception {\n"
            "        Cipher cipher = Cipher.getInstance(\"DES/ECB/PKCS5Padding\");\n"
            "        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, \"DES\"));\n"
            "        return cipher.doFinal(value);\n"
            "    }\n"
            "}\n")},
        "Cipher.getInstance(",
        {"Sealer.java": (
            "package app;\n\n"
            "import java.security.SecureRandom;\n"
            "import javax.crypto.Cipher;\n"
            "import javax.crypto.spec.GCMParameterSpec;\n"
            "import javax.crypto.spec.SecretKeySpec;\n\n"
            "public class Sealer {\n"
            "    static byte[] seal(byte[] key, byte[] value) throws Exception {\n"
            "        byte[] nonce = new byte[12];\n"
            "        SecureRandom.getInstanceStrong().nextBytes(nonce);\n"
            "        Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
            "        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, \"AES\"),\n"
            "                new GCMParameterSpec(128, nonce));\n"
            "        return cipher.doFinal(value);\n"
            "    }\n"
            "}\n")},
        "Cipher.getInstance(", "custom-effective",
        "a 56-bit key is brute-forceable and ECB leaks plaintext structure by encrypting equal blocks identically",
        "AES-GCM with a fresh random nonce gives both confidentiality and integrity",
    ),
]

# --- cross-site request forgery ---------------------------------------------

CSRF_T = [
    _plain(
        "java-csrf@protection-disabled", "java", "java", CSRF, "spring-security",
        {"WebConfig.java": (
            "package app;\n\n"
            "import org.springframework.context.annotation.Bean;\n"
            "import org.springframework.context.annotation.Configuration;\n"
            "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n"
            "import org.springframework.security.web.SecurityFilterChain;\n\n"
            "@Configuration\n"
            "public class WebConfig {\n"
            "    @Bean\n"
            "    SecurityFilterChain chain(HttpSecurity http) throws Exception {\n"
            "        http.csrf(csrf -> csrf.disable());\n"
            "        return http.build();\n"
            "    }\n"
            "}\n"),
         "pom.xml": (
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n"
             "  <modelVersion>4.0.0</modelVersion>\n"
             "  <groupId>org.sastcorpus</groupId>\n"
             "  <artifactId>webconfig</artifactId>\n"
             "  <version>1.0.0</version>\n"
             "  <properties>\n"
             "    <maven.compiler.release>21</maven.compiler.release>\n"
             "  </properties>\n"
             "  <dependencies>\n"
             "    <dependency>\n"
             "      <groupId>org.springframework.security</groupId>\n"
             "      <artifactId>spring-security-config</artifactId>\n"
             "      <version>6.4.2</version>\n"
             "    </dependency>\n"
             "    <dependency>\n"
             "      <groupId>org.springframework.security</groupId>\n"
             "      <artifactId>spring-security-web</artifactId>\n"
             "      <version>6.4.2</version>\n"
             "    </dependency>\n"
             "  </dependencies>\n"
             "  <build><plugins><plugin>\n"
             "    <groupId>org.apache.maven.plugins</groupId>\n"
             "    <artifactId>maven-compiler-plugin</artifactId>\n"
             "    <version>3.13.0</version>\n"
             "    <configuration><release>21</release></configuration>\n"
             "  </plugin></plugins></build>\n"
             "</project>\n"),
        },
        "csrf.disable()",
        {"WebConfig.java": (
            "package app;\n\n"
            "import org.springframework.context.annotation.Bean;\n"
            "import org.springframework.context.annotation.Configuration;\n"
            "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n"
            "import org.springframework.security.web.SecurityFilterChain;\n"
            "import org.springframework.security.web.csrf.CookieCsrfTokenRepository;\n\n"
            "@Configuration\n"
            "public class WebConfig {\n"
            "    @Bean\n"
            "    SecurityFilterChain chain(HttpSecurity http) throws Exception {\n"
            "        http.csrf(csrf -> csrf.csrfTokenRepository(\n"
            "                CookieCsrfTokenRepository.withHttpOnlyFalse()));\n"
            "        return http.build();\n"
            "    }\n"
            "}\n"),
         "pom.xml": (
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n"
             "  <modelVersion>4.0.0</modelVersion>\n"
             "  <groupId>org.sastcorpus</groupId>\n"
             "  <artifactId>webconfig</artifactId>\n"
             "  <version>1.0.0</version>\n"
             "  <properties>\n"
             "    <maven.compiler.release>21</maven.compiler.release>\n"
             "  </properties>\n"
             "  <dependencies>\n"
             "    <dependency>\n"
             "      <groupId>org.springframework.security</groupId>\n"
             "      <artifactId>spring-security-config</artifactId>\n"
             "      <version>6.4.2</version>\n"
             "    </dependency>\n"
             "    <dependency>\n"
             "      <groupId>org.springframework.security</groupId>\n"
             "      <artifactId>spring-security-web</artifactId>\n"
             "      <version>6.4.2</version>\n"
             "    </dependency>\n"
             "  </dependencies>\n"
             "  <build><plugins><plugin>\n"
             "    <groupId>org.apache.maven.plugins</groupId>\n"
             "    <artifactId>maven-compiler-plugin</artifactId>\n"
             "    <version>3.13.0</version>\n"
             "    <configuration><release>21</release></configuration>\n"
             "  </plugin></plugins></build>\n"
             "</project>\n"),
        },
        "csrf.csrfTokenRepository(", "framework-implicit",
        "turning the filter off lets any origin submit an authenticated state-changing request on a user's behalf",
        "the token repository is configured rather than disabled, so state-changing requests must carry a token",
    ),
]

# --- secret plane -----------------------------------------------------------

SECRET_T = [
    _plain(
        "secret-aws@cloud-key-literal", "python", "py", CREDS, None,
        {"deploy.py": (
            "ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n"
            "ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"
            "REGION = \"eu-west-1\"\n")},
        "ACCESS_KEY = ",
        {"deploy.py": (
            "import os\n\n"
            "ACCESS_KEY_ID = os.environ[\"AWS_ACCESS_KEY_ID\"]\n"
            "ACCESS_KEY = os.environ[\"AWS_SECRET_ACCESS_KEY\"]\n"
            "REGION = \"eu-west-1\"\n")},
        "ACCESS_KEY = ", "custom-effective",
        "a long-lived cloud credential pair committed to source, recoverable from history by anyone with the repository",
        "both halves are read from the environment, so neither appears in the repository",
        plane="secret",
        extra_v={"kind": "aws-access-key", "live_validatable": True, "in_git_history_only": False},
        extra_s={"kind": "aws-access-key", "live_validatable": False, "in_git_history_only": False},
        severity="critical",
    ),
    _plain(
        "secret-entropy@signing-key-literal", "python", "py", CREDS, None,
        {"session.py": (
            "SIGNING_KEY = \"hunter2-Zx9Qv7Lm3Rt8Wn2Kd6Yp4Bs1Hf5Jg0Ac\"\n\n\n"
            "def sign(payload):\n"
            "    return payload + SIGNING_KEY\n")},
        "SIGNING_KEY = ",
        {"assets.py": (
            "BUILD_ID = \"550e8400-e29b-41d4-a716-446655440000\"\n"
            "BUNDLE_DIGEST = \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"\n"
            "ICON = \"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk\"\n")},
        "BUNDLE_DIGEST = ", "custom-effective",
        "a long-lived signing key committed in source, so anyone with the repository can forge a valid signature",
        "a build identifier, a content digest and an embedded icon — all high-entropy, none of them credentials, "
        "which is what separates a secrets scanner from an entropy meter",
        plane="secret",
        extra_v={"kind": "generic-high-entropy", "live_validatable": False, "in_git_history_only": False},
        extra_s={"kind": "generic-high-entropy", "live_validatable": False, "in_git_history_only": False},
        severity="high",
    ),
]

# --- software composition analysis ------------------------------------------

SCA_T = [
    _plain(
        "sca-maven@vulnerable-version", "java", "xml", SCA_CWE, None,
        {"pom.xml": (
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>org.sastcorpus</groupId>\n"
            "  <artifactId>inventory</artifactId>\n"
            "  <version>1.0.0</version>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.apache.logging.log4j</groupId>\n"
            "      <artifactId>log4j-core</artifactId>\n"
            "      <version>2.14.1</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n")},
        "<version>2.14.1</version>",
        {"pom.xml": (
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>org.sastcorpus</groupId>\n"
            "  <artifactId>inventory</artifactId>\n"
            "  <version>1.0.0</version>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.apache.logging.log4j</groupId>\n"
            "      <artifactId>log4j-core</artifactId>\n"
            "      <version>2.24.3</version>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>\n")},
        "<version>2.24.3</version>", "custom-effective",
        "log4j-core 2.14.1 is affected by CVE-2021-44228 and reachable at runtime scope",
        "the same component pinned to a release long past every advisory affecting it",
        plane="sca",
        extra_v={"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                 "cve": "CVE-2021-44228", "transitive": False, "reachable": True, "scope": "runtime"},
        extra_s={"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.24.3",
                 "cve": None, "transitive": False, "reachable": True, "scope": "runtime"},
        severity="critical",
    ),
    _plain(
        "sca-npm@vulnerable-version", "javascript", "json", SCA_CWE, None,
        {"package.json": (
            "{\n"
            "  \"name\": \"inventory\",\n"
            "  \"version\": \"1.0.0\",\n"
            "  \"dependencies\": {\n"
            "    \"lodash\": \"4.17.15\"\n"
            "  }\n"
            "}\n")},
        "\"lodash\": \"4.17.15\"",
        {"package.json": (
            "{\n"
            "  \"name\": \"inventory\",\n"
            "  \"version\": \"1.0.0\",\n"
            "  \"dependencies\": {\n"
            "    \"lodash\": \"4.17.21\"\n"
            "  },\n"
            "  \"devDependencies\": {\n"
            "    \"handlebars\": \"4.0.5\"\n"
            "  }\n"
            "}\n")},
        "\"lodash\": \"4.17.21\"", "custom-effective",
        "lodash 4.17.15 is affected by CVE-2020-8203 prototype pollution and is a runtime dependency",
        "the runtime dependency is patched; the one advisory left applies to a devDependency that never ships, "
        "which a tool reporting every advisory regardless of scope will flag anyway",
        plane="sca",
        extra_v={"purl": "pkg:npm/lodash@4.17.15", "cve": "CVE-2020-8203",
                 "transitive": False, "reachable": True, "scope": "runtime"},
        extra_s={"purl": "pkg:npm/lodash@4.17.21", "cve": None,
                 "transitive": False, "reachable": True, "scope": "dev"},
        severity="high",
    ),
]

PLANES_ALL = XXE_T + CREDS_T + CRYPTO_T + CSRF_T + SECRET_T + SCA_T
