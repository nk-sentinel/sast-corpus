"""The SCA plane: eight package ecosystems, and the cases that separate tools.

Matching a version against an advisory range is the easy part, and every scanner
does it. What separates them is everything around that:

- whether the vulnerable code is **reachable** at all
- whether a dependency is **transitive** or **development-only**
- whether a version string that looks affected actually is

The last is the sharpest trap on this plane. A scanner reading only the manifest
cannot tell a genuinely vulnerable pin from one that sits just outside the
advisory range, or from a distribution that carries the fix under the old
version string — and a scanner reading the code can.

Reachability is recorded, not scored against. An unreachable vulnerable
dependency is still a real finding: the component is in the build, and a later
change can call it. Marking it safe would penalise every scanner for doing its
job. It is labelled `reachable: false` so a scorecard can split on it, which is
the honest way to report a distinction the industry has not settled.

Every advisory referenced here is real, and every version pair is a genuine
affected/fixed boundary from that advisory.

The code beside each manifest exists to make reachability a property of the case
rather than an assertion in a comment. It references the real package, which
means it cannot be compiled without that package present — inherent to the
plane, not a defect. Python, JavaScript and Go parse it regardless because their
checkers do not resolve imports; the Rust file is named `usage.rs` rather than
`main.rs` so the crate-root check does not try to link a crate that was never
fetched, and it is therefore unverified rather than verified-good.
"""

from gen.generate import Template, Variant

SCA_CWE = ("CWE-1395", ["CWE-1395", "CWE-937", "CWE-1104"], "A06")


def component(slug, language, extension, manifest_name,
              vulnerable_manifest, vulnerable_match, why_vulnerable,
              safe_manifest, safe_match, why_safe,
              purl_vulnerable, purl_safe, cve,
              reachable=True, transitive=False, scope="runtime",
              severity="high", extra_files=None, safe_extra_files=None):
    """One dependency case and its sibling.

    `extra_files` carries the source that calls — or does not call — the
    vulnerable API, which is what makes reachability a property of the case
    rather than an assertion in a comment.
    """
    cwe, acceptable, owasp = SCA_CWE
    vulnerable_files = dict(extra_files or {}, **{manifest_name: vulnerable_manifest})
    safe_files = dict(safe_extra_files or extra_files or {}, **{manifest_name: safe_manifest})

    built = Template(
        slug=slug, language=language, extension=extension,
        primary_cwe=cwe, acceptable_cwes=acceptable, owasp_2021=owasp,
        severity=severity, flow="intra-procedural", obfuscation="none",
        source="hand-authored",
        variants={
            "vulnerable": Variant(
                label="vulnerable", files=vulnerable_files,
                sink_file=manifest_name, sink_match=vulnerable_match,
                sanitizer="none", rationale=why_vulnerable),
            "safe": Variant(
                label="safe", files=safe_files,
                sink_file=manifest_name, sink_match=safe_match,
                sanitizer="custom-effective", rationale=why_safe),
        },
    )
    built.plane = "sca"
    built.variants["vulnerable"].extra_ground_truth = {
        "purl": purl_vulnerable, "cve": cve, "transitive": transitive,
        "reachable": reachable, "scope": scope}
    built.variants["safe"].extra_ground_truth = {
        "purl": purl_safe, "cve": None, "transitive": transitive,
        "reachable": reachable, "scope": scope}
    return built


def _requirements(package, version):
    return "flask==3.0.3\n{}=={}\npytest==8.3.2\n".format(package, version)


def _gomod(module, version):
    return ("module example.com/inventory\n\ngo 1.22\n\nrequire (\n"
            "\t{} {}\n\tgithub.com/google/uuid v1.6.0\n)\n".format(module, version))


def _csproj(package, version):
    return ("<Project Sdk=\"Microsoft.NET.Sdk\">\n"
            "  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n"
            "  </PropertyGroup>\n  <ItemGroup>\n"
            "    <PackageReference Include=\"{}\" Version=\"{}\" />\n"
            "  </ItemGroup>\n</Project>\n".format(package, version))


def _cargo(package, version):
    return ("[package]\nname = \"inventory\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n"
            "[dependencies]\n{} = \"{}\"\nserde = \"1.0\"\n".format(package, version))


def _composer(package, version):
    return ("{{\n  \"name\": \"sastcorpus/inventory\",\n  \"require\": {{\n"
            "    \"php\": \">=8.1\",\n    \"{}\": \"{}\"\n  }}\n}}\n".format(package, version))


def _gemfile(package, version):
    return ("source \"https://rubygems.org\"\n\n"
            "gem \"{}\", \"{}\"\ngem \"puma\", \"6.4.2\"\n".format(package, version))


SCA = [
    component(
        "sca-pypi@vulnerable-version", "python", "txt", "requirements.txt",
        _requirements("requests", "2.19.1"), "requests==2.19.1",
        "requests 2.19.1 is affected by CVE-2018-18074, which leaks the Authorization "
        "header across a redirect to a different host, and the code below issues "
        "exactly the kind of request that triggers it",
        _requirements("requests", "2.32.3"), "requests==2.32.3",
        "the same component at a release past every advisory affecting it",
        "pkg:pypi/requests@2.19.1", "pkg:pypi/requests@2.32.3", "CVE-2018-18074",
        extra_files={"fetch.py": (
            "import requests\n\n\n"
            "def load(url):\n"
            "    return requests.get(url, auth=(\"svc\", \"token\")).text\n")},
    ),
    component(
        "sca-gomod@vulnerable-version", "go", "mod", "go.mod",
        _gomod("github.com/gin-gonic/gin", "v1.6.3"), "gin-gonic/gin v1.6.3",
        "gin 1.6.3 is affected by CVE-2020-28483, where a caller-supplied "
        "X-Forwarded-For header is trusted outright, and the handler below reads the "
        "client address the affected code produces",
        _gomod("github.com/gin-gonic/gin", "v1.10.0"), "gin-gonic/gin v1.10.0",
        "the same module at a release past the advisory",
        "pkg:golang/github.com/gin-gonic/gin@v1.6.3",
        "pkg:golang/github.com/gin-gonic/gin@v1.10.0", "CVE-2020-28483",
        extra_files={"server.go": (
            "package main\n\nimport \"github.com/gin-gonic/gin\"\n\n"
            "func register(r *gin.Engine) {\n"
            "\tr.GET(\"/who\", func(c *gin.Context) {\n"
            "\t\tc.String(200, c.ClientIP())\n\t})\n}\n")},
    ),
    component(
        "sca-nuget@vulnerable-version", "csharp", "csproj", "Inventory.csproj",
        _csproj("Newtonsoft.Json", "12.0.3"), "Version=\"12.0.3\"",
        "Newtonsoft.Json 12.0.3 is affected by CVE-2024-21907, where deeply nested "
        "input exhausts the stack during parsing, and the code below parses input it "
        "did not produce",
        _csproj("Newtonsoft.Json", "13.0.3"), "Version=\"13.0.3\"",
        "the same package at the release that carries the fix",
        "pkg:nuget/Newtonsoft.Json@12.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3",
        "CVE-2024-21907",
        extra_files={"Parser.cs": (
            "using Newtonsoft.Json;\n\n"
            "public static class Parser\n{\n"
            "    public static object Load(string body) =>\n"
            "        JsonConvert.DeserializeObject(body);\n}\n")},
    ),
    component(
        "sca-cargo@vulnerable-version", "rust", "toml", "Cargo.toml",
        _cargo("time", "0.1.44"), "time = \"0.1.44\"",
        "time 0.1.44 is affected by CVE-2020-26235, a segmentation fault reachable "
        "from a call that reads the local UTC offset, which the code below makes",
        _cargo("time", "0.3.36"), "time = \"0.3.36\"",
        "the same crate at a release past the advisory",
        "pkg:cargo/time@0.1.44", "pkg:cargo/time@0.3.36", "CVE-2020-26235",
        extra_files={"src/usage.rs": (
            "fn main() {\n"
            "    let offset = time::now();\n"
            "    println!(\"{:?}\", offset.tm_utcoff);\n}\n")},
    ),
    component(
        "sca-composer@vulnerable-version", "php", "json", "composer.json",
        _composer("guzzlehttp/guzzle", "6.5.5"), "\"guzzlehttp/guzzle\": \"6.5.5\"",
        "guzzle 6.5.5 is affected by CVE-2022-31090, which forwards curl authorisation "
        "headers across a cross-domain redirect, and the client below follows redirects",
        _composer("guzzlehttp/guzzle", "7.9.2"), "\"guzzlehttp/guzzle\": \"7.9.2\"",
        "the same package at a release past the advisory",
        "pkg:composer/guzzlehttp/guzzle@6.5.5", "pkg:composer/guzzlehttp/guzzle@7.9.2",
        "CVE-2022-31090",
        extra_files={"fetch.php": (
            "<?php\n\nrequire __DIR__ . '/vendor/autoload.php';\n\n"
            "function load($url) {\n"
            "    $client = new GuzzleHttp\\Client(['allow_redirects' => true]);\n"
            "    return (string) $client->get($url)->getBody();\n}\n")},
    ),
    component(
        "sca-rubygems@vulnerable-version", "ruby", "gemfile", "Gemfile",
        _gemfile("rack", "2.2.3"), "gem \"rack\", \"2.2.3\"",
        "rack 2.2.3 is affected by CVE-2022-30123, a shell escape in the Lint and "
        "CommonLogger middleware reachable from a logged request path",
        _gemfile("rack", "3.1.7"), "gem \"rack\", \"3.1.7\"",
        "the same gem at a release past the advisory",
        "pkg:gem/rack@2.2.3", "pkg:gem/rack@3.1.7", "CVE-2022-30123",
        extra_files={"app.rb": (
            "require \"rack\"\n\n"
            "App = Rack::CommonLogger.new(lambda do |_env|\n"
            "  [200, { \"content-type\" => \"text/plain\" }, [\"ok\"]]\nend)\n")},
    ),

    # --- the scenarios that separate a manifest reader from a code reader ------

    component(
        "sca-maven@present-but-never-called", "java", "xml", "pom.xml",
        ("<project>\n  <modelVersion>4.0.0</modelVersion>\n"
         "  <groupId>org.sastcorpus</groupId>\n  <artifactId>inventory</artifactId>\n"
         "  <version>1.0.0</version>\n  <dependencies>\n    <dependency>\n"
         "      <groupId>com.fasterxml.jackson.core</groupId>\n"
         "      <artifactId>jackson-databind</artifactId>\n"
         "      <version>2.9.10.1</version>\n    </dependency>\n"
         "  </dependencies>\n  <build>\n"
         "    <sourceDirectory>${project.basedir}</sourceDirectory>\n"
         "  </build>\n</project>\n"),
        "<version>2.9.10.1</version>",
        "jackson-databind 2.9.10.1 is affected by CVE-2020-8840 through polymorphic "
        "deserialisation, and nothing in this project calls it — the component ships "
        "in the build and the vulnerable path is never entered. Still a finding: the "
        "dependency is present and one commit away from being used. Recorded as "
        "unreachable so a scorecard can weigh it separately rather than pretend the "
        "distinction does not exist",
        ("<project>\n  <modelVersion>4.0.0</modelVersion>\n"
         "  <groupId>org.sastcorpus</groupId>\n  <artifactId>inventory</artifactId>\n"
         "  <version>1.0.0</version>\n  <dependencies>\n    <dependency>\n"
         "      <groupId>com.fasterxml.jackson.core</groupId>\n"
         "      <artifactId>jackson-databind</artifactId>\n"
         "      <version>2.17.2</version>\n    </dependency>\n"
         "  </dependencies>\n  <build>\n"
         "    <sourceDirectory>${project.basedir}</sourceDirectory>\n"
         "  </build>\n</project>\n"),
        "<version>2.17.2</version>",
        "the same component at a release past the advisory",
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.1",
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.2",
        "CVE-2020-8840", reachable=False,
        extra_files={"Inventory.java": (
            "public final class Inventory {\n"
            "    public static String describe() {\n"
            "        return \"inventory service\";\n    }\n}\n")},
    ),
    component(
        "sca-npm@development-only", "javascript", "json", "package.json",
        ("{\n  \"name\": \"inventory\",\n  \"version\": \"1.0.0\",\n"
         "  \"dependencies\": {\n    \"express\": \"4.21.0\"\n  },\n"
         "  \"devDependencies\": {\n    \"lodash\": \"4.17.15\"\n  }\n}\n"),
        "\"lodash\": \"4.17.15\"",
        "lodash 4.17.15 is affected by CVE-2020-8203 through prototype pollution. It "
        "sits in devDependencies and never ships, which lowers the priority and does "
        "not remove the finding: it is installed on every developer machine and in "
        "every CI run, both of which are worth compromising. Recorded with a "
        "development scope",
        ("{\n  \"name\": \"inventory\",\n  \"version\": \"1.0.0\",\n"
         "  \"dependencies\": {\n    \"express\": \"4.21.0\"\n  },\n"
         "  \"devDependencies\": {\n    \"lodash\": \"4.17.21\"\n  }\n}\n"),
        "\"lodash\": \"4.17.21\"",
        "the same package at the release that carries the fix",
        "pkg:npm/lodash@4.17.15", "pkg:npm/lodash@4.17.21", "CVE-2020-8203",
        scope="dev", severity="medium",
    ),
    component(
        "sca-maven@just-outside-the-range", "java", "xml", "pom.xml",
        ("<project>\n  <modelVersion>4.0.0</modelVersion>\n"
         "  <groupId>org.sastcorpus</groupId>\n  <artifactId>reporting</artifactId>\n"
         "  <version>1.0.0</version>\n  <dependencies>\n    <dependency>\n"
         "      <groupId>org.apache.logging.log4j</groupId>\n"
         "      <artifactId>log4j-core</artifactId>\n"
         "      <version>2.17.0</version>\n    </dependency>\n"
         "  </dependencies>\n</project>\n"),
        "<version>2.17.0</version>",
        "log4j-core 2.17.0 is the last release affected by CVE-2021-44832, which "
        "remote code execution through a crafted JDBC appender configuration. The "
        "headline advisory of that family stops at 2.15.0, so a scanner working from "
        "the famous one alone misses this",
        ("<project>\n  <modelVersion>4.0.0</modelVersion>\n"
         "  <groupId>org.sastcorpus</groupId>\n  <artifactId>reporting</artifactId>\n"
         "  <version>1.0.0</version>\n  <dependencies>\n    <dependency>\n"
         "      <groupId>org.apache.logging.log4j</groupId>\n"
         "      <artifactId>log4j-core</artifactId>\n"
         "      <version>2.17.1</version>\n    </dependency>\n"
         "  </dependencies>\n</project>\n"),
        "<version>2.17.1</version>",
        "2.17.1 is the release that fixes CVE-2021-44832 and is outside every advisory "
        "in the family. A scanner matching the major-minor line rather than the "
        "advisory range reports it, and reporting it is a false positive — the "
        "difference between the two halves of this pair is one patch version",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
        "CVE-2021-44832", severity="high",
    ),
    component(
        "sca-pypi@transitive-only", "python", "txt", "requirements.txt",
        ("flask==2.0.3\nrequests==2.32.3\n"),
        "flask==2.0.3",
        "flask 2.0.3 depends on werkzeug, and werkzeug below 2.2.3 is affected by "
        "CVE-2023-25577 through unbounded multipart parsing. Nothing in this manifest "
        "names werkzeug: the vulnerable component arrives underneath a direct "
        "dependency, and a scanner reading only what is written here finds nothing to "
        "report",
        ("flask==3.0.3\nrequests==2.32.3\n"),
        "flask==3.0.3",
        "flask 3.0.3 requires a werkzeug past the advisory, so the transitive "
        "component arrives fixed",
        "pkg:pypi/werkzeug@2.0.3", "pkg:pypi/werkzeug@3.0.4", "CVE-2023-25577",
        transitive=True,
    ),
]

SCA_ALL = SCA


# --- secret plane -------------------------------------------------------------
#
# Every value below is synthetic. Each carries the prefix, length and shape a
# detector keys on, decodes to nothing, and was never issued.
#
# The traps carry more weight than the positives here. Finding *a* credential
# shape is not the hard part — gitleaks ships over 150 patterns. Telling a
# credential from a digest, a placeholder, a public key or a documentation
# example is, and that is where a secrets scanner is either usable or a source
# of daily noise.

CREDS = ("CWE-798", ["CWE-798", "CWE-259", "CWE-321"], "A07")


def secret(slug, kind, language, extension, filename,
           vulnerable_body, vulnerable_match, why_vulnerable,
           safe_body, safe_match, why_safe,
           live_validatable=False, severity="high", safe_kind=None,
           safe_variant=None, safe_filename=None):
    cwe, acceptable, owasp = CREDS
    built = Template(
        slug=slug, language=language, extension=extension,
        primary_cwe=cwe, acceptable_cwes=acceptable, owasp_2021=owasp,
        severity=severity, flow="intra-procedural", obfuscation="none",
        source="hand-authored",
        variants={
            "vulnerable": Variant(
                label="vulnerable", files={filename: vulnerable_body},
                sink_file=filename, sink_match=vulnerable_match,
                sanitizer="none", rationale=why_vulnerable),
            "safe": Variant(
                label="safe", files={safe_filename or filename: safe_body},
                sink_file=safe_filename or filename, sink_match=safe_match,
                sanitizer="custom-effective", rationale=why_safe),
        },
    )
    built.plane = "secret"
    built.variants["vulnerable"].extra_ground_truth = {
        "kind": kind, "live_validatable": live_validatable, "in_git_history_only": False}
    built.variants["safe"].extra_ground_truth = {
        "kind": safe_kind or kind, "live_validatable": False, "in_git_history_only": False}
    if safe_variant:
        built.variants["safe"].variant = safe_variant
    return built


SECRETS = [
    secret("secret-jwt@signing-key", "jwt-signing-key", "java", "java", "Tokens.java",
           "public final class Tokens {\n"
           "    private static final String SIGNING_KEY =\n"
           "        \"hV8kQ2mNvB7xJ4pL9wT6yD3nH5sG1fA0zZcXe2iOnQ7kR3mB9wT4yD6nH2sG8f\";\n\n"
           "    public static String sign(String subject) {\n"
           "        return subject + \".\" + SIGNING_KEY;\n    }\n}\n",
           "String SIGNING_KEY =",
           "the key that signs every session token, committed in source. Anyone holding "
           "it mints tokens for any account, and rotating it invalidates every session "
           "at once — which is why it is so often left alone after a leak",
           "public final class Tokens {\n"
           "    private static final String SIGNING_KEY =\n"
           "        System.getenv(\"JWT_SIGNING_KEY\");\n\n"
           "    public static String sign(String subject) {\n"
           "        return subject + \".\" + SIGNING_KEY;\n    }\n}\n",
           "String SIGNING_KEY =",
           "the key is read from the environment and never appears in the repository",
           live_validatable=False, severity="critical"),

    secret("secret-ssh@private-key-file", "ssh-private-key", "go", "go", "deploy.go",
           "package main\n\nconst deployKey = `-----BEGIN OPENSSH PRIVATE KEY-----\n"
           "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt\n"
           "cnNhAAAAAwEAAQAAAYEAvN2mQ8xJ4pL9wT6yB3nH5sD1fG0aZcX8eU2iOnQ7kV3mB9wT\n"
           "-----END OPENSSH PRIVATE KEY-----`\n\n"
           "func key() string {\n\treturn deployKey\n}\n",
           "const deployKey =",
           "an OpenSSH private key in source. The BEGIN OPENSSH PRIVATE KEY header is "
           "among the highest-confidence patterns any detector has, and a deploy key "
           "grants whatever the deployment account can reach",
           "package main\n\nconst deployHostKey = `-----BEGIN OPENSSH PUBLIC KEY-----\n"
           "AAAAB3NzaC1yc2EAAAADAQABAAABgQC83aZDzEnikv3BPrIHecPWwbRplxfx5TaI6dDu\n"
           "-----END OPENSSH PUBLIC KEY-----`\n\n"
           "func key() string {\n\treturn deployHostKey\n}\n",
           "const deployHostKey =",
           "a PUBLIC key in the same envelope. Public keys are meant to be distributed "
           "and pinning a host key in source is good practice; a detector matching "
           "BEGIN.*KEY rather than the private variants reports it every time",
           severity="critical", safe_kind="ssh-public-key"),

    secret("secret-dotenv@committed-env-file", "database-connection-string",
           "python", "env", ".env",
           "APP_NAME=inventory\nLOG_LEVEL=info\n"
           "DATABASE_URL=postgresql://reporting:Pr0d-Rep7ing-2024@db.internal:5432/orders\n"
           "SESSION_SECRET=kR8vN2mQ7xJ4pL9wT6yB3nH5sD1fG0aZ\n",
           "DATABASE_URL=",
           "a .env file that was meant to stay local and was committed. It holds real "
           "values rather than names of values, which is exactly what separates it from "
           "the template beside it",
           "APP_NAME=inventory\nLOG_LEVEL=info\n"
           "DATABASE_URL=postgresql://user:password@host:5432/database\n"
           "SESSION_SECRET=change-me\n",
           "DATABASE_URL=",
           "the template that is supposed to be committed. Same file shape, same keys, "
           "and every value a placeholder — a detector keying on the filename or on the "
           "presence of a URL reports it",
           live_validatable=True, severity="critical", safe_variant="in-example-config",
           safe_filename=".env.example"),

    secret("secret-ci@pipeline-configuration", "cloud-credential",
           "python", "yml", "pipeline.yml",
           "stages:\n  - deploy\n\ndeploy:\n  stage: deploy\n  variables:\n"
           "    AWS_ACCESS_KEY_ID: AKIA7Q2WZLMNBVCXK394\n"
           "    AWS_SECRET_ACCESS_KEY: mQ7xJ4pL9wT6yB3nH5sD1fG0aZcX8eU2iOnQ7kV3\n"
           "  script:\n    - ./deploy.sh\n",
           "AWS_SECRET_ACCESS_KEY:",
           "credentials inlined into pipeline configuration rather than injected as "
           "protected variables. CI configuration is committed by definition, so this "
           "is a credential in the repository with extra steps",
           "stages:\n  - deploy\n\ndeploy:\n  stage: deploy\n  variables:\n"
           "    AWS_REGION: eu-west-1\n"
           "    AWS_ROLE_ARN: arn:aws:iam::123456789012:role/deploy\n"
           "  id_tokens:\n    AWS_ID_TOKEN:\n      aud: sts.amazonaws.com\n"
           "  script:\n    - ./deploy.sh\n",
           "AWS_ROLE_ARN:",
           "the same deployment configured to exchange a short-lived identity token for "
           "a role. A role ARN is an identifier, not a credential, and an account number "
           "inside it is not a secret — a detector matching on aws plus a long string "
           "reports it",
           live_validatable=True, severity="critical", safe_kind="cloud-identifier"),

    secret("secret-k8s@manifest-literal", "kubernetes-secret",
           "python", "yml", "secret.yml",
           "apiVersion: v1\nkind: Secret\nmetadata:\n  name: reporting-db\n"
           "type: Opaque\nstringData:\n"
           "  password: Pr0d-Repor7ing-2024!\n"
           "  username: reporting\n",
           "password: Pr0d-Repor7ing-2024!",
           "a Kubernetes Secret with the value written in plain text under stringData. "
           "The resource type says secret and the manifest is committed like any other, "
           "which is the whole problem",
           "apiVersion: v1\nkind: Secret\nmetadata:\n  name: reporting-db\n"
           "  annotations:\n"
           "    kubernetes.io/service-account.name: reporting\n"
           "type: kubernetes.io/service-account-token\n",
           "type: kubernetes.io/service-account-token",
           "a Secret resource that declares a type and carries no value at all — the "
           "token is populated by the cluster. A detector matching on kind: Secret "
           "reports every one of these",
           severity="critical", safe_kind="kubernetes-secret"),

    secret("secret-base64@wrapped-credential", "api-key",
           "javascript", "js", "config.js",
           "const CONFIG = {\n"
           "  endpoint: 'https://api.internal/v2',\n"
           "  apiKey: Buffer.from('c2tfbGl2ZV80ZUMzOUhxTHlqV0Rhcmp0VDF6ZHA3ZGM=',\n"
           "                      'base64').toString('utf8'),\n};\n\n"
           "module.exports = { CONFIG };\n",
           "apiKey: Buffer.from(",
           "the credential is base64 and decoded at startup, which defeats every "
           "pattern keyed on the plaintext prefix while leaving the secret exactly as "
           "recoverable. Encoding is not encryption and the decode is right there",
           "const CONFIG = {\n"
           "  endpoint: 'https://api.internal/v2',\n"
           "  buildStamp: Buffer.from('MjAyNi0wOC0xMlQxMDozMDowMFo=',\n"
           "                          'base64').toString('utf8'),\n};\n\n"
           "module.exports = { CONFIG };\n",
           "buildStamp: Buffer.from(",
           "the identical construction decoding a build timestamp. A detector flagging "
           "base64 decoded at runtime reports both, and only one of them matters",
           live_validatable=True, severity="critical", safe_kind="build-metadata"),

    secret("secret-connstring@cloud-storage", "storage-account-key",
           "csharp", "cs", "Storage.cs",
           "public static class Storage\n{\n"
           "    private const string ConnectionString =\n"
           "        \"DefaultEndpointsProtocol=https;AccountName=reportingprod;\"\n"
           "        + \"AccountKey=kR8vN2mQ7xJ4pL9wT6yB3nH5sD1fG0aZcX8eU2iOnQ7kV3mB9wT4yD6nH2sG8fA1zZcXe5iOnQ==;\"\n"
           "        + \"EndpointSuffix=core.windows.net\";\n\n"
           "    public static string Get() => ConnectionString;\n}\n",
           "AccountKey=",
           "a storage account key inside a connection string. The AccountKey field with "
           "a base64 value ending in double equals is an unambiguous shape, and the key "
           "grants full control of the account rather than scoped access",
           "public static class Storage\n{\n"
           "    private const string AccountUri =\n"
           "        \"https://reportingprod.blob.core.windows.net\";\n\n"
           "    public static string Get() => AccountUri;\n}\n",
           "private const string AccountUri =",
           "the same account addressed by URI, with credentials supplied by a managed "
           "identity at runtime. The account name is not a secret",
           live_validatable=True, severity="critical", safe_kind="cloud-identifier"),
]

SCA_ALL = SCA_ALL + SECRETS
