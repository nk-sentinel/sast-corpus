"""Secret-plane templates: one per credential type, each with its trap.

Every value here is synthetic. They carry the right prefix and length to match a
detector's pattern and decode to nothing — none of them authenticates to
anything, and none was ever issued.

The traps carry more weight than the positives on this plane. Gitleaks ships
over 150 patterns and TruffleHog over 700 detectors, so finding *a* credential
shape is not the hard part. Telling a credential from a UUID, a commit SHA, a
content digest, a placeholder or a documentation example is, and that is where
a secrets scanner is either usable or a source of daily noise.

One trap deserves singling out. `AKIAIOSFODNN7EXAMPLE` is the key AWS publishes
in its own documentation, and mature scanners allowlist it by name. An earlier
version of this corpus used it as a *positive*, which meant a tool doing the
right thing scored a miss. It is a trap here.
"""

from gen.generate import Variant
from gen.templates import template

CREDS = ("CWE-798", ["CWE-798", "CWE-259", "CWE-321"], "A07")


def secret(slug, kind, vulnerable_files, vulnerable_sink, safe_files, safe_sink,
           why_vulnerable, why_safe, live_validatable=False, language="python",
           extension="py", severity="high", safe_kind=None, variant_safe=None):
    built = template(
        slug, language, extension, CREDS, None, "intra-procedural",
        vulnerable_files, next(iter(vulnerable_files)), vulnerable_sink, why_vulnerable,
        safe_files, next(iter(safe_files)), safe_sink, "custom-effective", why_safe,
        None, None, severity=severity,
    )
    built.plane = "secret"
    built.variants["vulnerable"].extra_ground_truth = {
        "kind": kind, "live_validatable": live_validatable, "in_git_history_only": False}
    built.variants["safe"].extra_ground_truth = {
        "kind": safe_kind or kind, "live_validatable": False, "in_git_history_only": False}
    if variant_safe:
        built.variants["safe"].variant = variant_safe
    return built


SECRETS = [
    secret(
        "secret-aws-pair@cloud-key-pair", "aws-access-key",
        {"deploy.py": (
            "ACCESS_KEY_ID = \"AKIA3T7QWZLMNBVCXK29\"\n"
            "ACCESS_KEY = \"kR8vN2mQ7xJ4pL9wT6yB3nH5sD1fG0aZcX8eU2iO\"\n"
            "REGION = \"eu-west-1\"\n")},
        "ACCESS_KEY = ",
        {"deploy.py": (
            "ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n"
            "ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"
            "REGION = \"eu-west-1\"\n")},
        "ACCESS_KEY = ",
        "a long-lived cloud credential pair committed in source, matching the AKIA prefix and "
        "40-character secret shape a detector keys on",
        "the exact key pair AWS publishes in its own documentation. Mature scanners allowlist it "
        "by name, so reporting it is a false positive — and a corpus that scored it as a real "
        "secret would penalise the tools doing the right thing",
        live_validatable=True, severity="critical", safe_kind="aws-access-key",
        variant_safe="in-example-config",
    ),
    secret(
        "secret-github@vcs-token", "github-pat",
        {"ci.py": ("TOKEN = \"ghp_R7kQ2mNvB8xJ4pL9wT6yD3nH5sG1fA0zZcXe\"\n\n\n"
                   "def headers():\n    return {\"Authorization\": \"token \" + TOKEN}\n")},
        "TOKEN = ",
        {"ci.py": ("import os\n\nTOKEN = os.environ[\"GITHUB_TOKEN\"]\n\n\n"
                   "def headers():\n    return {\"Authorization\": \"token \" + TOKEN}\n")},
        "TOKEN = ",
        "a GitHub personal access token in source, carrying the ghp_ prefix and 36-character body",
        "the token is read from the environment and never appears in the repository",
        live_validatable=True, severity="critical",
    ),
    secret(
        "secret-stripe@payment-key", "stripe-secret-key",
        {"billing.py": ("STRIPE_KEY = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n\n\n"
                        "def charge(amount):\n    return {\"key\": STRIPE_KEY, \"amount\": amount}\n")},
        "STRIPE_KEY = ",
        {"billing.py": ("STRIPE_KEY = \"sk_live_xxxxxxxxxxxxxxxxxxxxxxxx\"\n\n\n"
                        "def charge(amount):\n    return {\"key\": STRIPE_KEY, \"amount\": amount}\n")},
        "STRIPE_KEY = ",
        "a live-mode payment key in source. sk_live_ is the prefix that separates a production "
        "credential from a test one, and the distinction decides whether a leak moves money",
        "the same shape with the body replaced by a run of x characters — a placeholder left in a "
        "template. It matches a prefix-only pattern and authenticates to nothing",
        live_validatable=True, severity="critical", variant_safe="in-example-config",
    ),
    secret(
        "secret-privatekey@pem-private-key", "private-key",
        {"transport.py": (
            "SIGNING_KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIBOgIBAAJBAK7mZ2qXvN8bT4wR9yJ3pL6dH1sG5fA0cZxUe2iOnQ7kV3mB\n"
            "9wT4yD6nH2sG8fA1zZcXe5iOnQ3kR7vN2mQ8xJ4pL9wIDAQABAkA3kR7vN2m\n"
            "-----END RSA PRIVATE KEY-----\"\"\"\n")},
        "SIGNING_KEY = ",
        {"transport.py": (
            "VERIFY_KEY = \"\"\"-----BEGIN PUBLIC KEY-----\n"
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK7mZ2qXvN8bT4wR9yJ3pL6dH1sG\n"
            "5fA0cZxUe2iOnQ7kV3mB9wT4yD6nH2sG8fA1zZcXe5iOnQ3kR7vN2mQIDAQAB\n"
            "-----END PUBLIC KEY-----\"\"\"\n")},
        "VERIFY_KEY = ",
        "a PEM-encoded private key committed in source. The BEGIN RSA PRIVATE KEY header is one "
        "of the highest-confidence patterns any detector has",
        "a PUBLIC key in the same PEM envelope. Public keys are meant to be distributed and are "
        "not secrets; a detector matching on BEGIN.*KEY rather than on the private variants "
        "reports this every time a certificate is committed",
        severity="critical",
    ),
    secret(
        "secret-dburl@connection-string", "database-connection-string",
        {"db.py": ("DSN = \"postgresql://reporting:Pr0d-Rep7ing-2024@db.internal:5432/orders\"\n\n\n"
                   "def dsn():\n    return DSN\n")},
        "DSN = ",
        {"db.py": ("import os\n\nDSN = \"postgresql://reporting@db.internal:5432/orders\"\n\n\n"
                   "def dsn():\n    return DSN.replace(\"reporting@\", \"reporting:\" + os.environ[\"DB_PASSWORD\"] + \"@\")\n")},
        "DSN = ",
        "the password is embedded in the connection URL, which travels into logs, error messages "
        "and process listings as well as the repository",
        "the URL carries no password; it is injected from the environment at connection time",
        live_validatable=True,
    ),
    secret(
        "secret-slack@chat-token", "slack-bot-token",
        {"notify.py": ("WEBHOOK_TOKEN = \"xoxb-2417839265-4192837465-Kq7Rm2NvB8xJ4pL9wT6y\"\n\n\n"
                       "def post(text):\n    return {\"token\": WEBHOOK_TOKEN, \"text\": text}\n")},
        "WEBHOOK_TOKEN = ",
        {"notify.py": ("BUILD_ID = \"2417839265-4192837465-Kq7Rm2NvB8xJ4pL9wT6y\"\n\n\n"
                       "def post(text):\n    return {\"build\": BUILD_ID, \"text\": text}\n")},
        "BUILD_ID = ",
        "a Slack bot token in source. The xoxb- prefix is unambiguous and the token grants "
        "whatever the bot was scoped to",
        "the identical body with the xoxb- prefix removed — a compound build identifier. A "
        "detector keying on entropy or on the dash-separated shape rather than on the prefix "
        "reports this",
        live_validatable=True,
    ),
]

SECRET_TRAPS = [
    template(
        "secret-lookalikes@identifier-not-secret", "python", "py", CREDS, None, "intra-procedural",
        {"ids.py": (
            "SESSION_TOKEN = \"7f3a9c2e5b8d1064f2a7c9e3b5d8106af2c7e9b3\"\n\n\n"
            "def token():\n    return SESSION_TOKEN\n")},
        "ids.py", "SESSION_TOKEN = ",
        "a forty-character hex string used as a session token. It is a credential despite looking "
        "exactly like a commit SHA, which is what makes the pair below the interesting comparison",
        {"ids.py": (
            "BUILD_COMMIT = \"7f3a9c2e5b8d1064f2a7c9e3b5d8106af2c7e9b3\"\n"
            "REQUEST_ID = \"550e8400-e29b-41d4-a716-446655440000\"\n"
            "BUNDLE_DIGEST = \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"\n"
            "ICON = \"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk\"\n")},
        "ids.py", "BUILD_COMMIT = ", "custom-effective",
        "a commit SHA, a UUID, a content digest and an embedded icon. All four are high-entropy "
        "and none is a credential — and the commit SHA is byte-identical to the token above, so "
        "no amount of entropy analysis can separate them. Only the name and use can",
        None, None,
    ),
]

SECRETS_ALL = SECRETS + SECRET_TRAPS
