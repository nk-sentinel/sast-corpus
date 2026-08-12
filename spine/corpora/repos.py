"""Which repositories a derivation will spend time on.

Both tier-3 derivations clone real projects, and a few of the ones their
datasets point at are monorepos, mirrors or machine-learning trees measured in
gigabytes. Fetching those costs more than the case is worth and they are not
scan targets anyone wants in a corpus.

Two mechanisms, because one of them is not always available:

**A static list**, consulted first and never rate-limited. It exists because the
size check below asks the GitHub API, GitHub allows 60 unauthenticated requests
an hour, and a run of any size exhausts that partway through — after which every
check returns nothing and an "unknown size is allowed" fallback turns the cap
off exactly when it is still needed. chromium/chromium was admitted that way.

**A size check**, for everything else. An unknown size is allowed rather than
guessed: silence from the API is not evidence a repository is huge, and refusing
on it would drop cases for reasons unrelated to them.
"""

from __future__ import annotations

import json

MAX_REPO_MB = 400

# Refused without asking. Each entry records why, because a denylist whose
# reasons are not written down is one nobody can safely edit later.
ALWAYS_SKIP = {
    "torvalds/linux": "the kernel; hundreds of REEF's C entries and no one's scan target",
    "chromium/chromium": "tens of gigabytes, and a monorepo rather than a project",
    "llvm/llvm-project": "monorepo; a single commit's tree is larger than the cap",
    "mozilla/gecko-dev": "browser monorepo, mirrored and enormous",
    "WebKit/WebKit": "browser engine; same shape as the two above",
    "apple/swift": "compiler monorepo",
    "openjdk/jdk": "runtime monorepo",
    "php/php-src": "large and mostly generated C",
    "ImageMagick/ImageMagick": "very large history dominated by test corpora",
    "FederatedAI/FATE": "machine-learning monorepo carrying model and data artifacts",
    "kubernetes/kubernetes": "very large Go monorepo with a deep vendor tree",
    "apache/airflow": "large and dominated by provider packages",
    "elastic/elasticsearch": "large JVM monorepo",
    "ansible/ansible": "large and mostly module collections",
    "odoo/odoo": "very large application monorepo",
    "microsoft/vscode": "large editor monorepo",
    "gitlabhq/gitlabhq": "very large application monorepo",
    "SeleniumHQ/selenium": "polyglot monorepo with large binary fixtures",
}


def is_permitted_repo(repo):
    """Is this repository one we will consider at all?

    Matched on the full owner and name, so a project merely named after one of
    them is unaffected.
    """
    parts = str(repo).rstrip("/").replace(".git", "").split("/")
    if len(parts) < 2:
        return True
    return "{}/{}".format(parts[-2], parts[-1]) not in ALWAYS_SKIP


def within_size_cap(metadata, cap_mb=MAX_REPO_MB):
    if not metadata:
        return True
    size_kb = metadata.get("size")
    if not isinstance(size_kb, int):
        return True
    return size_kb <= cap_mb * 1024


def repository_metadata(repo, timeout=15):
    """Size and default branch from the GitHub API, or None if unavailable."""
    import urllib.error
    import urllib.request

    parts = str(repo).rstrip("/").replace(".git", "").split("/")
    if len(parts) < 2:
        return None
    api = "https://api.github.com/repos/{}/{}".format(parts[-2], parts[-1])
    try:
        with urllib.request.urlopen(api, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def worth_fetching(repo, ask_api=True):
    """The two checks together, cheapest first."""
    if not is_permitted_repo(repo):
        return False
    if not ask_api:
        return True
    return within_size_cap(repository_metadata(repo))
