#!/usr/bin/env bash
# Assert that an instrument run did not edit the corpus.
#
# Scanners that drive a build mutate what they read. Building a CodeQL Go
# database over tier1/ runs the Go toolchain, which tidied two SCA manifests and
# deleted `github.com/google/uuid v1.6.0` from them — the declared-but-never-
# imported dependency those cases exist to state. `go mod tidy` removes exactly
# the line the case is about, and nothing warned.
#
# Untracked files matter as much as modified ones: the same run wrote a `go.sum`
# in both directories, which `git status` does not show without -uall. So this
# checks both, and treats either as a failure.
#
# Run it after any scan of the working tree. Better still, scan a copy:
#
#     cp -R tier1 /tmp/scan/tier1   &&   codeql database create ... --source-root=/tmp/scan/tier1
#
# See docs/THREATS-TO-VALIDITY.md, "An extractor can rewrite the corpus it reads".
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}" || exit 1

TARGETS=("${@:-tier1}")

STATUS=0

for target in "${TARGETS[@]}"; do
    if ! git diff --quiet -- "${target}"; then
        echo "MODIFIED  ${target}" >&2
        git diff --stat -- "${target}" | sed 's/^/    /' >&2
        STATUS=1
    fi

    # Untracked-but-ignored output (target/, __pycache__) is build residue and
    # not the corpus changing under us, so only non-ignored files count.
    untracked="$(git ls-files --others --exclude-standard -- "${target}")"
    if [ -n "${untracked}" ]; then
        echo "NEW FILES in ${target}" >&2
        printf '%s\n' "${untracked}" | sed 's/^/    /' >&2
        STATUS=1
    fi
done

if [ "${STATUS}" -ne 0 ]; then
    echo >&2
    echo "The corpus changed during this run. Ground truth may have been rewritten;" >&2
    echo "restore it (git checkout -- tier1, and delete the new files) before scoring." >&2
    exit 1
fi

echo "corpus unchanged: ${TARGETS[*]}"
