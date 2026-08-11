#!/usr/bin/env bash
# Compile Java fixtures that need third-party libraries.
#
# Each such fixture carries its own pom.xml. Dependencies resolve from Maven
# Central; this environment is not air-gapped and does not pretend to be.
#
# What is enforced is *pinning*, which is a different concern from connectivity.
# A fixture whose pom resolves a range or a snapshot would quietly change what
# it is testing between runs, and two scorecards taken a month apart would not
# be comparable — with nothing in either one revealing it. So every version must
# be an exact literal, and this script fails the build otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAILURES=0

check_pinned() {
    local pom="$1"
    # Versions Maven would resolve at build time rather than at authoring time.
    if grep -qE '<version>[^<]*(\[|\(|LATEST|RELEASE|SNAPSHOT)[^<]*</version>' "${pom}"; then
        echo "FAIL  ${pom#"${ROOT}/"}: version range, LATEST, RELEASE or SNAPSHOT" >&2
        grep -nE '<version>[^<]*(\[|\(|LATEST|RELEASE|SNAPSHOT)[^<]*</version>' "${pom}" | sed 's/^/      /' >&2
        return 1
    fi
    return 0
}

while IFS= read -r pom; do
    fixture="$(dirname "${pom}")"
    rel="${fixture#"${ROOT}/"}"

    # An SCA fixture is a manifest, not a project: it declares dependencies so a
    # composition scanner has something to read, and has no sources to compile.
    if [ -z "$(find "${fixture}" -name '*.java' -type f -print -quit)" ]; then
        echo "skip  ${rel} (dependency manifest, no sources to compile)"
        continue
    fi

    if ! check_pinned "${pom}"; then
        FAILURES=$((FAILURES + 1))
        continue
    fi

    if mvn -q -B -f "${pom}" -Dmaven.test.skip=true compile > "/tmp/mvn-$(basename "${fixture}").log" 2>&1; then
        # Maven exits 0 when it finds no sources to compile. A fixture whose
        # layout does not match sourceDirectory therefore reports a clean build
        # while producing an empty artifact — and a build-required engine then
        # sees nothing, which is the exact failure this gate exists to prevent.
        classes=$(find "${fixture}" -name '*.class' -print -quit 2>/dev/null)
        if [ -z "${classes}" ]; then
            echo "FAIL  ${rel}: build succeeded but produced no class files" >&2
            echo "       check <sourceDirectory> against the fixture layout" >&2
            FAILURES=$((FAILURES + 1))
            continue
        fi
        echo "ok    ${rel}"
    else
        echo "FAIL  ${rel}" >&2
        tail -25 "/tmp/mvn-$(basename "${fixture}").log" | sed 's/^/      /' >&2
        FAILURES=$((FAILURES + 1))
    fi
done < <(find "${ROOT}/tier1" -name pom.xml -type f | sort)

if [ "${FAILURES}" -gt 0 ]; then
    echo >&2
    echo "${FAILURES} fixture(s) failed; build-required engines cannot be scored on them." >&2
    exit 1
fi

echo "all maven fixtures compile with pinned versions"
