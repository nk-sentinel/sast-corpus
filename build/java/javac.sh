#!/usr/bin/env bash
# Compile every Java fixture that declares build.required, using the JDK alone.
#
# Build-required engines (Fortify, Coverity, Veracode) analyse compiled
# artifacts. A fixture that does not compile is invisible to them, and they
# score zero in a way that is indistinguishable from poor detection. That is
# why this check gates the pipeline rather than merely tidying it.
#
# Fixtures handled here depend on the JDK alone, so no dependency resolution
# is involved. Fixtures needing third-party libraries use build/java/maven.sh,
# which pins every version exactly — not for connectivity, but so that what a
# fixture compiles to cannot drift between one scorecard and the next.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${ROOT}/build-out/java"
FAILURES=0

rm -rf "${OUT}"
mkdir -p "${OUT}"

# Each fixture compiles in isolation: two fixtures may legitimately declare the
# same package and class names.
while IFS= read -r fixture; do
    name="$(basename "${fixture}")"

    # A fixture declares its build system by what it contains. One holding a
    # pom.xml belongs to build/java/maven.sh; compiling it here would fail on
    # missing third-party classes and report a broken corpus that is not broken.
    [ -f "${fixture}/pom.xml" ] && continue

    sources=$(find "${fixture}" -name '*.java' -type f)
    [ -z "${sources}" ] && continue

    if javac -nowarn -d "${OUT}/${name}" ${sources} 2>"${OUT}/${name}.log"; then
        echo "ok    ${fixture#"${ROOT}/"}"
    else
        echo "FAIL  ${fixture#"${ROOT}/"}" >&2
        sed 's/^/      /' "${OUT}/${name}.log" >&2
        FAILURES=$((FAILURES + 1))
    fi
done < <(find "${ROOT}/tier1/java" -mindepth 1 -maxdepth 1 -type d | sort)

if [ "${FAILURES}" -gt 0 ]; then
    echo >&2
    echo "${FAILURES} fixture(s) do not compile; build-required engines cannot be scored until they do." >&2
    exit 1
fi

echo "all java fixtures compile"
