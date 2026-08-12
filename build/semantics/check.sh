#!/usr/bin/env bash
# Are the ineffective sanitizers actually ineffective?
#
# Compiling a fixture proves it is well-formed, not that it is labelled
# correctly. A pair marked `sanitizer: ineffective` whose sanitizer in fact
# works puts a vulnerability in the answer key that does not exist, and every
# tool that correctly reports nothing is then scored as having missed it. One of
# these was wrong when first written: a `trim()` left the validated and the used
# value identical, so the "vulnerable" half rejected the attack.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

JDK="${ROOT}/tier3/cwe-bench-java/java-env/jdk-17"
JAVAC="${JDK}/bin/javac"
JAVA="${JDK}/bin/java"
command -v javac >/dev/null 2>&1 && [ ! -x "${JAVAC}" ] && { JAVAC=javac; JAVA=java; }

if [ ! -x "${JAVAC}" ] && ! command -v javac >/dev/null 2>&1; then
    echo "sanitizer claims: no JDK, not checked (unverified, not verified-good)"
    exit 0
fi

python3 "${ROOT}/build/semantics/sanitizer_claims.py" || exit 1
echo

echo "sanitizer claims:"
"${JAVAC}" -d "${WORK}" "${ROOT}/build/semantics/SanitizerClaims.java" || exit 1
"${JAVA}" -cp "${WORK}" SanitizerClaims
