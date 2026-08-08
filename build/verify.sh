#!/usr/bin/env bash
# Run every build recipe.
#
# Build-required engines (Fortify, Coverity, Veracode) analyse compiled
# artifacts and see nothing in a fixture that will not build. A fixture that
# silently stops compiling makes those tools score zero, which is
# indistinguishable from poor detection in the scorecard. This gate is the only
# thing standing between that and a published number.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATUS=0

for recipe in "${ROOT}"/build/*/*.sh; do
    [ "$(basename "${recipe}")" = "verify.sh" ] && continue
    echo "== ${recipe#"${ROOT}/"}"
    if ! "${recipe}"; then
        STATUS=1
    fi
    echo
done

if [ "${STATUS}" -ne 0 ]; then
    echo "build verification FAILED" >&2
    exit 1
fi

echo "build verification passed"
