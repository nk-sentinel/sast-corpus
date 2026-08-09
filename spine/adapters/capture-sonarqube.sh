#!/usr/bin/env bash
# Scan the corpus with SonarQube and capture a real export for the adapter.
#
# The adapter has only ever been tested against fixtures we wrote. An adapter
# validated against a guessed schema emits plausible SARIF and wrong scores —
# the run completes and the number looks credible. This produces the genuine
# payload that makes the test honest.
#
#   SONAR_TOKEN=squ_xxx ./spine/adapters/capture-sonarqube.sh
#
# The token needs "Execute Analysis" plus browse permission. Generate one under
# My Account -> Security. It is read from the environment and never written to
# disk by this script.
#
# Nothing is installed: the scanner runs from the sonarsource/sonar-scanner-cli
# image, which is already present locally.
set -euo pipefail

SONAR_URL="${SONAR_URL:-https://sonarqube.shadow-lab.org}"
PROJECT_KEY="${PROJECT_KEY:-sast-corpus-tier1}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${OUT:-${ROOT}/spine/tests/data/real-sonarqube.json}"

if [ -z "${SONAR_TOKEN:-}" ]; then
    echo "SONAR_TOKEN is not set." >&2
    echo "Generate one at ${SONAR_URL}/account/security and export it." >&2
    exit 2
fi

echo "== 1/4 scanning tier1 as ${PROJECT_KEY}"
docker run --rm \
    -e SONAR_HOST_URL="${SONAR_URL}" \
    -e SONAR_TOKEN="${SONAR_TOKEN}" \
    -v "${ROOT}/tier1:/usr/src" \
    sonarsource/sonar-scanner-cli \
    -Dsonar.projectKey="${PROJECT_KEY}" \
    -Dsonar.projectName="sast-corpus tier1" \
    -Dsonar.sources=. \
    -Dsonar.scm.disabled=true

echo "== 2/4 waiting for the analysis to be processed"
# The scanner returns as soon as the report is submitted; the issues API shows
# nothing until the compute engine has finished with it.
for _ in $(seq 1 60); do
    pending=$(curl -sS -u "${SONAR_TOKEN}:" \
        "${SONAR_URL}/api/ce/component?component=${PROJECT_KEY}" \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d.get("queue", [])))' 2>/dev/null || echo 1)
    [ "${pending}" = "0" ] && break
    sleep 5
done

echo "== 3/4 exporting issues"
# additionalFields=rules is not optional. SonarQube records the CWE on the rule
# as securityStandards and never on the issue, so an export without it yields
# findings that carry no CWE at all and every one falls back to the
# location-only match rule.
curl -sS -u "${SONAR_TOKEN}:" \
    "${SONAR_URL}/api/issues/search?componentKeys=${PROJECT_KEY}&ps=500&additionalFields=rules" \
    -o "${OUT}"

python3 - "${OUT}" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
issues = data.get("issues", [])
rules = data.get("rules", [])
with_cwe = [r for r in rules if any(str(s).startswith("cwe:")
                                    for s in (r.get("securityStandards") or []))]
print("   issues {}   rules {}   rules carrying a CWE {}".format(
    len(issues), len(rules), len(with_cwe)))
if not rules:
    print("   WARNING: no rules block — re-export with additionalFields=rules,")
    print("   or every finding will arrive without a CWE.", file=sys.stderr)
PY

echo "== 4/4 converting and scoring"
python3 "${ROOT}/spine/adapters/sonarqube.py" "${OUT}" \
    --tool-version "$(curl -sS "${SONAR_URL}/api/server/version")" \
    --out /tmp/sonarqube.sarif

python3 "${ROOT}/spine/score/score.py" /tmp/sonarqube.sarif \
    "${ROOT}/answers/expectedresults-1.0.csv"

echo
echo "Real export saved to ${OUT}."
echo "Build the adapter regression test from THAT file, not from a hand-written one."
