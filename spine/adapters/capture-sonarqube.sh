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

echo "== 3/4 exporting issues, then enriching the rules with their CWEs"
# additionalFields=rules is necessary but NOT sufficient. It returns rules
# carrying only key, name, lang, status and langName — no CWE anywhere. On 25.1
# Community `securityStandards` does not exist at all; the API rejects it as an
# unknown value for `f`. The CWE is recoverable only from each rule's own
# description, so every rule is fetched individually and merged back in.
#
# Skip this and every finding arrives with no CWE, falls back to the
# location-only match rule, and SonarQube looks like it does not tag weaknesses.
curl -sS -u "${SONAR_TOKEN}:" \
    "${SONAR_URL}/api/issues/search?componentKeys=${PROJECT_KEY}&ps=500&additionalFields=rules" \
    -o "${OUT}"

SONAR_URL="${SONAR_URL}" SONAR_TOKEN="${SONAR_TOKEN}" python3 - "${OUT}" <<'ENRICH'
import base64, json, os, sys, urllib.request

path = sys.argv[1]
url, token = os.environ["SONAR_URL"], os.environ["SONAR_TOKEN"]
auth = base64.b64encode("{}:".format(token).encode()).decode()
export = json.load(open(path))

for rule in export.get("rules", []):
    request = urllib.request.Request(
        "{}/api/rules/show?key={}".format(url, rule["key"]),
        headers={"Authorization": "Basic {}".format(auth)})
    try:
        detail = json.load(urllib.request.urlopen(request))["rule"]
    except Exception as error:
        print("   could not fetch {}: {}".format(rule["key"], error), file=sys.stderr)
        continue
    rule["descriptionSections"] = detail.get("descriptionSections", [])

json.dump(export, open(path, "w"), indent=1)
print("   enriched {} rule(s) with their descriptions".format(len(export.get("rules", []))))
ENRICH

ROOT="${ROOT}" python3 - "${OUT}" <<'CHECK'
import json, os, sys
sys.path.insert(0, os.path.join(os.environ["ROOT"], "spine"))
from adapters.sonarqube import cwes_for_rule

data = json.load(open(sys.argv[1]))
issues, rules = data.get("issues", []), data.get("rules", [])
with_cwe = [r for r in rules if cwes_for_rule(r)]
print("   issues {}   rules {}   rules resolving to a CWE {}".format(
    len(issues), len(rules), len(with_cwe)))

if not rules:
    print("   WARNING: no rules block — re-export with additionalFields=rules.", file=sys.stderr)
elif not with_cwe:
    print("   WARNING: no rule resolved to a CWE. Every finding will fall back to", file=sys.stderr)
    print("   the location-only match rule, which reads as the tool not tagging", file=sys.stderr)
    print("   weaknesses when the real cause is an incomplete export.", file=sys.stderr)
CHECK

echo "== 4/4 converting and scoring"
python3 "${ROOT}/spine/adapters/sonarqube.py" "${OUT}" \
    --tool-version "$(curl -sS "${SONAR_URL}/api/server/version")" \
    --out /tmp/sonarqube.sarif

python3 "${ROOT}/spine/score/score.py" /tmp/sonarqube.sarif \
    "${ROOT}/answers/expectedresults-1.0.csv"

echo
echo "Real export saved to ${OUT}."
echo "Build the adapter regression test from THAT file, not from a hand-written one."
