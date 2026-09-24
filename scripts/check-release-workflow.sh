#!/usr/bin/env bash
# Structural invariants for the release-plz workflow. Requires mikefarah yq v4
# (preinstalled on GitHub's ubuntu runners).

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
workflow=".github/workflows/release-plz.yml"

[[ -r "$workflow" ]] || { echo "cannot read $workflow" >&2; exit 1; }
yq --version 2>/dev/null | grep -q mikefarah || { echo "mikefarah yq v4 is required" >&2; exit 1; }
yq -e '.jobs' "$workflow" >/dev/null || { echo "$workflow is not a parseable workflow" >&2; exit 1; }

failed=0
check() {
  local description="$1"
  local expression="$2"
  if ! yq -e "$expression" "$workflow" >/dev/null 2>&1; then
    echo "release workflow invariant failed: $description" >&2
    failed=1
  fi
}

check "top-level permissions are exactly contents: read" \
  '.permissions | (length == 1 and .contents == "read")'

check "release-gate job is gated to push on main in cipherstash/envelopers" \
  '(.jobs."release-gate".if | sub("\s+"; " ")) == "github.event_name == '"'push'"' && github.ref == '"'refs/heads/main'"' && github.repository == '"'cipherstash/envelopers'"'"'

check "release-gate job only reads the repository and pull requests" \
  '.jobs."release-gate".permissions | (length == 2 and .contents == "read" and ."pull-requests" == "read")'

check "release job needs release-gate and runs only for a merged release PR pushed to main" \
  '.jobs.release.needs == "release-gate" and (.jobs.release.if | sub("\s+"; " ")) == "needs.release-gate.outputs.release == '"'true'"' && github.event_name == '"'push'"' && github.ref == '"'refs/heads/main'"' && github.repository == '"'cipherstash/envelopers'"'"'

check "release job binds the release environment" \
  '.jobs.release.environment == "release"'

check "release job permissions are exactly contents: read and id-token: write" \
  '.jobs.release.permissions | (length == 2 and .contents == "read" and ."id-token" == "write")'

check "release job has no concurrency group" \
  '.jobs.release | has("concurrency") | not'

check "release-pr job is gated to cipherstash/envelopers" \
  '.jobs."release-pr".if == "github.repository == '"'cipherstash/envelopers'"'"'

check "only the release job has id-token: write or an environment" \
  '[.jobs | to_entries[] | select(.key != "release") | select(.value.permissions."id-token" != null or .value.environment != null)] | length == 0'

check "release job runs release-plz 'release', and only that job does" \
  '[.jobs | to_entries[] | select(.value.steps[] | select((.uses // "") | test("^release-plz/action@")) | .with.command == "release") | .key] | (length == 1 and .[0] == "release")'

check "release-pr job runs release-plz 'release-pr' with concurrency" \
  '(.jobs."release-pr".steps[] | select((.uses // "") | test("^release-plz/action@")) | .with.command) == "release-pr" and .jobs."release-pr".concurrency.group != null'

check "every action is pinned to a full commit SHA" \
  '[.jobs[].steps[] | select(has("uses")) | .uses | select(test("@[0-9a-f]{40}$") | not)] | length == 0'

check "every release-plz step pins the same explicit CLI version" \
  '[.jobs[].steps[] | select((.uses // "") | test("^release-plz/action@")) | .with.version // ""] | (length > 0 and all_c(. != "") and (unique | length) == 1)'

check "every checkout sets persist-credentials: false" \
  '[.jobs[].steps[] | select((.uses // "") | test("^actions/checkout@")) | .with."persist-credentials" | select(. != false)] | length == 0'

check "GitHub App tokens use the client-id variable" \
  '[.jobs[].steps[] | select((.uses // "") | test("^actions/create-github-app-token@")) | .with."client-id" | select(. != "${{ vars.RELEASE_PLZ_APP_CLIENT_ID }}")] | length == 0'

if grep -Eq 'CARGO_REGISTRY_TOKEN|rust-lang/crates-io-auth-action' "$workflow"; then
  echo "release workflow must use Trusted Publishing without a registry token helper" >&2
  failed=1
fi

exit "$failed"
