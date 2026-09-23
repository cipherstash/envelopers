#!/usr/bin/env bash

set -euo pipefail

workflow=".github/workflows/release-plz.yml"

assert_count() {
  local expected="$1"
  local pattern="$2"
  local actual

  actual="$(grep -Fxc "$pattern" "$workflow" || true)"
  if [[ "$actual" != "$expected" ]]; then
    echo "expected $expected occurrence(s) of '$pattern' in $workflow, found $actual" >&2
    exit 1
  fi
}

assert_count 1 "permissions:"
assert_count 1 "  contents: read"
assert_count 1 "      id-token: write"
assert_count 1 "          command: release"
assert_count 1 "          command: release-pr"
assert_count 2 "        uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3.2.0"
assert_count 2 "        uses: release-plz/action@b8d6b54b02889ff2ae2bb82e8b57c3a8fc1683a5 # v0.5.139"
assert_count 2 "          version: 0.3.169"
assert_count 2 "          persist-credentials: false"
assert_count 1 "    concurrency:"

if grep -Eq 'CARGO_REGISTRY_TOKEN|rust-lang/crates-io-auth-action' "$workflow"; then
  echo "release workflow must use Trusted Publishing without a registry token helper" >&2
  exit 1
fi
