#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
record=$(mktemp)
hash_record=
trap 'rm -f "$record" "$hash_record"' EXIT
jq '.image = "ghcr.io/r-hub/containers/ubuntu-release"' "$repo_dir/ci/pak-gate-inputs.json" >"$record"
if sh "$repo_dir/scripts/validate-pak-gate-inputs.sh" "$record"; then
  echo "floating image negative control unexpectedly passed" >&2
  exit 1
fi
hash_record=$(mktemp)
jq '.closure_manifest_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' "$repo_dir/ci/pak-gate-inputs.json" >"$hash_record"
if sh "$repo_dir/scripts/validate-pak-gate-inputs.sh" "$hash_record"; then
  echo "closure hash negative control unexpectedly passed" >&2
  exit 1
fi
