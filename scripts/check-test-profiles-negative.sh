#!/bin/sh
# Every mutation of the accepted profile must be rejected by the evaluator.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$root/scripts/test-fixtures/profile-guard
evaluator=$root/scripts/check-test-profiles-evaluate.sh
metadata=$fixture_dir/metadata.json
default_list=$fixture_dir/valid/default.json
valid_profile=$fixture_dir/valid/profile.json
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/nrr-profile-negative.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

assert_rejected() {
    label=$1
    profile_list=$2
    if sh "$evaluator" "$metadata" "$default_list" "$profile_list" nrr-provider r_interop >/dev/null 2>&1; then
        echo "profile guard mutation unexpectedly passed: $label" >&2
        exit 1
    fi
    echo "profile guard mutation rejected: $label"
}

for kind in test lib bin example; do
    jq --arg kind "$kind" '
        .["rust-suites"]["nrr-provider::fresh-\($kind)"] = {
            "package-name": "nrr-provider",
            "binary-id": "nrr-provider::fresh-\($kind)",
            "binary-name": "fresh-\($kind)",
            "package-id": "path+file:///workspace/crates/nrr-provider#0.1.0",
            "kind": $kind,
            "status": "listed"
        }
    ' "$valid_profile" >"$tmp_dir/add-$kind.json"
    assert_rejected "add-listed-$kind-suite" "$tmp_dir/add-$kind.json"
done

jq '."rust-suites"["nrr-provider::r_interop"]["package-id"] = "path+file:///workspace/crates/changed#0.1.0"' \
    "$valid_profile" >"$tmp_dir/change-package-id.json"
assert_rejected "change-package-id" "$tmp_dir/change-package-id.json"

jq '."rust-suites"["nrr-provider::r_interop"]["binary-id"] = "nrr-provider::changed"' \
    "$valid_profile" >"$tmp_dir/change-binary-id.json"
assert_rejected "change-binary-id" "$tmp_dir/change-binary-id.json"

jq '."rust-suites"["nrr-provider::r_interop"].kind = "lib"' \
    "$valid_profile" >"$tmp_dir/change-kind.json"
assert_rejected "change-kind" "$tmp_dir/change-kind.json"

jq '."rust-suites"["nrr-provider::r_interop"].status = "skipped-filter"' \
    "$valid_profile" >"$tmp_dir/change-status.json"
assert_rejected "change-expected-status" "$tmp_dir/change-status.json"

for field in package-id binary-id kind; do
    jq --arg field "$field" 'del(."rust-suites"["nrr-provider::r_interop"][$field])' \
        "$valid_profile" >"$tmp_dir/omit-$field.json"
    assert_rejected "omit-$field" "$tmp_dir/omit-$field.json"

    jq --arg field "$field" '."rust-suites"["nrr-provider::r_interop"][$field] = null' \
        "$valid_profile" >"$tmp_dir/null-$field.json"
    assert_rejected "null-$field" "$tmp_dir/null-$field.json"
done
