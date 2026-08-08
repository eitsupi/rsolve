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
    default_fixture=$2
    profile_fixture=$3
    if sh "$evaluator" "$metadata" "$default_fixture" "$profile_fixture" nrr-provider r_interop >/dev/null 2>&1; then
        echo "profile guard mutation unexpectedly passed: $label" >&2
        exit 1
    fi
    echo "profile guard mutation rejected: $label"
}

for field in package-id binary-id kind; do
    jq --arg field "$field" 'del(."rust-suites"["nrr-provider::r_interop"][$field])' \
        "$default_list" >"$tmp_dir/default-omit-$field.json"
    assert_rejected "default-omit-$field" "$tmp_dir/default-omit-$field.json" "$valid_profile"

    jq --arg field "$field" '."rust-suites"["nrr-provider::r_interop"][$field] = null' \
        "$default_list" >"$tmp_dir/default-null-$field.json"
    assert_rejected "default-null-$field" "$tmp_dir/default-null-$field.json" "$valid_profile"
done

jq '."rust-suites"["nrr-provider::r_interop"].status = "listed"' \
    "$default_list" >"$tmp_dir/default-change-expected-status.json"
assert_rejected "default-change-expected-status" "$tmp_dir/default-change-expected-status.json" "$valid_profile"

jq '."rust-suites"["nrr-provider::r_interop"].status = "skipped-filter"' \
    "$default_list" >"$tmp_dir/default-change-status.json"
assert_rejected "default-change-status" "$tmp_dir/default-change-status.json" "$valid_profile"

jq '."rust-suites"["nrr-provider::r_interop"]["package-id"] = "path+file:///workspace/crates/changed#0.1.0"' \
    "$default_list" >"$tmp_dir/default-change-package-id.json"
assert_rejected "default-change-package-id" "$tmp_dir/default-change-package-id.json" "$valid_profile"

jq '."rust-suites"["nrr-provider::r_interop"]["binary-id"] = "nrr-provider::changed"' \
    "$default_list" >"$tmp_dir/default-change-binary-id.json"
assert_rejected "default-change-binary-id" "$tmp_dir/default-change-binary-id.json" "$valid_profile"

jq '."rust-suites"["nrr-provider::r_interop"].kind = "lib"' \
    "$default_list" >"$tmp_dir/default-change-kind.json"
assert_rejected "default-change-kind" "$tmp_dir/default-change-kind.json" "$valid_profile"

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
    assert_rejected "add-listed-$kind-suite" "$default_list" "$tmp_dir/add-$kind.json"
done

jq '."rust-suites"["nrr-provider::r_interop"]["package-id"] = "path+file:///workspace/crates/changed#0.1.0"' \
    "$valid_profile" >"$tmp_dir/change-package-id.json"
assert_rejected "change-package-id" "$default_list" "$tmp_dir/change-package-id.json"

jq '."rust-suites"["nrr-provider::r_interop"]["binary-id"] = "nrr-provider::changed"' \
    "$valid_profile" >"$tmp_dir/change-binary-id.json"
assert_rejected "change-binary-id" "$default_list" "$tmp_dir/change-binary-id.json"

jq '."rust-suites"["nrr-provider::r_interop"].kind = "lib"' \
    "$valid_profile" >"$tmp_dir/change-kind.json"
assert_rejected "change-kind" "$default_list" "$tmp_dir/change-kind.json"

jq '."rust-suites"["nrr-provider::r_interop"].status = "skipped-filter"' \
    "$valid_profile" >"$tmp_dir/change-status.json"
assert_rejected "change-expected-status" "$default_list" "$tmp_dir/change-status.json"

for field in package-id binary-id kind; do
    jq --arg field "$field" 'del(."rust-suites"["nrr-provider::r_interop"][$field])' \
        "$valid_profile" >"$tmp_dir/omit-$field.json"
    assert_rejected "omit-$field" "$default_list" "$tmp_dir/omit-$field.json"

    jq --arg field "$field" '."rust-suites"["nrr-provider::r_interop"][$field] = null' \
        "$valid_profile" >"$tmp_dir/null-$field.json"
    assert_rejected "null-$field" "$default_list" "$tmp_dir/null-$field.json"
done
