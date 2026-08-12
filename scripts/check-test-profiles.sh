#!/bin/sh
# Guard the nextest opt-in boundary.
#
# Test target paths are not authoritative: an explicit [[test]] target may use
# any source path. Cargo metadata and nextest's list output are the authorities
# for target existence and profile selection.
# Invariant: each existing opt-in target is skipped by profile.default, and the
# dedicated profile's selected test-suite identity set is exactly that target.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
metadata=$(mktemp "${TMPDIR:-/tmp}/nrr-test-profile-metadata.XXXXXX")
default_list=$(mktemp "${TMPDIR:-/tmp}/nrr-test-profile-default.XXXXXX")
profile_list=$(mktemp "${TMPDIR:-/tmp}/nrr-test-profile-opt-in.XXXXXX")
trap 'rm -f "$metadata" "$default_list" "$profile_list"' EXIT

# package name, target name, and the profile that must select the target.
opt_in_targets='nrr-provider:r_interop:r-interop nrr-repository:repository_r_interop:r-interop'

cargo metadata --format-version 1 --all-features --no-deps --locked --offline \
    --manifest-path "$root/Cargo.toml" >"$metadata"

found=0
for spec in $opt_in_targets; do
    package_name=${spec%%:*}
    target_and_profile=${spec#*:}
    target_name=${target_and_profile%%:*}
    if jq -e --arg package "$package_name" --arg target "$target_name" '
        any(.packages[]?;
            .name == $package and
            any(.targets[]?; (.kind | index("test")) and .name == $target))
    ' "$metadata" >/dev/null; then
        found=$((found + 1))
    fi
done

if [ "$found" -eq 0 ]; then
    echo "nextest profiles: opt-in binaries absent"
    exit 0
fi

cargo nextest list --workspace --all-targets --profile default --locked --offline \
    --message-format json >"$default_list"

for spec in $opt_in_targets; do
    package_name=${spec%%:*}
    target_and_profile=${spec#*:}
    target_name=${target_and_profile%%:*}
    profile=${target_and_profile#*:}

    if ! jq -e --arg package "$package_name" --arg target "$target_name" '
        any(.packages[]?;
            .name == $package and
            any(.targets[]?; (.kind | index("test")) and .name == $target))
    ' "$metadata" >/dev/null; then
        continue
    fi

    cargo nextest list --workspace --all-targets --profile "$profile" --locked --offline \
        --message-format json >"$profile_list"
    expected_count=$(printf '%s\n' "$opt_in_targets" | wc -w | tr -d ' ')
    selected_count=$(jq '[."rust-suites"[]? | select(.status == "listed")] | length' "$profile_list")
    if [ "$selected_count" -ne "$expected_count" ]; then
        echo "nextest profiles: $profile selected $selected_count suites, expected exactly $expected_count opt-in suites" >&2
        exit 1
    fi
    target_profile=$(mktemp "${TMPDIR:-/tmp}/nrr-test-profile-target.XXXXXX")
    trap 'rm -f "$metadata" "$default_list" "$profile_list" "$target_profile"' EXIT
    jq --arg package "$package_name" --arg target "$target_name" \
        '."rust-suites" |= with_entries(select(.value["package-name"] == $package and .value["binary-name"] == $target))' \
        "$profile_list" >"$target_profile"
    sh "$root/scripts/check-test-profiles-evaluate.sh" \
        "$metadata" "$default_list" "$target_profile" "$package_name" "$target_name"
done

echo "nextest profiles: every existing opt-in target passed full-identity set checks"
