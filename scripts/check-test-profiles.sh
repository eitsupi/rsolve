#!/bin/sh
# Guard the nextest opt-in boundary.
#
# Test target paths are not authoritative: an explicit [[test]] target may use
# any source path. Cargo metadata and nextest's list output are the authorities
# for target existence and profile selection.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
metadata=$(mktemp "${TMPDIR:-/tmp}/nrr-test-profile-metadata.XXXXXX")
default_list=$(mktemp "${TMPDIR:-/tmp}/nrr-test-profile-default.XXXXXX")
profile_list=$(mktemp "${TMPDIR:-/tmp}/nrr-test-profile-opt-in.XXXXXX")
trap 'rm -f "$metadata" "$default_list" "$profile_list"' EXIT

opt_in_binaries='r_interop pak_isolated live_network'

cargo metadata --format-version 1 --all-features --no-deps --locked --offline \
    --manifest-path "$root/Cargo.toml" >"$metadata"

found=''
for name in $opt_in_binaries; do
    if jq -e --arg name "$name" '
        any(.packages[]?.targets[]?; (.kind | index("test")) and .name == $name)
    ' "$metadata" >/dev/null; then
        found="$found $name"
    fi
done

if [ -z "$found" ]; then
    echo "nextest profiles: opt-in binaries absent"
    exit 0
fi

cargo nextest list --workspace --all-targets --profile default --locked --offline \
    --message-format json >"$default_list"

for name in $found; do
    case "$name" in
        r_interop) profile='r-interop' ;;
        pak_isolated) profile='pak-isolated' ;;
        live_network) profile='live-network' ;;
        *) echo "nextest profiles: no profile mapping for $name" >&2; exit 1 ;;
    esac

    default_status=$(jq -r --arg name "$name" '
        [."rust-suites" | to_entries[]
         | select(.value.kind == "test" and .value."binary-name" == $name)
         | .value.status] | if length == 1 then .[0] else "ambiguous-or-missing" end
    ' "$default_list")
    if [ "$default_status" != skipped-default-filter ]; then
        echo "nextest profiles: $name is not excluded by profile.default (status: $default_status)" >&2
        exit 1
    fi

    cargo nextest list --workspace --all-targets --profile "$profile" --locked --offline \
        --message-format json >"$profile_list"
    selected_status=$(jq -r --arg name "$name" '
        [."rust-suites" | to_entries[]
         | select(.value.kind == "test" and .value."binary-name" == $name)
         | .value.status] | if length == 1 then .[0] else "ambiguous-or-missing" end
    ' "$profile_list")
    if [ "$selected_status" != listed ]; then
        echo "nextest profiles: $name is not selected by profile.$profile (status: $selected_status)" >&2
        exit 1
    fi
done

echo "nextest profiles: every existing opt-in target is excluded by default and selected by its dedicated profile:$found"
