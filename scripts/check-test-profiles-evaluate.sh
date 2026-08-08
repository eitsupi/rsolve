#!/bin/sh
# Evaluate one opt-in profile from captured cargo metadata and nextest JSON.
# The production guard supplies live command output; the negative-control
# runner supplies checked-in JSON fixtures.

set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: $0 METADATA DEFAULT_LIST PROFILE_LIST PACKAGE TARGET" >&2
    exit 2
fi

metadata=$1
default_list=$2
profile_list=$3
package_name=$4
target_name=$5

expected=$(jq -c --arg package "$package_name" --arg target "$target_name" '
    [.packages[]?
     | select(.name == $package) as $pkg
     | $pkg.targets[]?
     | select((.kind | index("test")) and .name == $target)
     | {package_id: $pkg.id,
        binary_id: ($pkg.name + "::" + .name),
        kind: "test"}]
    | if length == 1 then .[0] else empty end
' "$metadata")

if [ -z "$expected" ]; then
    echo "profile guard: metadata does not identify exactly one $package_name test target $target_name" >&2
    exit 1
fi

default_statuses=$(jq -c --argjson expected "$expected" '
    def identity:
        {package_id: .["package-id"], binary_id: .["binary-id"], kind: .kind};
    [."rust-suites"? // {}
     | to_entries[]
     | .value
     | select(identity == $expected)
     | .status]
' "$default_list")
if [ "$default_statuses" != '["skipped-default-filter"]' ]; then
    echo "profile guard: profile.default identity/status is $default_statuses; expected exactly skipped-default-filter for $expected" >&2
    exit 1
fi

expected_set=$(printf '%s\n' "$expected" | jq -S -c '[.]')
selected_set=$(jq -S -c '
    def identity:
        {package_id: .["package-id"], binary_id: .["binary-id"], kind: .kind};
    [."rust-suites"? // {}
     | to_entries[]
     | .value
     | select(.status == "listed" and .kind == "test")
     | identity]
    | sort_by([.package_id, .binary_id, .kind])
' "$profile_list")

if [ "$selected_set" != "$expected_set" ]; then
    echo "profile guard: selected identity set is $selected_set; expected $expected_set" >&2
    exit 1
fi

echo "profile guard: $package_name/$target_name identity set is exact"
