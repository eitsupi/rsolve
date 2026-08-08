#!/bin/sh
# Guard the nextest opt-in boundary.
#
# `.config/nextest.toml` currently uses `default-filter = "all()"` because nextest
# validates `binary(...)` names while loading the file, and the opt-in test binaries
# do not exist yet. That placeholder is safe only while those binaries are absent:
# the moment one is added, the default profile would run it in the normal local
# suite, which is exactly what the design forbids (a pak gate silently joining the
# hermetic run). A comment cannot enforce that, so this check does.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config="$root/.config/nextest.toml"

opt_in_binaries='r_interop pak_isolated live_network'

found=''
for name in $opt_in_binaries; do
    for candidate in "$root"/crates/*/tests/"$name".rs; do
        [ -e "$candidate" ] || continue
        found="$found $name"
        break
    done
done

if [ -z "$found" ]; then
    echo "nextest profiles: opt-in binaries absent; placeholder filters still valid"
    exit 0
fi

if grep -q '^default-filter = "all()"' "$config"; then
    echo "nextest profile filters are still placeholders, but opt-in test binaries now exist:$found" >&2
    echo "" >&2
    echo "Replace the placeholder filters in $config:" >&2
    echo "  [profile.default]      not binary(r_interop) & not binary(pak_isolated) & not binary(live_network)" >&2
    echo "  [profile.r-interop]    binary(r_interop)" >&2
    echo "  [profile.pak-isolated] binary(pak_isolated)" >&2
    echo "  [profile.live-network] binary(live_network)" >&2
    echo "" >&2
    echo "Leaving them as all() would run the opt-in suites in the default local run." >&2
    exit 1
fi

echo "nextest profiles: opt-in binaries present ($found) and filters are no longer placeholders"
