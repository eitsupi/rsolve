#!/usr/bin/env bash
set -euo pipefail

# Check the resolved Cargo graph, rather than manifest text. A path is printed
# for every violation so a transitive edge is actionable.

repo_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
metadata_file=$(mktemp "${TMPDIR:-/tmp}/rsolve-cargo-metadata.XXXXXX")
edges_file=$(mktemp "${TMPDIR:-/tmp}/rsolve-cargo-edges.XXXXXX")
trap 'rm -f "$metadata_file" "$edges_file"' EXIT

cargo metadata --format-version 1 --all-features --locked --offline \
    --manifest-path "$repo_dir/Cargo.toml" >"$metadata_file"

jq -r '
  . as $metadata
  | $metadata.resolve.nodes[] as $node
  | ($metadata.packages[] | select(.id == $node.id) | .name) as $package
  | $node.deps[] as $dependency
  | [$package, ($metadata.packages[] | select(.id == $dependency.pkg) | .name)]
  | @tsv
' "$metadata_file" | sort -u >"$edges_file"

# Find one shortest resolved-graph path using the jq-produced edge list.
find_path() {
    local source=$1
    local target=$2

    awk -F '\t' -v src="$source" -v dst="$target" '
        {
            if (!edge[$1 SUBSEP $2]++) {
                adjacency[$1, ++degree[$1]] = $2
            }
        }
        END {
            queue[1] = src
            head = 1
            tail = 1
            visited[src] = 1

            while (head <= tail) {
                current = queue[head++]
                if (current == dst) {
                    break
                }
                for (i = 1; i <= degree[current]; i++) {
                    next_node = adjacency[current, i]
                    if (!visited[next_node]) {
                        visited[next_node] = 1
                        parent[next_node] = current
                        queue[++tail] = next_node
                    }
                }
            }

            if (!visited[dst]) {
                exit 1
            }

            path = dst
            current = dst
            while (current != src) {
                current = parent[current]
                path = current " -> " path
            }
            print path
        }
    ' "$edges_file"
}

check_forbidden_path() {
    local invariant=$1
    local source=$2
    local target=$3
    local path

    if path=$(find_path "$source" "$target"); then
        printf 'dependency invariant %s violated: %s\n' "$invariant" "$path" >&2
        exit 1
    fi
}

check_forbidden_path "1 (resolver -> repository)" rsolve-resolver rsolve-repository
check_forbidden_path "2 (repository -> resolver)" rsolve-repository rsolve-resolver
check_forbidden_path "3 (resolver -> provider)" rsolve-resolver rsolve-provider

# Invariant 4 is an allowlist, not a finite denylist: rsolve-core currently has
# only opaque implementation dependencies. This catches every HTTP client,
# runtime, and other
# future external crate, including optional dependencies resolved by
# --all-features. An allowlist is complete; a denylist would only improve
# wording while inevitably missing a new crate name.
# `jiff` and `sha2` are used only behind opaque core APIs; neither the date
# library type nor the hashing implementation is exposed in the public domain
# surface.
ALLOWED_CORE_CRATES=(jiff sha2)
while IFS=$'\t' read -r source target; do
    if [[ "$source" == rsolve-core ]]; then
        allowed=false
        for permitted in "${ALLOWED_CORE_CRATES[@]}"; do
            if [[ "$target" == "$permitted" ]]; then
                allowed=true
                break
            fi
        done
        if [[ "$allowed" != true ]]; then
            printf 'rsolve-core dependency allowlist violated: %s -> %s\n' "$source" "$target" >&2
            exit 1
        fi
    fi
done < <(awk -F '\t' '$1 == "rsolve-core" { print }' "$edges_file")

# Invariant 5's mechanical boundary check: core may not resolve another
# workspace implementation. Public trait semantics still require mandatory
# review, which is reported below.
for forbidden in rsolve-provider rsolve-resolver rsolve-repository; do
    check_forbidden_path "5 mechanical type boundary (core -> provider/transport/runtime: $forbidden)" rsolve-core "$forbidden"
done

# Enforce the complete workspace-local allowlist from the architecture. Use
# metadata.workspace_members rather than a name prefix so the rsolve binary and
# any future differently named member are covered too.
while IFS=$'\t' read -r source target; do
    case "$source->$target" in
        rsolve-provider-\>rsolve-core|rsolve-resolver-\>rsolve-core|rsolve-repository-\>rsolve-core|rsolve-\>rsolve-core|rsolve-\>rsolve-provider|rsolve-\>rsolve-resolver|rsolve-\>rsolve-repository)
            ;;
        *)
            printf 'workspace dependency allowlist violated: %s -> %s\n' "$source" "$target" >&2
            exit 1
            ;;
    esac
done < <(
    jq -r '
      . as $metadata
      | ($metadata.workspace_members | map({key: ., value: true}) | from_entries) as $workspace
      | ($metadata.packages | map({key: .id, value: .name}) | from_entries) as $names
      | $metadata.resolve.nodes[] as $node
      | select($workspace[$node.id] == true)
      | $node.deps[] as $dependency
      | select($workspace[$dependency.pkg] == true)
      | [$names[$node.id], $names[$dependency.pkg]]
      | @tsv
    ' "$metadata_file" | sort -u
)

printf '%s\n' 'dependency invariants passed (resolved graph)'
printf '%s\n' 'invariant 5: crate-level boundary passed; provider-trait URL/error semantics require mandatory semantic review'
