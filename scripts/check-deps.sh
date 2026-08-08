#!/usr/bin/env bash
set -euo pipefail

# Check the resolved Cargo graph, rather than manifest text. A path is printed
# for every violation so a transitive edge is actionable.

repo_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
metadata_file=$(mktemp "${TMPDIR:-/tmp}/nrr-cargo-metadata.XXXXXX")
edges_file=$(mktemp "${TMPDIR:-/tmp}/nrr-cargo-edges.XXXXXX")
trap 'rm -f "$metadata_file" "$edges_file"' EXIT

cargo metadata --format-version 1 --locked --offline --manifest-path "$repo_dir/Cargo.toml" >"$metadata_file"

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

# Initial transport/runtime denylist. It covers the HTTP and async stacks the
# design explicitly excludes and common lower-level async runtimes that could
# otherwise enter core transitively. Extend this list when a new transport or
# runtime is admitted to the workspace dependency universe.
FORBIDDEN_CORE_CRATES=(
    reqwest
    hyper
    hyper-util
    tokio
    async-std
    smol
    surf
)

check_forbidden_path "1 (resolver -> repository)" nrr-resolver nrr-repository
check_forbidden_path "2 (repository -> resolver)" nrr-repository nrr-resolver
check_forbidden_path "3 (resolver -> provider)" nrr-resolver nrr-provider

for forbidden in "${FORBIDDEN_CORE_CRATES[@]}"; do
    check_forbidden_path "4 (core -> HTTP client/async runtime: $forbidden)" nrr-core "$forbidden"
done

# Invariant 5's mechanical boundary check: core may not resolve any provider
# implementation, transport, or runtime crate. This is intentionally only a
# crate-level dependency boundary check; public trait semantics still require
# mandatory review (see the report emitted by this script).
for forbidden in nrr-provider nrr-resolver nrr-repository "${FORBIDDEN_CORE_CRATES[@]}"; do
    check_forbidden_path "5 mechanical type boundary (core -> provider/transport/runtime: $forbidden)" nrr-core "$forbidden"
done

# Enforce the complete workspace-local allowlist from the architecture. This
# also catches a new local edge that is not one of the five explicit checks.
while IFS=$'\t' read -r source target; do
    case "$source->$target" in
        nrr-provider\>nrr-core|nrr-resolver\>nrr-core|nrr-repository\>nrr-core|nrr\>nrr-core|nrr\>nrr-provider|nrr\>nrr-resolver|nrr\>nrr-repository)
            ;;
        nrr-core\>*|nrr-provider\>*|nrr-resolver\>*|nrr-repository\>*)
            printf 'workspace dependency allowlist violated: %s -> %s\n' "$source" "$target" >&2
            exit 1
            ;;
    esac
done < <(awk -F '\t' '$1 ~ /^nrr-/ && $2 ~ /^nrr-/ { print }' "$edges_file")

printf '%s\n' 'dependency invariants passed (resolved graph)'
printf '%s\n' 'invariant 5: crate-level boundary passed; provider-trait URL/error semantics require mandatory semantic review'
