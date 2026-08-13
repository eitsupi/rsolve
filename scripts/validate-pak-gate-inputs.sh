#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
record=${1:-"$repo_dir/ci/pak-gate-inputs.json"}
if [ "$#" -gt 1 ]; then
  echo "usage: validate-pak-gate-inputs.sh [record]" >&2
  exit 2
fi

check_jq() {
  if ! jq -e "$1" "$record" >/dev/null; then
    echo "pak gate validation failed: $2" >&2
    exit 1
  fi
}

check_jq '
  type == "object" and
  (keys | sort) == ["closure_manifest_sha256", "digest_policy", "fixture_manifest", "image", "native_toolchain", "pak", "r", "r_home_library_allowlist", "schema_version", "tool_library_closure"] and
  .schema_version == 1 and
  (.image | type == "string" and test("^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$"))
' "schema or image is invalid"

check_jq '
  (.r | type == "object" and
    (keys | sort) == ["architecture", "executable", "executable_sha256", "platform", "r_home", "version_string"] and
    all(.[]; type == "string" and length > 0) and
    (.executable_sha256 | test("^[0-9a-f]{64}$"))) and
  (.pak | type == "object" and
    (keys | sort) == ["containing_oci_layer_digest", "installed_tree_sha256", "library_root", "name", "package_path", "source_archive_sha256", "source_archive_status", "version"] and
    .name == "pak" and (.version | type == "string" and length > 0) and
    (.package_path | startswith("/") and (test("(^|/)\\.\\.?(/|$)") | not)) and
    (.library_root | type == "string" and startswith("/")) and
    (.installed_tree_sha256 | test("^[0-9a-f]{64}$")) and
    (.containing_oci_layer_digest | test("^sha256:[0-9a-f]{64}$")) and
    .source_archive_sha256 == null and .source_archive_status == "unavailable_in_extracted_rootfs")
' "R or pak pin is invalid"

check_jq '
  (.digest_policy | type == "object" and
    (keys | sort) == ["closure_manifest", "installed_build_identity", "tree_manifest"] and
    all(.[]; type == "string" and length > 0)) and
  (.tool_library_closure | type == "array" and length > 0) and
  (.r_home_library_allowlist | type == "array" and length > 0)
' "digest policy or package collections are invalid"

check_jq '
  def ordered_unique($key): . as $items | ($items | map(.[$key])) as $values |
    ($values == ($values | sort) and (($values | unique | length) == ($values | length)));
  def package: type == "object" and
    (keys | sort) == ["installed_tree_sha256", "name", "package_path", "version"] and
    (.name | type == "string" and length > 0) and (.version | type == "string" and length > 0) and
    (.package_path | type == "string" and startswith("/") and (test("(^|/)\\.\\.?(/|$)") | not)) and
    (.installed_tree_sha256 | test("^[0-9a-f]{64}$"));
  (.tool_library_closure | all(.[]; package) and ordered_unique("name") and ((map(.package_path) | unique | length) == length)) and
  (.r_home_library_allowlist | all(.[]; package) and ordered_unique("name") and ordered_unique("package_path"))
' "package closure shape or ordering is invalid"

check_jq '
  ([.tool_library_closure[].name] | unique) as $closure_names |
  ([.r_home_library_allowlist[].name] | unique) as $allow_names |
  ([.tool_library_closure[].package_path] | unique) as $closure_paths |
  ([.r_home_library_allowlist[].package_path] | unique) as $allow_paths |
  (($closure_names - $allow_names) | length == ($closure_names | length)) and
  (($closure_paths - $allow_paths) | length == ($closure_paths | length)) and
  ([.tool_library_closure[] | select(.name == "pak")] | length) == 1 and
  (([.tool_library_closure[] | select(.name == "pak")][0]) ==
    ({name: .pak.name, version: .pak.version, package_path: .pak.package_path, installed_tree_sha256: .pak.installed_tree_sha256}))
' "closure and allowlist are not disjoint or pak does not match"

closure_payload=$(jq -S -c '.tool_library_closure' "$record")
closure_hash=$(printf '%s' "$closure_payload" | sha256sum | awk '{print $1}')
expected_hash=$(jq -r '.closure_manifest_sha256' "$record")
[ "$closure_hash" = "$expected_hash" ] || {
  echo "pak gate validation failed: closure manifest self hash mismatch" >&2
  exit 1
}

check_jq '
  (.native_toolchain | type == "object" and
    (keys | sort) == ["executables", "headers", "os_packages"] and
    (.executables | type == "array" and length > 0 and all(.[];
      type == "object" and (keys | sort) == ["os_package", "path", "resolved_path", "sha256", "symlink_target", "version"] and
      all(.[]; type == "string") and (.sha256 | test("^[0-9a-f]{64}$")))) and
    (.headers | type == "array" and length > 0 and all(.[];
      type == "object" and (keys | sort) == ["os_package", "path", "scope", "tree_sha256"] and
      (.tree_sha256 | test("^[0-9a-f]{64}$")))) and
    (.os_packages | type == "array" and length > 0 and all(.[];
      type == "object" and (keys | sort) == ["name", "version"] and all(.[]; type == "string" and length > 0))))
' "native toolchain pin is invalid"

check_jq '
  def ordered_unique($key): . as $items | ($items | map(.[$key])) as $values |
    ($values == ($values | sort) and (($values | unique | length) == ($values | length)));
  (.fixture_manifest | type == "array" and length > 0 and ordered_unique("path") and
    all(.[]; type == "object" and (keys | sort) == ["kind", "path", "sha256"] and
      (.path | type == "string" and test("^[A-Za-z0-9._/-]+$") and (startswith("/") | not) and (test("(^|/)\\.\\.?(/|$)") | not)) and
      (.sha256 | test("^[0-9a-f]{64}$")) and (.kind == "tarball" or .kind == "packages")))
' "fixture manifest shape or ordering is invalid"

for path in $(jq -r '.fixture_manifest[].path' "$record"); do
  expected=$(jq -r --arg path "$path" '.fixture_manifest[] | select(.path == $path) | .sha256' "$record")
  actual_path="$repo_dir/$path"
  [ -f "$actual_path" ] || {
    echo "pak gate validation failed: fixture is missing: $path" >&2
    exit 1
  }
  actual=$(sha256sum "$actual_path" | awk '{print $1}')
  [ "$actual" = "$expected" ] || {
    echo "pak gate validation failed: fixture digest mismatch: $path" >&2
    exit 1
  }
done

echo "validated $record"
