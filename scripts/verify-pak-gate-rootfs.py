#!/usr/bin/env python3
"""Fail-closed verification of the pinned pak-gate release root filesystem.

This is intentionally a release-only verifier.  It does not pull images,
extract layers, or update the pin record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RECORD = REPO_ROOT / "ci" / "pak-gate-inputs.json"
class VerificationError(Exception):
    """A concise, user-actionable verification failure."""


def fail(message: str) -> None:
    raise VerificationError(message)


def load_record(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"record: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"record {path}: invalid JSON: {error}")
    if not isinstance(value, dict):
        fail("record: top-level value must be an object")
    return value


def require_keys(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label}: unexpected schema keys")


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label}: expected non-empty string")
    return value


def require_hash(value: Any, label: str, prefix: str = "") -> str:
    text = require_string(value, label)
    if len(text) != len(prefix) + 64 or not text.startswith(prefix):
        fail(f"{label}: expected SHA-256")
    digest = text[len(prefix) :]
    if any(char not in "0123456789abcdef" for char in digest):
        fail(f"{label}: expected lowercase SHA-256")
    return text


def validate_schema(record: dict[str, Any]) -> None:
    require_keys(
        record,
        {
            "schema_version",
            "image",
            "r",
            "digest_policy",
            "pak",
            "tool_library_closure",
            "closure_manifest_sha256",
            "r_home_library_allowlist",
            "native_toolchain",
            "fixture_manifest",
        },
        "record",
    )
    if record["schema_version"] != 1:
        fail("record.schema_version: expected 1")
    require_string(record["image"], "record.image")
    if "@sha256:" not in record["image"]:
        fail("record.image: expected digest-pinned image")
    require_hash(record["closure_manifest_sha256"], "record.closure_manifest_sha256")

    r = record["r"]
    require_keys(r, {"version_string", "platform", "architecture", "r_home", "executable", "executable_sha256"}, "record.r")
    for key, value in r.items():
        require_string(value, f"record.r.{key}")
    require_hash(r["executable_sha256"], "record.r.executable_sha256")

    policy = record["digest_policy"]
    require_keys(policy, {"tree_manifest", "closure_manifest", "installed_build_identity"}, "record.digest_policy")
    for key, value in policy.items():
        require_string(value, f"record.digest_policy.{key}")

    pak = record["pak"]
    require_keys(
        pak,
        {
            "name",
            "version",
            "package_path",
            "library_root",
            "installed_tree_sha256",
            "containing_oci_layer_digest",
            "source_archive_sha256",
            "source_archive_status",
        },
        "record.pak",
    )
    if pak["name"] != "pak":
        fail("record.pak.name: expected pak")
    for key in ("version", "package_path", "library_root", "source_archive_status"):
        require_string(pak[key], f"record.pak.{key}")
    require_hash(pak["installed_tree_sha256"], "record.pak.installed_tree_sha256")
    require_hash(pak["containing_oci_layer_digest"], "record.pak.containing_oci_layer_digest", "sha256:")
    if pak["source_archive_sha256"] is not None:
        fail("record.pak.source_archive_sha256: expected null for an extracted rootfs pin")

    def validate_packages(items: Any, label: str) -> None:
        if not isinstance(items, list) or not items:
            fail(f"{label}: expected non-empty array")
        for index, item in enumerate(items):
            item_label = f"{label}[{index}]"
            require_keys(item, {"name", "version", "package_path", "installed_tree_sha256"}, item_label)
            require_string(item["name"], f"{item_label}.name")
            require_string(item["version"], f"{item_label}.version")
            require_absolute_record_path(item["package_path"], f"{item_label}.package_path")
            require_hash(item["installed_tree_sha256"], f"{item_label}.installed_tree_sha256")

    validate_packages(record["tool_library_closure"], "record.tool_library_closure")
    validate_packages(record["r_home_library_allowlist"], "record.r_home_library_allowlist")
    closure = record["tool_library_closure"]
    allowlist = record["r_home_library_allowlist"]
    if {item["name"] for item in closure} & {item["name"] for item in allowlist}:
        fail("record package inventories: closure and R-home names overlap")
    if {item["package_path"] for item in closure} & {item["package_path"] for item in allowlist}:
        fail("record package inventories: closure and R-home paths overlap")
    payload = json.dumps(closure, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(payload).hexdigest() != record["closure_manifest_sha256"]:
        fail("record.closure_manifest_sha256: self-hash mismatch")

    native = record["native_toolchain"]
    require_keys(native, {"executables", "headers", "os_packages"}, "record.native_toolchain")
    for index, item in enumerate(native["executables"]):
        label = f"record.native_toolchain.executables[{index}]"
        require_keys(item, {"path", "resolved_path", "symlink_target", "version", "sha256", "os_package"}, label)
        for key in ("path", "resolved_path", "version", "os_package"):
            require_string(item[key], f"{label}.{key}")
        if not isinstance(item["symlink_target"], str):
            fail(f"{label}.symlink_target: expected string")
        require_absolute_record_path(item["path"], f"{label}.path")
        require_absolute_record_path(item["resolved_path"], f"{label}.resolved_path")
        require_hash(item["sha256"], f"{label}.sha256")
    for index, item in enumerate(native["headers"]):
        label = f"record.native_toolchain.headers[{index}]"
        require_keys(item, {"path", "scope", "tree_sha256", "os_package"}, label)
        require_absolute_record_path(item["path"], f"{label}.path")
        require_string(item["scope"], f"{label}.scope")
        require_string(item["os_package"], f"{label}.os_package")
        require_hash(item["tree_sha256"], f"{label}.tree_sha256")
    if not isinstance(native["os_packages"], list) or not native["os_packages"]:
        fail("record.native_toolchain.os_packages: expected non-empty array")
    for index, item in enumerate(native["os_packages"]):
        label = f"record.native_toolchain.os_packages[{index}]"
        require_keys(item, {"name", "version"}, label)
        require_string(item["name"], f"{label}.name")
        require_string(item["version"], f"{label}.version")

    fixtures = record["fixture_manifest"]
    if not isinstance(fixtures, list) or not fixtures:
        fail("record.fixture_manifest: expected non-empty array")
    for index, item in enumerate(fixtures):
        label = f"record.fixture_manifest[{index}]"
        require_keys(item, {"path", "sha256", "kind"}, label)
        path = require_string(item["path"], f"{label}.path")
        if path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")):
            fail(f"{label}.path: unsafe repository-relative path")
        if item["kind"] not in ("tarball", "packages"):
            fail(f"{label}.kind: unknown fixture kind")
        require_hash(item["sha256"], f"{label}.sha256")


def require_absolute_record_path(value: Any, label: str) -> str:
    path = require_string(value, label)
    parsed = PurePosixPath(path)
    if not parsed.is_absolute() or any(part in (".", "..") for part in parsed.parts):
        fail(f"{label}: unsafe absolute path")
    return path


def rootfs_path(rootfs: Path, value: str, label: str) -> Path:
    require_absolute_record_path(value, label)
    relative = PurePosixPath(value).relative_to("/")
    candidate = rootfs.joinpath(*relative.parts)
    root_real = rootfs.resolve()
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root_real)
    except ValueError:
        fail(f"{label}: path escapes rootfs through a symlink")
    return candidate


def internal_path(rootfs: Path, path: Path) -> str:
    return "/" + path.resolve().relative_to(rootfs.resolve()).as_posix().lstrip("/")


def _resolve_symlink(rootfs: Path, link: Path, measured_root: Path) -> Path:
    try:
        link_relative = tuple(link.relative_to(rootfs).parts)
        measured_relative = tuple(measured_root.relative_to(rootfs).parts)
    except ValueError:
        fail(f"tree {link}: path is outside rootfs")
    resolved: list[str] = []
    pending = list(link_relative)
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    for _ in range(256):
        if not pending:
            current = tuple(resolved)
            if current[: len(measured_relative)] != measured_relative:
                fail(f"tree {link}: final symlink target escapes measured tree")
            return rootfs.joinpath(*current)
        state = (tuple(resolved), tuple(pending))
        if state in seen:
            fail(f"tree {link}: symlink chain loops")
        seen.add(state)
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            if not resolved:
                fail(f"tree {link}: symlink target escapes rootfs")
            resolved.pop()
            continue
        candidate = rootfs.joinpath(*resolved, component)
        try:
            info = candidate.lstat()
        except OSError as error:
            fail(f"tree {link}: symlink target is dangling: {error}")
        if stat.S_ISLNK(info.st_mode):
            try:
                target = os.readlink(candidate)
                target.encode("utf-8")
            except (OSError, UnicodeError) as error:
                fail(f"tree {link}: invalid symlink target: {error}")
            target_parts = target.split("/")
            if target.startswith("/"):
                resolved.clear()
                pending = target_parts[1:] + pending
            else:
                pending = target_parts + pending
            continue
        if pending and not stat.S_ISDIR(info.st_mode):
            fail(f"tree {link}: symlink target has a non-directory ancestor")
        resolved.append(component)
    fail(f"tree {link}: symlink chain is too deep")


def tree_digest(root: Path, rootfs: Path) -> str:
    if not root.is_dir() or root.is_symlink():
        fail(f"tree {root}: expected physical directory")
    if not rootfs.is_dir() or rootfs.is_symlink():
        fail(f"rootfs {rootfs}: expected physical directory")
    try:
        root.relative_to(rootfs)
    except ValueError:
        fail(f"tree {root}: outside rootfs")
    entries: list[dict[str, Any]] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dirnames.sort()
        filenames.sort()
        names = list(dirnames) + list(filenames)
        for name in names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            try:
                relative.encode("utf-8")
            except UnicodeEncodeError:
                fail(f"tree {path}: relative path is not UTF-8")
            try:
                info = path.lstat()
            except OSError as error:
                fail(f"tree {path}: cannot stat: {error}")
            entry: dict[str, Any] = {"mode": stat.S_IMODE(info.st_mode), "path": relative}
            if stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256()
                try:
                    with path.open("rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(block)
                except OSError as error:
                    fail(f"tree {path}: cannot read: {error}")
                entry["sha256"] = digest.hexdigest()
                entry["type"] = "file"
            elif stat.S_ISDIR(info.st_mode):
                entry["type"] = "directory"
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                try:
                    target.encode("utf-8")
                except UnicodeEncodeError:
                    fail(f"tree {path}: symlink target is not UTF-8")
                _resolve_symlink(rootfs, path, root)
                entry["target"] = target
                entry["type"] = "symlink"
            else:
                fail(f"tree {path}: unsupported filesystem entry type")
            entries.append(entry)
    entries.sort(key=lambda entry: entry["path"].encode("utf-8"))
    payload = b"".join(
        json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        for entry in entries
    )
    return hashlib.sha256(payload).hexdigest()


def file_sha256(path: Path, label: str) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        fail(f"{label}: cannot read: {error}")
    return digest.hexdigest()


def parse_dpkg_owners(output: str) -> set[str]:
    owners: set[str] = set()
    for line in output.splitlines():
        if not line or ": /" not in line:
            fail("dpkg-query -S: malformed owner line")
        owner_text, path = line.rsplit(": /", 1)
        if not owner_text or not path:
            fail("dpkg-query -S: malformed owner line")
        for owner in owner_text.split(","):
            owner = owner.strip()
            match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9+.-]*)(?::([A-Za-z0-9][A-Za-z0-9+.-]*))?", owner)
            if match is None:
                fail("dpkg-query -S: malformed package owner")
            owners.add(match.group(1))
    if not owners:
        fail("dpkg-query -S: no package owners")
    return owners


def parse_description(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        fail(f"{path}: cannot read DESCRIPTION: {error}")
    fields: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        if line.startswith((" ", "\t")):
            if current is None:
                fail(f"{path}: continuation without a field")
            fields[current] += "\n" + line.lstrip()
        elif not line:
            continue
        elif ":" in line:
            name, value = line.split(":", 1)
            if not name or name in fields:
                fail(f"{path}: invalid or duplicate DESCRIPTION field {name!r}")
            current = name
            fields[name] = value.lstrip(" ")
        else:
            fail(f"{path}: malformed DESCRIPTION line")
    return fields


def verify_package_inventory(rootfs: Path, record: dict[str, Any]) -> None:
    entries = record["tool_library_closure"] + record["r_home_library_allowlist"]
    by_library: dict[Path, set[str]] = {}
    for item in entries:
        package_path = rootfs_path(rootfs, item["package_path"], f"package {item['name']}.package_path")
        if package_path.is_symlink() or not package_path.is_dir():
            fail(f"package {item['name']}: package_path is not a physical directory")
        description = package_path / "DESCRIPTION"
        if description.is_symlink() or not description.is_file():
            fail(f"package {item['name']}: DESCRIPTION is not a regular file")
        fields = parse_description(description)
        if fields.get("Package") != item["name"] or fields.get("Version") != item["version"]:
            fail(f"package {item['name']}: DESCRIPTION identity mismatch")
        actual = tree_digest(package_path, rootfs)
        if actual != item["installed_tree_sha256"]:
            fail(f"package {item['name']}: tree digest mismatch")
        by_library.setdefault(package_path.parent, set()).add(package_path.name)

    for library, declared in by_library.items():
        if not library.is_dir() or library.is_symlink():
            fail(f"package library {library}: not a physical directory")
        actual: set[str] = set()
        for entry in os.scandir(library):
            path = Path(entry.path)
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                fail(f"package library {library}: undeclared non-package entry {path.name}")
            actual.add(path.name)
        if actual != declared:
            fail(f"package library {library}: top-level package set mismatch")

    pak = record["pak"]
    pak_entry = next(item for item in record["tool_library_closure"] if item["name"] == "pak")
    if pak_entry != {key: pak[key] for key in ("name", "version", "package_path", "installed_tree_sha256")}:
        fail("record.pak: does not match pak closure entry")


def build_isolated_command(rootfs: Path, argv: list[str]) -> list[str]:
    return [
        "unshare",
        "--user",
        "--map-root-user",
        "--net",
        "bwrap",
        "--die-with-parent",
        "--ro-bind",
        str(rootfs),
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--unshare-pid",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--chdir",
        "/",
        *argv,
    ]


def run_isolated(rootfs: Path, argv: list[str], input_text: str | None = None) -> str:
    command = build_isolated_command(rootfs, argv)
    try:
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except OSError as error:
        fail(f"isolated command unavailable ({' '.join(command[:4])}): {error}")
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no stderr"
        fail(f"isolated command failed ({' '.join(argv)}): {detail}")
    return result.stdout


def verify_r(rootfs: Path, record: dict[str, Any]) -> None:
    r = record["r"]
    executable = rootfs_path(rootfs, r["executable"], "record.r.executable")
    if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        fail("record.r.executable: expected regular executable")
    digest = file_sha256(executable, "record.r.executable")
    if digest != r["executable_sha256"]:
        fail("record.r.executable_sha256: digest mismatch")
    pak_path_literal = json.dumps(record["pak"]["package_path"], ensure_ascii=False)
    script = (
        f"pak_path <- {pak_path_literal}; .libPaths(c(dirname(pak_path), file.path(pak_path, 'library'), .libPaths()));"
        'cat(paste0("NRR_R_VERSION_STRING=", R.version.string, "\\n"));'
        'cat(paste0("NRR_R_PLATFORM=", R.version$platform, "\\n"));'
        'cat(paste0("NRR_R_HOME=", R.home(), "\\n"));'
        "library(pak, lib.loc=dirname(pak_path));"
        'cat(paste0("NRR_PAK_VERSION=", as.character(packageVersion("pak")), "\\n"));'
        'cat(paste0("NRR_PAK_PATH=", normalizePath(find.package("pak", lib.loc=dirname(pak_path)), mustWork=TRUE), "\\n"));'
    )
    output = run_isolated(rootfs, [r["executable"], "--vanilla", "--slave", "-e", script])
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    expected = {
        "NRR_R_VERSION_STRING": r["version_string"],
        "NRR_R_PLATFORM": r["platform"],
        "NRR_R_HOME": r["r_home"],
        "NRR_PAK_VERSION": record["pak"]["version"],
        "NRR_PAK_PATH": record["pak"]["package_path"],
    }
    for key, value in expected.items():
        if values.get(key) != value:
            fail(f"R identity {key}: expected {value!r}, got {values.get(key)!r}")


def verify_native(rootfs: Path, record: dict[str, Any]) -> None:
    native = record["native_toolchain"]
    os_packages = {item["name"]: item["version"] for item in native["os_packages"]}
    for item in native["executables"]:
        path = rootfs_path(rootfs, item["path"], f"native executable {item['path']}")
        if path.is_symlink():
            if os.readlink(path) != item["symlink_target"]:
                fail(f"native executable {item['path']}: symlink target mismatch")
        elif item["symlink_target"]:
            fail(f"native executable {item['path']}: unexpected symlink target pin")
        resolved = path.resolve()
        if internal_path(rootfs, resolved) != item["resolved_path"]:
            fail(f"native executable {item['path']}: resolved path mismatch")
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            fail(f"native executable {item['path']}: resolved target is not executable")
        if file_sha256(resolved, f"native executable {item['path']}") != item["sha256"]:
            fail(f"native executable {item['path']}: digest mismatch")
        if item["os_package"] not in os_packages:
            fail(f"native executable {item['path']}: owner package is not declared")
        owner = run_isolated(rootfs, ["/usr/bin/dpkg-query", "-S", item["resolved_path"]])
        owners = parse_dpkg_owners(owner)
        if item["os_package"] not in owners:
            fail(f"native executable {item['path']}: dpkg owner mismatch")
        output = run_isolated(rootfs, [item["path"], "--version"])
        first = next((line for line in output.splitlines() if line.strip()), "")
        if first != item["version"]:
            fail(f"native executable {item['path']}: --version mismatch")

    requested = sorted(os_packages.items())
    output = run_isolated(
        rootfs,
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${Package}\\t${Version}\\n",
            *(name for name, _ in requested),
        ],
    )
    actual: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) == 2:
            actual[fields[0]] = fields[1]
    if actual != os_packages:
        fail("native_toolchain.os_packages: dpkg versions mismatch")

    for item in native["headers"]:
        path = rootfs_path(rootfs, item["path"], f"header {item['path']}")
        if not path.is_dir() or path.is_symlink():
            fail(f"header {item['path']}: expected physical directory")
        if tree_digest(path, rootfs) != item["tree_sha256"]:
            fail(f"header {item['path']}: tree digest mismatch")
        if item["os_package"] not in os_packages:
            fail(f"header {item['path']}: owner package is not declared")
        owner = run_isolated(rootfs, ["/usr/bin/dpkg-query", "-S", item["path"]])
        owners = parse_dpkg_owners(owner)
        if item["os_package"] not in owners:
            fail(f"header {item['path']}: dpkg owner mismatch")


def verify_fixtures(record: dict[str, Any]) -> None:
    repo_real = REPO_ROOT.resolve()
    for item in record["fixture_manifest"]:
        path = PurePosixPath(item["path"])
        fixture = REPO_ROOT.joinpath(*path.parts)
        try:
            fixture.resolve().relative_to(repo_real)
        except ValueError:
            fail(f"fixture {item['path']}: escapes repository")
        if fixture.is_symlink() or not fixture.is_file():
            fail(f"fixture {item['path']}: expected regular file")
        if file_sha256(fixture, f"fixture {item['path']}") != item["sha256"]:
            fail(f"fixture {item['path']}: digest mismatch")


def verify(rootfs: Path, record_path: Path) -> None:
    record = load_record(record_path)
    validator = REPO_ROOT / "scripts" / "validate-pak-gate-inputs.sh"
    try:
        result = subprocess.run(
            ["sh", str(validator), str(record_path)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except OSError as error:
        fail(f"static record validator unavailable: {error}")
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "validation failed"
        fail(f"static record validation failed: {detail}")
    validate_schema(record)
    verify_fixtures(record)
    verify_package_inventory(rootfs, record)
    verify_r(rootfs, record)
    verify_native(rootfs, record)


def resolve_record_path(value: Path) -> Path:
    candidate = value if value.is_absolute() else Path.cwd() / value
    if candidate.is_symlink() or not candidate.is_file():
        fail("record: expected an existing regular non-symlink file")
    return candidate.resolve()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--record", type=Path, default=DEFAULT_RECORD)
    args = parser.parse_args(argv)
    rootfs = args.rootfs
    if not rootfs.is_absolute() or not rootfs.is_dir() or rootfs.is_symlink():
        print("rootfs: expected an absolute existing physical directory", file=sys.stderr)
        return 2
    try:
        record_path = resolve_record_path(args.record)
        verify(rootfs, record_path)
    except VerificationError as error:
        print(f"pak gate rootfs verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified pak gate rootfs: {rootfs}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
