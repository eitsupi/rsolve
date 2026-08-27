#!/usr/bin/env python3
"""Benchmark the prebuilt tidyverse resolver through its metrics boundary.

This is intentionally a small consumer of the rsolve CLI.  It never uses the
process user's metadata cache: every cache and artifact path is below the
explicit (or newly-created) output root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import shlex
import subprocess
import sys
import tempfile
from typing import Any, Iterable
from urllib.parse import urlsplit


MODES = ("isolated-cold", "fresh-online-warm", "offline-warm", "projection-warm")
CAPABILITY_NAME = ".benchmark-capability.json"
CAPABILITY_SCHEMA_VERSION = 1
SOURCE_NAMES = (
    "current_index",
    "archive_history",
    "allpackages",
    "package_local_index",
    "tarball_description",
)
PHASE_NAMES = (
    "snapshot_cache_decision_ns",
    "refresh_acquisition_ns",
    "closure_lookup_ns",
    "snapshot_composition_and_publication_ns",
    "prepared_loader_lookup_ns",
    "solve_ns",
    "lock_projection_ns",
    "lock_serialization_ns",
    "lock_round_trip_ns",
    "atomic_lock_write_ns",
)
METRICS_NAMES = {
    "phases",
    "metrics_overflow",
    "snapshot_cache_decision",
    "loader_lookup_calls",
    "loader_unique_package_count",
    "solve_output_package_count",
    "provider_refresh",
}
PROVIDER_NAMES = {
    "http_attempts",
    "successful_response_body_bytes",
    "statuses",
    *SOURCE_NAMES,
    "raw_cache_hits",
    "raw_cache_misses",
    "raw_cache_corrupt",
    "projection_reuses",
    "projection_builds",
    "projection_rebuilds",
    "package_history_lookups",
    "allpackages_adoptions",
    "package_local_fallbacks",
    "quarantined_releases",
    "coverage_gaps",
    "coverage_conflicts",
}
STATUS_NAMES = {"status_200", "status_304", "status_404", "status_410", "other"}


class BenchmarkError(RuntimeError):
    """An unsafe benchmark input or invalid benchmark artifact."""


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _reject_symlink(path: Path) -> None:
    metadata = _lstat(path)
    if metadata is not None and path.is_symlink():
        raise BenchmarkError(f"refusing symlink path: {path}")


def _assert_directory(path: Path) -> None:
    _reject_symlink(path)
    if not path.is_dir():
        raise BenchmarkError(f"expected directory: {path}")


def _assert_no_symlink_ancestors(path: Path) -> None:
    current = path
    while True:
        _reject_symlink(current)
        if current.parent == current:
            return
        current = current.parent


def _assert_no_symlinks(root: Path) -> None:
    _reject_symlink(root)
    _assert_directory(root)
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            child = current_path / name
            if child.is_symlink():
                raise BenchmarkError(f"refusing symlink below benchmark root: {child}")


def _remove_tree(path: Path) -> None:
    """Remove a previously validated tree without following symlinks."""
    _assert_no_symlinks(path)
    shutil.rmtree(path)


def prepare_output_root(path: Path | None) -> Path:
    """Create an empty absolute output root, rejecting unsafe targets."""
    if path is None:
        return Path(tempfile.mkdtemp(prefix="rsolve-tidyverse-benchmark-")).resolve()
    path = path.expanduser()
    if not path.is_absolute():
        raise BenchmarkError("--output-root must be an absolute path")
    # Refuse symlinked ancestors as well as a symlink at the root itself.
    _assert_no_symlink_ancestors(path.parent)
    metadata = _lstat(path)
    if metadata is not None:
        _assert_directory(path)
        if any(path.iterdir()):
            raise BenchmarkError(f"output root must be empty: {path}")
    else:
        path.mkdir()
    return path


def _copy_tree(source: Path, destination: Path) -> None:
    _assert_no_symlinks(source)
    _assert_no_symlink_ancestors(destination.parent)
    try:
        destination.resolve().relative_to(source.resolve())
    except ValueError:
        pass
    else:
        raise BenchmarkError("copy destination must not be below source")
    if destination.exists() or destination.is_symlink():
        raise BenchmarkError(f"copy destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, symlinks=False)


def reset_cache(cache: Path) -> None:
    """Reset only the known cache version directory used by rsolve."""
    _assert_no_symlink_ancestors(cache.parent)
    if cache.exists() or cache.is_symlink():
        _assert_directory(cache)
        entries = list(cache.iterdir())
        for entry in entries:
            if entry.name != "v1":
                raise BenchmarkError(f"unexpected cache child: {entry}")
            _remove_tree(entry)
    else:
        cache.mkdir(parents=True)


def initialize_capability(root: Path) -> str:
    """Create a random capability marker after the root has been verified empty."""
    marker = root / CAPABILITY_NAME
    token = secrets.token_hex(32)
    _atomic_json(
        marker,
        {"schema_version": CAPABILITY_SCHEMA_VERSION, "token": token},
    )
    return token


def _read_capability(root: Path, token: str) -> None:
    marker = root / CAPABILITY_NAME
    _reject_symlink(marker)
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkError("invalid benchmark capability marker") from error
    if value != {"schema_version": CAPABILITY_SCHEMA_VERSION, "token": token}:
        raise BenchmarkError("benchmark capability marker mismatch")


def prepare_trial(root: Path, mode: str, token: str) -> None:
    """Perform one hyperfine prepare using only capability-derived paths."""
    if mode not in MODES:
        raise BenchmarkError(f"unknown benchmark mode: {mode}")
    root = root.expanduser()
    if not root.is_absolute():
        raise BenchmarkError("benchmark root must be absolute")
    _assert_no_symlink_ancestors(root)
    _assert_directory(root)
    _read_capability(root, token)
    mode_root = root / mode
    _assert_directory(mode_root)
    cache = mode_root / "cache"
    lock = mode_root / "lock.toml"
    report = mode_root / "metrics.json"
    for output in (lock, report):
        _reject_symlink(output)
        if output.exists():
            if not output.is_file():
                raise BenchmarkError(f"benchmark output is not a file: {output}")
            output.unlink()
    if mode == "isolated-cold":
        reset_cache(cache)
        return
    if mode != "projection-warm":
        _assert_directory(cache)
        return
    source = root / "isolated-cold" / "cache"
    _assert_directory(source)
    if cache.exists() or cache.is_symlink():
        _remove_tree(cache)
    prepare_projection_cache(source, cache)


def locate_registry_store(cache: Path) -> Path:
    """Find the one registry store in a cache, rejecting ambiguous layouts."""
    _assert_no_symlink_ancestors(cache)
    _assert_directory(cache)
    version = cache / "v1"
    registries = version / "registries"
    _assert_directory(version)
    _assert_directory(registries)
    entries = list(registries.iterdir())
    if len(entries) != 1:
        raise BenchmarkError("expected exactly one registry store")
    store = entries[0]
    _assert_directory(store)
    for required in (store / "generations", store / "raw-cache" / "v1" / "projections"):
        _assert_directory(required)
    for required_file in (store / "current", store / "current-validation"):
        _reject_symlink(required_file)
        if not required_file.is_file():
            raise BenchmarkError(f"expected registry pointer file: {required_file}")
    return store


def prepare_projection_cache(source: Path, destination: Path) -> Path:
    """Copy a cache and strip only snapshot pointers/generations."""
    source_store = locate_registry_store(source)
    _copy_tree(source, destination)
    relative_store = source_store.relative_to(source)
    store = destination / relative_store
    for name in ("current", "current-validation"):
        path = store / name
        _reject_symlink(path)
        path.unlink()
    generations = store / "generations"
    _remove_tree(generations)
    generations.mkdir()
    _assert_directory(store / "raw-cache" / "v1" / "projections")
    return store


def validate_mirror(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        # Accessing port validates the optional numeric port and can raise
        # ValueError for malformed values even after urlsplit succeeds.
        parsed.port
    except ValueError as exc:
        raise BenchmarkError("mirror must be a valid HTTP(S) URL") from exc
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise BenchmarkError("mirror must be an HTTP(S) URL with a host")
    if parsed.username is not None or parsed.password is not None:
        raise BenchmarkError("mirror userinfo is not permitted")
    if parsed.query or parsed.fragment:
        raise BenchmarkError("mirror query and fragment are not permitted")
    return value


def shell_command(binary: Path, cache: Path, lock: Path, report: Path, *, offline: bool, mirror: str, r_version: str, package: str) -> str:
    args = [
        str(binary),
        "lock",
        "--r-version",
        r_version,
        "--package",
        package,
        "--cran-mirror",
        mirror,
        "--metadata-cache",
        str(cache),
        "--output",
        str(lock),
        "--metrics-output",
        str(report),
    ]
    if offline:
        args.append("--offline")
    return shlex.join(args)


def prepare_command(root: Path, mode: str, token: str) -> str:
    return shlex.join(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--prepare-trial",
            "--output-root",
            str(root),
            "--mode",
            mode,
            "--capability-token",
            token,
        ]
    )


def _run_version(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise BenchmarkError(f"unable to query version: {command[0]}") from error
    line = (completed.stdout or completed.stderr).strip().splitlines()
    return line[0] if line else "unknown"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise BenchmarkError(f"unable to hash binary: {path}") from error
    return digest.hexdigest()


def run_hyperfine(hyperfine: Path, command: str, output: Path, *, prepare: str | None, warmup: int, runs: int) -> None:
    args = [str(hyperfine), "--warmup", str(warmup), "--runs", str(runs), "--export-json", str(output)]
    if prepare is not None:
        args.extend(["--prepare", prepare])
    args.append(command)
    try:
        subprocess.run(args, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise BenchmarkError("hyperfine benchmark failed") from error


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BenchmarkError(f"{label} must be a non-negative integer")
    return value


def _validate_provider(provider: Any, mode: str) -> dict[str, Any] | None:
    if provider is None:
        if mode in {"isolated-cold", "projection-warm"}:
            raise BenchmarkError(f"{mode}: provider_refresh is required")
        return None
    if not isinstance(provider, dict) or set(provider) != PROVIDER_NAMES:
        raise BenchmarkError("provider_refresh schema mismatch")
    attempts = _integer(provider["http_attempts"], "http_attempts")
    body_bytes = _integer(provider["successful_response_body_bytes"], "successful_response_body_bytes")
    statuses = provider["statuses"]
    if not isinstance(statuses, dict) or set(statuses) != STATUS_NAMES:
        raise BenchmarkError("provider status schema mismatch")
    status_total = sum(_integer(statuses[name], name) for name in STATUS_NAMES)
    if status_total > attempts:
        raise BenchmarkError("provider status count exceeds http_attempts")
    source_requests = 0
    source_bytes = 0
    for name in SOURCE_NAMES:
        source = provider[name]
        if not isinstance(source, dict) or set(source) != {"requests", "successful_body_bytes"}:
            raise BenchmarkError(f"provider source schema mismatch: {name}")
        source_requests += _integer(source["requests"], f"{name}.requests")
        source_bytes += _integer(source["successful_body_bytes"], f"{name}.successful_body_bytes")
    if attempts != source_requests or body_bytes != source_bytes:
        raise BenchmarkError("provider aggregate counters do not match source counters")
    scalar_names = PROVIDER_NAMES - {"statuses", *SOURCE_NAMES}
    for name in scalar_names:
        _integer(provider[name], f"provider.{name}")
    if mode in {"fresh-online-warm", "offline-warm"} and attempts != 0:
        raise BenchmarkError(f"{mode}: warm provider must be null or all-zero")
    if mode == "projection-warm" and (
        attempts != 0
        or any(provider[name]["requests"] != 0 for name in SOURCE_NAMES)
        or provider["allpackages_adoptions"] == 0
        or provider["raw_cache_hits"] == 0
        or provider["projection_reuses"] == 0
    ):
        raise BenchmarkError("projection-warm: expected cache reuse without HTTP")
    if mode == "isolated-cold" and (
        attempts == 0 or provider["allpackages"]["requests"] != 1
    ):
        raise BenchmarkError("isolated-cold: expected one ALLPACKAGES acquisition")
    return provider


def validate_metrics_report(path: Path, mode: str, lock: Path) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"invalid metrics report: {path}") from error
    if not isinstance(report, dict) or set(report) != {"schema_version", "metrics", "lock_byte_count"} or report["schema_version"] != 1:
        raise BenchmarkError("metrics report schema_version must be 1")
    lock_bytes = lock.read_bytes()
    if _integer(report["lock_byte_count"], "lock_byte_count") != len(lock_bytes):
        raise BenchmarkError("metrics lock_byte_count does not match lock")
    metrics = report["metrics"]
    if not isinstance(metrics, dict) or set(metrics) != METRICS_NAMES or metrics["metrics_overflow"] is not False:
        raise BenchmarkError("metrics schema mismatch or overflow")
    phases = metrics["phases"]
    if not isinstance(phases, dict) or set(phases) != set(PHASE_NAMES):
        raise BenchmarkError("phase schema mismatch")
    for name, value in phases.items():
        if value is not None:
            _integer(value, f"phase.{name}")
    required_phases = {
        "snapshot_cache_decision_ns",
        "solve_ns",
        "lock_projection_ns",
        "lock_serialization_ns",
        "lock_round_trip_ns",
        "atomic_lock_write_ns",
    }
    if mode in {"isolated-cold", "projection-warm"}:
        required_phases.update(
            {"refresh_acquisition_ns", "snapshot_composition_and_publication_ns"}
        )
    missing_phases = [name for name in required_phases if phases[name] is None]
    if missing_phases:
        raise BenchmarkError(f"{mode}: required phase is absent: {missing_phases[0]}")
    expected_decision = {
        "isolated-cold": "refreshed",
        "fresh-online-warm": "fresh_hit",
        "offline-warm": "offline_compatible",
        "projection-warm": "refreshed",
    }[mode]
    if metrics["snapshot_cache_decision"] != expected_decision:
        raise BenchmarkError(f"{mode}: unexpected cache decision")
    for name in ("loader_lookup_calls", "loader_unique_package_count", "solve_output_package_count"):
        _integer(metrics[name], name)
    if metrics["solve_output_package_count"] == 0:
        raise BenchmarkError(f"{mode}: solve produced no packages")
    if mode in {"fresh-online-warm", "offline-warm"} and phases["refresh_acquisition_ns"] is not None:
        raise BenchmarkError(f"{mode}: refresh phase must be absent")
    _validate_provider(metrics["provider_refresh"], mode)
    return report


def _hyperfine_summary(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"invalid hyperfine JSON: {path}") from error
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != 1:
        raise BenchmarkError("hyperfine must contain exactly one result")
    result = results[0]
    if not isinstance(result, dict) or not isinstance(result.get("times"), list):
        raise BenchmarkError("hyperfine times are missing")
    times = result["times"]
    if not times or not all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in times):
        raise BenchmarkError("hyperfine times are invalid")
    exit_codes = result.get("exit_codes")
    if not isinstance(exit_codes, list) or len(exit_codes) != len(times) or any(code != 0 for code in exit_codes):
        raise BenchmarkError("hyperfine contains a failed trial")
    fields = ("mean", "stddev", "min", "max", "median", "user", "system")
    summary: dict[str, Any] = {"trial_count": len(times)}
    for field in fields:
        value = result.get(field)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise BenchmarkError(f"hyperfine field is missing: {field}")
        summary[field] = value
    return summary


def fallback_summary(provider: dict[str, Any] | None) -> dict[str, int]:
    """Return fallback counters suitable for the public benchmark manifest."""
    if provider is None:
        return {"package_count": 0, "package_local_bytes": 0}
    return {
        "package_count": provider["package_local_fallbacks"],
        "package_local_bytes": provider["package_local_index"]["successful_body_bytes"],
    }


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise BenchmarkError(f"artifact escapes output root: {path}") from error


def _atomic_json(path: Path, value: Any) -> None:
    _reject_symlink(path)
    encoded = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as temporary:
        temporary.write(encoded)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    try:
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def benchmark(args: argparse.Namespace) -> Path:
    binary = args.binary.expanduser()
    hyperfine = args.hyperfine.expanduser()
    _reject_symlink(binary)
    if not binary.is_file():
        raise BenchmarkError(f"binary is not a file: {binary}")
    _reject_symlink(hyperfine)
    if not hyperfine.is_file() and shutil.which(str(hyperfine)) is None:
        raise BenchmarkError(f"hyperfine was not found: {hyperfine}")
    mirror = validate_mirror(args.mirror)
    root = prepare_output_root(args.output_root)
    capability_token = initialize_capability(root)
    binary_version = _run_version([str(binary), "--version"])
    hyperfine_version = _run_version([str(hyperfine), "--version"])
    mode_data: dict[str, Any] = {}
    cold_cache: Path | None = None
    for mode in MODES:
        mode_root = root / mode
        mode_root.mkdir()
        cache = mode_root / "cache"
        lock = mode_root / "lock.toml"
        report = mode_root / "metrics.json"
        hyperfine_json = mode_root / "hyperfine.json"
        if mode == "isolated-cold":
            cache.mkdir()
            cold_cache = cache
        elif cold_cache is None:
            raise BenchmarkError("cold cache must be prepared first")
        elif mode == "projection-warm":
            # The isolated copy is made by prepare_trial immediately before
            # every warmup and timed trial, never during setup.
            pass
        else:
            _copy_tree(cold_cache, cache)
        command = shell_command(binary, cache, lock, report, offline=mode == "offline-warm", mirror=mirror, r_version=args.r_version, package=args.package)
        run_hyperfine(
            hyperfine,
            command,
            hyperfine_json,
            prepare=prepare_command(root, mode, capability_token),
            warmup=args.cold_warmup if mode == "isolated-cold" else args.warm_warmup,
            runs=args.cold_runs if mode == "isolated-cold" else args.warm_runs,
        )
        validated = validate_metrics_report(report, mode, lock)
        timing = _hyperfine_summary(hyperfine_json)
        provider = validated["metrics"]["provider_refresh"]
        mode_data[mode] = {
            "artifacts": {
                "lock": _relative(root, lock),
                "metrics": _relative(root, report),
                "hyperfine": _relative(root, hyperfine_json),
            },
            "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
            "lock_byte_count": validated["lock_byte_count"],
            "timing": timing,
            "cache_decision": validated["metrics"]["snapshot_cache_decision"],
            "provider_refresh": validated["metrics"]["provider_refresh"],
            "fallback": fallback_summary(provider),
            "phases": validated["metrics"]["phases"],
            "metrics": validated["metrics"],
        }
    hashes = {entry["lock_sha256"] for entry in mode_data.values()}
    if len(hashes) != 1:
        raise BenchmarkError("lock hashes differ across benchmark modes")
    manifest = {
        "schema_version": 1,
        "environment": {
            "python": sys.version.split()[0],
            "binary": binary.name,
            "binary_version": binary_version,
            "binary_sha256": _sha256(binary),
            "hyperfine": hyperfine.name,
            "hyperfine_version": hyperfine_version,
            "platform_system": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "platform_machine": platform.machine(),
            "platform_processor": platform.processor(),
            "cpu_count": os.cpu_count() or 1,
        },
        "arguments": {
            "r_version": args.r_version,
            "package": args.package,
            "cold_warmup": args.cold_warmup,
            "cold_runs": args.cold_runs,
            "warm_warmup": args.warm_warmup,
            "warm_runs": args.warm_runs,
            "mirror": mirror,
        },
        "lock_sha256": next(iter(hashes)),
        "modes": mode_data,
    }
    _atomic_json(root / "manifest.json", manifest)
    print(root)
    return root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="prebuilt release rsolve binary")
    parser.add_argument("--hyperfine", type=Path, default=Path("hyperfine"))
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--r-version", default="3.6.0")
    parser.add_argument("--package", default="tidyverse")
    parser.add_argument("--mirror", default="https://cloud.r-project.org")
    parser.add_argument("--cold-warmup", type=int, default=0)
    parser.add_argument("--cold-runs", type=int, default=3)
    parser.add_argument("--warm-warmup", type=int, default=2)
    parser.add_argument("--warm-runs", type=int, default=10)
    parser.add_argument("--prepare-trial", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--mode", choices=MODES, help=argparse.SUPPRESS)
    parser.add_argument("--capability-token", help=argparse.SUPPRESS)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.prepare_trial:
            if args.output_root is None or args.mode is None or args.capability_token is None:
                raise BenchmarkError("prepare-trial requires output root, mode, and capability token")
            prepare_trial(args.output_root, args.mode, args.capability_token)
            return 0
        if args.binary is None:
            parser.error("--binary is required")
        if (
            args.cold_warmup < 0
            or args.cold_runs < 1
            or args.warm_warmup < 0
            or args.warm_runs < 1
        ):
            raise BenchmarkError("warmups must be >= 0 and runs must be >= 1")
        benchmark(args)
        return 0
    except BenchmarkError as error:
        print(f"benchmark-tidyverse: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
