import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("benchmark-tidyverse.py")
SPEC = importlib.util.spec_from_file_location("benchmark_tidyverse", SCRIPT)
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def provider(*, attempts=1, body_bytes=4, raw_hits=0, projection_reuses=0, allpackages_adoptions=0, package_local_bytes=0, fallback_count=0):
    sources = {
        name: {"requests": 0, "successful_body_bytes": 0}
        for name in benchmark.SOURCE_NAMES
    }
    local_requests = 1 if package_local_bytes else 0
    sources["allpackages"] = {
        "requests": attempts - local_requests,
        "successful_body_bytes": body_bytes - package_local_bytes,
    }
    sources["package_local_index"] = {
        "requests": local_requests,
        "successful_body_bytes": package_local_bytes,
    }
    return {
        "http_attempts": attempts,
        "successful_response_body_bytes": body_bytes,
        "statuses": {"status_200": attempts, "status_304": 0, "status_404": 0, "status_410": 0, "other": 0},
        **sources,
        "raw_cache_hits": raw_hits,
        "raw_cache_misses": 0,
        "raw_cache_corrupt": 0,
        "projection_reuses": projection_reuses,
        "projection_builds": 0,
        "projection_rebuilds": 0,
        "package_history_lookups": 0,
        "allpackages_adoptions": allpackages_adoptions,
        "package_local_fallbacks": fallback_count,
        "quarantined_releases": 0,
        "coverage_gaps": 0,
        "coverage_conflicts": 0,
    }


def report_for(mode, lock_length, provider_value):
    phases = {name: None for name in benchmark.PHASE_NAMES}
    for name in (
        "snapshot_cache_decision_ns",
        "solve_ns",
        "lock_projection_ns",
        "lock_serialization_ns",
        "lock_round_trip_ns",
        "atomic_lock_write_ns",
    ):
        phases[name] = 0
    if mode in {"isolated-cold", "projection-warm"}:
        phases["refresh_acquisition_ns"] = 0
        phases["snapshot_composition_and_publication_ns"] = 0
    return {
        "schema_version": 1,
        "lock_byte_count": lock_length,
        "metrics": {
            "phases": phases,
            "metrics_overflow": False,
            "snapshot_cache_decision": {
                "isolated-cold": "refreshed",
                "fresh-online-warm": "fresh_hit",
                "offline-warm": "offline_compatible",
                "projection-warm": "refreshed",
            }[mode],
            "loader_lookup_calls": 0,
            "loader_unique_package_count": 0,
            "solve_output_package_count": 1,
            "provider_refresh": provider_value,
        },
    }


class BenchmarkHarnessTests(unittest.TestCase):
    def test_output_root_must_be_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            root.mkdir()
            (root / "unexpected").write_text("keep", encoding="utf-8")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.prepare_output_root(root)

    def test_manifest_write_replaces_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text("stale", encoding="utf-8")
            benchmark._atomic_json(path, {"schema_version": 1, "ok": True})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["ok"], True)

    def test_symlink_output_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.prepare_output_root(link)

    def test_prepare_trial_refuses_output_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            root.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (outside / "keep").write_text("keep", encoding="utf-8")
            token = benchmark.initialize_capability(root)
            mode_root = root / "fresh-online-warm"
            mode_root.mkdir()
            (mode_root / "cache").mkdir()
            for output_name in ("lock.toml", "metrics.json"):
                try:
                    (mode_root / output_name).symlink_to(outside / "keep")
                except (NotImplementedError, OSError):
                    self.skipTest("symlinks unavailable")
                with self.assertRaises(benchmark.BenchmarkError):
                    benchmark.prepare_trial(root, "fresh-online-warm", token)
                (mode_root / output_name).unlink()
            self.assertTrue((outside / "keep").exists())

    def test_projection_copy_strips_only_snapshot_pointers(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            store = source / "v1" / "registries" / "registry"
            (store / "generations").mkdir(parents=True)
            (store / "raw-cache" / "v1" / "projections").mkdir(parents=True)
            (store / "current").write_text("current", encoding="utf-8")
            (store / "current-validation").write_text("validation", encoding="utf-8")
            (store / "generations" / "old.redb").write_bytes(b"old")
            projection = store / "raw-cache" / "v1" / "projections" / "keep"
            projection.write_bytes(b"projection")
            destination = Path(directory) / "destination"

            copied_store = benchmark.prepare_projection_cache(source, destination)
            self.assertEqual(copied_store, destination / "v1" / "registries" / "registry")
            self.assertFalse((copied_store / "current").exists())
            self.assertFalse((copied_store / "current-validation").exists())
            self.assertEqual(list((copied_store / "generations").iterdir()), [])
            self.assertEqual((copied_store / "raw-cache" / "v1" / "projections" / "keep").read_bytes(), b"projection")

    def test_projection_prepare_recopies_for_each_trial_and_outputs_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = benchmark.initialize_capability(root)
            cold = root / "isolated-cold" / "cache" / "v1" / "registries" / "registry"
            (cold / "generations").mkdir(parents=True)
            (cold / "raw-cache" / "v1" / "projections").mkdir(parents=True)
            (cold / "current").write_text("current", encoding="utf-8")
            (cold / "current-validation").write_text("validation", encoding="utf-8")
            (cold / "raw-cache" / "v1" / "projections" / "keep").write_text("keep", encoding="utf-8")
            (root / "projection-warm").mkdir()
            mode_root = root / "projection-warm"
            (mode_root / "lock.toml").write_text("stale", encoding="utf-8")
            benchmark.prepare_trial(root, "projection-warm", token)
            projection_store = mode_root / "cache" / "v1" / "registries" / "registry"
            (projection_store / "extra").write_text("stale copy", encoding="utf-8")
            (mode_root / "lock.toml").write_text("stale", encoding="utf-8")
            (mode_root / "metrics.json").write_text("stale", encoding="utf-8")
            benchmark.prepare_trial(root, "projection-warm", token)
            self.assertFalse((projection_store / "extra").exists())
            self.assertFalse((mode_root / "lock.toml").exists())
            self.assertFalse((mode_root / "metrics.json").exists())

    def test_prepare_trial_requires_capability_and_exact_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = benchmark.initialize_capability(root)
            (root / "fresh-online-warm").mkdir()
            (root / "fresh-online-warm" / "cache").mkdir()
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.prepare_trial(root, "fresh-online-warm", "wrong-token")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.prepare_trial(root, "offline-warm", token)

    def test_hyperfine_command_wires_prepare_and_uses_single_result_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "hyperfine.json"
            output.write_text(json.dumps({"results": [{
                "times": [1.0, 2.0], "exit_codes": [0, 0],
                "mean": 1.5, "stddev": 0.5, "min": 1.0, "max": 2.0,
                "median": 1.5, "user": 0.1, "system": 0.2,
            }]}), encoding="utf-8")
            summary = benchmark._hyperfine_summary(output)
            self.assertEqual(summary["trial_count"], 2)
            with patch.object(benchmark.subprocess, "run") as run:
                benchmark.run_hyperfine(Path("hyperfine"), "rsolve lock", output, prepare="prepare", warmup=2, runs=10)
            command = run.call_args.args[0]
            self.assertIn("--prepare", command)
            self.assertEqual(command[command.index("--warmup") + 1], "2")
            self.assertEqual(command[command.index("--runs") + 1], "10")
            projection_prepare = benchmark.prepare_command(Path("/tmp/output"), "projection-warm", "token")
            self.assertIn("--prepare-trial", projection_prepare)
            self.assertIn("projection-warm", projection_prepare)

    def test_projection_layout_with_multiple_stores_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cache" / "v1" / "registries"
            for name in ("one", "two"):
                store = root / name
                (store / "generations").mkdir(parents=True)
                (store / "raw-cache" / "v1" / "projections").mkdir(parents=True)
                (store / "current").write_text("current", encoding="utf-8")
                (store / "current-validation").write_text("validation", encoding="utf-8")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.locate_registry_store(root.parent.parent)

    def test_metrics_schema_modes_and_provider_aggregate(self):
        lock = b"version = 1\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock_path = root / "lock.toml"
            report_path = root / "metrics.json"
            lock_path.write_bytes(lock)
            report_path.write_text(json.dumps(report_for("isolated-cold", len(lock), provider())), encoding="utf-8")
            value = provider(attempts=2, body_bytes=7, package_local_bytes=3, fallback_count=2)
            report_path.write_text(json.dumps(report_for("isolated-cold", len(lock), value)), encoding="utf-8")
            validated = benchmark.validate_metrics_report(report_path, "isolated-cold", lock_path)
            self.assertEqual(validated["metrics"]["provider_refresh"]["http_attempts"], 2)
            validated_provider = validated["metrics"]["provider_refresh"]
            self.assertEqual(
                benchmark.fallback_summary(validated_provider),
                {"package_count": 2, "package_local_bytes": 3},
            )

            report_path.write_text(json.dumps(report_for("fresh-online-warm", len(lock), None)), encoding="utf-8")
            validated = benchmark.validate_metrics_report(report_path, "fresh-online-warm", lock_path)
            self.assertIsNone(validated["metrics"]["provider_refresh"])

            bad = provider()
            bad["successful_response_body_bytes"] = 99
            report_path.write_text(json.dumps(report_for("isolated-cold", len(lock), bad)), encoding="utf-8")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.validate_metrics_report(report_path, "isolated-cold", lock_path)

            incomplete = report_for("fresh-online-warm", len(lock), None)
            incomplete["metrics"]["phases"]["lock_round_trip_ns"] = None
            report_path.write_text(json.dumps(incomplete), encoding="utf-8")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.validate_metrics_report(report_path, "fresh-online-warm", lock_path)
            incomplete = report_for("fresh-online-warm", len(lock), None)
            incomplete["metrics"]["solve_output_package_count"] = 0
            report_path.write_text(json.dumps(incomplete), encoding="utf-8")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.validate_metrics_report(report_path, "fresh-online-warm", lock_path)

    def test_projection_provider_requires_cache_reuse_and_no_http(self):
        lock = b"version = 1\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock_path = root / "lock.toml"
            report_path = root / "metrics.json"
            lock_path.write_bytes(lock)
            value = provider(attempts=0, body_bytes=0, raw_hits=1, projection_reuses=1, allpackages_adoptions=1)
            report_path.write_text(json.dumps(report_for("projection-warm", len(lock), value)), encoding="utf-8")
            benchmark.validate_metrics_report(report_path, "projection-warm", lock_path)
            value["projection_reuses"] = 0
            report_path.write_text(json.dumps(report_for("projection-warm", len(lock), value)), encoding="utf-8")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.validate_metrics_report(report_path, "projection-warm", lock_path)

    def test_commands_quote_paths_and_reject_mirror_userinfo(self):
        command = benchmark.shell_command(
            Path("/tmp/rsolve binary"),
            Path("/tmp/cache root"),
            Path("/tmp/lock.toml"),
            Path("/tmp/report.json"),
            offline=True,
            mirror="https://cran.example/cran",
            r_version="4.4.0",
            package="tidy verse",
        )
        self.assertIn("'/tmp/rsolve binary'", command)
        self.assertIn("'tidy verse'", command)
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.validate_mirror("https://user:secret@cran.example/cran")
        for malformed in ("https://[2001:db8::1/cran", "https://cran.example:invalid/cran"):
            with self.subTest(mirror=malformed):
                with self.assertRaises(benchmark.BenchmarkError):
                    benchmark.validate_mirror(malformed)


if __name__ == "__main__":
    unittest.main()
