#!/usr/bin/env python3

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("verify-pak-gate-rootfs.py")
SPEC = importlib.util.spec_from_file_location("verify_pak_gate_rootfs", SCRIPT)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class RootfsVerifierTests(unittest.TestCase):
    def test_tree_digest_covers_types_modes_and_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dir").mkdir()
            (root / "dir" / "café").write_text("payload", encoding="utf-8")
            (root / "file").write_bytes(b"file")
            (root / "link").symlink_to("dir/café")
            os.chmod(root / "dir", stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            os.chmod(root / "dir" / "café", stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            os.chmod(root / "file", stat.S_IRUSR | stat.S_IWUSR)
            first = verifier.tree_digest(root, root)
            self.assertEqual(first, "848bbfd30fb1f7e88acfaf1d41ffb95013feac7134693b89bfc63f347af94722")
            os.chmod(root / "file", stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            self.assertNotEqual(first, verifier.tree_digest(root, root))
            (root / "file").write_bytes(b"changed")
            self.assertNotEqual(first, verifier.tree_digest(root, root))

    def test_rootfs_path_rejects_parent_and_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "inside").mkdir()
            (root / "escape").symlink_to("/tmp")
            with self.assertRaises(verifier.VerificationError):
                verifier.rootfs_path(root, "/inside/../outside", "path")
            with self.assertRaises(verifier.VerificationError):
                verifier.rootfs_path(root, "/escape/file", "path")

    def test_tree_digest_rejects_bad_symlink_targets(self) -> None:
        cases = ("/absolute", "../escape", "missing", "loop")
        for target in cases:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "dir").mkdir()
                if target == "loop":
                    (root / "link").symlink_to("loop2")
                    (root / "loop2").symlink_to("link")
                else:
                    (root / "link").symlink_to(target)
                with self.assertRaises(verifier.VerificationError):
                    verifier.tree_digest(root, root)

    def test_tree_digest_resolves_container_absolute_intermediary_inside_measured_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rootfs = Path(directory)
            measured = rootfs / "usr/include"
            measured.mkdir(parents=True)
            (measured / "real.h").write_text("header", encoding="utf-8")
            alternatives = rootfs / "etc/alternatives"
            alternatives.mkdir(parents=True)
            (measured / "link.h").symlink_to("/etc/alternatives/header.h")
            (alternatives / "header.h").symlink_to("/usr/include/real.h")
            verifier.tree_digest(measured, rootfs)

    def test_tree_digest_rejects_symlink_final_outside_rootfs_or_measured_tree(self) -> None:
        cases = ("outside", "escape", "dangling", "loop")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                rootfs = Path(directory)
                measured = rootfs / "usr/include"
                measured.mkdir(parents=True)
                if case == "outside":
                    (rootfs / "etc").mkdir()
                    (rootfs / "etc/outside").write_text("outside", encoding="utf-8")
                    target = "/etc/outside"
                elif case == "escape":
                    target = "../../outside"
                elif case == "dangling":
                    target = "/etc/missing"
                else:
                    (rootfs / "etc").mkdir()
                    (rootfs / "etc/a").symlink_to("/etc/b")
                    (rootfs / "etc/b").symlink_to("/etc/a")
                    target = "/etc/a"
                (measured / "link").symlink_to(target)
                with self.assertRaises(verifier.VerificationError):
                    verifier.tree_digest(measured, rootfs)

    def test_symlink_intermediary_cannot_inspect_host_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rootfs = Path(directory)
            measured = rootfs / "usr/include"
            measured.mkdir(parents=True)
            (rootfs / "etc").mkdir()
            host_target = rootfs.parent / f"{rootfs.name}-host-existing-target"
            (rootfs / "etc/alternative").symlink_to(host_target)
            (measured / "link").symlink_to("/etc/alternative")
            try:
                host_target.write_text("host", encoding="utf-8")
                with self.assertRaises(verifier.VerificationError):
                    verifier.tree_digest(measured, rootfs)
            finally:
                host_target.unlink(missing_ok=True)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as stream:
            stream.write('{"schema_version":1,"schema_version":2}')
            stream.flush()
            with self.assertRaises(verifier.VerificationError):
                verifier.load_record(Path(stream.name))

    def test_dpkg_owner_parser_normalizes_architectures_and_rejects_malformed(self) -> None:
        self.assertEqual(
            verifier.parse_dpkg_owners("gcc-13-x86-64-linux-gnu: /usr/bin/gcc\n"),
            {"gcc-13-x86-64-linux-gnu"},
        )
        self.assertEqual(
            verifier.parse_dpkg_owners(
                "libc6-dev:amd64, libcrypt-dev:amd64: /usr/include\n"
            ),
            {"libc6-dev", "libcrypt-dev"},
        )
        for malformed in ("", "not-an-owner-line", ": /usr/include\n", "bad owner: /usr/include\n"):
            with self.subTest(malformed=malformed), self.assertRaises(verifier.VerificationError):
                verifier.parse_dpkg_owners(malformed)

    def test_package_inventory_rejects_extra_top_level_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "lib"
            for name in ("pak", "foo", "extra"):
                package = library / name
                package.mkdir(parents=True)
                (package / "DESCRIPTION").write_text(
                    f"Package: {name}\nVersion: 1.0.0\n", encoding="utf-8"
                )
            package_items = []
            for name in ("pak", "foo"):
                package_path = library / name
                package_items.append(
                    {
                        "name": name,
                        "version": "1.0.0",
                        "package_path": f"/lib/{name}",
                        "installed_tree_sha256": verifier.tree_digest(package_path, root),
                    }
                )
            record = {
                "tool_library_closure": package_items,
                "r_home_library_allowlist": [],
                "pak": package_items[0],
            }
            with self.assertRaises(verifier.VerificationError):
                verifier.verify_package_inventory(root, record)
            shutil.rmtree(library / "extra")
            shutil.rmtree(library / "foo")
            with self.assertRaises(verifier.VerificationError):
                verifier.verify_package_inventory(root, record)

    def test_isolated_command_has_rootfs_boundary(self) -> None:
        command = verifier.build_isolated_command(Path("/tmp/rootfs"), ["/bin/true"])
        self.assertEqual(command[:5], ["unshare", "--user", "--map-root-user", "--net", "bwrap"])
        self.assertIn("--net", command)
        self.assertIn("--ro-bind", command)
        self.assertIn("--unshare-pid", command)
        self.assertEqual(command[command.index("--ro-bind") + 2], "/")
        self.assertIn("--clearenv", command)
        self.assertEqual(command[command.index("--setenv") + 1], "PATH")
        self.assertEqual(command[command.index("--setenv") + 2], "/usr/bin:/bin")
        self.assertEqual(command[-1], "/bin/true")

    def test_r_verification_uses_launcher_without_conflating_runtime_bin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "opt/R/4.6.1/bin/R"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"launcher")
            executable.chmod(0o755)
            record = {
                "r": {
                    "version_string": "R version 4.6.1 (2026-06-24)",
                    "platform": "x86_64-pc-linux-gnu",
                    "r_home": "/opt/R/4.6.1/lib/R",
                    "executable": "/opt/R/4.6.1/bin/R",
                    "executable_sha256": verifier.file_sha256(executable, "test"),
                },
                "pak": {
                    "package_path": "/opt/R/4.6.1/lib/R/library/pak",
                    "version": "0.11.1",
                },
            }
            output = "\n".join(
                (
                    "NRR_R_VERSION_STRING=R version 4.6.1 (2026-06-24)",
                    "NRR_R_PLATFORM=x86_64-pc-linux-gnu",
                    "NRR_R_HOME=/opt/R/4.6.1/lib/R",
                    "NRR_PAK_VERSION=0.11.1",
                    "NRR_PAK_PATH=/opt/R/4.6.1/lib/R/library/pak",
                )
            )
            with patch.object(verifier, "run_isolated", return_value=output) as run:
                verifier.verify_r(root, record)
            argv = run.call_args.args[1]
            self.assertEqual(argv[:2], ["/opt/R/4.6.1/bin/R", "--vanilla"])
            self.assertNotIn("NRR_R_EXECUTABLE", output)

    def test_record_path_is_cwd_resolved_and_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = root / "record.json"
            record.write_text("{}", encoding="utf-8")
            original = Path.cwd()
            try:
                os.chdir(root)
                self.assertEqual(verifier.resolve_record_path(Path("record.json")), record)
                symlink = root / "record-link.json"
                symlink.symlink_to(record)
                with self.assertRaises(verifier.VerificationError):
                    verifier.resolve_record_path(Path("record-link.json"))
            finally:
                os.chdir(original)


if __name__ == "__main__":
    unittest.main()
