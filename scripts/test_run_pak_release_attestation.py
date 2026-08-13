import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

SCRIPT = Path(__file__).with_name("run-pak-release-attestation.py")
SPEC = importlib.util.spec_from_file_location("attestation", SCRIPT)
assert SPEC and SPEC.loader
attestation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(attestation)


def tar_payload(entries, compression="w:gz"):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode=compression) as archive:
        for name, kind, value in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = value
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = value
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = value
                archive.addfile(info)
    return payload.getvalue()


class FakeRegistry:
    def __init__(self, responses):
        self.responses = responses

    def request(self, path, accept="application/octet-stream"):
        return self.responses[path]


class RecordingRegistry:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, path, accept="application/octet-stream"):
        self.calls.append((path, accept))
        return self.response


class AttestationTests(unittest.TestCase):
    def test_digest_image_ref_requires_immutable_digest(self):
        self.assertEqual(attestation.image_ref("registry.example/a/b@sha256:" + "a" * 64), ("registry.example", "a/b"))
        for value in ("registry.example/a:latest", "registry.example/a@sha256:" + "A" * 64):
            with self.assertRaises(attestation.AttestationError):
                attestation.image_ref(value)

    def test_duplicate_json_and_malformed_descriptor_fail_closed(self):
        with self.assertRaises(attestation.AttestationError):
            attestation.json_no_dupes(b'{"x":1,"x":2}', "test")
        for value in ({"digest": "sha256:" + "a" * 64, "size": -1}, {"digest": "sha256:" + "a" * 64, "size": True}, {}):
            with self.assertRaises(attestation.AttestationError):
                attestation.descriptor(value, "test")

    def test_digest_and_size_mismatch(self):
        class Registry:
            def request(self, path, accept=attestation.OCTET_STREAM):
                return b"wrong"

        with self.assertRaisesRegex(attestation.AttestationError, "size mismatch"):
            attestation.fetch_verified(Registry(), "blobs/x", "sha256:" + "a" * 64, 99)
        with self.assertRaisesRegex(attestation.AttestationError, "digest mismatch"):
            attestation.fetch_verified(Registry(), "blobs/x", "sha256:" + hashlib.sha256(b"expected").hexdigest())

    def test_manifest_and_blob_accept_negotiation_and_safe_http_diagnostic(self):
        digest = attestation.digest_bytes(b"payload")
        registry = RecordingRegistry(b"payload")
        attestation.fetch_verified(registry, "manifests/" + digest, digest, accept=attestation.MANIFEST_ACCEPT)
        attestation.fetch_verified(registry, "blobs/" + digest, digest)
        self.assertEqual(registry.calls[0], ("manifests/" + digest, attestation.MANIFEST_ACCEPT))
        self.assertEqual(registry.calls[1], ("blobs/" + digest, attestation.OCTET_STREAM))

        with patch.object(attestation, "urlopen", side_effect=HTTPError("https://registry.invalid", 404, "Not Found", {}, None)):
            with self.assertRaisesRegex(attestation.AttestationError, r"OCI manifest sha256:[0-9a-f]{64}: request failed \(404\)"):
                attestation.fetch_verified(attestation.Registry("registry.invalid", "repo"), "manifests/" + digest, digest)

    def test_safe_layer_paths_reject_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(attestation.safe_member(root, "a/b").name, "b")
            for value in ("", "/etc/passwd", "../escape", "a/../../escape", "a\x00b"):
                with self.assertRaises(attestation.AttestationError):
                    attestation.safe_member(root, value)

    def test_nested_symlink_ancestor_and_existing_target_symlink_are_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").mkdir()
            (root / "a").symlink_to("real")
            with self.assertRaises(attestation.AttestationError):
                attestation.apply_layer(root, tar_payload([("a/deeper/file", "file", b"bad")]))
            outside = root.parent / "outside-target"
            outside.write_text("keep", encoding="utf-8")
            (root / "out").symlink_to(outside)
            attestation.apply_layer(root, tar_payload([("out", "file", b"new")]))
            self.assertEqual((root / "out").read_bytes(), b"new")
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep")
            outside.unlink()

    def test_layer_whiteout_and_opaque_semantics_and_symlink_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "old").write_text("old", encoding="utf-8")
            attestation.apply_layer(root, tar_payload([(".wh.old", "file", b"")]))
            self.assertFalse((root / "old").exists())
            (root / "directory").mkdir()
            (root / "directory/a").write_text("a", encoding="utf-8")
            (root / "directory/b").write_text("b", encoding="utf-8")
            attestation.apply_layer(root, tar_payload([("directory/.wh..wh..opq", "file", b"")]))
            self.assertEqual(list((root / "directory").iterdir()), [])
            (root / "real").mkdir()
            (root / "link").symlink_to("real")
            with self.assertRaises(attestation.AttestationError):
                attestation.apply_layer(root, tar_payload([("link/.wh.old", "file", b"")]))

    def test_same_layer_whiteouts_only_remove_lower_layer_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "old").write_text("lower", encoding="utf-8")
            entries = [
                ("new-before/.wh..wh..opq", "file", b""),
                ("new-before/file", "file", b"survives"),
                ("new-after/file", "file", b"survives"),
                ("new-after/.wh..wh..opq", "file", b""),
            ]
            (root / "new-before").mkdir()
            (root / "new-after").mkdir()
            attestation.apply_layer(root, tar_payload(entries))
            self.assertEqual((root / "new-before/file").read_bytes(), b"survives")
            self.assertEqual((root / "new-after/file").read_bytes(), b"survives")

            (root / "name").write_text("lower", encoding="utf-8")
            attestation.apply_layer(root, tar_payload([
                ("name", "file", b"replacement"),
                (".wh.name", "file", b""),
            ]))
            self.assertEqual((root / "name").read_bytes(), b"replacement")

    def test_normal_nested_directories_and_same_layer_opaque_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = tar_payload([
                ("dir", "dir", b""),
                ("dir/file", "file", b"content"),
                ("dir/nested", "dir", b""),
                ("dir/nested/child", "file", b"child"),
                ("introduced/.wh..wh..opq", "file", b""),
                ("introduced/file", "file", b"survives"),
            ])
            attestation.apply_layer(root, payload)
            self.assertEqual((root / "dir/file").read_bytes(), b"content")
            self.assertEqual((root / "dir/nested/child").read_bytes(), b"child")
            self.assertEqual((root / "introduced/file").read_bytes(), b"survives")

    def test_hardlink_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            attestation.apply_layer(root, tar_payload([
                ("source", "file", b"shared"),
                ("copy", "hardlink", "source"),
            ]))
            self.assertEqual((root / "copy").read_bytes(), b"shared")
            self.assertEqual((root / "source").stat().st_ino, (root / "copy").stat().st_ino)

    def test_hardlink_attacks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").write_bytes(b"source")
            for name, linkname in (("missing", "absent"), ("escape", "../outside")):
                with self.assertRaises(attestation.AttestationError):
                    attestation.apply_layer(root, tar_payload([(name, "hardlink", linkname)]))
            (root / "real").write_bytes(b"real")
            (root / "sym").symlink_to("real")
            with self.assertRaises(attestation.AttestationError):
                attestation.apply_layer(root, tar_payload([("bad", "hardlink", "sym")]))

    def test_symlink_escape_and_compression_media_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            attestation.apply_layer(root, tar_payload([("awk", "symlink", "/usr/bin/mawk")]))
            self.assertTrue((root / "awk").is_symlink())
            self.assertEqual((root / "awk").readlink().as_posix(), "/usr/bin/mawk")
            attestation.apply_layer(root, tar_payload([("usr/bin/tool", "symlink", "../lib/tool")]))
            self.assertEqual((root / "usr/bin/tool").readlink().as_posix(), "../lib/tool")
            for target in ("/", "/../../host", "/usr/../etc", "//host"):
                with self.assertRaises(attestation.AttestationError):
                    attestation.apply_layer(root, tar_payload([("bad", "symlink", target)]))
            with self.assertRaises(attestation.AttestationError):
                attestation.validate_symlink_target(root, root / "bad", "/usr\x00/bin", "bad")
            with self.assertRaises(attestation.AttestationError):
                attestation.apply_layer(root, tar_payload([("bad", "symlink", "../../escape")]))
            with self.assertRaises(attestation.AttestationError):
                attestation.apply_layer(root, tar_payload([]), "application/vnd.oci.image.layer.v1.tar+zstd")

    def test_index_selection_fetches_unique_linux_amd64_child(self):
        child = {"mediaType": next(iter(attestation.SUPPORTED_MANIFESTS)), "config": {}, "layers": []}
        child_bytes = json.dumps(child, separators=(",", ":")).encode()
        child_digest = attestation.digest_bytes(child_bytes)
        index = {"mediaType": next(iter(attestation.SUPPORTED_INDEXES)), "manifests": [{"mediaType": next(iter(attestation.SUPPORTED_MANIFESTS)), "digest": child_digest, "size": len(child_bytes), "platform": {"os": "linux", "architecture": "amd64"}}]}
        document, selected = attestation.select_manifest(FakeRegistry({"manifests/" + child_digest: child_bytes}), json.dumps(index).encode(), "sha256:" + "a" * 64)
        self.assertEqual(selected, child_digest)
        self.assertEqual(document["mediaType"], next(iter(attestation.SUPPORTED_MANIFESTS)))

    def test_index_selection_rejects_nonunique_or_malformed_children(self):
        media = next(iter(attestation.SUPPORTED_INDEXES))
        index = json.dumps({"mediaType": media, "manifests": [{"platform": {"os": "linux", "architecture": "amd64"}}]}).encode()
        with self.assertRaises(attestation.AttestationError):
            attestation.select_manifest(FakeRegistry({}), index, "sha256:" + "a" * 64)

    def test_command_contains_namespace_environment_and_fixture_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rootfs").mkdir()
            (root / "fixtures").mkdir()
            binary = root / "test"
            binary.write_bytes(b"#!/bin/sh\n")
            binary.chmod(0o755)
            command = attestation.isolated_command(
                root / "rootfs", binary,
                {"r": {"executable": "/opt/R/bin/R"}, "pak": {"library_root": "/opt/R/lib", "package_path": "/opt/R/lib/pak"}},
                {"user": "user:[1]", "pid": "pid:[2]", "net": "net:[3]"}, root / "fixtures",
            )
        self.assertIn("--net", command)
        self.assertIn("--unshare-pid", command)
        self.assertIn("--clearenv", command)
        self.assertIn("/nrr/fixtures", command)
        self.assertIn("NRR_PAK_PARENT_USERNS", command)
        self.assertIn("linux-user-pid-netns-v1", command)
        self.assertIn("LANG", command)
        self.assertIn("C.utf8", command)
        self.assertIn("LC_ALL", command)

    def test_command_rejects_invalid_bind_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture"
            fixture.mkdir()
            binary = root / "binary"
            binary.write_bytes(b"x")
            for bad_root, bad_binary, bad_fixture in (
                (root / "missing", binary, fixture),
                (fixture, root / "missing", fixture),
                (fixture, binary, root / "missing-fixture"),
            ):
                with self.assertRaises(attestation.AttestationError):
                    attestation.isolated_command(
                        bad_root, bad_binary,
                        {"r": {"executable": "/opt/R/bin/R"}, "pak": {"library_root": "/opt/R/lib", "package_path": "/opt/R/lib/pak"}},
                        {"user": "user:[1]", "pid": "pid:[2]", "net": "net:[3]"}, bad_fixture,
                    )

    def test_debug_workspace_is_explicitly_retained(self):
        with attestation.workspace_context(True) as workspace:
            self.assertTrue(workspace.is_dir())
            retained = workspace
        self.assertTrue(retained.is_dir())
        shutil.rmtree(retained)


if __name__ == "__main__":
    unittest.main()
