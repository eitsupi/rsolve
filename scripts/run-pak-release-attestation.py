#!/usr/bin/env python3
"""Pull and attest the pinned pak release image, then run its isolated contract."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Iterator
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent
RECORD = REPO_ROOT / "ci" / "pak-gate-inputs.json"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SUPPORTED_MANIFESTS = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
SUPPORTED_INDEXES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_ACCEPT = ", ".join(sorted(SUPPORTED_MANIFESTS | SUPPORTED_INDEXES))
OCTET_STREAM = "application/octet-stream"
SUPPORTED_CONFIGS = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
SUPPORTED_LAYERS = {
    "application/vnd.oci.image.layer.v1.tar": "r:",
    "application/vnd.oci.image.layer.v1.tar+gzip": "r:gz",
    "application/vnd.docker.image.rootfs.diff.tar": "r:",
    "application/vnd.docker.image.rootfs.diff.tar.gzip": "r:gz",
}
MAX_MEMBER_SIZE = 2 * 1024 * 1024 * 1024

# The release attestation runs on Linux. O_PATH permits checking and walking
# image-provided directories without requiring read permission, while
# O_NOFOLLOW/O_DIRECTORY ensure that each fd names the directory we intended.
_DIRECTORY_FD_FLAGS = (
    getattr(os, "O_PATH", os.O_RDONLY)
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | os.O_CLOEXEC
)


class AttestationError(Exception):
    """A release attestation input or execution failed closed."""


def image_ref(value: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise AttestationError("image must be a digest-qualified @sha256 reference")
    parsed = urlparse("//" + value)
    if parsed.query or parsed.fragment or not parsed.netloc or parsed.path.count("@") != 1:
        raise AttestationError("image must use a digest-qualified @sha256 reference")
    repository, digest = parsed.path.lstrip("/").rsplit("@", 1)
    if not repository or not DIGEST_RE.fullmatch(digest):
        raise AttestationError("image must use a lowercase sha256 digest")
    return parsed.netloc, repository


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def json_no_dupes(data: bytes, label: str) -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AttestationError(f"{label}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=hook)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AttestationError(f"{label}: invalid JSON: {error}") from error


def _bearer_parameters(challenge: str) -> dict[str, str]:
    scheme, separator, parameters = challenge.strip().partition(" ")
    if not separator or scheme.lower() != "bearer":
        raise AttestationError("OCI registry returned unsupported auth challenge")
    result: dict[str, str] = {}
    pattern = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*"((?:\\.|[^"\\])*)"')
    for match in pattern.finditer(parameters):
        key, value = match.groups()
        result[key.lower()] = bytes(value, "utf-8").decode("unicode_escape")
    return result


class Registry:
    def __init__(self, host: str, repository: str) -> None:
        if not host or not repository:
            raise AttestationError("OCI image has an empty registry or repository")
        self.base = f"https://{host}"
        self.repository = repository
        self.token: str | None = None

    def request(self, path: str, accept: str = OCTET_STREAM) -> bytes:
        url = f"{self.base}/v2/{self.repository}/{path}"
        request = Request(url, headers={"Accept": accept})
        if self.token:
            request.add_header("Authorization", "Bearer " + self.token)
        try:
            with urlopen(request, timeout=60) as response:
                return response.read()
        except HTTPError as error:
            if error.code != 401 or self.token:
                category, value = (path.split("/", 1) + [path])[:2]
                if category not in ("manifests", "blobs"):
                    category, value = "request", "metadata"
                else:
                    category = category[:-1]
                raise AttestationError(f"OCI {category} {value}: request failed ({error.code})") from error
            try:
                parameters = _bearer_parameters(error.headers.get("WWW-Authenticate", ""))
                realm = parameters.get("realm", "")
                if urlparse(realm).scheme.lower() != "https":
                    raise AttestationError("OCI bearer realm must use HTTPS")
                query: list[str] = []
                for key in ("service", "scope"):
                    if key in parameters:
                        query.append(key + "=" + quote(parameters[key]))
                with urlopen(realm + ("?" + "&".join(query) if query else ""), timeout=60) as token_response:
                    token_document = json_no_dupes(token_response.read(), "OCI bearer token")
                token = token_document.get("token") or token_document.get("access_token")
                if not isinstance(token, str) or not token:
                    raise AttestationError("OCI bearer response has no token")
                self.token = token
            except AttestationError:
                raise
            except (OSError, TypeError, AttributeError, UnicodeError, ValueError) as token_error:
                raise AttestationError("OCI bearer authentication failed") from token_error
            return self.request(path, accept)


def fetch_verified(
    registry: Registry,
    reference: str,
    expected_digest: str,
    expected_size: int | None = None,
    accept: str = OCTET_STREAM,
) -> bytes:
    if not DIGEST_RE.fullmatch(expected_digest):
        raise AttestationError(f"OCI {reference}: invalid expected digest")
    data = registry.request(reference, accept)
    if expected_size is not None and len(data) != expected_size:
        raise AttestationError(f"OCI {reference}: size mismatch")
    if digest_bytes(data) != expected_digest:
        raise AttestationError(f"OCI {reference}: digest mismatch")
    return data


def descriptor(value: Any, label: str) -> tuple[str, int]:
    if not isinstance(value, dict):
        raise AttestationError(f"{label}: invalid digest descriptor")
    digest = value.get("digest")
    size = value.get("size")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise AttestationError(f"{label}: invalid digest descriptor")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise AttestationError(f"{label}: invalid size descriptor")
    return digest, size


def safe_member(root: Path, name: str) -> Path:
    if not name or "\x00" in name:
        raise AttestationError("layer entry has an empty or NUL path")
    raw_parts = name.split("/")
    if raw_parts[-1] == "":
        raw_parts.pop()
    if not raw_parts or any(part in ("", ".", "..") for part in raw_parts):
        raise AttestationError(f"unsafe layer path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise AttestationError(f"unsafe layer path: {name!r}")
    target = root.joinpath(*path.parts)
    try:
        target.parent.resolve(strict=False).relative_to(root.resolve())
    except ValueError as error:
        raise AttestationError(f"layer path escapes root: {name!r}") from error
    return target


def ensure_real_parent(root: Path, target: Path) -> None:
    try:
        relative = target.relative_to(root)
    except ValueError as error:
        raise AttestationError(f"layer path escapes root: {target}") from error
    current = root
    for component in relative.parts[:-1]:
        current /= component
        if current.is_symlink() or not current.is_dir():
            raise AttestationError(f"symlink or non-directory ancestor: {target}")


def validate_parent(root: Path, target: Path) -> None:
    """Validate present ancestors without requiring this layer's dirs yet."""
    try:
        relative = target.relative_to(root)
    except ValueError as error:
        raise AttestationError(f"layer path escapes root: {target}") from error
    current = root
    for component in relative.parts[:-1]:
        current /= component
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise AttestationError(f"symlink or non-directory ancestor: {target}")


def prepare_parent(root: Path, target: Path) -> None:
    """Create missing ancestors while checking every component before mkdir."""
    try:
        relative = target.relative_to(root)
    except ValueError as error:
        raise AttestationError(f"layer path escapes root: {target}") from error
    current = root
    for component in relative.parts[:-1]:
        current /= component
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise AttestationError(f"symlink or non-directory ancestor: {target}")
        if not current.exists():
            current.mkdir()


def remove_entry(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def validate_symlink_target(root: Path, target: Path, linkname: str, member_name: str) -> None:
    if not linkname or "\x00" in linkname:
        raise AttestationError(f"unsafe symlink: {member_name}")
    if posixpath.isabs(linkname):
        absolute_parts = linkname.split("/")
        if len(absolute_parts) == 2 and absolute_parts[1] == "":
            raise AttestationError(f"unsafe root symlink: {member_name}")
        if absolute_parts[0] != "" or any(not part or part in (".", "..") for part in absolute_parts[1:]):
            raise AttestationError(f"unsafe absolute symlink: {member_name}")
        return
    lexical = list(target.parent.relative_to(root).parts)
    for part in linkname.split("/"):
        if not part:
            raise AttestationError(f"unsafe symlink: {member_name}")
        if part == ".":
            continue
        if part == "..":
            if not lexical:
                raise AttestationError(f"escaping symlink: {member_name}")
            lexical.pop()
        else:
            lexical.append(part)


def _layer_mode(media_type: str | None, payload: bytes) -> str:
    if media_type is not None:
        try:
            return SUPPORTED_LAYERS[media_type]
        except KeyError as error:
            raise AttestationError(f"unsupported OCI layer media type: {media_type}") from error
    return "r:gz" if payload.startswith(b"\x1f\x8b") else "r:"


def apply_layer(root: Path, payload: bytes, media_type: str | None = None) -> None:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode=_layer_mode(media_type, payload))
    except (tarfile.TarError, OSError) as error:
        raise AttestationError("OCI layer is not a supported tar archive") from error
    with archive:
        seen: set[str] = set()
        try:
            members = archive.getmembers()
        except (tarfile.TarError, OSError) as error:
            raise AttestationError("OCI layer has malformed tar metadata") from error
        operations: list[tuple[tarfile.TarInfo, Path]] = []
        for member in members:
            if member.size < 0 or member.size > MAX_MEMBER_SIZE:
                raise AttestationError(f"layer entry has unsafe size: {member.name}")
            if member.name in seen:
                raise AttestationError(f"duplicate layer entry: {member.name}")
            seen.add(member.name)
            target = safe_member(root, member.name)
            basename = PurePosixPath(member.name).name
            validate_parent(root, target)
            if basename == ".wh..wh..opq" or basename.startswith(".wh."):
                if not member.isreg() or member.size != 0:
                    raise AttestationError(f"whiteout is not an empty regular file: {member.name}")
                if basename != ".wh..wh..opq" and not basename[4:]:
                    raise AttestationError("whiteout has empty victim")
            operations.append((member, target))

        # Whiteouts describe entries inherited from lower layers. Applying them
        # first keeps same-layer additions from being mistaken for lower-layer
        # content, regardless of tar member order.
        directory_modes: list[tuple[Path, int]] = []
        for member, target in operations:
            basename = PurePosixPath(member.name).name
            if basename != ".wh..wh..opq" and not basename.startswith(".wh."):
                continue
            prepare_parent(root, target)
            if basename == ".wh..wh..opq":
                for child in list(target.parent.iterdir()):
                    remove_entry(child)
            else:
                victim = target.parent / basename[4:]
                if victim.exists() or victim.is_symlink():
                    remove_entry(victim)

        for member, target in operations:
            basename = PurePosixPath(member.name).name
            if basename == ".wh..wh..opq" or basename.startswith(".wh."):
                continue
            prepare_parent(root, target)
            ensure_real_parent(root, target)
            if member.isdir():
                if target.is_symlink():
                    remove_entry(target)
                if target.exists() and not target.is_dir():
                    raise AttestationError(f"directory collides with file: {member.name}")
                target.mkdir(exist_ok=True)
                directory_modes.append((target, member.mode & 0o7777))
            elif member.isreg():
                try:
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise AttestationError(f"regular layer entry has no data: {member.name}")
                    with stream:
                        data = stream.read(MAX_MEMBER_SIZE + 1)
                except (tarfile.TarError, OSError) as error:
                    raise AttestationError(f"could not read layer entry: {member.name}") from error
                if len(data) > MAX_MEMBER_SIZE:
                    raise AttestationError(f"layer entry has unsafe size: {member.name}")
                if target.exists() or target.is_symlink():
                    remove_entry(target)
                target.write_bytes(data)
                os.chmod(target, member.mode & 0o7777)
            elif member.issym():
                linkname = member.linkname
                validate_symlink_target(root, target, linkname, member.name)
                if target.exists() or target.is_symlink():
                    remove_entry(target)
                target.symlink_to(linkname)
            elif member.islnk():
                link = safe_member(root, member.linkname)
                ensure_real_parent(root, link)
                if link.is_symlink() or not link.is_file():
                    raise AttestationError(f"unsafe hardlink: {member.name}")
                if target.exists() or target.is_symlink():
                    remove_entry(target)
                os.link(link, target)
            else:
                raise AttestationError(f"unsupported layer entry: {member.name}")
        for directory, mode in directory_modes:
            if directory.is_dir() and not directory.is_symlink():
                os.chmod(directory, mode)


def _manifest_media(document: dict[str, Any]) -> str:
    media = document.get("mediaType")
    if not isinstance(media, str):
        raise AttestationError("OCI document has no media type")
    return media


def select_manifest(registry: Registry, manifest_bytes: bytes, digest: str) -> tuple[dict[str, Any], str]:
    document = json_no_dupes(manifest_bytes, "OCI manifest")
    if not isinstance(document, dict):
        raise AttestationError("OCI document must be an object")
    media = _manifest_media(document)
    if media in SUPPORTED_MANIFESTS:
        return document, digest
    if media not in SUPPORTED_INDEXES:
        raise AttestationError("unsupported OCI manifest media type")
    entries = document.get("manifests")
    if not isinstance(entries, list) or not entries:
        raise AttestationError("OCI index must contain manifests")
    candidates: list[tuple[str, int]] = []
    for index, item in enumerate(entries):
        child_digest, child_size = descriptor(item, f"OCI index child {index}")
        child_media = item.get("mediaType")
        if child_media not in SUPPORTED_MANIFESTS | SUPPORTED_INDEXES:
            raise AttestationError(f"OCI index child {index}: unsupported media type")
        platform = item.get("platform")
        if not isinstance(platform, dict):
            raise AttestationError(f"OCI index child {index}: missing platform")
        if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
            candidates.append((child_digest, child_size))
    if len(candidates) != 1:
        raise AttestationError("OCI index does not have exactly one linux/amd64 child")
    child_digest, child_size = candidates[0]
    child = fetch_verified(registry, "manifests/" + child_digest, child_digest, child_size, MANIFEST_ACCEPT)
    return select_manifest(registry, child, child_digest)


def _open_directory_at(parent_fd: int, name: str, display_path: str) -> int:
    try:
        fd = os.open(name, _DIRECTORY_FD_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise AttestationError(f"wrapper bind destination is not a directory: {display_path}") from error
    try:
        mode = os.fstat(fd).st_mode
    except OSError as error:
        os.close(fd)
        raise AttestationError(f"could not validate wrapper bind destination: {display_path}") from error
    if not stat.S_ISDIR(mode):
        os.close(fd)
        raise AttestationError(f"wrapper bind destination is not a directory: {display_path}")
    return fd


def _ensure_directory_at(parent_fd: int, name: str, display_path: str) -> int:
    try:
        os.mkdir(name, 0o755, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as error:
        raise AttestationError(f"could not create wrapper bind destination: {display_path}") from error
    return _open_directory_at(parent_fd, name, display_path)


def _ensure_regular_file_at(parent_fd: int, name: str, display_path: str) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | os.O_NONBLOCK
    )
    try:
        fd = os.open(name, flags, 0o666, dir_fd=parent_fd)
    except OSError as error:
        raise AttestationError(f"wrapper bind destination is not a regular file: {display_path}") from error
    try:
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise AttestationError(f"wrapper bind destination is not a regular file: {display_path}")
            # Preserve touch()'s existing behavior without reopening the path.
            os.utime(fd, None)
        except OSError as error:
            raise AttestationError(f"could not validate wrapper bind destination: {display_path}") from error
    finally:
        os.close(fd)


def prepare_bind_destinations(root: Path) -> None:
    """Create bwrap destinations while rejecting image-controlled symlinks."""
    try:
        root_fd = os.open(root, _DIRECTORY_FD_FLAGS)
    except OSError as error:
        raise AttestationError("rootfs must be an existing physical directory") from error
    try:
        try:
            if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
                raise AttestationError("rootfs must be an existing physical directory")
        except OSError as error:
            raise AttestationError("could not validate rootfs directory") from error

        for mountpoint in ("proc", "dev", "tmp"):
            mount_fd = _ensure_directory_at(root_fd, mountpoint, f"/{mountpoint}")
            os.close(mount_fd)

        nrr_fd = _ensure_directory_at(root_fd, "nrr", "/nrr")
        try:
            fixtures_fd = _ensure_directory_at(nrr_fd, "fixtures", "/nrr/fixtures")
            os.close(fixtures_fd)
            _ensure_regular_file_at(nrr_fd, "pak_isolated", "/nrr/pak_isolated")
        finally:
            os.close(nrr_fd)
    finally:
        os.close(root_fd)


def rootfs_from_image(registry: Registry, image_digest: str, workspace: Path) -> tuple[Path, str]:
    manifest = fetch_verified(registry, "manifests/" + image_digest, image_digest, accept=MANIFEST_ACCEPT)
    document, selected_digest = select_manifest(registry, manifest, image_digest)
    config_digest, config_size = descriptor(document.get("config"), "OCI config")
    config_media = document.get("config", {}).get("mediaType")
    if config_media not in SUPPORTED_CONFIGS:
        raise AttestationError("OCI config has unsupported media type")
    config_bytes = fetch_verified(registry, "blobs/" + config_digest, config_digest, config_size)
    config_doc = json_no_dupes(config_bytes, "OCI config")
    if not isinstance(config_doc, dict) or config_doc.get("os") != "linux" or config_doc.get("architecture") != "amd64":
        raise AttestationError("OCI config must be linux/amd64")
    root = workspace / "rootfs"
    root.mkdir()
    layers = document.get("layers")
    if not isinstance(layers, list) or not layers:
        raise AttestationError("OCI manifest must contain non-empty layers")
    for index, layer in enumerate(layers):
        layer_digest, layer_size = descriptor(layer, f"OCI layer {index}")
        media_type = layer.get("mediaType")
        if media_type not in SUPPORTED_LAYERS:
            raise AttestationError(f"OCI layer {index}: unsupported media type")
        payload = fetch_verified(registry, "blobs/" + layer_digest, layer_digest, layer_size)
        apply_layer(root, payload, media_type)
    # Bubblewrap requires bind destinations to exist in its read-only root.
    prepare_bind_destinations(root)
    return root, selected_digest


def isolated_command(rootfs: Path, binary: Path, record: dict[str, Any], parent_ids: dict[str, str], fixture: Path) -> list[str]:
    for path, label, directory in (
        (rootfs, "rootfs", True),
        (fixture, "fixture", True),
        (binary, "test binary", False),
    ):
        if not path.is_absolute() or path.is_symlink():
            raise AttestationError(f"{label} bind source must be an absolute non-symlink path")
        if directory:
            if not path.is_dir():
                raise AttestationError(f"{label} bind source must be a directory")
        elif not path.is_file() or not os.access(path, os.X_OK):
            raise AttestationError(f"test binary bind source must be an executable regular file")
    try:
        rscript = Path(record["r"]["executable"]).with_name("Rscript")
        env = {
            "NRR_TEST_MODE": "pak-isolated",
            "NRR_PAK_ISOLATION_MODE": "linux-user-pid-netns-v1",
            "NRR_PAK_PARENT_USERNS": parent_ids["user"],
            "NRR_PAK_PARENT_PIDNS": parent_ids["pid"],
            "NRR_PAK_PARENT_NETNS": parent_ids["net"],
            "NRR_RSCRIPT": str(rscript),
            "NRR_PAK_LIBRARY": record["pak"]["library_root"],
            "NRR_PAK_PRIVATE_LIBRARY": record["pak"]["package_path"] + "/library",
            "PATH": "/usr/bin:/bin",
            "LANG": "C.utf8",
            "LC_ALL": "C.utf8",
            "NRR_PAK_FIXTURE_ROOT": "/nrr/fixtures",
        }
    except (KeyError, TypeError) as error:
        raise AttestationError("record is missing pak isolation fields") from error
    command = [
        "unshare", "--user", "--map-root-user", "--net", "bwrap", "--die-with-parent",
        "--ro-bind", str(rootfs), "/", "--ro-bind", str(fixture), "/nrr/fixtures",
        "--ro-bind", str(binary), "/nrr/pak_isolated", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--unshare-pid", "--clearenv",
    ]
    for key, value in env.items():
        command += ["--setenv", key, value]
    command += ["--chdir", "/", "/nrr/pak_isolated", "isolated_pak_contract_requires_wrapper_preflight_and_runs_shared_contract", "--exact", "--nocapture"]
    return command


def locate_test_binary() -> Path:
    command = ["cargo", "test", "-p", "nrr", "--test", "pak_isolated", "--no-run", "--locked", "--offline", "--message-format", "json"]
    try:
        result = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise AttestationError("could not build the pak_isolated test binary") from error
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = event.get("target") if isinstance(event, dict) else None
        if isinstance(target, dict) and event.get("reason") == "compiler-artifact" and target.get("name") == "pak_isolated":
            executable = event.get("executable")
            if isinstance(executable, str) and executable:
                return Path(executable)
    raise AttestationError("cargo did not report the pak_isolated test binary")


def parent_namespace_ids() -> dict[str, str]:
    result: dict[str, str] = {}
    for kind in ("user", "pid", "net"):
        identity = os.readlink(f"/proc/self/ns/{kind}")
        if not re.fullmatch(rf"{kind}:\[\d+\]", identity):
            raise AttestationError(f"invalid parent {kind} namespace identity")
        result[kind] = identity
    return result


@contextmanager
def workspace_context(debug_keep: bool) -> Iterator[Path]:
    if debug_keep:
        path = Path(tempfile.mkdtemp(prefix="nrr-pak-attestation-"))
        try:
            yield path
        finally:
            print(f"debug workspace retained: {path}", file=sys.stderr)
    else:
        with tempfile.TemporaryDirectory(prefix="nrr-pak-attestation-") as directory:
            yield Path(directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, default=RECORD)
    parser.add_argument("--debug-keep", action="store_true")
    args = parser.parse_args(argv)
    try:
        record_path = args.record.resolve()
        if args.record.is_symlink() or not args.record.is_file():
            raise AttestationError("record must be an existing regular non-symlink file")
        record = json_no_dupes(record_path.read_bytes(), "record")
        if not isinstance(record, dict) or not isinstance(record.get("image"), str):
            raise AttestationError("record must be an object with a string image")
        host, repository = image_ref(record["image"])
        image_digest = record["image"].rsplit("@", 1)[1]
        fixture = REPO_ROOT / "crates/nrr-repository/tests/fixtures/closure"
        if not fixture.is_dir() or fixture.is_symlink():
            raise AttestationError("pak closure fixture directory is unavailable")
        with workspace_context(args.debug_keep) as workspace:
            root, selected_digest = rootfs_from_image(Registry(host, repository), image_digest, workspace)
            verifier = [sys.executable, str(REPO_ROOT / "scripts/verify-pak-gate-rootfs.py"), "--rootfs", str(root), "--record", str(record_path)]
            subprocess.run(verifier, check=True)
            binary = locate_test_binary()
            rscript = Path(record["r"]["executable"]).with_name("Rscript")
            rscript_path = root / rscript.as_posix().lstrip("/")
            if rscript_path.is_symlink() or not rscript_path.is_file() or not os.access(rscript_path, os.X_OK):
                raise AttestationError("record.r executable sibling Rscript is not a regular executable")
            command = isolated_command(root, binary, record, parent_namespace_ids(), fixture)
            result = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                message = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "isolated contract failed"
                raise AttestationError(message)
            print(f"verified image {image_digest}; selected manifest {selected_digest}; rootfs verifier passed; isolated pak contract passed")
    except (OSError, AttestationError, KeyError, TypeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"pak release attestation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
