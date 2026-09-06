#!/usr/bin/env -S python3 -I
"""Build deterministic source archives from one immutable Git object snapshot."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PRODUCT_SLUG = "mergegrounds"
MAX_RELEASE_FILE_BYTES = 32 * 1024 * 1024
MAX_RELEASE_FILES = 10_000
MAX_TREE_LISTING_BYTES = 8 * 1024 * 1024
MAX_RELEASE_PATH_BYTES = 1_024
SEMANTIC_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
)
GIT_OBJECT_ID = re.compile(r"[0-9a-f]{40}")
WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
WINDOWS_INVALID_CHARACTERS = frozenset('<>:"|?*')


class ReleaseError(RuntimeError):
    """Raised when a release cannot be built without ambiguous input."""


@dataclass(frozen=True)
class SnapshotFile:
    """One regular file read directly from a Git tree object."""

    name: str
    object_id: str
    mode: int
    payload: bytes


@dataclass(frozen=True)
class GitSnapshot:
    """A commit, its root tree, and the immutable blobs reachable from that tree."""

    commit: str
    tree: str
    files: tuple[SnapshotFile, ...]

    def file(self, name: str) -> SnapshotFile:
        for item in self.files:
            if item.name == name:
                return item
        raise ReleaseError(
            f"required release input is absent from the Git snapshot: {name}"
        )


def git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def git(
    *arguments: str,
    root: Path = ROOT,
    binary: bool = False,
) -> str | bytes:
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            *arguments,
        ],
        cwd=root,
        env=git_environment(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
        timeout=30,
    )
    if completed.returncode != 0:
        stderr = (
            completed.stderr
            if isinstance(completed.stderr, str)
            else completed.stderr.decode("utf-8", "replace")
        )
        raise ReleaseError(f"git {' '.join(arguments)} failed: {stderr.strip()}")
    output = completed.stdout
    if binary:
        if not isinstance(output, bytes):
            raise ReleaseError("git returned text for a binary request")
        return output
    if not isinstance(output, str):
        raise ReleaseError("git returned bytes for a text request")
    return output


def _object_id(value: str, field: str) -> str:
    normalized = value.strip()
    if GIT_OBJECT_ID.fullmatch(normalized) is None:
        raise ReleaseError(f"Git returned an invalid {field} object ID")
    return normalized


def _safe_snapshot_path(path_bytes: bytes) -> str:
    try:
        relative = path_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ReleaseError("release paths must be valid UTF-8") from exc
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in relative
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in relative
        )
    ):
        raise ReleaseError(f"unsafe release path in Git snapshot: {relative!r}")
    if len(path_bytes) > MAX_RELEASE_PATH_BYTES:
        raise ReleaseError(f"release path exceeds the portable byte boundary: {relative!r}")
    if unicodedata.normalize("NFC", relative) != relative:
        raise ReleaseError(f"release path must use Unicode NFC normalization: {relative!r}")
    for component in path.parts:
        if component.endswith((".", " ")):
            raise ReleaseError(
                f"release path component has a trailing dot or space: {relative!r}"
            )
        if any(character in WINDOWS_INVALID_CHARACTERS for character in component):
            raise ReleaseError(
                f"release path contains a Windows-invalid character: {relative!r}"
            )
        device_name = component.split(".", 1)[0].casefold()
        if device_name in WINDOWS_RESERVED_NAMES:
            raise ReleaseError(
                f"release path uses a Windows reserved name: {relative!r}"
            )
    return path.as_posix()


def _portable_path_key(name: str) -> str:
    return "/".join(
        unicodedata.normalize("NFC", component).casefold()
        for component in PurePosixPath(name).parts
    )


def _validate_snapshot_paths(files: tuple[SnapshotFile, ...]) -> None:
    observed: dict[str, str] = {}
    reserved_key = _portable_path_key("release-manifest.json")
    for item in files:
        key = _portable_path_key(item.name)
        if key == reserved_key:
            raise ReleaseError(
                "release snapshot contains the reserved generated path: "
                "release-manifest.json"
            )
        previous = observed.get(key)
        if previous is not None:
            raise ReleaseError(
                "release snapshot contains a portable path collision: "
                f"{previous!r} and {item.name!r}"
            )
        observed[key] = item.name


def git_snapshot(revision: str = "HEAD", *, root: Path | None = None) -> GitSnapshot:
    """Read one commit snapshot without consulting the index or worktree."""

    if root is None:
        root = ROOT
    object_format_raw = git("rev-parse", "--show-object-format", root=root)
    assert isinstance(object_format_raw, str)
    if object_format_raw.strip() != "sha1":
        raise ReleaseError("release snapshots require the canonical Git SHA-1 object format")
    commit_raw = git("rev-parse", "--verify", f"{revision}^{{commit}}", root=root)
    assert isinstance(commit_raw, str)
    commit = _object_id(commit_raw, "commit")
    tree_raw = git("rev-parse", "--verify", f"{commit}^{{tree}}", root=root)
    assert isinstance(tree_raw, str)
    tree = _object_id(tree_raw, "tree")
    listing = git("ls-tree", "-r", "-z", "--full-tree", tree, root=root, binary=True)
    assert isinstance(listing, bytes)
    if len(listing) > MAX_TREE_LISTING_BYTES:
        raise ReleaseError("Git tree listing exceeds the bounded release inventory")
    files: list[SnapshotFile] = []
    total_bytes = 0
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        if len(files) >= MAX_RELEASE_FILES:
            raise ReleaseError("release snapshot exceeds the file-count boundary")
        try:
            metadata, path_bytes = entry.split(b"\t", 1)
            mode_bytes, object_type, object_id_bytes = metadata.split(b" ", 2)
            mode = int(mode_bytes, 8)
            object_id = object_id_bytes.decode("ascii", "strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReleaseError("git returned an invalid tree entry") from exc
        name = _safe_snapshot_path(path_bytes)
        if object_type != b"blob" or mode not in {0o100644, 0o100755}:
            raise ReleaseError(f"release input must be a regular file: {name}")
        _object_id(object_id, "blob")
        payload = git("cat-file", "blob", object_id, root=root, binary=True)
        assert isinstance(payload, bytes)
        canonical_object_id = hashlib.sha1(  # noqa: S324 - canonical Git SHA-1 format.
            b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload
        ).hexdigest()
        if canonical_object_id != object_id:
            raise ReleaseError(
                f"Git blob bytes do not match the canonical blob object ID: {name}"
            )
        if len(payload) > MAX_RELEASE_FILE_BYTES:
            raise ReleaseError(f"release input exceeds 32 MiB boundary: {name}")
        total_bytes += len(payload)
        if total_bytes > MAX_RELEASE_FILE_BYTES:
            raise ReleaseError("release snapshot exceeds 32 MiB aggregate boundary")
        files.append(SnapshotFile(name, object_id, mode, payload))
    if not files:
        raise ReleaseError("release contains no tracked files")
    names = [item.name for item in files]
    if len(names) != len(set(names)):
        raise ReleaseError("release snapshot contains duplicate paths")
    ordered_files = tuple(sorted(files, key=lambda item: item.name))
    _validate_snapshot_paths(ordered_files)
    return GitSnapshot(commit, tree, ordered_files)


def _strict_json(payload: bytes, field: str) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseError(f"{field} contains a duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ReleaseError(f"{field} contains a non-finite JSON value: {value}")

    try:
        text = payload.decode("utf-8", "strict")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"{field} must be strict UTF-8 JSON") from exc


def project_version(snapshot: GitSnapshot) -> str:
    version_payload = snapshot.file("VERSION").payload
    if version_payload.endswith(b"\n"):
        version_payload = version_payload[:-1]
    try:
        version = version_payload.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise ReleaseError(
            "VERSION must use strict ASCII semantic-version syntax"
        ) from exc
    if SEMANTIC_VERSION.fullmatch(version) is None:
        raise ReleaseError(
            "VERSION must contain one strict three-component semantic version"
        )
    plugin = _strict_json(
        snapshot.file(".codex-plugin/plugin.json").payload, "plugin manifest"
    )
    if not isinstance(plugin, dict) or type(plugin.get("version")) is not str:
        raise ReleaseError("plugin manifest version must be a string")
    if plugin["version"] != version:
        raise ReleaseError("VERSION and .codex-plugin/plugin.json disagree")
    return version


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def release_manifest(snapshot: GitSnapshot, version: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "product": PRODUCT_SLUG,
        "version": version,
        "git_commit": snapshot.commit,
        "git_tree": snapshot.tree,
        "reproducible_epoch": 0,
        "files": {
            item.name: {
                "mode": format(item.mode, "06o"),
                "sha256": sha256(item.payload),
                "bytes": len(item.payload),
            }
            for item in snapshot.files
        },
    }


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def tar_bytes(
    files: tuple[SnapshotFile, ...],
    prefix: str,
    manifest_bytes: bytes,
) -> bytes:
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive:
                for item in files:
                    info = tarfile.TarInfo(f"{prefix}/{item.name}")
                    info.size = len(item.payload)
                    info.mode = 0o755 if item.mode == 0o100755 else 0o644
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, fileobj=io.BytesIO(item.payload))
                info = tarfile.TarInfo(f"{prefix}/release-manifest.json")
                info.size = len(manifest_bytes)
                info.mode = 0o644
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                archive.addfile(info, fileobj=io.BytesIO(manifest_bytes))
        raw.seek(0)
        return raw.read()


def zip_bytes(
    files: tuple[SnapshotFile, ...],
    prefix: str,
    manifest_bytes: bytes,
) -> bytes:
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as raw:
        with zipfile.ZipFile(
            raw, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for item in files:
                info = zipfile.ZipInfo(
                    f"{prefix}/{item.name}", date_time=(1980, 1, 1, 0, 0, 0)
                )
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                file_mode = 0o755 if item.mode == 0o100755 else 0o644
                info.external_attr = (stat.S_IFREG | file_mode) << 16
                archive.writestr(info, item.payload)
            info = zipfile.ZipInfo(
                f"{prefix}/release-manifest.json",
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, manifest_bytes)
        raw.seek(0)
        return raw.read()


def _reject_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    trusted_root = Path(os.path.abspath(os.fspath(ROOT)))
    try:
        relative = absolute.relative_to(trusted_root)
    except ValueError:
        candidates = [absolute]
    else:
        candidates = [
            trusted_root.joinpath(*relative.parts[:index])
            for index in range(1, len(relative.parts) + 1)
        ]
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise ReleaseError(f"refusing symbolic-link output component: {candidate}")


def _open_empty_output_directory(path: Path) -> int:
    _reject_symlink_components(path)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReleaseError(f"cannot create release output directory: {path}") from exc
    _reject_symlink_components(path)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(path, flags)
    except OSError as exc:
        raise ReleaseError(f"release output must be a real directory: {path}") from exc
    try:
        if os.listdir(directory_fd):
            raise ReleaseError("release output directory must be empty")
    except BaseException:
        os.close(directory_fd)
        raise
    return directory_fd


def atomic_write(directory_fd: int, name: str, payload: bytes) -> None:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise ReleaseError(f"unsafe release output name: {name!r}")
    temporary = f".{name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise ReleaseError(f"release output already exists: {name}") from exc
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            # The successful publish path already removed the temporary link.
            pass


def build(
    output_directory: Path,
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> list[Path]:
    directory_fd = _open_empty_output_directory(output_directory)
    try:
        snapshot = git_snapshot()
        if expected_commit is not None and snapshot.commit != expected_commit:
            raise ReleaseError("HEAD commit does not match the expected release commit")
        if expected_tree is not None and snapshot.tree != expected_tree:
            raise ReleaseError("HEAD tree does not match the expected release tree")
        version = project_version(snapshot)
        manifest = release_manifest(snapshot, version)
        manifest_bytes = canonical_json(manifest)
        prefix = f"{PRODUCT_SLUG}-{version}"
        outputs = {
            f"{prefix}.tar.gz": tar_bytes(snapshot.files, prefix, manifest_bytes),
            f"{prefix}.zip": zip_bytes(snapshot.files, prefix, manifest_bytes),
            "release-manifest.json": manifest_bytes,
        }
        for name, payload in outputs.items():
            if len(payload) > MAX_RELEASE_FILE_BYTES:
                raise ReleaseError(f"release output exceeds 32 MiB boundary: {name}")
        checksums = "".join(
            f"{sha256(payload)}  {name}\n" for name, payload in sorted(outputs.items())
        ).encode("ascii")
        if len(checksums) > MAX_RELEASE_FILE_BYTES:
            raise ReleaseError("SHA256SUMS exceeds 32 MiB boundary")
        outputs["SHA256SUMS"] = checksums
        for name, payload in outputs.items():
            atomic_write(directory_fd, name, payload)
        return [output_directory / name for name in sorted(outputs)]
    finally:
        os.close(directory_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="release-dist")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-tree")
    arguments = parser.parse_args()
    output = Path(arguments.output_dir)
    if not output.is_absolute():
        output = ROOT / output
    try:
        output.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise SystemExit("release output must remain inside the repository") from exc
    try:
        paths = build(
            output,
            expected_commit=arguments.expected_commit,
            expected_tree=arguments.expected_tree,
        )
    except (OSError, ReleaseError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"release build failed: {exc}", file=sys.stderr)
        return 1
    for path in paths:
        print(path.relative_to(ROOT).as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
