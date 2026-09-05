#!/usr/bin/env -S python3 -I
"""Build deterministic source archives and a digest-bound release manifest."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PRODUCT_SLUG = "mergegrounds"
MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024


class ReleaseError(RuntimeError):
    """Raised when a release cannot be built without ambiguous input."""


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


def git(*arguments: str, binary: bool = False) -> str | bytes:
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
        cwd=ROOT,
        env=git_environment(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
        timeout=30,
    )
    if completed.returncode != 0:
        stderr = completed.stderr if isinstance(completed.stderr, str) else completed.stderr.decode("utf-8", "replace")
        raise ReleaseError(f"git {' '.join(arguments)} failed: {stderr.strip()}")
    output = completed.stdout
    if binary:
        if not isinstance(output, bytes):
            raise ReleaseError("git returned text for a binary request")
        return output
    if not isinstance(output, str):
        raise ReleaseError("git returned bytes for a text request")
    return output


def project_version() -> str:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not version or any(character not in "0123456789." for character in version):
        raise ReleaseError("VERSION must contain one numeric dotted version")
    manifest = json.loads((ROOT / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
    if manifest.get("version") != version:
        raise ReleaseError("VERSION and .codex-plugin/plugin.json disagree")
    return version


def tracked_files() -> list[tuple[str, Path, int]]:
    raw = git("ls-files", "--stage", "-z", binary=True)
    assert isinstance(raw, bytes)
    values: list[tuple[str, Path, int]] = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            metadata, path_bytes = entry.split(b"\t", 1)
            mode_bytes, _object_id, stage_bytes = metadata.split(b" ", 2)
            relative = os.fsdecode(path_bytes)
            mode = int(mode_bytes, 8)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReleaseError("git returned an invalid index entry") from exc
        path = PurePosixPath(relative)
        if (
            stage_bytes != b"0"
            or path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or mode not in {0o100644, 0o100755}
        ):
            raise ReleaseError(f"unsupported release index entry: {relative!r}")
        source = ROOT.joinpath(*path.parts)
        try:
            metadata_result = source.lstat()
        except OSError as exc:
            raise ReleaseError(f"tracked release input is unavailable: {relative}") from exc
        if not stat.S_ISREG(metadata_result.st_mode) or source.is_symlink():
            raise ReleaseError(f"release input must be a regular non-symlink file: {relative}")
        if metadata_result.st_size > MAX_RELEASE_FILE_BYTES:
            raise ReleaseError(f"release input exceeds size boundary: {relative}")
        values.append((path.as_posix(), source, mode))
    if not values:
        raise ReleaseError("release contains no tracked files")
    return sorted(values)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def release_manifest(files: list[tuple[str, Path, int]], version: str) -> dict[str, Any]:
    commit = git("rev-parse", "--verify", "HEAD^{commit}")
    tree = git("rev-parse", "--verify", "HEAD^{tree}")
    assert isinstance(commit, str) and isinstance(tree, str)
    return {
        "schema_version": 1,
        "product": PRODUCT_SLUG,
        "version": version,
        "git_commit": commit.strip(),
        "git_tree": tree.strip(),
        "reproducible_epoch": 0,
        "files": {
            name: {
                "mode": format(mode, "06o"),
                "sha256": sha256(source.read_bytes()),
                "bytes": source.stat().st_size,
            }
            for name, source, mode in files
        },
    }


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def tar_bytes(
    files: list[tuple[str, Path, int]],
    prefix: str,
    manifest_bytes: bytes,
) -> bytes:
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, source, mode in files:
                    payload = source.read_bytes()
                    info = tarfile.TarInfo(f"{prefix}/{name}")
                    info.size = len(payload)
                    info.mode = 0o755 if mode == 0o100755 else 0o644
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, fileobj=io.BytesIO(payload))
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
    files: list[tuple[str, Path, int]],
    prefix: str,
    manifest_bytes: bytes,
) -> bytes:
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as raw:
        with zipfile.ZipFile(raw, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, source, mode in files:
                info = zipfile.ZipInfo(f"{prefix}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                file_mode = 0o755 if mode == 0o100755 else 0o644
                info.external_attr = (stat.S_IFREG | file_mode) << 16
                archive.writestr(info, source.read_bytes())
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


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise ReleaseError(f"refusing symbolic-link output: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def build(output_directory: Path) -> list[Path]:
    version = project_version()
    files = tracked_files()
    manifest = release_manifest(files, version)
    manifest_bytes = canonical_json(manifest)
    prefix = f"{PRODUCT_SLUG}-{version}"
    outputs = {
        f"{prefix}.tar.gz": tar_bytes(files, prefix, manifest_bytes),
        f"{prefix}.zip": zip_bytes(files, prefix, manifest_bytes),
        "release-manifest.json": manifest_bytes,
    }
    for name, payload in outputs.items():
        atomic_write(output_directory / name, payload)
    checksums = "".join(
        f"{sha256(payload)}  {name}\n"
        for name, payload in sorted(outputs.items())
    ).encode("ascii")
    atomic_write(output_directory / "SHA256SUMS", checksums)
    return [output_directory / name for name in sorted((*outputs, "SHA256SUMS"))]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="release-dist")
    arguments = parser.parse_args()
    output = Path(arguments.output_dir)
    if not output.is_absolute():
        output = ROOT / output
    try:
        output.relative_to(ROOT)
    except ValueError as exc:
        raise SystemExit("release output must remain inside the repository") from exc
    try:
        paths = build(output)
    except (OSError, ReleaseError, json.JSONDecodeError) as exc:
        print(f"release build failed: {exc}", file=sys.stderr)
        return 1
    for path in paths:
        print(path.relative_to(ROOT).as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
