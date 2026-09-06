#!/usr/bin/env -S python3 -I
"""Validate a release bundle against an exact Git commit, tree, and tag ref."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import importlib.util
import io
import json
import re
import stat
import struct
import sys
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
MANIFEST_KEYS = {
    "schema_version",
    "product",
    "version",
    "git_commit",
    "git_tree",
    "reproducible_epoch",
    "files",
}
FILE_RECORD_KEYS = {"mode", "sha256", "bytes"}


def _load_builder() -> ModuleType:
    path = Path(__file__).resolve().with_name("build_release.py")
    specification = importlib.util.spec_from_file_location(
        "_mergegrounds_build_release", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load the release snapshot implementation")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


build_release = _load_builder()
ReleaseError = build_release.ReleaseError
MAX_ARCHIVE_MEMBERS = build_release.MAX_RELEASE_FILES + 1
MAX_ARCHIVE_EXPANDED_BYTES = 2 * build_release.MAX_RELEASE_FILE_BYTES
ZIP_EOCD = struct.Struct("<4s4H2LH")


def _strict_version_ref(expected_ref: str) -> str:
    match = re.fullmatch(r"refs/tags/v(.+)", expected_ref)
    if (
        match is None
        or build_release.SEMANTIC_VERSION.fullmatch(match.group(1)) is None
    ):
        raise ReleaseError("expected ref must be one strict version tag")
    return match.group(1)


def _exact_object_id(value: str, field: str) -> str:
    if (
        not isinstance(value, str)
        or build_release.GIT_OBJECT_ID.fullmatch(value) is None
    ):
        raise ReleaseError(f"expected {field} must be one full lowercase Git object ID")
    return value


def _read_bundle(bundle_directory: Path, expected_names: set[str]) -> dict[str, bytes]:
    try:
        directory_metadata = bundle_directory.lstat()
    except OSError as exc:
        raise ReleaseError("candidate bundle directory is unavailable") from exc
    if not stat.S_ISDIR(directory_metadata.st_mode) or bundle_directory.is_symlink():
        raise ReleaseError("candidate bundle must be a real non-symlink directory")
    try:
        entries = list(bundle_directory.iterdir())
    except OSError as exc:
        raise ReleaseError("candidate bundle directory cannot be enumerated") from exc
    if {entry.name for entry in entries} != expected_names or len(entries) != len(
        expected_names
    ):
        raise ReleaseError(
            "candidate bundle must contain exactly the four expected files"
        )
    payloads: dict[str, bytes] = {}
    for entry in entries:
        try:
            metadata = entry.lstat()
        except OSError as exc:
            raise ReleaseError(
                f"candidate bundle entry is unavailable: {entry.name}"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or entry.is_symlink()
            or metadata.st_mode & 0o111
        ):
            raise ReleaseError(
                f"candidate bundle entry must be a non-executable regular file: {entry.name}"
            )
        if metadata.st_size > build_release.MAX_RELEASE_FILE_BYTES:
            raise ReleaseError(
                f"candidate bundle entry exceeds 32 MiB boundary: {entry.name}"
            )
        try:
            payload = entry.read_bytes()
        except OSError as exc:
            raise ReleaseError(
                f"candidate bundle entry cannot be read: {entry.name}"
            ) from exc
        if len(payload) != metadata.st_size:
            raise ReleaseError(
                f"candidate bundle entry changed while it was read: {entry.name}"
            )
        payloads[entry.name] = payload
    return payloads


def _validate_manifest(
    payload: bytes,
    *,
    snapshot: Any,
    version: str,
) -> tuple[dict[str, Any], bytes]:
    manifest = build_release._strict_json(payload, "release manifest")
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        raise ReleaseError("release manifest keys do not match the exact schema")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ReleaseError("release manifest schema_version must be the integer 1")
    if (
        type(manifest["product"]) is not str
        or manifest["product"] != build_release.PRODUCT_SLUG
    ):
        raise ReleaseError("release manifest product does not match MergeGrounds")
    if (
        type(manifest["version"]) is not str
        or build_release.SEMANTIC_VERSION.fullmatch(manifest["version"]) is None
        or manifest["version"] != version
    ):
        raise ReleaseError(
            "release manifest version does not match the exact tag and source version"
        )
    if (
        type(manifest["git_commit"]) is not str
        or manifest["git_commit"] != snapshot.commit
    ):
        raise ReleaseError(
            "release manifest git_commit does not match the source snapshot"
        )
    if type(manifest["git_tree"]) is not str or manifest["git_tree"] != snapshot.tree:
        raise ReleaseError(
            "release manifest git_tree does not match the source snapshot"
        )
    if (
        type(manifest["reproducible_epoch"]) is not int
        or manifest["reproducible_epoch"] != 0
    ):
        raise ReleaseError(
            "release manifest reproducible epoch must be the integer zero"
        )
    records = manifest["files"]
    if not isinstance(records, dict):
        raise ReleaseError("release manifest file inventory must be an object")
    expected_files = {item.name: item for item in snapshot.files}
    if set(records) != set(expected_files):
        raise ReleaseError(
            "release manifest file inventory does not match the Git snapshot"
        )
    for name, item in expected_files.items():
        record = records[name]
        if not isinstance(record, dict) or set(record) != FILE_RECORD_KEYS:
            raise ReleaseError(f"release manifest record keys are invalid: {name}")
        expected_mode = format(item.mode, "06o")
        if type(record["mode"]) is not str or record["mode"] != expected_mode:
            raise ReleaseError(
                f"release manifest mode does not match the Git snapshot: {name}"
            )
        if type(record["bytes"]) is not int or record["bytes"] != len(item.payload):
            raise ReleaseError(
                f"release manifest bytes do not match the Git snapshot: {name}"
            )
        digest = record["sha256"]
        if (
            type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or digest != hashlib.sha256(item.payload).hexdigest()
        ):
            raise ReleaseError(
                f"release manifest sha256 does not match the Git snapshot: {name}"
            )
    canonical = _canonical_json(manifest)
    if payload != canonical:
        raise ReleaseError("release manifest is not canonical JSON")
    return manifest, canonical


def _validate_checksums(payloads: dict[str, bytes], expected_names: set[str]) -> None:
    bound_names = sorted(expected_names - {"SHA256SUMS"})
    expected = "".join(
        f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}\n"
        for name in bound_names
    ).encode("ascii")
    if payloads["SHA256SUMS"] != expected:
        raise ReleaseError(
            "SHA256SUMS is not canonical or does not bind the exact candidate bytes"
        )


def _archive_members(
    snapshot: Any, version: str, manifest_bytes: bytes
) -> list[tuple[str, bytes, int]]:
    prefix = f"{build_release.PRODUCT_SLUG}-{version}"
    result = [
        (
            f"{prefix}/{item.name}",
            item.payload,
            0o755 if item.mode == 0o100755 else 0o644,
        )
        for item in snapshot.files
    ]
    result.append((f"{prefix}/release-manifest.json", manifest_bytes, 0o644))
    names = [name for name, _content, _mode in result]
    if len(names) != len(set(names)):
        raise ReleaseError("expected archive inventory contains duplicate member names")
    if len(result) > MAX_ARCHIVE_MEMBERS:
        raise ReleaseError("expected archive inventory exceeds the member-count bound")
    if sum(len(content) for _name, content, _mode in result) > MAX_ARCHIVE_EXPANDED_BYTES:
        raise ReleaseError("expected archive inventory exceeds the expanded-byte bound")
    return result


def _validate_tar(payload: bytes, expected: list[tuple[str, bytes, int]]) -> None:
    expected_names = [name for name, _content, _mode in expected]
    if len(expected_names) != len(set(expected_names)):
        raise ReleaseError("expected tar inventory contains duplicate member names")
    if len(payload) > build_release.MAX_RELEASE_FILE_BYTES:
        raise ReleaseError("tar archive exceeds the compressed-byte bound")
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members: list[tarfile.TarInfo] = []
            expanded_bytes = 0
            while True:
                member = archive.next()
                if member is None:
                    break
                if len(members) >= MAX_ARCHIVE_MEMBERS:
                    raise ReleaseError("tar archive exceeds the member-count bound")
                if member.size < 0 or member.size > build_release.MAX_RELEASE_FILE_BYTES:
                    raise ReleaseError("tar archive member exceeds the per-file bound")
                expanded_bytes += member.size
                if expanded_bytes > MAX_ARCHIVE_EXPANDED_BYTES:
                    raise ReleaseError("tar archive exceeds the expanded-byte bound")
                members.append(member)
            observed_names = [member.name for member in members]
            if len(observed_names) != len(set(observed_names)):
                raise ReleaseError("tar archive contains duplicate member names")
            if observed_names != expected_names:
                raise ReleaseError(
                    "tar member inventory does not match the exact source snapshot"
                )
            for member, (name, content, mode) in zip(members, expected, strict=True):
                if (
                    not member.isreg()
                    or member.mode != mode
                    or member.size != len(content)
                    or member.mtime != 0
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.linkname != ""
                    or member.pax_headers
                ):
                    raise ReleaseError(f"tar member metadata is not canonical: {name}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReleaseError(f"tar member content is unavailable: {name}")
                observed = extracted.read(len(content) + 1)
                if observed != content:
                    if name.endswith("/release-manifest.json"):
                        raise ReleaseError(
                            "tar embedded manifest does not match the standalone manifest"
                        )
                    raise ReleaseError(
                        f"tar member content does not match the Git snapshot: {name}"
                    )
    except ReleaseError:
        raise
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise ReleaseError("tar archive is malformed") from exc


def _validate_zip(payload: bytes, expected: list[tuple[str, bytes, int]]) -> None:
    expected_names = [name for name, _content, _mode in expected]
    if len(expected_names) != len(set(expected_names)):
        raise ReleaseError("expected zip inventory contains duplicate member names")
    if len(payload) > build_release.MAX_RELEASE_FILE_BYTES:
        raise ReleaseError("zip archive exceeds the compressed-byte bound")
    if len(payload) < ZIP_EOCD.size:
        raise ReleaseError("zip archive is malformed")
    try:
        (
            signature,
            disk_number,
            directory_disk,
            disk_entries,
            total_entries,
            directory_size,
            directory_offset,
            comment_size,
        ) = ZIP_EOCD.unpack(payload[-ZIP_EOCD.size :])
    except struct.error as exc:
        raise ReleaseError("zip archive is malformed") from exc
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or directory_disk != 0
        or disk_entries != total_entries
        or total_entries == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
        or comment_size != 0
        or directory_offset + directory_size != len(payload) - ZIP_EOCD.size
    ):
        raise ReleaseError("zip archive directory metadata is not canonical")
    if total_entries > MAX_ARCHIVE_MEMBERS:
        raise ReleaseError("zip archive exceeds the member-count bound")
    if directory_size > build_release.MAX_TREE_LISTING_BYTES:
        raise ReleaseError("zip archive directory exceeds the metadata-byte bound")
    try:
        with zipfile.ZipFile(io.BytesIO(payload), mode="r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise ReleaseError("zip archive exceeds the member-count bound")
            observed_names = [info.filename for info in infos]
            if len(observed_names) != len(set(observed_names)):
                raise ReleaseError("zip archive contains duplicate member names")
            if any(
                info.file_size < 0
                or info.file_size > build_release.MAX_RELEASE_FILE_BYTES
                for info in infos
            ):
                raise ReleaseError("zip archive member exceeds the per-file bound")
            if sum(info.file_size for info in infos) > MAX_ARCHIVE_EXPANDED_BYTES:
                raise ReleaseError("zip archive exceeds the expanded-byte bound")
            if observed_names != expected_names:
                raise ReleaseError(
                    "zip member inventory does not match the exact source snapshot"
                )
            if archive.comment != b"":
                raise ReleaseError("zip archive metadata is not canonical")
            for info, (name, content, mode) in zip(infos, expected, strict=True):
                expected_external = (stat.S_IFREG | mode) << 16
                if (
                    info.is_dir()
                    or info.date_time != (1980, 1, 1, 0, 0, 0)
                    or info.create_system != 3
                    or info.external_attr != expected_external
                    or info.compress_type != zipfile.ZIP_DEFLATED
                    or info.file_size != len(content)
                    or info.extra != b""
                    or info.comment != b""
                ):
                    raise ReleaseError(f"zip member metadata is not canonical: {name}")
                with archive.open(info, mode="r") as extracted:
                    observed = extracted.read(len(content) + 1)
                if observed != content:
                    if name.endswith("/release-manifest.json"):
                        raise ReleaseError(
                            "zip embedded manifest does not match the standalone manifest"
                        )
                    raise ReleaseError(
                        f"zip member content does not match the Git snapshot: {name}"
                    )
            bad_member = archive.testzip()
            if bad_member is not None:
                raise ReleaseError(f"zip member CRC is invalid: {bad_member}")
    except ReleaseError:
        raise
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ReleaseError("zip archive is malformed") from exc


def _bind_annotated_tag(
    *, expected_ref: str, expected_commit: str, source_root: Path
) -> None:
    object_type = build_release.git("cat-file", "-t", expected_ref, root=source_root)
    if not isinstance(object_type, str) or object_type.strip() != "tag":
        raise ReleaseError("expected release ref must identify an annotated Git tag")
    peeled_raw = build_release.git(
        "rev-parse", "--verify", f"{expected_ref}^{{commit}}", root=source_root
    )
    if not isinstance(peeled_raw, str):
        raise ReleaseError("annotated release tag did not resolve to a commit")
    peeled = _exact_object_id(peeled_raw.strip(), "tag commit")
    if peeled != expected_commit:
        raise ReleaseError("annotated release tag does not bind the exact expected commit")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")


def _expected_manifest(snapshot: Any, version: str) -> bytes:
    return _canonical_json(
        {
            "schema_version": 1,
            "product": build_release.PRODUCT_SLUG,
            "version": version,
            "git_commit": snapshot.commit,
            "git_tree": snapshot.tree,
            "reproducible_epoch": 0,
            "files": {
                item.name: {
                    "mode": format(item.mode, "06o"),
                    "sha256": hashlib.sha256(item.payload).hexdigest(),
                    "bytes": len(item.payload),
                }
                for item in snapshot.files
            },
        }
    )


def _expected_tar(
    files: tuple[Any, ...], prefix: str, manifest_bytes: bytes
) -> bytes:
    raw = io.BytesIO()
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
    return raw.getvalue()


def _expected_zip(
    files: tuple[Any, ...], prefix: str, manifest_bytes: bytes
) -> bytes:
    raw = io.BytesIO()
    with zipfile.ZipFile(
        raw, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for item in files:
            info = zipfile.ZipInfo(
                f"{prefix}/{item.name}", date_time=(1980, 1, 1, 0, 0, 0)
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o755 if item.mode == 0o100755 else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, item.payload)
        info = zipfile.ZipInfo(
            f"{prefix}/release-manifest.json", date_time=(1980, 1, 1, 0, 0, 0)
        )
        info.compress_type = zipfile.ZIP_DEFLATED
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, manifest_bytes)
    return raw.getvalue()


def _expected_bundle(snapshot: Any, version: str) -> dict[str, bytes]:
    manifest_bytes = _expected_manifest(snapshot, version)
    prefix = f"{build_release.PRODUCT_SLUG}-{version}"
    payloads = {
        f"{prefix}.tar.gz": _expected_tar(snapshot.files, prefix, manifest_bytes),
        f"{prefix}.zip": _expected_zip(snapshot.files, prefix, manifest_bytes),
        "release-manifest.json": manifest_bytes,
    }
    payloads["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
        for name, payload in sorted(payloads.items())
    ).encode("ascii")
    for name, payload in payloads.items():
        if len(payload) > build_release.MAX_RELEASE_FILE_BYTES:
            raise ReleaseError(f"expected release file exceeds 32 MiB boundary: {name}")
    return payloads


def _require_raw_bundle_equality(
    observed: dict[str, bytes], expected: dict[str, bytes]
) -> None:
    if set(observed) != set(expected):
        raise ReleaseError("candidate names do not match the independently generated bundle")
    for name in sorted(expected):
        observed_digest = hashlib.sha256(observed[name]).digest()
        expected_digest = hashlib.sha256(expected[name]).digest()
        if not hmac.compare_digest(observed_digest, expected_digest) or not hmac.compare_digest(
            observed[name], expected[name]
        ):
            raise ReleaseError(
                "candidate raw bytes do not match the independently generated "
                f"expected bundle: {name}"
            )


def validate_bundle(
    bundle_directory: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    expected_ref: str,
    source_root: Path = ROOT,
) -> dict[str, Any]:
    version = _strict_version_ref(expected_ref)
    expected_commit = _exact_object_id(expected_commit, "commit")
    expected_tree = _exact_object_id(expected_tree, "tree")
    _bind_annotated_tag(
        expected_ref=expected_ref,
        expected_commit=expected_commit,
        source_root=source_root,
    )
    snapshot = build_release.git_snapshot(expected_commit, root=source_root)
    if snapshot.commit != expected_commit:
        raise ReleaseError("expected commit does not identify the source snapshot")
    if snapshot.tree != expected_tree:
        raise ReleaseError("expected tree does not identify the source snapshot")
    source_version = build_release.project_version(snapshot)
    if source_version != version:
        raise ReleaseError("tag version does not match the source snapshot")
    expected_names = {
        f"{build_release.PRODUCT_SLUG}-{version}.tar.gz",
        f"{build_release.PRODUCT_SLUG}-{version}.zip",
        "release-manifest.json",
        "SHA256SUMS",
    }
    payloads = _read_bundle(bundle_directory, expected_names)
    expected_payloads = _expected_bundle(snapshot, version)
    _require_raw_bundle_equality(payloads, expected_payloads)
    _manifest, manifest_bytes = _validate_manifest(
        payloads["release-manifest.json"],
        snapshot=snapshot,
        version=version,
    )
    _validate_checksums(payloads, expected_names)
    members = _archive_members(snapshot, version, manifest_bytes)
    _validate_tar(payloads[f"{build_release.PRODUCT_SLUG}-{version}.tar.gz"], members)
    _validate_zip(payloads[f"{build_release.PRODUCT_SLUG}-{version}.zip"], members)
    if (
        payloads[f"{build_release.PRODUCT_SLUG}-{version}.tar.gz"]
        != expected_payloads[f"{build_release.PRODUCT_SLUG}-{version}.tar.gz"]
    ):
        raise ReleaseError("tar archive encoding or metadata is not canonical")
    if (
        payloads[f"{build_release.PRODUCT_SLUG}-{version}.zip"]
        != expected_payloads[f"{build_release.PRODUCT_SLUG}-{version}.zip"]
    ):
        raise ReleaseError("zip archive encoding or metadata is not canonical")
    return {
        "schema_version": 1,
        "status": "pass",
        "version": version,
        "git_commit": snapshot.commit,
        "git_tree": snapshot.tree,
        "files": len(snapshot.files),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-ref", required=True)
    arguments = parser.parse_args()
    try:
        result = validate_bundle(
            Path(arguments.bundle_dir),
            expected_commit=arguments.expected_commit,
            expected_tree=arguments.expected_tree,
            expected_ref=arguments.expected_ref,
        )
    except (OSError, ReleaseError, json.JSONDecodeError) as exc:
        print(f"release validation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
