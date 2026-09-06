from __future__ import annotations

import copy
import importlib.util
import gzip
import hashlib
import io
import json
import stat
import subprocess
import struct
import sys
import tarfile
import tempfile
import unittest
import unittest.mock as mock
import zipfile
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    specification = importlib.util.spec_from_file_location(
        name, ROOT / f"scripts/{name}.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


build_release = load_script("build_release")
validate_release = load_script("validate_release")


def run_git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def rewrite_checksums(bundle: Path) -> None:
    names = [
        "mergegrounds-1.0.0.tar.gz",
        "mergegrounds-1.0.0.zip",
        "release-manifest.json",
    ]
    payload = "".join(
        f"{hashlib.sha256((bundle / name).read_bytes()).hexdigest()}  {name}\n"
        for name in sorted(names)
    )
    (bundle / "SHA256SUMS").write_text(payload, encoding="ascii")


def rewrite_tar(
    bundle: Path,
    *,
    target: str,
    content: bytes | None = None,
    mode: int | None = None,
    add_member: bool = False,
) -> None:
    path = bundle / "mergegrounds-1.0.0.tar.gz"
    with tarfile.open(path, mode="r:gz") as archive:
        records = [
            (member, archive.extractfile(member).read())
            for member in archive.getmembers()
        ]
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive:
                for original, payload in records:
                    info = tarfile.TarInfo(original.name)
                    info.mode = (
                        mode
                        if original.name == target and mode is not None
                        else original.mode
                    )
                    info.mtime = original.mtime
                    info.uid = original.uid
                    info.gid = original.gid
                    info.uname = original.uname
                    info.gname = original.gname
                    value = (
                        content
                        if original.name == target and content is not None
                        else payload
                    )
                    info.size = len(value)
                    archive.addfile(info, io.BytesIO(value))
                if add_member:
                    info = tarfile.TarInfo("mergegrounds-1.0.0/unexpected.txt")
                    info.mode = 0o644
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.size = 1
                    archive.addfile(info, io.BytesIO(b"x"))
    rewrite_checksums(bundle)


def rewrite_zip(
    bundle: Path,
    *,
    target: str,
    content: bytes | None = None,
    mode: int | None = None,
    add_member: bool = False,
) -> None:
    path = bundle / "mergegrounds-1.0.0.zip"
    with zipfile.ZipFile(path) as archive:
        records = [(info, archive.read(info)) for info in archive.infolist()]
    with zipfile.ZipFile(
        path, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for original, payload in records:
            info = zipfile.ZipInfo(original.filename, date_time=original.date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = original.create_system
            info.external_attr = (
                (stat.S_IFREG | mode) << 16
                if original.filename == target and mode is not None
                else original.external_attr
            )
            value = (
                content
                if original.filename == target and content is not None
                else payload
            )
            archive.writestr(info, value)
        if add_member:
            info = zipfile.ZipInfo(
                "mergegrounds-1.0.0/unexpected.txt", date_time=(1980, 1, 1, 0, 0, 0)
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, b"x")
    rewrite_checksums(bundle)


@contextmanager
def built_release():
    with (
        tempfile.TemporaryDirectory() as source_raw,
        tempfile.TemporaryDirectory() as bundle_raw,
    ):
        source = Path(source_raw)
        bundle = Path(bundle_raw)
        (source / ".codex-plugin").mkdir()
        (source / "scripts").mkdir()
        (source / "VERSION").write_text("1.0.0\n", encoding="ascii")
        (source / ".codex-plugin/plugin.json").write_text(
            json.dumps({"version": "1.0.0"}) + "\n",
            encoding="utf-8",
        )
        (source / "README.md").write_bytes(b"fixture\n")
        executable = source / "scripts/example.py"
        executable.write_bytes(b"#!/usr/bin/env python3\n")
        executable.chmod(0o755)
        run_git(source, "init", "--quiet")
        run_git(source, "config", "user.name", "ExCoder")
        run_git(
            source, "config", "user.email", "3510267+ExCoder@users.noreply.github.com"
        )
        run_git(source, "add", "--all")
        run_git(source, "commit", "--quiet", "-m", "fixture")
        commit = run_git(source, "rev-parse", "HEAD^{commit}")
        tree = run_git(source, "rev-parse", "HEAD^{tree}")
        run_git(source, "tag", "-a", "v1.0.0", "-m", "release fixture", commit)
        with mock.patch.object(build_release, "ROOT", source):
            build_release.build(bundle, expected_commit=commit, expected_tree=tree)
        yield source, bundle, commit, tree


class ReleaseBundleValidationTests(unittest.TestCase):
    def test_validator_binds_the_annotated_tag_to_the_exact_commit(self) -> None:
        with (
            built_release() as (source, _bundle, _commit, _tree),
            tempfile.TemporaryDirectory() as bundle_raw,
        ):
            (source / "README.md").write_bytes(b"newer commit\n")
            run_git(source, "add", "README.md")
            run_git(source, "commit", "--quiet", "-m", "newer")
            newer_commit = run_git(source, "rev-parse", "HEAD^{commit}")
            newer_tree = run_git(source, "rev-parse", "HEAD^{tree}")
            bundle = Path(bundle_raw)
            with mock.patch.object(build_release, "ROOT", source):
                build_release.build(
                    bundle,
                    expected_commit=newer_commit,
                    expected_tree=newer_tree,
                )

            with self.assertRaisesRegex(validate_release.ReleaseError, "tag.*commit"):
                validate_release.validate_bundle(
                    bundle,
                    expected_commit=newer_commit,
                    expected_tree=newer_tree,
                    expected_ref="refs/tags/v1.0.0",
                    source_root=source,
                )

    def test_validator_accepts_one_exact_git_bound_bundle(self) -> None:
        with built_release() as (source, bundle, commit, tree):
            result = validate_release.validate_bundle(
                bundle,
                expected_commit=commit,
                expected_tree=tree,
                expected_ref="refs/tags/v1.0.0",
                source_root=source,
            )

        self.assertEqual(
            {
                "schema_version": 1,
                "status": "pass",
                "version": "1.0.0",
                "git_commit": commit,
                "git_tree": tree,
                "files": 4,
            },
            result,
        )

    def test_validator_rejects_unsafe_or_unexpected_bundle_entries(self) -> None:
        cases = ("extra", "symlink", "executable", "oversized")
        for case in cases:
            with (
                self.subTest(case=case),
                built_release() as (source, bundle, commit, tree),
            ):
                if case == "extra":
                    (bundle / "unexpected.txt").write_bytes(b"x")
                elif case == "symlink":
                    checksum = bundle / "SHA256SUMS"
                    checksum.unlink()
                    checksum.symlink_to(bundle / "release-manifest.json")
                elif case == "executable":
                    (bundle / "release-manifest.json").chmod(0o755)
                else:
                    with (bundle / "mergegrounds-1.0.0.zip").open("r+b") as handle:
                        handle.truncate(32 * 1024 * 1024 + 1)

                with self.assertRaisesRegex(
                    validate_release.ReleaseError, "bundle|candidate|32 MiB"
                ):
                    validate_release.validate_bundle(
                        bundle,
                        expected_commit=commit,
                        expected_tree=tree,
                        expected_ref="refs/tags/v1.0.0",
                        source_root=source,
                    )

    def test_validator_rejects_noncanonical_or_unbound_manifest_fields(self) -> None:
        def alter_record(document: dict, field: str, value) -> None:
            first = sorted(document["files"])[0]
            document["files"][first][field] = value

        cases = (
            ("extra root key", lambda value: value.__setitem__("extra", None), "keys"),
            (
                "boolean schema",
                lambda value: value.__setitem__("schema_version", True),
                "schema_version",
            ),
            (
                "wrong product",
                lambda value: value.__setitem__("product", "other"),
                "product",
            ),
            (
                "wrong version",
                lambda value: value.__setitem__("version", "1.0.1"),
                "version",
            ),
            (
                "wrong commit",
                lambda value: value.__setitem__("git_commit", "0" * 40),
                "git_commit",
            ),
            (
                "wrong tree",
                lambda value: value.__setitem__("git_tree", "0" * 40),
                "git_tree",
            ),
            (
                "boolean epoch",
                lambda value: value.__setitem__("reproducible_epoch", False),
                "epoch",
            ),
            (
                "missing file",
                lambda value: value["files"].pop(sorted(value["files"])[0]),
                "inventory",
            ),
            (
                "extra record key",
                lambda value: alter_record(value, "extra", None),
                "record keys",
            ),
            (
                "boolean byte count",
                lambda value: alter_record(value, "bytes", True),
                "bytes",
            ),
            ("wrong mode", lambda value: alter_record(value, "mode", "100777"), "mode"),
            (
                "uppercase digest",
                lambda value: alter_record(value, "sha256", "A" * 64),
                "sha256",
            ),
        )
        for label, mutate, _message in cases:
            with (
                self.subTest(case=label),
                built_release() as (source, bundle, commit, tree),
            ):
                path = bundle / "release-manifest.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                mutate(document)
                path.write_bytes(build_release.canonical_json(document))

                with self.assertRaisesRegex(validate_release.ReleaseError, "raw.*bytes"):
                    validate_release.validate_bundle(
                        bundle,
                        expected_commit=commit,
                        expected_tree=tree,
                        expected_ref="refs/tags/v1.0.0",
                        source_root=source,
                    )

    def test_manifest_parser_directly_rejects_every_schema_binding_branch(self) -> None:
        with built_release() as (source, _bundle, commit, _tree):
            snapshot = validate_release.build_release.git_snapshot(
                commit, root=source
            )
            base = validate_release.build_release.release_manifest(snapshot, "1.0.0")

            def alter_record(document: dict, field: str, value) -> None:
                document["files"][sorted(document["files"])[0]][field] = value

            mutations = (
                (lambda value: [], "keys"),
                (lambda value: {**value, "extra": None}, "keys"),
                (
                    lambda value: {**value, "schema_version": True},
                    "schema_version",
                ),
                (lambda value: {**value, "product": "other"}, "product"),
                (lambda value: {**value, "version": 1}, "version"),
                (lambda value: {**value, "git_commit": "0" * 40}, "git_commit"),
                (lambda value: {**value, "git_tree": "0" * 40}, "git_tree"),
                (
                    lambda value: {**value, "reproducible_epoch": False},
                    "epoch",
                ),
                (lambda value: {**value, "files": []}, "inventory"),
                (
                    lambda value: (
                        value["files"].pop(sorted(value["files"])[0]), value
                    )[1],
                    "inventory",
                ),
                (
                    lambda value: (
                        value["files"].__setitem__(
                            sorted(value["files"])[0], []
                        ),
                        value,
                    )[1],
                    "record keys",
                ),
                (
                    lambda value: (alter_record(value, "mode", "100777"), value)[1],
                    "mode",
                ),
                (
                    lambda value: (alter_record(value, "bytes", True), value)[1],
                    "bytes",
                ),
                (
                    lambda value: (alter_record(value, "sha256", "A" * 64), value)[1],
                    "sha256",
                ),
            )
            for mutate, message in mutations:
                with self.subTest(message=message):
                    document = mutate(copy.deepcopy(base))
                    payload = validate_release._canonical_json(document)
                    with self.assertRaisesRegex(validate_release.ReleaseError, message):
                        validate_release._validate_manifest(
                            payload,
                            snapshot=snapshot,
                            version="1.0.0",
                        )

            noncanonical = json.dumps(base, sort_keys=True).encode("utf-8")
            with self.assertRaisesRegex(validate_release.ReleaseError, "canonical"):
                validate_release._validate_manifest(
                    noncanonical,
                    snapshot=snapshot,
                    version="1.0.0",
                )

    def test_validator_rejects_noncanonical_checksum_grammar(self) -> None:
        def uppercase_digest(value: bytes) -> bytes:
            for index, byte in enumerate(value[:64]):
                if byte in b"abcdef":
                    return value[:index] + bytes([byte - 32]) + value[index + 1 :]
            raise AssertionError("fixture digest contains no hexadecimal letter")

        mutations = (
            ("uppercase digest", uppercase_digest),
            ("single separator", lambda value: value.replace(b"  ", b" ", 1)),
            (
                "reordered",
                lambda value: b"\n".join(reversed(value.splitlines())) + b"\n",
            ),
            ("missing final newline", lambda value: value.rstrip(b"\n")),
            (
                "duplicate",
                lambda value: b"\n".join([value.splitlines()[0]] * 3) + b"\n",
            ),
        )
        for label, mutate in mutations:
            with (
                self.subTest(case=label),
                built_release() as (source, bundle, commit, tree),
            ):
                path = bundle / "SHA256SUMS"
                path.write_bytes(mutate(path.read_bytes()))

                with self.assertRaisesRegex(
                    validate_release.ReleaseError, "SHA256SUMS"
                ):
                    validate_release.validate_bundle(
                        bundle,
                        expected_commit=commit,
                        expected_tree=tree,
                        expected_ref="refs/tags/v1.0.0",
                        source_root=source,
                    )

    def test_validator_rejects_tar_member_inventory_content_and_metadata_changes(
        self,
    ) -> None:
        cases = (
            ("extra", {"target": "", "add_member": True}, "inventory"),
            (
                "content",
                {"target": "mergegrounds-1.0.0/README.md", "content": b"FIXTURE\n"},
                "content",
            ),
            (
                "metadata",
                {"target": "mergegrounds-1.0.0/README.md", "mode": 0o777},
                "metadata",
            ),
            (
                "manifest",
                {
                    "target": "mergegrounds-1.0.0/release-manifest.json",
                    "content": b"replace at runtime",
                },
                "manifest",
            ),
        )
        for label, mutation, _message in cases:
            with (
                self.subTest(case=label),
                built_release() as (source, bundle, commit, tree),
            ):
                rewrite_tar(bundle, **mutation)
                with self.assertRaisesRegex(validate_release.ReleaseError, "raw.*bytes"):
                    validate_release.validate_bundle(
                        bundle,
                        expected_commit=commit,
                        expected_tree=tree,
                        expected_ref="refs/tags/v1.0.0",
                        source_root=source,
                    )

    def test_validator_rejects_zip_member_inventory_content_and_metadata_changes(
        self,
    ) -> None:
        cases = (
            ("extra", {"target": "", "add_member": True}, "inventory"),
            (
                "content",
                {"target": "mergegrounds-1.0.0/README.md", "content": b"FIXTURE\n"},
                "content",
            ),
            (
                "metadata",
                {"target": "mergegrounds-1.0.0/README.md", "mode": 0o777},
                "metadata",
            ),
            (
                "manifest",
                {
                    "target": "mergegrounds-1.0.0/release-manifest.json",
                    "content": b"{}\n",
                },
                "manifest",
            ),
        )
        for label, mutation, _message in cases:
            with (
                self.subTest(case=label),
                built_release() as (source, bundle, commit, tree),
            ):
                rewrite_zip(bundle, **mutation)
                with self.assertRaisesRegex(validate_release.ReleaseError, "raw.*bytes"):
                    validate_release.validate_bundle(
                        bundle,
                        expected_commit=commit,
                        expected_tree=tree,
                        expected_ref="refs/tags/v1.0.0",
                        source_root=source,
                    )

    def test_archive_parsers_directly_reject_content_metadata_and_inventory(self) -> None:
        tar_cases = (
            ({"target": "", "add_member": True}, "inventory"),
            (
                {"target": "mergegrounds-1.0.0/README.md", "content": b"changed\n"},
                "content",
            ),
            (
                {"target": "mergegrounds-1.0.0/README.md", "mode": 0o777},
                "metadata",
            ),
            (
                {
                    "target": "mergegrounds-1.0.0/release-manifest.json",
                    "content": b"{}\n",
                },
                "manifest",
            ),
        )
        for kind, cases, rewrite, validator in (
            ("tar", tar_cases, rewrite_tar, validate_release._validate_tar),
            ("zip", tar_cases, rewrite_zip, validate_release._validate_zip),
        ):
            for mutation, message in cases:
                with (
                    self.subTest(kind=kind, message=message),
                    built_release() as (source, bundle, commit, _tree),
                ):
                    snapshot = validate_release.build_release.git_snapshot(
                        commit, root=source
                    )
                    manifest_bytes = (bundle / "release-manifest.json").read_bytes()
                    expected = validate_release._archive_members(
                        snapshot, "1.0.0", manifest_bytes
                    )
                    actual_mutation = dict(mutation)
                    if message == "manifest":
                        actual_mutation["content"] = b"x" * len(manifest_bytes)
                    rewrite(bundle, **actual_mutation)
                    suffix = "tar.gz" if kind == "tar" else "zip"
                    payload = (bundle / f"mergegrounds-1.0.0.{suffix}").read_bytes()
                    with self.assertRaisesRegex(validate_release.ReleaseError, message):
                        validator(payload, expected)

    def test_validator_rejects_duplicate_tar_member_names_even_if_expected(self) -> None:
        expected = [("root/file.txt", b"x", 0o644)] * 2
        raw = io.BytesIO()
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive:
                for name, content, mode in expected:
                    info = tarfile.TarInfo(name)
                    info.mode = mode
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))

        with self.assertRaisesRegex(validate_release.ReleaseError, "duplicate"):
            validate_release._validate_tar(raw.getvalue(), expected)

    def test_validator_rejects_duplicate_zip_member_names_even_if_expected(self) -> None:
        expected = [("root/file.txt", b"x", 0o644)] * 2
        raw = io.BytesIO()
        with zipfile.ZipFile(
            raw, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for name, content, mode in expected:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(info, content)

        with self.assertRaisesRegex(validate_release.ReleaseError, "duplicate"):
            validate_release._validate_zip(raw.getvalue(), expected)

    def test_validator_compares_raw_expected_bytes_before_candidate_parsing(self) -> None:
        with built_release() as (source, bundle, commit, tree):
            archive = bundle / "mergegrounds-1.0.0.tar.gz"
            archive.write_bytes(archive.read_bytes() + b"attacker trailer")
            rewrite_checksums(bundle)
            with mock.patch.object(
                validate_release,
                "_validate_manifest",
                side_effect=AssertionError("candidate parser ran before raw equality"),
            ) as parser:
                with self.assertRaisesRegex(validate_release.ReleaseError, "raw.*bytes"):
                    validate_release.validate_bundle(
                        bundle,
                        expected_commit=commit,
                        expected_tree=tree,
                        expected_ref="refs/tags/v1.0.0",
                        source_root=source,
                    )
            parser.assert_not_called()

    def test_validator_independently_encodes_the_expected_bundle(self) -> None:
        with built_release() as (source, bundle, commit, tree):
            with (
                mock.patch.object(
                    validate_release.build_release,
                    "release_manifest",
                    side_effect=AssertionError("reused candidate manifest encoder"),
                ),
                mock.patch.object(
                    validate_release.build_release,
                    "tar_bytes",
                    side_effect=AssertionError("reused candidate tar encoder"),
                ),
                mock.patch.object(
                    validate_release.build_release,
                    "zip_bytes",
                    side_effect=AssertionError("reused candidate zip encoder"),
                ),
            ):
                result = validate_release.validate_bundle(
                    bundle,
                    expected_commit=commit,
                    expected_tree=tree,
                    expected_ref="refs/tags/v1.0.0",
                    source_root=source,
                )

        self.assertEqual("pass", result["status"])

    def test_tar_validator_enforces_member_and_expanded_byte_bounds(self) -> None:
        expected = [
            ("root/one.txt", b"x", 0o644),
            ("root/two.txt", b"y", 0o644),
        ]
        raw = io.BytesIO()
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive:
                for name, content, mode in expected:
                    info = tarfile.TarInfo(name)
                    info.mode = mode
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))

        with (
            mock.patch.object(validate_release, "MAX_ARCHIVE_MEMBERS", 1, create=True),
            self.assertRaisesRegex(validate_release.ReleaseError, "member.*bound"),
        ):
            validate_release._validate_tar(raw.getvalue(), expected)
        with (
            mock.patch.object(
                validate_release, "MAX_ARCHIVE_EXPANDED_BYTES", 1, create=True
            ),
            self.assertRaisesRegex(validate_release.ReleaseError, "expanded.*bound"),
        ):
            validate_release._validate_tar(raw.getvalue(), expected)

    def test_tar_compressed_bytes_are_bounded_before_tarfile_parses(self) -> None:
        with (
            mock.patch.object(
                validate_release.build_release, "MAX_RELEASE_FILE_BYTES", 1
            ),
            mock.patch.object(
                validate_release.tarfile,
                "open",
                side_effect=AssertionError("tarfile parsed over-limit bytes"),
            ) as parser,
            self.assertRaisesRegex(validate_release.ReleaseError, "compressed.*bound"),
        ):
            validate_release._validate_tar(b"xx", [])
        parser.assert_not_called()

    def test_zip_validator_enforces_member_and_expanded_byte_bounds(self) -> None:
        expected = [
            ("root/one.txt", b"x", 0o644),
            ("root/two.txt", b"y", 0o644),
        ]
        raw = io.BytesIO()
        with zipfile.ZipFile(
            raw, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for name, content, mode in expected:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(info, content)

        with (
            mock.patch.object(validate_release, "MAX_ARCHIVE_MEMBERS", 1, create=True),
            self.assertRaisesRegex(validate_release.ReleaseError, "member.*bound"),
        ):
            validate_release._validate_zip(raw.getvalue(), expected)
        with (
            mock.patch.object(
                validate_release, "MAX_ARCHIVE_EXPANDED_BYTES", 1, create=True
            ),
            self.assertRaisesRegex(validate_release.ReleaseError, "expanded.*bound"),
        ):
            validate_release._validate_zip(raw.getvalue(), expected)

    def test_zip_member_count_is_bounded_before_zipfile_parses_entries(self) -> None:
        raw = io.BytesIO()
        with zipfile.ZipFile(
            raw, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            archive.writestr("one.txt", b"x")
            archive.writestr("two.txt", b"y")
        with (
            mock.patch.object(validate_release, "MAX_ARCHIVE_MEMBERS", 1),
            mock.patch.object(
                validate_release.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZipFile parsed an over-limit directory"),
            ) as parser,
            self.assertRaisesRegex(validate_release.ReleaseError, "member.*bound"),
        ):
            validate_release._validate_zip(raw.getvalue(), [])
        parser.assert_not_called()

    def test_zip_preflight_rejects_noncanonical_directory_fields(self) -> None:
        raw = io.BytesIO()
        with zipfile.ZipFile(
            raw, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            archive.writestr("one.txt", b"x")
        payload = raw.getvalue()
        fields = list(validate_release.ZIP_EOCD.unpack(payload[-22:]))
        mutations = (
            (0, b"BAD!"),
            (1, 1),
            (2, 1),
            (3, 2),
            (4, 0xFFFF),
            (5, 0xFFFFFFFF),
            (6, 0xFFFFFFFF),
            (7, 1),
        )
        for index, value in mutations:
            with self.subTest(field=index):
                altered = fields.copy()
                altered[index] = value
                candidate = payload[:-22] + struct.pack("<4s4H2LH", *altered)
                with self.assertRaisesRegex(
                    validate_release.ReleaseError, "directory metadata"
                ):
                    validate_release._validate_zip(candidate, [("one.txt", b"x", 0o600)])


if __name__ == "__main__":
    unittest.main()
