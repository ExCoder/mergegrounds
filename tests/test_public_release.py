from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import unicodedata
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_release",
    ROOT / "scripts/build_release.py",
)
assert SPEC and SPEC.loader
build_release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = build_release
SPEC.loader.exec_module(build_release)


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


def run_git_bytes(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout


@contextmanager
def release_repository(
    *,
    version_bytes: bytes = b"1.0.0\n",
    plugin_version: str = "1.0.0",
):
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw) / "source"
        root.mkdir()
        (root / ".codex-plugin").mkdir()
        (root / "VERSION").write_bytes(version_bytes)
        (root / ".codex-plugin/plugin.json").write_text(
            json.dumps({"version": plugin_version}) + "\n",
            encoding="utf-8",
        )
        (root / "payload.txt").write_bytes(b"committed payload\n")
        run_git(root, "init", "--quiet")
        run_git(root, "config", "user.name", "ExCoder")
        run_git(
            root, "config", "user.email", "3510267+ExCoder@users.noreply.github.com"
        )
        run_git(root, "add", "--all")
        run_git(root, "commit", "--quiet", "-m", "fixture")
        with mock.patch.object(build_release, "ROOT", root):
            yield root


class PublicReleaseTests(unittest.TestCase):
    def test_release_primitives_fail_closed_on_malformed_git_and_metadata(self) -> None:
        failures = (
            (
                "git failure",
                subprocess.CompletedProcess([], 1, stdout="", stderr="denied"),
                False,
                "git .* failed",
            ),
            (
                "binary returned text",
                subprocess.CompletedProcess([], 0, stdout="text", stderr=""),
                True,
                "text for a binary",
            ),
            (
                "text returned bytes",
                subprocess.CompletedProcess([], 0, stdout=b"bytes", stderr=b""),
                False,
                "bytes for a text",
            ),
        )
        for label, completed, binary, message in failures:
            with (
                self.subTest(label=label),
                mock.patch.object(build_release.subprocess, "run", return_value=completed),
                self.assertRaisesRegex(build_release.ReleaseError, message),
            ):
                build_release.git("status", binary=binary)

        with self.assertRaisesRegex(build_release.ReleaseError, "invalid test object"):
            build_release._object_id("not-an-object", "test")
        with self.assertRaisesRegex(build_release.ReleaseError, "required release input"):
            build_release.GitSnapshot("0" * 40, "1" * 40, ()).file("missing")

        for payload, message in (
            (b"\xff", "valid UTF-8"),
            (b"/absolute", "unsafe"),
            (b"a" * (build_release.MAX_RELEASE_PATH_BYTES + 1), "byte boundary"),
            (b"bad:name", "Windows-invalid"),
        ):
            with self.subTest(path=payload[:16]):
                with self.assertRaisesRegex(build_release.ReleaseError, message):
                    build_release._safe_snapshot_path(payload)

        for payload, message in (
            (b'{"x":1,"x":2}', "duplicate JSON key"),
            (b'{"x":NaN}', "non-finite"),
            (b"\xff", "strict UTF-8 JSON"),
        ):
            with self.subTest(json=payload):
                with self.assertRaisesRegex(build_release.ReleaseError, message):
                    build_release._strict_json(payload, "fixture")

    def test_release_snapshot_enforces_inventory_and_source_byte_bounds(self) -> None:
        with release_repository() as source:
            for field, value, message in (
                ("MAX_TREE_LISTING_BYTES", 1, "tree listing"),
                ("MAX_RELEASE_FILES", 1, "file-count"),
                ("MAX_RELEASE_FILE_BYTES", 1, "release input"),
                ("MAX_RELEASE_FILE_BYTES", 32, "aggregate"),
            ):
                with (
                    self.subTest(field=field, value=value),
                    mock.patch.object(build_release, field, value),
                    self.assertRaisesRegex(build_release.ReleaseError, message),
                ):
                    build_release.git_snapshot(root=source)

        commit = "0" * 40
        tree = "1" * 40
        payload = b"x"
        object_id = hashlib.sha1(b"blob 1\0x").hexdigest()
        for listing, responses, message in (
            (b"invalid\0", ["sha1\n", commit, tree], "tree entry"),
            (
                f"120000 blob {object_id}\tlink\0".encode("ascii"),
                ["sha1\n", commit, tree],
                "regular file",
            ),
            (b"", ["sha1\n", commit, tree], "no tracked files"),
        ):
            with (
                self.subTest(message=message),
                mock.patch.object(
                    build_release,
                    "git",
                    side_effect=[*responses, listing, payload],
                ),
                self.assertRaisesRegex(build_release.ReleaseError, message),
            ):
                build_release.git_snapshot(root=ROOT)

    def test_release_project_version_rejects_nonascii_and_plugin_disagreement(self) -> None:
        def snapshot(version: bytes, plugin: bytes) -> object:
            return build_release.GitSnapshot(
                "0" * 40,
                "1" * 40,
                (
                    build_release.SnapshotFile(
                        ".codex-plugin/plugin.json", "2" * 40, 0o100644, plugin
                    ),
                    build_release.SnapshotFile(
                        "VERSION", "3" * 40, 0o100644, version
                    ),
                ),
            )

        for value, message in (
            (snapshot(b"\xff", b'{"version":"1.0.0"}'), "strict ASCII"),
            (snapshot(b"1.0.0\n", b'{"version":1}'), "must be a string"),
            (snapshot(b"1.0.0\n", b'{"version":"1.0.1"}'), "disagree"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(build_release.ReleaseError, message):
                    build_release.project_version(value)

    def test_release_snapshot_recomputes_each_canonical_sha1_blob_id(self) -> None:
        with release_repository() as source:
            original_git = build_release.git

            def tampered_git(*arguments: str, **kwargs):
                if arguments[:2] == ("cat-file", "blob"):
                    return b"substituted bytes\n"
                return original_git(*arguments, **kwargs)

            with (
                mock.patch.object(build_release, "git", side_effect=tampered_git),
                self.assertRaisesRegex(build_release.ReleaseError, "blob.*object ID"),
            ):
                build_release.git_snapshot(root=source)

    def test_release_snapshot_rejects_non_sha1_git_object_format(self) -> None:
        with release_repository() as source:
            original_git = build_release.git

            def sha256_git(*arguments: str, **kwargs):
                if arguments == ("rev-parse", "--show-object-format"):
                    return "sha256\n"
                return original_git(*arguments, **kwargs)

            with (
                mock.patch.object(build_release, "git", side_effect=sha256_git),
                self.assertRaisesRegex(build_release.ReleaseError, "SHA-1.*format"),
            ):
                build_release.git_snapshot(root=source)

    def test_release_snapshot_rejects_tracked_reserved_manifest(self) -> None:
        with (
            release_repository() as source,
            tempfile.TemporaryDirectory() as output_raw,
        ):
            (source / "release-manifest.json").write_text("{}\n", encoding="utf-8")
            run_git(source, "add", "release-manifest.json")
            run_git(source, "commit", "--quiet", "-m", "reserved manifest")
            with self.assertRaisesRegex(build_release.ReleaseError, "reserved"):
                build_release.build(Path(output_raw))

    def test_release_paths_enforce_portable_normalization_and_names(self) -> None:
        decomposed = unicodedata.normalize("NFD", "café.txt")
        for path, message in (
            (decomposed, "NFC"),
            ("docs/CON.txt", "Windows reserved"),
            ("docs/trailing. ", "trailing"),
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(build_release.ReleaseError, message):
                    build_release._safe_snapshot_path(path.encode("utf-8"))

    def test_release_paths_reject_casefold_collisions(self) -> None:
        files = (
            build_release.SnapshotFile("README.md", "0" * 40, 0o100644, b"a"),
            build_release.SnapshotFile("readme.md", "1" * 40, 0o100644, b"b"),
        )
        with self.assertRaisesRegex(build_release.ReleaseError, "portable.*collision"):
            build_release._validate_snapshot_paths(files)

    def test_release_builder_reads_the_committed_snapshot_not_dirty_worktree(
        self,
    ) -> None:
        with (
            release_repository() as source,
            tempfile.TemporaryDirectory() as output_raw,
        ):
            (source / "payload.txt").write_bytes(b"uncommitted attacker payload\n")
            output = Path(output_raw)

            build_release.build(output)

            manifest = json.loads(
                (output / "release-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                hashlib.sha256(b"committed payload\n").hexdigest(),
                manifest["files"]["payload.txt"]["sha256"],
            )
            archive = output / "mergegrounds-1.0.0.zip"
            with zipfile.ZipFile(archive) as value:
                self.assertEqual(
                    b"committed payload\n",
                    value.read("mergegrounds-1.0.0/payload.txt"),
                )

    def test_release_version_uses_strict_three_component_grammar(self) -> None:
        for invalid in (b"01.0.0\n", b"1.00.0\n", b"1.0\n", b"1..0\n", b"1.0.0\n\n"):
            with (
                self.subTest(version=invalid),
                release_repository(
                    version_bytes=invalid,
                    plugin_version=invalid.decode("ascii").strip(),
                ) as _source,
                tempfile.TemporaryDirectory() as output_raw,
            ):
                with self.assertRaisesRegex(build_release.ReleaseError, "VERSION"):
                    build_release.build(Path(output_raw))

    def test_release_builder_uses_the_same_32_mib_boundary_as_validation(self) -> None:
        self.assertEqual(32 * 1024 * 1024, build_release.MAX_RELEASE_FILE_BYTES)

    def test_release_builder_rejects_a_nonempty_output_directory(self) -> None:
        with (
            release_repository() as _source,
            tempfile.TemporaryDirectory() as output_raw,
        ):
            output = Path(output_raw)
            sentinel = output / "do-not-overwrite.txt"
            sentinel.write_bytes(b"owner data\n")

            with self.assertRaisesRegex(build_release.ReleaseError, "empty"):
                build_release.build(output)

            self.assertEqual(b"owner data\n", sentinel.read_bytes())
            self.assertEqual([sentinel], list(output.iterdir()))

    def test_release_builder_rejects_a_symlinked_output_ancestor(self) -> None:
        with (
            release_repository() as source,
            tempfile.TemporaryDirectory() as outside_raw,
        ):
            outside = Path(outside_raw)
            link = source / "redirect"
            link.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(build_release.ReleaseError, "symbolic-link"):
                build_release.build(link / "release-dist")

            self.assertEqual([], list(outside.iterdir()))

    def test_release_cli_rejects_parent_traversal_output(self) -> None:
        with release_repository() as source:
            escaped = source.parent / "escaped-release"
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["build_release.py", "--output-dir", "../escaped-release"],
                ),
                self.assertRaisesRegex(SystemExit, "inside the repository"),
            ):
                build_release.main()

            self.assertFalse(escaped.exists())

    def test_release_atomic_publish_never_replaces_a_racing_file(self) -> None:
        with tempfile.TemporaryDirectory() as output_raw:
            output = Path(output_raw)
            existing = output / "asset.bin"
            existing.write_bytes(b"owner bytes\n")
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(output, flags)
            try:
                with self.assertRaisesRegex(build_release.ReleaseError, "already exists"):
                    build_release.atomic_write(directory_fd, "asset.bin", b"release bytes\n")
            finally:
                os.close(directory_fd)

            self.assertEqual(b"owner bytes\n", existing.read_bytes())

    def test_readme_leads_with_reproducible_first_value_and_honest_status(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("## 90-second proof", readme)
        first_value = readme.index("## 90-second proof")
        feature_inventory = readme.index("## What is included")

        self.assertLess(first_value, feature_inventory)
        first_screen = readme[:feature_inventory]
        for expected in (
            "git clone --branch v1.0.1 --depth 1",
            "https://github.com/ExCoder/mergegrounds-demo.git",
            "python3 demo.py",
            "DEMO PASSED: 1 admitted control; 5 negative controls denied",
            "Educational demo only — this is not a production assurance claim.",
            "educational model",
            "v1.0.0",
            "Maximum Assurance",
            "two independent human reviewer seats",
        ):
            self.assertIn(expected, first_screen)

        self.assertIn("reference adapter definitions", readme)
        self.assertIn("end-to-end", readme)
        self.assertNotIn("a reusable Codex skill for bootstrap, audit", readme)

    def test_release_build_is_reproducible_and_manifest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as first_raw, tempfile.TemporaryDirectory() as second_raw:
            first = Path(first_raw)
            second = Path(second_raw)
            first_paths = build_release.build(first)
            second_paths = build_release.build(second)
            self.assertEqual(
                [path.name for path in first_paths],
                [path.name for path in second_paths],
            )
            for first_path, second_path in zip(first_paths, second_paths, strict=True):
                self.assertEqual(first_path.read_bytes(), second_path.read_bytes(), first_path.name)

            manifest = json.loads((first / "release-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(1, manifest["schema_version"])
            self.assertEqual((ROOT / "VERSION").read_text().strip(), manifest["version"])
            self.assertIn("scripts/mergegrounds.py", manifest["files"])
            self.assertIn(".github/workflows/release.yml", manifest["files"])
            for name, record in manifest["files"].items():
                self.assertEqual(
                    hashlib.sha256(run_git_bytes(ROOT, "show", f"HEAD:{name}")).hexdigest(),
                    record["sha256"],
                )

            archive = first / f"mergegrounds-{manifest['version']}.zip"
            with zipfile.ZipFile(archive) as value:
                names = set(value.namelist())
            prefix = f"mergegrounds-{manifest['version']}"
            self.assertIn(f"{prefix}/release-manifest.json", names)
            self.assertIn(f"{prefix}/scripts/mergegrounds.py", names)

    def test_community_health_files_and_intake_forms_are_present(self) -> None:
        for relative in (
            "CODE_OF_CONDUCT.md",
            "CONTRIBUTING.md",
            "GOVERNANCE.md",
            "ROADMAP.md",
            "SECURITY.md",
            "SUPPORT.md",
            ".github/ISSUE_TEMPLATE/bug-report.yml",
            ".github/ISSUE_TEMPLATE/design-review.yml",
            ".github/ISSUE_TEMPLATE/feature-request.yml",
            ".github/ISSUE_TEMPLATE/integration-request.yml",
        ):
            with self.subTest(relative=relative):
                path = ROOT / relative
                self.assertTrue(path.is_file())
                self.assertGreater(path.stat().st_size, 32)

    def test_release_workflow_is_tag_bound_and_attests_without_publishing(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertIn('python-version: "3.13.15"', workflow)
        self.assertIn(
            "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0",
            workflow,
        )
        self.assertIn("verification.verified", workflow)
        self.assertIn("3510267+ExCoder@users.noreply.github.com", workflow)
        self.assertIn("needs: identity", workflow)
        self.assertIn("git cat-file -t \"refs/tags/$RELEASE_REF\"", workflow)
        self.assertIn('git merge-base --is-ancestor "$RELEASE_SHA"', workflow)
        self.assertIn("refs/remotes/origin/$DEFAULT_BRANCH", workflow)
        self.assertIn("git status --porcelain=v1 --untracked-files=all", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("artifact-metadata: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn(
            "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2",
            workflow,
        )
        self.assertIn("release-dist/mergegrounds-*.tar.gz", workflow)
        self.assertIn("release-dist/mergegrounds-*.zip", workflow)
        self.assertNotIn("gh release create", workflow)
        self.assertNotIn("contents: write", workflow)

    def test_release_workflow_validates_exact_source_bundle_before_retention_and_attestation(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        for expected in (
            "WORKFLOW_SHA: ${{ github.workflow_sha }}",
            "WORKFLOW_REF: ${{ github.workflow_ref }}",
            "RELEASE_FULL_REF: ${{ github.ref }}",
            '[[ "$WORKFLOW_SHA" == "$RELEASE_SHA" ]]',
            '[[ "$WORKFLOW_REF" == "${GITHUB_REPOSITORY}/.github/workflows/release.yml@${RELEASE_FULL_REF}" ]]',
            'default_head="$(git rev-parse "refs/remotes/origin/$DEFAULT_BRANCH^{commit}")"',
            '[[ "$default_head" == "$RELEASE_SHA" ]]',
            'release_tree="$(git rev-parse "$RELEASE_SHA^{tree}")"',
            'release_tree="$(git rev-parse "$GITHUB_SHA^{tree}")"',
            "python3 -I scripts/build_release.py --output-dir release-first",
            "python3 -I scripts/validate_release.py --bundle-dir release-dist",
            '--expected-commit "$GITHUB_SHA" --expected-tree "$RELEASE_TREE"',
            '--expected-ref "$GITHUB_REF"',
        ):
            self.assertIn(expected, workflow)
        self.assertGreaterEqual(
            workflow.count('release_tree="$(git rev-parse "$GITHUB_SHA^{tree}")"'),
            2,
        )
        self.assertGreaterEqual(workflow.count("scripts/validate_release.py"), 3)
        self.assertLess(
            workflow.rindex("scripts/validate_release.py"),
            workflow.index("actions/attest@"),
        )
        self.assertNotIn("python3 -I - <<'PY'", workflow)
        self.assertNotIn("needs.build.outputs", workflow)

    def test_release_workflow_pins_tools_and_keeps_candidate_code_out_of_oidc_job(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertRegex(
            workflow, r"REVIEWED_BUILD_RELEASE_SHA256: [0-9a-f]{64}"
        )
        self.assertRegex(
            workflow, r"REVIEWED_VALIDATE_RELEASE_SHA256: [0-9a-f]{64}"
        )
        build_digest = hashlib.sha256(
            (ROOT / "scripts/build_release.py").read_bytes()
        ).hexdigest()
        validator_digest = hashlib.sha256(
            (ROOT / "scripts/validate_release.py").read_bytes()
        ).hexdigest()
        self.assertEqual(
            [build_digest, build_digest],
            re.findall(r"REVIEWED_BUILD_RELEASE_SHA256: ([0-9a-f]{64})", workflow),
        )
        self.assertEqual(
            [validator_digest, validator_digest],
            re.findall(
                r"REVIEWED_VALIDATE_RELEASE_SHA256: ([0-9a-f]{64})", workflow
            ),
        )
        self.assertIn("sha256sum --check", workflow)
        first_execution = workflow.index("python3 -I scripts/build_release.py")
        self.assertLess(workflow.index("REVIEWED_BUILD_RELEASE_SHA256"), first_execution)
        first_compare = workflow.index("cmp release-first/SHA256SUMS")
        first_parser = workflow.index("python3 -I scripts/validate_release.py")
        self.assertLess(first_compare, first_parser)

        validate_job = workflow.index("\n  validate:\n")
        attest_job = workflow.index("\n  attest:\n")
        validate_text = workflow[validate_job:attest_job]
        attest_text = workflow[attest_job:]
        self.assertIn("scripts/validate_release.py", validate_text)
        self.assertIn("needs: validate", attest_text)
        self.assertNotIn("actions/checkout@", attest_text)
        self.assertNotIn("setup-python@", attest_text)
        self.assertNotIn("scripts/", attest_text)
        self.assertNotIn("python", attest_text.lower())
        self.assertIn(
            "find release-dist -mindepth 1 -maxdepth 1 -print0", attest_text
        )
        self.assertNotIn("-type f -print0", attest_text)

    def test_self_check_covers_release_builder_and_validator(self) -> None:
        self_check = (ROOT / "scripts/self_check.py").read_text(encoding="utf-8")
        self.assertIn('"scripts/build_release.py"', self_check)
        self.assertIn('"scripts/validate_release.py"', self_check)

    def test_release_runbook_pins_provenance_identity_and_documents_unsigned_tag(self) -> None:
        runbook = (ROOT / "docs/releasing.md").read_text(encoding="utf-8")
        for expected in (
            "--signer-workflow ExCoder/mergegrounds/.github/workflows/release.yml",
            '--source-ref "refs/tags/$tag"',
            '--source-digest "$release_sha"',
            "--deny-self-hosted-runners",
            'gh release create "$tag"',
            'gh release verify "$tag"',
            ".commit.verification.verified == true",
            "unsigned annotated Git tag",
            "does not publish a GitHub Release",
            "scripts/validate_release.py",
            "exact current default-branch HEAD",
            "32 MiB",
            '--expected-commit "$release_sha"',
            '--expected-tree "$release_tree"',
            '--expected-ref "refs/tags/$tag"',
        ):
            self.assertIn(expected, runbook)

        evidence = (ROOT / "docs/release-evidence-v1.0.0.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("exact current default-branch HEAD", evidence)
        self.assertIn("scripts/validate_release.py", evidence)
        self.assertNotIn("default-branch ancestry on the final tagged commit", evidence)


if __name__ == "__main__":
    unittest.main()
