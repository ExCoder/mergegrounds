from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_release",
    ROOT / "scripts/build_release.py",
)
assert SPEC and SPEC.loader
build_release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = build_release
SPEC.loader.exec_module(build_release)


class PublicReleaseTests(unittest.TestCase):
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
                    hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
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
        ):
            self.assertIn(expected, runbook)


if __name__ == "__main__":
    unittest.main()
