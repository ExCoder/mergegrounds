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


if __name__ == "__main__":
    unittest.main()
