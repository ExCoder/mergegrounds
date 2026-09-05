from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "mergegrounds_policy_hardening_under_test", ROOT / "scripts" / "mergegrounds.py"
)
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)


def secure_config() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "risk_tier": "R3",
        "fail_closed": True,
        "execution": {
            "sanitize_environment": True,
            "require_git": True,
            "require_clean_tree": True,
        },
        "evidence": {"directory": ".mergegrounds/evidence"},
        "thresholds": dict(mergegrounds.MINIMUM_THRESHOLDS),
        "mutation_policy": dict(mergegrounds.REQUIRED_MUTATION_CONTROLS),
        "profiles": {
            "fast": {
                "stages": sorted(mergegrounds.MINIMUM_PROFILE_STAGES["fast"]),
                "required_stages": sorted(mergegrounds.MINIMUM_PROFILE_STAGES["fast"]),
            },
            "pr": {
                "stages": sorted(mergegrounds.MINIMUM_PROFILE_STAGES["pr"]),
                "required_stages": sorted(mergegrounds.MINIMUM_PROFILE_STAGES["pr"]),
            },
            "full": {
                "stages": sorted(mergegrounds.MINIMUM_PROFILE_STAGES["full"]),
                "required_stages": sorted(mergegrounds.MINIMUM_PROFILE_STAGES["full"]),
            },
        },
        "attestation": {"required_markers": sorted(mergegrounds.MINIMUM_ATTESTATION_MARKERS)},
        "policy": {
            "required_files": sorted(mergegrounds.MINIMUM_POLICY_MEMBERS["required_files"]),
            "required_codeowners_patterns": sorted(
                mergegrounds.MINIMUM_POLICY_MEMBERS["required_codeowners_patterns"]
            ),
            "critical_paths": sorted(mergegrounds.MINIMUM_POLICY_MEMBERS["critical_paths"]),
            "control_lock": ".mergegrounds/control-plane.lock.json",
        },
    }


class GitFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "config", "user.email", "mergegrounds-tests@example.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "MergeGrounds Tests"],
            cwd=self.root,
            check=True,
        )

    def commit(self, path: str, content: str = "baseline\n") -> Path:
        candidate = self.root / path
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", "--", path], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=self.root, check=True)
        return candidate

    def close(self) -> None:
        self.temp.cleanup()


class PolicyHardeningTests(unittest.TestCase):
    def test_evidence_directory_is_canonical(self) -> None:
        config = secure_config()
        mergegrounds.validate_config(config)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.assertEqual(root / ".mergegrounds/evidence", mergegrounds.evidence_directory(root, config))
            for unsafe in (".", ".mergegrounds", "reports", "./.mergegrounds/evidence"):
                changed = copy.deepcopy(config)
                changed["evidence"]["directory"] = unsafe
                with self.subTest(unsafe=unsafe), self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.validate_config(changed)
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.evidence_directory(root, changed)

    def test_source_state_never_excludes_configured_root(self) -> None:
        fixture = GitFixture()
        try:
            tracked = fixture.commit("tracked.txt")
            tracked.write_text("changed\n", encoding="utf-8")
            state = mergegrounds.git_source_state(fixture.root, fixture.root)
            self.assertIn("tracked.txt", state["status"])
        finally:
            fixture.close()

    def test_purge_refuses_git_metadata(self) -> None:
        fixture = GitFixture()
        try:
            fixture.commit("source.py")
            index = fixture.root / ".git/index"
            original = index.read_bytes()
            for pattern in (".git/index", ".GIT/index"):
                with self.subTest(pattern=pattern), self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.purge_output_files(fixture.root, [pattern], "fixture")
            self.assertEqual(original, index.read_bytes())
        finally:
            fixture.close()

    def test_purge_preflights_all_matches_before_deleting_any(self) -> None:
        fixture = GitFixture()
        try:
            protected = fixture.commit("z-source.tmp")
            generated = fixture.root / "a-output.tmp"
            generated.write_text("generated\n", encoding="utf-8")
            with self.assertRaises(mergegrounds.MergeGroundsError):
                mergegrounds.purge_output_files(fixture.root, ["*.tmp"], "fixture")
            self.assertTrue(generated.is_file())
            self.assertTrue(protected.is_file())
        finally:
            fixture.close()

    def test_purge_recognizes_tracked_whitespace_filename(self) -> None:
        fixture = GitFixture()
        try:
            protected = fixture.commit(" ")
            with self.assertRaises(mergegrounds.MergeGroundsError):
                mergegrounds.purge_output_files(fixture.root, [" "], "fixture")
            self.assertTrue(protected.is_file())
        finally:
            fixture.close()

    def test_purge_refuses_untracked_control_plane(self) -> None:
        fixture = GitFixture()
        try:
            fixture.commit("source.py")
            control = fixture.root / ".mergegrounds/mergegrounds.toml"
            control.parent.mkdir(parents=True)
            control.write_text("schema_version = 1\n", encoding="utf-8")
            with self.assertRaises(mergegrounds.MergeGroundsError):
                mergegrounds.purge_output_files(
                    fixture.root, [".mergegrounds/mergegrounds.toml"], "fixture"
                )
            self.assertTrue(control.is_file())
        finally:
            fixture.close()

    def test_purge_denies_when_git_state_cannot_be_checked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "output.tmp"
            output.write_text("generated\n", encoding="utf-8")
            with self.assertRaises(mergegrounds.MergeGroundsError):
                mergegrounds.purge_output_files(root, ["output.tmp"], "fixture")
            self.assertTrue(output.is_file())

    def test_purge_removes_only_preflighted_untracked_output(self) -> None:
        fixture = GitFixture()
        try:
            fixture.commit("source.py")
            output = fixture.root / "output.tmp"
            output.write_text("generated\n", encoding="utf-8")
            self.assertEqual(
                {"output.tmp"},
                mergegrounds.purge_output_files(fixture.root, ["output.tmp"], "fixture"),
            )
            self.assertFalse(output.exists())
        finally:
            fixture.close()

    def test_purge_allows_untracked_report_beside_tracked_control_files(self) -> None:
        fixture = GitFixture()
        try:
            fixture.commit(".mergegrounds/mergegrounds.toml")
            output = fixture.root / ".mergegrounds/reports/metrics.json"
            output.parent.mkdir(parents=True)
            output.write_text("{}\n", encoding="utf-8")
            self.assertEqual(
                {".mergegrounds/reports/metrics.json"},
                mergegrounds.purge_output_files(
                    fixture.root,
                    [".mergegrounds/reports/metrics.json"],
                    "metric report",
                ),
            )
            self.assertFalse(output.exists())
            self.assertTrue((fixture.root / ".mergegrounds/mergegrounds.toml").is_file())
        finally:
            fixture.close()

    def test_secure_minimum_policy_cannot_be_emptied(self) -> None:
        mergegrounds.validate_config(secure_config())
        cases: list[tuple[str, dict[str, Any]]] = []

        no_profiles = secure_config()
        no_profiles["profiles"] = {}
        cases.append(("profiles", no_profiles))

        no_attestation = secure_config()
        no_attestation["attestation"] = {"required_markers": []}
        cases.append(("attestation", no_attestation))

        for key in mergegrounds.MINIMUM_POLICY_MEMBERS:
            no_policy = secure_config()
            no_policy["policy"][key] = []
            cases.append((key, no_policy))

        weak_pr = secure_config()
        weak_pr["profiles"]["pr"] = {
            "stages": ["unit"],
            "required_stages": ["unit"],
        }
        cases.append(("pr minimum stages", weak_pr))

        for name, config in cases:
            with self.subTest(name=name), self.assertRaises(mergegrounds.MergeGroundsError):
                mergegrounds.validate_config(config)

    def test_security_floors_and_secret_scrubbing_cannot_be_weakened(self) -> None:
        cases: list[tuple[str, dict[str, Any]]] = []
        for key in mergegrounds.REQUIRED_EXECUTION_CONTROLS:
            changed = secure_config()
            changed["execution"][key] = False
            cases.append((f"execution.{key}", changed))
        for key, expected in mergegrounds.REQUIRED_MUTATION_CONTROLS.items():
            changed = secure_config()
            changed["mutation_policy"][key] = not expected
            cases.append((f"mutation_policy.{key}", changed))
        for key, floor in mergegrounds.MINIMUM_THRESHOLDS.items():
            changed = secure_config()
            changed["thresholds"][key] = floor - 0.1
            cases.append((f"thresholds.{key}", changed))
        changed = secure_config()
        changed["execution"]["allowed_environment"] = ["GITHUB_TOKEN"]
        cases.append(("sensitive allowlist", changed))

        for name, config in cases:
            with self.subTest(name=name), self.assertRaises(mergegrounds.MergeGroundsError):
                mergegrounds.validate_config(config)

    def test_verify_repository_reports_invalid_empty_policy(self) -> None:
        config = secure_config()
        config["profiles"] = {}
        config["attestation"] = {}
        config["policy"] = {
            "required_files": [],
            "required_codeowners_patterns": [],
            "critical_paths": [],
            "control_lock": ".mergegrounds/control-plane.lock.json",
        }
        with tempfile.TemporaryDirectory() as raw:
            findings = mergegrounds.verify_repository(Path(raw), config)
        self.assertEqual(["CONFIG_INVALID"], [finding.code for finding in findings])


if __name__ == "__main__":
    unittest.main()
