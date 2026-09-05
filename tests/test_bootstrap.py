from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import sys
import unittest
import unittest.mock as mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bootstrap", ROOT / "scripts" / "bootstrap.py")
assert SPEC and SPEC.loader
bootstrap = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bootstrap
SPEC.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def make_source(self, root: Path) -> None:
        for item in bootstrap.CONTROL_ITEMS:
            path = root / item
            if item not in {".mergegrounds", ".github", "docs/decisions", "scripts"}:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"source:{item}\n", encoding="utf-8")
            else:
                path.mkdir(parents=True, exist_ok=True)
                (path / "fixture.txt").write_text(f"source:{item}\n", encoding="utf-8")
        (root / ".mergegrounds/LICENSE.mergegrounds").write_text(
            "source:.mergegrounds/LICENSE.mergegrounds\n",
            encoding="utf-8",
        )
        template = root / "templates/bootstrap/CODEOWNERS"
        template.parent.mkdir(parents=True)
        template.write_text("* @org/security-team\n", encoding="utf-8")

    def test_dry_plan_detects_conflict_and_create(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as target_raw:
            source = Path(source_raw)
            target = Path(target_raw)
            self.make_source(source)
            (target / "SECURITY.md").write_text("existing\n", encoding="utf-8")
            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                changes = bootstrap.plan(target)
            statuses = {change.destination.relative_to(target).as_posix(): change.status for change in changes}
            self.assertEqual("conflict", statuses["SECURITY.md"])
            self.assertIn("create", statuses.values())

    def test_force_creates_backup_before_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as target_raw:
            source = Path(source_raw)
            target = Path(target_raw)
            self.make_source(source)
            existing = target / "SECURITY.md"
            existing.write_text("existing\n", encoding="utf-8")
            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                changes = bootstrap.plan(target)
                bootstrap.apply(changes, target, force=True)
            self.assertEqual("source:SECURITY.md\n", existing.read_text(encoding="utf-8"))
            backups = list((target / ".mergegrounds/backups").glob("*/SECURITY.md"))
            self.assertEqual(1, len(backups))
            self.assertEqual("existing\n", backups[0].read_text(encoding="utf-8"))

    def test_same_clock_backups_are_distinct_and_never_merged(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as target_raw:
            source = Path(source_raw)
            target = Path(target_raw)
            self.make_source(source)
            existing = target / "SECURITY.md"
            existing.write_text("first snapshot\n", encoding="utf-8")
            fixed_time = bootstrap.dt.datetime(2026, 9, 5, 12, 34, 56, tzinfo=bootstrap.dt.timezone.utc)
            first_suffix = "0" * 31 + "1"
            second_suffix = "0" * 31 + "2"

            with (
                mock.patch.object(bootstrap, "SOURCE_ROOT", source),
                mock.patch.object(bootstrap.dt, "datetime") as datetime_mock,
                mock.patch.object(
                    bootstrap.secrets,
                    "token_hex",
                    side_effect=[first_suffix, first_suffix, second_suffix],
                ),
            ):
                datetime_mock.now.return_value = fixed_time
                bootstrap.apply(bootstrap.plan(target), target, force=True)
                existing.write_text("second snapshot\n", encoding="utf-8")
                bootstrap.apply(bootstrap.plan(target), target, force=True)

            backup_roots = sorted((target / ".mergegrounds/backups").iterdir())
            self.assertEqual(2, len(backup_roots))
            self.assertNotEqual(backup_roots[0], backup_roots[1])
            snapshots = {
                (backup_root / "SECURITY.md").read_text(encoding="utf-8")
                for backup_root in backup_roots
            }
            self.assertEqual({"first snapshot\n", "second snapshot\n"}, snapshots)

    def test_plan_rejects_symlinked_destination_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as target_raw, tempfile.TemporaryDirectory() as outside_raw:
            source = Path(source_raw)
            target = Path(target_raw)
            outside = Path(outside_raw)
            self.make_source(source)
            (target / ".mergegrounds").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                changes = bootstrap.plan(target)
            mergegrounds_changes = [change for change in changes if ".mergegrounds" in change.destination.parts]
            self.assertTrue(mergegrounds_changes)
            self.assertTrue(all(change.status == "unsafe-symlink" for change in mergegrounds_changes))
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.apply(changes, target, force=True)

    def test_source_rejects_symlinked_directory(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as outside_raw:
            source = Path(source_raw)
            outside = Path(outside_raw)
            self.make_source(source)
            (source / ".mergegrounds/linked").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.source_files()

    def test_source_excludes_generated_evidence_but_keeps_marker(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw:
            source = Path(source_raw)
            self.make_source(source)
            evidence = source / ".mergegrounds" / "evidence"
            evidence.mkdir()
            marker = evidence / ".gitkeep"
            marker.write_text("", encoding="utf-8")
            (evidence / "stale.json").write_text('{"decision":"allow"}\n', encoding="utf-8")
            reports = source / ".mergegrounds" / "reports"
            reports.mkdir()
            (reports / "metrics.json").write_text("{}\n", encoding="utf-8")
            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                paths = {path.relative_to(source).as_posix() for path in bootstrap.source_files()}
            self.assertIn(".mergegrounds/evidence/.gitkeep", paths)
            self.assertNotIn(".mergegrounds/evidence/stale.json", paths)
            self.assertNotIn(".mergegrounds/reports/metrics.json", paths)

    def test_plan_retains_mergegrounds_license_without_replacing_project_license(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as target_raw:
            source = Path(source_raw)
            target = Path(target_raw)
            self.make_source(source)
            target_license = target / "LICENSE"
            target_license.write_text("Target project license\n", encoding="utf-8")

            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                changes = bootstrap.plan(target)
            mapped = {
                change.destination.relative_to(target).as_posix(): change
                for change in changes
            }

            self.assertNotIn("LICENSE", mapped)
            license_change = mapped[".mergegrounds/LICENSE.mergegrounds"]
            self.assertEqual("create", license_change.status)
            self.assertEqual(source / ".mergegrounds/LICENSE.mergegrounds", license_change.source)
            self.assertIn(".mergegrounds/fixture.txt", mapped)
            bootstrap.apply(changes, target, force=False)
            self.assertEqual(
                "source:.mergegrounds/LICENSE.mergegrounds\n",
                (target / ".mergegrounds/LICENSE.mergegrounds").read_text(encoding="utf-8"),
            )
            self.assertEqual("Target project license\n", target_license.read_text(encoding="utf-8"))

    def test_distribution_includes_assurance_boundary_readme(self) -> None:
        paths = {
            path.relative_to(bootstrap.SOURCE_ROOT).as_posix()
            for path in bootstrap.source_files()
        }
        self.assertIn(".mergegrounds/README.mergegrounds.md", paths)

    def test_source_bindings_do_not_leak_into_bootstrap_target(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as target_raw:
            source = Path(source_raw)
            target = Path(target_raw)
            self.make_source(source)
            source_codeowners = source / ".github/CODEOWNERS"
            source_codeowners.write_text("* @real-upstream-owner\n", encoding="utf-8")
            marker = source / ".mergegrounds/custom.enabled"
            marker.write_text("source-only\n", encoding="utf-8")

            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                mappings = {
                    destination.as_posix(): path
                    for path, destination in bootstrap.source_mappings()
                }
                changes = bootstrap.plan(target)
                bootstrap.apply(changes, target, force=False)

            self.assertEqual(
                source / "templates/bootstrap/CODEOWNERS",
                mappings[".github/CODEOWNERS"],
            )
            self.assertNotIn(".mergegrounds/custom.enabled", mappings)
            self.assertEqual(
                "* @org/security-team\n",
                (target / ".github/CODEOWNERS").read_text(encoding="utf-8"),
            )
            self.assertFalse((target / ".mergegrounds/custom.enabled").exists())

    def test_namespaced_distribution_license_matches_starter_license(self) -> None:
        self.assertEqual(
            (bootstrap.SOURCE_ROOT / "LICENSE").read_bytes(),
            (bootstrap.SOURCE_ROOT / ".mergegrounds/LICENSE.mergegrounds").read_bytes(),
        )

    def test_target_must_be_exact_git_toplevel(self) -> None:
        with tempfile.TemporaryDirectory() as target_raw:
            target = Path(target_raw)
            subprocess.run(["git", "init", "-q", str(target)], check=True)
            nested = target / "nested"
            nested.mkdir()
            self.assertTrue(bootstrap.is_git_repository(target))
            self.assertFalse(bootstrap.is_git_repository(nested))
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_target(str(nested), allow_non_git=False)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_target(str(nested), allow_non_git=True)

    def test_target_validation_ignores_inherited_git_redirection(self) -> None:
        with tempfile.TemporaryDirectory() as decoy_raw, tempfile.TemporaryDirectory() as target_raw:
            decoy = Path(decoy_raw)
            target = Path(target_raw)
            subprocess.run(["git", "init", "-q", str(decoy)], check=True)
            (target / "existing.txt").write_text("not a repository\n", encoding="utf-8")
            poisoned = {
                "GIT_DIR": str(decoy / ".git"),
                "GIT_WORK_TREE": str(target),
                "GIT_INDEX_FILE": str(decoy / ".git" / "attacker-index"),
                "GIT_OBJECT_DIRECTORY": str(decoy / ".git" / "objects"),
                "GIT_REPLACE_REF_BASE": "refs/attacker-replacements/",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.worktree",
                "GIT_CONFIG_VALUE_0": str(target),
            }
            with mock.patch.dict(os.environ, poisoned, clear=False):
                self.assertIsNone(bootstrap.git_toplevel(target))
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_target(str(target), allow_non_git=False)
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_target(str(target), allow_non_git=True)

    def test_target_validation_is_fail_closed_for_invalid_locations(self) -> None:
        with tempfile.TemporaryDirectory() as target_raw:
            target = Path(target_raw)
            missing = target / "missing"
            with self.assertRaisesRegex(bootstrap.BootstrapError, "not a directory"):
                bootstrap.validate_target(str(missing), allow_non_git=True)
            (target / "occupied.txt").write_text("occupied\n", encoding="utf-8")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "new empty project"):
                bootstrap.validate_target(str(target), allow_non_git=True)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "not a Git worktree"):
                bootstrap.validate_target(str(target), allow_non_git=False)

        for unsafe in (Path(Path.cwd().anchor), Path.home()):
            with self.subTest(unsafe=unsafe):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "filesystem root or home"):
                    bootstrap.validate_target(str(unsafe), allow_non_git=True)

    def test_target_validation_rejects_starter_and_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw:
            source = Path(source_raw)
            descendant = source / "child"
            descendant.mkdir()
            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                for target in (source, descendant):
                    with self.subTest(target=target):
                        with self.assertRaisesRegex(bootstrap.BootstrapError, "starter source"):
                            bootstrap.validate_target(str(target), allow_non_git=True)

    def test_git_toplevel_rejects_process_and_malformed_output(self) -> None:
        with tempfile.TemporaryDirectory() as target_raw:
            target = Path(target_raw)
            with mock.patch.object(
                bootstrap.subprocess,
                "run",
                side_effect=OSError("git unavailable"),
            ):
                self.assertIsNone(bootstrap.git_toplevel(target))
            for result in (
                subprocess.CompletedProcess([], 1, stdout="", stderr=""),
                subprocess.CompletedProcess([], 0, stdout="", stderr=""),
                subprocess.CompletedProcess([], 0, stdout="first\nsecond\n", stderr=""),
            ):
                with self.subTest(result=result):
                    with mock.patch.object(bootstrap.subprocess, "run", return_value=result):
                        self.assertIsNone(bootstrap.git_toplevel(target))

    def test_destination_and_descriptor_guards_reject_escape(self) -> None:
        with tempfile.TemporaryDirectory() as target_raw, tempfile.TemporaryDirectory() as outside_raw:
            target = Path(target_raw)
            outside = Path(outside_raw)
            self.assertTrue(bootstrap.destination_is_unsafe(target, outside / "file"))
            with self.assertRaisesRegex(bootstrap.BootstrapError, "escaped repository root"):
                bootstrap.open_target_directory(target, outside, create=False)
            with self.assertRaises(FileNotFoundError):
                bootstrap.open_target_directory(target, target / "missing", create=False)

    def test_secure_copy_rejects_non_regular_source(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX descriptor invariant")
        with tempfile.TemporaryDirectory() as target_raw:
            target = Path(target_raw)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "not a regular file"):
                bootstrap.copy_into_target(target, target / "copied", target)

    def test_source_and_override_manifest_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw:
            source = Path(source_raw)
            self.make_source(source)
            missing = source / "SECURITY.md"
            missing.unlink()
            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "starter is incomplete"):
                    bootstrap.source_files()

            missing.write_text("restored\n", encoding="utf-8")
            override = source / "templates/bootstrap/CODEOWNERS"
            override.unlink()
            with mock.patch.object(bootstrap, "SOURCE_ROOT", source):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "bootstrap override"):
                    bootstrap.source_mappings()

    def test_show_plan_and_apply_conflict_contract(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as target_raw:
            source = Path(source_raw)
            target = Path(target_raw)
            source_file = source / "control"
            source_file.write_text("new\n", encoding="utf-8")
            conflict = target / "control"
            conflict.write_text("old\n", encoding="utf-8")
            changes = [bootstrap.Change(source_file, conflict, "conflict")]
            with mock.patch("builtins.print") as output:
                bootstrap.show_plan(changes, target)
            self.assertGreaterEqual(output.call_count, 2)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "conflicts found"):
                bootstrap.apply(changes, target, force=False)
            self.assertIsNone(bootstrap.backup_conflicts([], target))

    def test_apply_revalidates_destination_before_copy(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as target_raw:
            source = Path(source_raw) / "control"
            source.write_text("new\n", encoding="utf-8")
            target = Path(target_raw)
            destination = target / "control"
            change = bootstrap.Change(source, destination, "create")
            with mock.patch.object(bootstrap, "destination_is_unsafe", return_value=True):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "became unsafe"):
                    bootstrap.apply([change], target, force=False)

    def test_main_covers_dry_run_apply_and_error_exit_contracts(self) -> None:
        target = Path("/safe-target")
        change = bootstrap.Change(Path("/source"), target / "file", "create")
        with (
            mock.patch.object(bootstrap, "validate_target", return_value=target),
            mock.patch.object(bootstrap, "plan", return_value=[change]),
            mock.patch.object(bootstrap, "show_plan") as show,
            mock.patch.object(bootstrap, "apply") as apply,
        ):
            self.assertEqual(0, bootstrap.main(["--target", str(target)]))
            show.assert_called_once()
            apply.assert_not_called()
            self.assertEqual(0, bootstrap.main(["--target", str(target), "--apply"]))
            apply.assert_called_once_with([change], target, False)
        self.assertEqual(2, bootstrap.main(["--force", "--target", str(target)]))


if __name__ == "__main__":
    unittest.main()
