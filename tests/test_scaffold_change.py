from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock as mock
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scaffold_change.py"
sys.path.insert(0, str(ROOT / "scripts"))
import scaffold_change as scaffold  # noqa: E402

mergegrounds = scaffold.mergegrounds


def materialize_draft(value: Any) -> Any:
    """Replace scaffold sentinels with concrete test-fixture statements."""
    if isinstance(value, dict):
        return {key: materialize_draft(child) for key, child in value.items()}
    if isinstance(value, list):
        return [materialize_draft(child) for child in value]
    if isinstance(value, str) and value.startswith("EDIT ME:"):
        return "Reviewed concrete project statement with measurable boundaries and named ownership."
    return value


def materialize_file(path: Path) -> dict[str, Any]:
    value = materialize_draft(json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(value, dict)
    path.write_bytes(scaffold.render_json(value))
    return value


class RepositoryFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "docs/decisions").mkdir(parents=True)
        (self.root / ".mergegrounds/changes").mkdir(parents=True)
        shutil.copyfile(
            ROOT / ".mergegrounds/mergegrounds.toml",
            self.root / ".mergegrounds/mergegrounds.toml",
        )
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
        subprocess.run(
            ["git", "add", ".mergegrounds/mergegrounds.toml"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-qm", "baseline"],
            cwd=self.root,
            check=True,
        )

    def run(self, command: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                os.fspath(SCRIPT),
                command,
                "--repo",
                os.fspath(self.root),
                *arguments,
            ],
            cwd=self.root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )

    def create_design(self, design_id: str | None = None) -> tuple[str, Path]:
        arguments = ["--write"]
        if design_id is not None:
            arguments.extend(["--design-id", design_id])
        result = self.run("design", *arguments)
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        relative = result.stdout.strip().removeprefix("created ")
        return relative, self.root / relative

    def close(self) -> None:
        self.temp.cleanup()


class ScaffoldChangeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RepositoryFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_generated_design_uuid_matches_path_and_structural_schema(self) -> None:
        relative, path = self.fixture.create_design()
        match = re.fullmatch(r"docs/decisions/([0-9a-f-]{36})\.json", relative)
        self.assertIsNotNone(match)
        assert match is not None
        design_id = match.group(1)
        self.assertEqual(str(uuid.UUID(design_id)), design_id)
        raw = path.read_bytes()
        value = mergegrounds.strict_json_document(
            raw,
            "generated design",
            mergegrounds.MAX_DESIGN_CONTRACT_BYTES,
        )
        self.assertEqual(value["design_id"], design_id)
        self.assertEqual(
            {"positive", "negative", "adversarial", "recovery"},
            {item["class"] for item in value["evaluation"]["acceptance_criteria"]},
        )
        self.assertTrue(all("EDIT ME:" in text for text in value["goals"]))

    def test_dry_run_is_deterministic_and_does_not_write(self) -> None:
        design_id = str(uuid.uuid4())
        arguments = ("--design-id", design_id)
        first = self.fixture.run("design", *arguments)
        second = self.fixture.run("design", *arguments)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(json.loads(first.stdout)["design_id"], design_id)
        self.assertFalse((self.fixture.root / f"docs/decisions/{design_id}.json").exists())
        self.assertIn("dry run", first.stderr)
        self.assertIn("DRAFT ONLY", first.stderr)
        self.assertIn("denies admission", first.stderr)

    def test_explicit_output_infers_matching_design_id(self) -> None:
        design_id = str(uuid.uuid4())
        output = f"docs/decisions/{design_id}.json"
        result = self.fixture.run("design", "--output", output, "--write")
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads((self.fixture.root / output).read_text(encoding="utf-8"))
        self.assertEqual(value["design_id"], design_id)

    def test_implementation_binds_digest_and_copies_design_semantics(self) -> None:
        design_relative, design_path = self.fixture.create_design()
        design = materialize_file(design_path)
        mergegrounds.validate_design_contract(design, Path(design_relative).stem)
        result = self.fixture.run(
            "implementation",
            "--design",
            design_relative,
            "--write",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        change_relative = result.stdout.strip().removeprefix("created ")
        match = re.fullmatch(r"\.mergegrounds/changes/([0-9a-f-]{36})\.json", change_relative)
        self.assertIsNotNone(match)
        assert match is not None
        change_id = match.group(1)
        change = json.loads((self.fixture.root / change_relative).read_text(encoding="utf-8"))
        design_raw = design_path.read_bytes()
        self.assertEqual(
            change["design"]["record_sha256"],
            f"sha256:{hashlib.sha256(design_raw).hexdigest()}",
        )
        self.assertEqual(change["acceptance_criteria"], design["evaluation"]["acceptance_criteria"])
        self.assertEqual(change["failure_modes"], design["failure_modes"])
        self.assertEqual(
            change["challenge_plan"][0]["evaluation_ref"],
            next(
                item["oracle"]["ref"]
                for item in change["acceptance_criteria"]
                if item["class"] == "adversarial"
            ),
        )
        self.assertEqual(
            change["evidence_policy"],
            {
                "author_claims_are_evidence": False,
                "model_output_is_evidence": False,
                "self_review_is_evidence": False,
            },
        )
        self.assertEqual(
            change["ai_assistance"],
            {"used": False, "systems": [], "affected_paths": []},
        )
        admitted_change = materialize_draft(change)
        assert isinstance(admitted_change, dict)
        _, config = mergegrounds.config_for(self.fixture.root)
        mergegrounds.validate_change_contract(
            admitted_change,
            change_id,
            config,
            [change_relative],
        )

    def test_design_change_pair_passes_git_pr_validation_after_editing(self) -> None:
        design_relative, design_path = self.fixture.create_design()
        design = materialize_file(design_path)
        design_id = Path(design_relative).stem
        mergegrounds.validate_design_contract(design, design_id)

        declaration_result = self.fixture.run(
            "design-change",
            "--design",
            design_relative,
            "--write",
        )
        self.assertEqual(declaration_result.returncode, 0, declaration_result.stderr)
        declaration_relative = declaration_result.stdout.strip().removeprefix("created ")
        declaration_path = self.fixture.root / declaration_relative
        declaration = materialize_file(declaration_path)
        self.assertEqual(declaration["lane"], "design-only")
        self.assertEqual(declaration["design"]["record_id"], design_id)
        self.assertEqual(
            declaration["design"]["record_sha256"],
            f"sha256:{hashlib.sha256(design_path.read_bytes()).hexdigest()}",
        )

        base = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "add", "--", design_relative, declaration_relative],
            cwd=self.fixture.root,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-qm", "reviewed design"],
            cwd=self.fixture.root,
            check=True,
        )
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        _, config = mergegrounds.config_for(self.fixture.root)
        result = mergegrounds.validate_change_between(self.fixture.root, config, base, head)
        self.assertEqual(result["lane"], "design-only")
        self.assertEqual(result["design_id"], design_id)
        self.assertEqual(result["change_path"], declaration_relative)

    def test_design_change_rejects_unedited_design_draft(self) -> None:
        design_relative, _ = self.fixture.create_design()
        result = self.fixture.run(
            "design-change",
            "--design",
            design_relative,
            "--write",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unresolved draft placeholder", result.stderr)
        self.assertEqual(list((self.fixture.root / ".mergegrounds/changes").iterdir()), [])

    def test_existing_output_is_never_overwritten(self) -> None:
        design_id = str(uuid.uuid4())
        output = f"docs/decisions/{design_id}.json"
        first = self.fixture.run(
            "design",
            "--design-id",
            design_id,
            "--output",
            output,
            "--write",
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        path = self.fixture.root / output
        original = path.read_bytes()
        second = self.fixture.run(
            "design",
            "--design-id",
            design_id,
            "--output",
            output,
            "--write",
        )
        self.assertEqual(second.returncode, 2)
        self.assertIn("refusing to overwrite", second.stderr)
        self.assertEqual(path.read_bytes(), original)

    def test_traversal_absolute_and_mismatched_outputs_are_rejected(self) -> None:
        design_id = str(uuid.uuid4())
        unsafe = (
            f"docs/decisions/../{design_id}.json",
            f"/tmp/{design_id}.json",
            f"docs/decisions/{uuid.uuid4()}.json",
            f"docs//decisions/{design_id}.json",
        )
        for output in unsafe:
            with self.subTest(output=output):
                result = self.fixture.run(
                    "design",
                    "--design-id",
                    design_id,
                    "--output",
                    output,
                    "--write",
                )
                self.assertEqual(result.returncode, 2)
        self.assertEqual(list((self.fixture.root / "docs/decisions").iterdir()), [])

    def test_symlinked_output_directory_is_rejected_without_external_write(self) -> None:
        outside_temp = tempfile.TemporaryDirectory()
        try:
            outside = Path(outside_temp.name)
            decisions = self.fixture.root / "docs/decisions"
            decisions.rmdir()
            decisions.symlink_to(outside, target_is_directory=True)
            design_id = str(uuid.uuid4())
            result = self.fixture.run(
                "design",
                "--design-id",
                design_id,
                "--write",
            )
            self.assertEqual(result.returncode, 2)
            self.assertFalse((outside / f"{design_id}.json").exists())
        finally:
            outside_temp.cleanup()

    def test_symlinked_target_is_rejected_without_modifying_referent(self) -> None:
        outside_temp = tempfile.TemporaryDirectory()
        try:
            outside = Path(outside_temp.name) / "protected.json"
            outside.write_text("protected\n", encoding="utf-8")
            design_id = str(uuid.uuid4())
            target = self.fixture.root / f"docs/decisions/{design_id}.json"
            target.symlink_to(outside)
            result = self.fixture.run(
                "design",
                "--design-id",
                design_id,
                "--write",
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(outside.read_text(encoding="utf-8"), "protected\n")
            self.assertTrue(target.is_symlink())
        finally:
            outside_temp.cleanup()

    def test_symlinked_design_input_is_rejected(self) -> None:
        outside_temp = tempfile.TemporaryDirectory()
        try:
            design_id = str(uuid.uuid4())
            outside = Path(outside_temp.name) / "design.json"
            outside.write_bytes(scaffold.render_json(scaffold.design_document(design_id)))
            relative = f"docs/decisions/{design_id}.json"
            (self.fixture.root / relative).symlink_to(outside)
            result = self.fixture.run("implementation", "--design", relative)
            self.assertEqual(result.returncode, 2)
            self.assertIn("missing or unsafe", result.stderr)
            self.assertEqual(list((self.fixture.root / ".mergegrounds/changes").iterdir()), [])
        finally:
            outside_temp.cleanup()

    def test_non_repository_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(SCRIPT),
                    "design",
                    "--repo",
                    raw,
                    "--write",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot locate Git repository", result.stderr)

    def test_explicit_symlink_repository_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            link = Path(raw) / "repository-link"
            link.symlink_to(self.fixture.root, target_is_directory=True)
            result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(SCRIPT),
                    "design",
                    "--repo",
                    os.fspath(link),
                    "--write",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("must not be a symlink", result.stderr)

    def test_local_core_worktree_cannot_redirect_output_outside_selected_repository(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            repository = parent / "repository"
            outside = parent / "outside"
            repository.mkdir()
            (outside / "docs" / "decisions").mkdir(parents=True)
            (outside / ".mergegrounds" / "changes").mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "core.worktree", str(outside)],
                check=True,
            )
            design_id = "123e4567-e89b-42d3-a456-426614174000"
            result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(SCRIPT),
                    "design",
                    "--repo",
                    os.fspath(repository),
                    "--design-id",
                    design_id,
                    "--write",
                ],
                cwd=parent,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("outside the explicitly selected repository target", result.stderr)
            self.assertFalse((outside / "docs" / "decisions" / f"{design_id}.json").exists())

    def test_primitive_identifiers_and_paths_fail_closed(self) -> None:
        valid = str(uuid.uuid4())
        for value in ("", "not-a-uuid", "00000000-0000-0000-0000-000000000000"):
            with self.subTest(uuid=value):
                with self.assertRaises(scaffold.ScaffoldError):
                    scaffold.canonical_uuid(value, "fixture id")
        for value in ("", "bad\\path", "bad\x00path", "/absolute", "a/../b", "a//b"):
            with self.subTest(path=value):
                with self.assertRaises(scaffold.ScaffoldError):
                    scaffold.canonical_relative(value, "fixture path")
        with self.assertRaisesRegex(scaffold.ScaffoldError, "must match"):
            scaffold.id_and_output(
                None,
                f"docs/wrong/{valid}.json",
                scaffold.DESIGN_DIRECTORY,
                "design id",
                "design output",
            )
        with self.assertRaisesRegex(scaffold.ScaffoldError, "must be exactly"):
            scaffold.canonical_contract_path(
                f"docs/decisions/{valid}.json",
                scaffold.DESIGN_DIRECTORY,
                str(uuid.uuid4()),
                "design output",
            )

    def test_repository_discovery_rejects_io_and_invalid_git_roots(self) -> None:
        with tempfile.TemporaryDirectory() as root_raw:
            root = Path(root_raw)
            missing = root / "missing"
            with self.assertRaisesRegex(scaffold.ScaffoldError, "cannot be resolved"):
                scaffold.discover_repository(str(missing))
            regular = root / "file"
            regular.write_text("not a directory\n", encoding="utf-8")
            with self.assertRaisesRegex(scaffold.ScaffoldError, "must be a directory"):
                scaffold.discover_repository(str(regular))

            for result in (
                subprocess.CompletedProcess([], 0, stdout="", stderr=""),
                subprocess.CompletedProcess([], 0, stdout="one\ntwo\n", stderr=""),
            ):
                with self.subTest(result=result):
                    with mock.patch.object(scaffold.subprocess, "run", return_value=result):
                        with self.assertRaisesRegex(scaffold.ScaffoldError, "invalid repository root"):
                            scaffold.discover_repository(str(root))
            invalid_root = subprocess.CompletedProcess(
                [],
                0,
                stdout=str(regular) + "\n",
                stderr="",
            )
            with mock.patch.object(scaffold.subprocess, "run", return_value=invalid_root):
                with self.assertRaisesRegex(scaffold.ScaffoldError, "root is not a directory"):
                    scaffold.discover_repository(str(root))
            with mock.patch.object(scaffold.subprocess, "run", side_effect=OSError("git failed")):
                with self.assertRaisesRegex(scaffold.ScaffoldError, "cannot locate Git repository"):
                    scaffold.discover_repository(str(root))

    def test_platform_without_no_follow_directory_primitives_is_rejected(self) -> None:
        with mock.patch("builtins.hasattr", return_value=False):
            with self.assertRaisesRegex(scaffold.ScaffoldError, "lacks required no-follow"):
                scaffold._directory_flags()

    def test_descriptor_guards_reject_missing_and_non_regular_inputs(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX no-follow descriptor contract")
        with tempfile.TemporaryDirectory() as root_raw:
            root = Path(root_raw)
            with self.assertRaisesRegex(scaffold.ScaffoldError, "cannot open repository root"):
                scaffold.open_repository_directory(root / "missing", ())
            with self.assertRaisesRegex(scaffold.ScaffoldError, "missing or unsafe"):
                scaffold.open_repository_directory(root, ("missing",))

            (root / "inputs").mkdir()
            empty = root / "inputs/empty.json"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(scaffold.ScaffoldError, "between 1 and"):
                scaffold.read_repository_file(root, "inputs/empty.json", 10)
            (root / "inputs/directory").mkdir()
            with self.assertRaisesRegex(scaffold.ScaffoldError, "must be regular"):
                scaffold.read_repository_file(root, "inputs/directory", 10)

    def test_atomic_writer_rejects_no_progress_and_publish_failure(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX no-follow descriptor contract")
        with tempfile.TemporaryDirectory() as root_raw:
            root = Path(root_raw)
            (root / "output").mkdir()
            with mock.patch.object(scaffold.os, "write", return_value=0):
                with self.assertRaisesRegex(scaffold.ScaffoldError, "made no progress"):
                    scaffold.write_repository_file_atomic(root, "output/no-progress", b"data")
            with mock.patch.object(scaffold.os, "link", side_effect=OSError("link denied")):
                with self.assertRaisesRegex(scaffold.ScaffoldError, "cannot publish output safely"):
                    scaffold.write_repository_file_atomic(root, "output/no-link", b"data")

    def test_change_and_design_input_reject_invalid_lanes_and_paths(self) -> None:
        identifier = str(uuid.uuid4())
        design = scaffold.design_document(identifier)
        with self.assertRaisesRegex(scaffold.ScaffoldError, "change lane"):
            scaffold.change_document(
                identifier,
                identifier,
                f"docs/decisions/{identifier}.json",
                "sha256:" + "0" * 64,
                design,
                "R3",
                "unknown",
            )
        with tempfile.TemporaryDirectory() as root_raw:
            with self.assertRaisesRegex(scaffold.ScaffoldError, "design input must be exactly"):
                scaffold.load_design(Path(root_raw), "wrong/location.json")


if __name__ == "__main__":
    unittest.main()
