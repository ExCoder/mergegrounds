from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mergegrounds", ROOT / "scripts" / "mergegrounds.py")
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)


ADAPTER = """
schema_version = 1
id = "fixture"
ecosystem = "fixture"
priority = 1

[detect]
any_files = ["fixture.marker"]

[toolchain]
required_commands = ["python3"]
setup_hint = "Python 3 is required"

[commands]
format = ["python3 -c 'print(42)'"]
lint = ["python3 -c 'print(42)'"]
typecheck = ["python3 -c 'print(42)'"]
unit = ["python3 -c 'import pathlib,xml.etree.ElementTree as E; pathlib.Path(\\\"reports\\\").mkdir(exist_ok=True); r=E.Element(\\\"testsuite\\\",tests=\\\"1\\\",failures=\\\"0\\\",errors=\\\"0\\\"); E.SubElement(r,\\\"testcase\\\",name=\\\"ok\\\"); E.ElementTree(r).write(\\\"reports/junit.xml\\\")'"]
mutation = ["python3 -c 'print(100)'"]

[thresholds]
line_coverage = 90.0
branch_coverage = 85.0
mutation_score = 80.0

[artifacts]
unit = ["reports/*.xml"]
"""

SAFE_WORKFLOW = """
name: MergeGrounds
permissions:
  contents: read
on:
  pull_request:
concurrency:
  group: mergegrounds-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: false
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          persist-credentials: false
      - run: python3 -I scripts/mergegrounds.py verify-repo --strict
"""


class RepositoryFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "config", "user.email", "mergegrounds-tests@example.invalid"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "MergeGrounds Tests"], cwd=self.root, check=True)
        for directory in (
            ".mergegrounds/adapters",
            ".mergegrounds/changes",
            ".mergegrounds/schemas",
            ".github/ISSUE_TEMPLATE",
            ".github/workflows",
            "docs/decisions",
            "scripts",
        ):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / ".mergegrounds/mergegrounds.toml").write_text(
            (ROOT / ".mergegrounds/mergegrounds.toml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (self.root / ".mergegrounds/exceptions.toml").write_text("schema_version = 1\nexceptions = []\n", encoding="utf-8")
        (self.root / ".mergegrounds/ai-assurance.toml").write_text("schema_version = 1\n", encoding="utf-8")
        (self.root / ".mergegrounds/LICENSE.mergegrounds").write_bytes(
            (ROOT / ".mergegrounds/LICENSE.mergegrounds").read_bytes()
        )
        (self.root / ".mergegrounds/README.mergegrounds.md").write_bytes(
            (ROOT / ".mergegrounds/README.mergegrounds.md").read_bytes()
        )
        (self.root / ".mergegrounds/schemas/ai-assurance.example.toml").write_text(
            "schema_version = 1\n",
            encoding="utf-8",
        )
        (self.root / ".mergegrounds/adapters/fixture.toml").write_text(textwrap.dedent(ADAPTER), encoding="utf-8")
        (self.root / ".github/CODEOWNERS").write_text(
            "* @security\n"
            "/.codex-plugin/ @security\n"
            "/.agents/ @security\n"
            "/.github/ @security\n"
            "/.mergegrounds/ @security\n"
            "/.coveragerc @security\n"
            "/.gitattributes @security\n"
            "/mergegrounds-custom @security\n"
            "/requirements-self.in @security\n"
            "/requirements-self.lock @security\n"
            "/templates/bootstrap/ @security\n"
            "/VERSION @security\n"
            "/scripts/ @security\n"
            "/skills/mergegrounds/ @security\n"
            "/SECURITY.md @security\n",
            encoding="utf-8",
        )
        for workflow in ("mergegrounds.yml", "codeql.yml", "full-scan.yml", "scorecard.yml"):
            (self.root / ".github/workflows" / workflow).write_bytes(
                (ROOT / ".github/workflows" / workflow).read_bytes()
            )
        (self.root / ".github/dependabot.yml").write_text("version: 2\nupdates: []\n", encoding="utf-8")
        (self.root / ".github/ISSUE_TEMPLATE/design-review.yml").write_text("name: fixture\n", encoding="utf-8")
        (self.root / ".github/pull_request_template.md").write_text("fixture\n", encoding="utf-8")
        (self.root / ".mergegrounds/changes/README.md").write_text("fixture\n", encoding="utf-8")
        (self.root / "docs/decisions/README.md").write_text("fixture\n", encoding="utf-8")
        (self.root / ".gitignore").write_bytes((ROOT / ".gitignore").read_bytes())
        (self.root / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")
        (self.root / "scripts/mergegrounds.py").write_text("# fixture\n", encoding="utf-8")
        (self.root / "scripts/ai_assurance.py").write_text("# fixture\n", encoding="utf-8")
        (self.root / "scripts/scaffold_change.py").write_text("# fixture\n", encoding="utf-8")
        (self.root / "scripts/apply-github-ruleset.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        (self.root / "SECURITY.md").write_text("fixture\n", encoding="utf-8")
        (self.root / "fixture.marker").touch()
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=self.root, check=True)
        _, config = mergegrounds.config_for(self.root)
        mergegrounds.write_json_atomic(
            self.root / ".mergegrounds/control-plane.lock.json",
            mergegrounds.seal_payload(self.root, config),
            self.root,
        )
        subprocess.run(["git", "add", ".mergegrounds/control-plane.lock.json"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "seal control plane"], cwd=self.root, check=True)

    def close(self) -> None:
        self.temp.cleanup()


class MergeGroundsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RepositoryFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_detects_fixture_adapter(self) -> None:
        adapters = mergegrounds.detected_adapters(self.fixture.root)
        self.assertEqual(["fixture"], [item["id"] for item in adapters])

    def test_subject_adapter_globs_preserve_repository_root_semantics(self) -> None:
        self.assertTrue(mergegrounds.rooted_git_glob_match("project.sln", "*.sln"))
        self.assertFalse(mergegrounds.rooted_git_glob_match("nested/project.sln", "*.sln"))
        self.assertTrue(mergegrounds.rooted_git_glob_match("project.csproj", "**/*.csproj"))
        self.assertTrue(mergegrounds.rooted_git_glob_match("nested/project.csproj", "**/*.csproj"))

    def test_critical_skill_glob_requires_zero_depth_and_nested_paths(self) -> None:
        pattern = "skills/mergegrounds/**/*"
        self.assertTrue(
            mergegrounds.repository_glob_match("skills/mergegrounds/SKILL.md", pattern)
        )
        self.assertTrue(
            mergegrounds.repository_glob_match(
                "skills/mergegrounds/references/workflow.md",
                pattern,
            )
        )
        self.assertFalse(
            mergegrounds.repository_glob_match("skills/unrelated/SKILL.md", pattern)
        )

    def test_custom_dispatcher_and_complete_scripts_tree_are_r4_controls(self) -> None:
        _, config = mergegrounds.config_for(self.fixture.root)
        patterns = config["policy"]["critical_paths"]
        for path in (
            ".mergegrounds/custom.enabled",
            "mergegrounds-custom",
            "scripts/nested/helper.tool",
            "scripts/deeper/path/helper.bin",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    mergegrounds.critical_control_paths_changed([path], patterns)
                )

    def test_optional_custom_dispatcher_and_nested_script_are_sealed_with_modes(self) -> None:
        marker = self.fixture.root / ".mergegrounds/custom.enabled"
        dispatcher = self.fixture.root / "mergegrounds-custom"
        helper = self.fixture.root / "scripts/nested/helper.tool"
        helper.parent.mkdir(parents=True)
        marker.write_text("enabled\n", encoding="utf-8")
        dispatcher.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        dispatcher.chmod(0o755)
        helper.write_text("nested control helper\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", ".mergegrounds/custom.enabled", "mergegrounds-custom", "scripts/nested/helper.tool"],
            cwd=self.fixture.root,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-qm", "add custom control dispatcher"],
            cwd=self.fixture.root,
            check=True,
        )
        _, config = mergegrounds.config_for(self.fixture.root)
        lock_path = self.fixture.root / ".mergegrounds/control-plane.lock.json"
        mergegrounds.write_json_atomic(
            lock_path,
            mergegrounds.seal_payload(self.fixture.root, config),
            self.fixture.root,
        )
        subprocess.run(["git", "add", str(lock_path)], cwd=self.fixture.root, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "seal custom controls"],
            cwd=self.fixture.root,
            check=True,
        )
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertIn(".mergegrounds/custom.enabled", lock["files"])
        self.assertEqual("100755", lock["files"]["mergegrounds-custom"]["mode"])
        self.assertIn("scripts/nested/helper.tool", lock["files"])
        self.assertEqual([], mergegrounds.seal_findings(self.fixture.root, config))

        dispatcher.chmod(0o644)
        helper.chmod(0o755)
        mode_paths = {
            finding.path
            for finding in mergegrounds.seal_findings(self.fixture.root, config)
            if finding.code == "CONTROL_FILE_MODE"
        }
        self.assertEqual({"mergegrounds-custom", "scripts/nested/helper.tool"}, mode_paths)

    def test_ignored_script_caches_do_not_destabilize_seal(self) -> None:
        cache = self.fixture.root / "scripts/__pycache__/mergegrounds.cpython-311.pyc"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(b"generated bytecode cache")
        _, config = mergegrounds.config_for(self.fixture.root)
        payload = mergegrounds.seal_payload(self.fixture.root, config)
        self.assertNotIn("scripts/__pycache__/mergegrounds.cpython-311.pyc", payload["files"])

    def test_subject_resolution_ignores_git_replace_refs(self) -> None:
        original = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        original_tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        (self.fixture.root / "replacement-controlled.txt").write_text(
            "candidate replacement\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "replacement-controlled.txt"], cwd=self.fixture.root, check=True)
        subprocess.run(["git", "commit", "-qm", "replacement target"], cwd=self.fixture.root, check=True)
        replacement_tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        subprocess.run(
            ["git", "replace", original_tree, replacement_tree],
            cwd=self.fixture.root,
            check=True,
        )
        replacement_content = subprocess.run(
            ["git", "show", f"{original}:replacement-controlled.txt"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        self.assertEqual("candidate replacement", replacement_content)

        context = mergegrounds.subject_evidence_context(self.fixture.root, original, "fast")
        self.assertEqual(original, context["commit"])
        self.assertEqual(original_tree, context["tree"])
        self.assertNotIn("replacement-controlled.txt", mergegrounds.subject_regular_paths(self.fixture.root, original))

    def test_doctor_and_version_discovery_never_execute_declared_tool(self) -> None:
        binary_directory = self.fixture.root / "probe-bin"
        binary_directory.mkdir()
        marker = self.fixture.root / "declared-tool-executed"
        tool = binary_directory / "mergegrounds-version-probe"
        tool.write_text(
            "#!/bin/sh\n"
            f"printf executed > {marker.as_posix()!r}\n",
            encoding="utf-8",
        )
        tool.chmod(0o755)
        adapter_path = self.fixture.root / ".mergegrounds/adapters/fixture.toml"
        adapter_path.write_text(
            adapter_path.read_text(encoding="utf-8").replace(
                'required_commands = ["python3"]',
                'required_commands = ["mergegrounds-version-probe"]',
            ).replace("mutation_score = 80.0", "mutation_score = 85.0"),
            encoding="utf-8",
        )
        old_path = os.environ.get("PATH")
        probe_path = str(binary_directory) + (os.pathsep + old_path if old_path else "")
        os.environ["PATH"] = probe_path
        try:
            args = argparse.Namespace(root=str(self.fixture.root))
            self.assertEqual(0, mergegrounds.doctor(args))
            adapters = mergegrounds.detected_adapters(self.fixture.root)
            versions = mergegrounds.tool_versions(
                adapters,
                self.fixture.root,
                {"PATH": probe_path},
            )
        finally:
            if old_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = old_path
        self.assertFalse(marker.exists())
        self.assertIn("version-not-executed", versions["mergegrounds-version-probe"])

    def test_verified_repository_has_no_findings(self) -> None:
        _, config = mergegrounds.config_for(self.fixture.root)
        self.assertEqual([], mergegrounds.verify_repository(self.fixture.root, config))

    def test_mutable_action_is_rejected(self) -> None:
        workflow = self.fixture.root / ".github/workflows/mergegrounds.yml"
        workflow.write_text(
            textwrap.dedent(SAFE_WORKFLOW).replace(
                "@0123456789abcdef0123456789abcdef01234567",
                "@v4",
            ),
            encoding="utf-8",
        )
        findings = mergegrounds.workflow_findings(self.fixture.root)
        self.assertIn("MUTABLE_ACTION", {item.code for item in findings})

    def test_workflow_parser_rejects_adversarial_yaml_forms(self) -> None:
        workflow = self.fixture.root / ".github/workflows/mergegrounds.yml"
        workflow.write_text(
            textwrap.dedent(
                """
                name: Adversarial
                on: [pull_request]
                permissions:
                  id-token: write
                jobs:
                  check:
                    runs-on: ubuntu-latest
                    steps:
                      - uses : actions/checkout@v4
                      - {uses: docker://evil/image@sha256:x}
                      - run: echo "${{ secrets['TOP_SECRET'] }}"
                        env:
                          EXFIL: ${{ github.token }}
                """
            ),
            encoding="utf-8",
        )
        codes = {item.code for item in mergegrounds.workflow_findings(self.fixture.root)}
        self.assertTrue({"PR_WRITE_PERMISSION", "MUTABLE_ACTION", "PR_SECRET", "PR_TOKEN", "WORKFLOW_SYNTAX"} <= codes)

    def test_pull_request_target_is_rejected_in_mapping_form(self) -> None:
        workflow = self.fixture.root / ".github/workflows/mergegrounds.yml"
        workflow.write_text(
            "name: x\non:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps: []\n",
            encoding="utf-8",
        )
        self.assertIn("UNTRUSTED_TRIGGER", {item.code for item in mergegrounds.workflow_findings(self.fixture.root)})

    def test_checkout_comment_cannot_satisfy_credentials_control(self) -> None:
        workflow = self.fixture.root / ".github/workflows/mergegrounds.yml"
        workflow.write_text(
            SAFE_WORKFLOW.replace("        with:\n          persist-credentials: false\n", "        # persist-credentials: false\n"),
            encoding="utf-8",
        )
        self.assertIn("CHECKOUT_CREDENTIALS", {item.code for item in mergegrounds.workflow_findings(self.fixture.root)})

    def test_checkout_identity_is_case_insensitive(self) -> None:
        workflow = self.fixture.root / ".github/workflows/mergegrounds.yml"
        value = SAFE_WORKFLOW.replace("actions/checkout@", "Actions/Checkout@").replace(
            "        with:\n          persist-credentials: false\n",
            "",
        )
        workflow.write_text(value, encoding="utf-8")
        self.assertIn("CHECKOUT_CREDENTIALS", {item.code for item in mergegrounds.workflow_findings(self.fixture.root)})

    def test_self_hosted_and_additional_pr_text_contexts_are_rejected(self) -> None:
        workflow = self.fixture.root / ".github/workflows/mergegrounds.yml"
        workflow.write_text(
            textwrap.dedent(
                """
                name: x
                on: pull_request
                permissions:
                  contents: read
                jobs:
                  x:
                    runs-on:
                      - self-hosted
                    steps:
                      - run: echo "${{ github.event.pull_request.head.label }} ${{ github.head_ref }}"
                """
            ),
            encoding="utf-8",
        )
        codes = {item.code for item in mergegrounds.workflow_findings(self.fixture.root)}
        self.assertTrue({"SELF_HOSTED_PR", "SCRIPT_INJECTION"} <= codes)

    def test_codeowners_late_override_is_rejected(self) -> None:
        codeowners = self.fixture.root / ".github/CODEOWNERS"
        codeowners.write_text(codeowners.read_text() + "* @attacker\n", encoding="utf-8")
        _, config = mergegrounds.config_for(self.fixture.root)
        self.assertIn("OWNERSHIP_OVERRIDE", {item.code for item in mergegrounds.verify_repository(self.fixture.root, config)})

    def test_oversized_codeowners_is_rejected(self) -> None:
        codeowners = self.fixture.root / ".github/CODEOWNERS"
        codeowners.write_bytes(b"#" * mergegrounds.MAX_CODEOWNERS_BYTES)
        _, config = mergegrounds.config_for(self.fixture.root)
        self.assertIn("CODEOWNERS_TOO_LARGE", {item.code for item in mergegrounds.verify_repository(self.fixture.root, config)})

    def test_control_plane_drift_is_rejected(self) -> None:
        (self.fixture.root / "scripts/mergegrounds.py").write_text("# changed\n", encoding="utf-8")
        _, config = mergegrounds.config_for(self.fixture.root)
        findings = mergegrounds.seal_findings(self.fixture.root, config)
        self.assertIn("CONTROL_FILE_DRIFT", {item.code for item in findings})

    def test_control_plane_executable_mode_drift_is_rejected(self) -> None:
        control = self.fixture.root / "scripts/mergegrounds.py"
        control.chmod(0o755)
        _, config = mergegrounds.config_for(self.fixture.root)
        findings = mergegrounds.seal_findings(self.fixture.root, config)
        self.assertIn("CONTROL_FILE_MODE", {item.code for item in findings})

    def test_namespaced_license_is_required_and_sealed_by_content_and_mode(self) -> None:
        source_license = ROOT / ".mergegrounds/LICENSE.mergegrounds"
        self.assertEqual((ROOT / "LICENSE").read_bytes(), source_license.read_bytes())
        _, config = mergegrounds.config_for(self.fixture.root)
        policy = config["policy"]
        self.assertIn(".mergegrounds/LICENSE.mergegrounds", policy["required_files"])
        self.assertIn(".mergegrounds/LICENSE.mergegrounds", policy["critical_paths"])

        deployed_license = self.fixture.root / ".mergegrounds/LICENSE.mergegrounds"
        deployed_license.write_text("tampered license\n", encoding="utf-8")
        self.assertIn(
            "CONTROL_FILE_DRIFT",
            {item.code for item in mergegrounds.seal_findings(self.fixture.root, config)},
        )

        deployed_license.write_bytes(source_license.read_bytes())
        deployed_license.chmod(0o755)
        self.assertIn(
            "CONTROL_FILE_MODE",
            {item.code for item in mergegrounds.seal_findings(self.fixture.root, config)},
        )

    def test_seal_refuses_uncommitted_controls_and_old_commit_forgery(self) -> None:
        control = self.fixture.root / "scripts/mergegrounds.py"
        control.write_text("# dirty forged control\n", encoding="utf-8")
        _, config = mergegrounds.config_for(self.fixture.root)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "commit them before sealing"):
            mergegrounds.seal_payload(self.fixture.root, config)

        lock_path = self.fixture.root / ".mergegrounds/control-plane.lock.json"
        forged = json.loads(lock_path.read_text(encoding="utf-8"))
        forged["files"]["scripts/mergegrounds.py"] = {
            "sha256": mergegrounds.sha256_file(control),
            "mode": mergegrounds.canonical_regular_mode(control),
        }
        lock_path.write_text(json.dumps(forged) + "\n", encoding="utf-8")
        findings = mergegrounds.seal_findings(self.fixture.root, config)
        self.assertEqual(["CONTROL_LOCK_INVALID"], [item.code for item in findings])

    def test_seal_binds_committed_git_mode_and_rejects_index_only_mode(self) -> None:
        control = self.fixture.root / "scripts/mergegrounds.py"
        subprocess.run(
            ["git", "update-index", "--chmod=+x", "scripts/mergegrounds.py"],
            cwd=self.fixture.root,
            check=True,
        )
        _, config = mergegrounds.config_for(self.fixture.root)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "Git index differ"):
            mergegrounds.seal_payload(self.fixture.root, config)
        self.assertIn(
            "CONTROL_INDEX_DRIFT",
            {item.code for item in mergegrounds.seal_findings(self.fixture.root, config)},
        )

        subprocess.run(
            ["git", "update-index", "--chmod=-x", "scripts/mergegrounds.py"],
            cwd=self.fixture.root,
            check=True,
        )
        control.write_text("# reviewed executable control\n", encoding="utf-8")
        control.chmod(0o755)
        subprocess.run(["git", "add", "scripts/mergegrounds.py"], cwd=self.fixture.root, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "review executable control"],
            cwd=self.fixture.root,
            check=True,
        )
        payload = mergegrounds.seal_payload(self.fixture.root, config)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        self.assertEqual(head, payload["git_commit"])
        self.assertEqual("100755", payload["files"]["scripts/mergegrounds.py"]["mode"])

    def test_legacy_content_only_control_lock_requires_migration(self) -> None:
        _, config = mergegrounds.config_for(self.fixture.root)
        lock_path = self.fixture.root / ".mergegrounds/control-plane.lock.json"
        current = json.loads(lock_path.read_text(encoding="utf-8"))
        legacy = {
            **current,
            "schema_version": 1,
            "files": {
                name: record["sha256"]
                for name, record in current["files"].items()
            },
        }
        lock_path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
        findings = mergegrounds.seal_findings(self.fixture.root, config)
        self.assertEqual(["CONTROL_LOCK_INVALID"], [item.code for item in findings])

    def test_policy_and_control_lock_data_files_must_not_be_executable(self) -> None:
        config_path = self.fixture.root / ".mergegrounds/mergegrounds.toml"
        config_path.chmod(0o755)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "must not be executable"):
            mergegrounds.config_for(self.fixture.root)
        config_path.chmod(0o644)
        _, config = mergegrounds.config_for(self.fixture.root)
        lock_path = self.fixture.root / ".mergegrounds/control-plane.lock.json"
        lock_path.chmod(0o755)
        findings = mergegrounds.seal_findings(self.fixture.root, config)
        self.assertEqual(["CONTROL_LOCK_INVALID"], [item.code for item in findings])

    def test_sensitive_environment_is_removed(self) -> None:
        old = os.environ.get("EXAMPLE_API_TOKEN")
        os.environ["EXAMPLE_API_TOKEN"] = "do-not-pass"
        try:
            _, config = mergegrounds.config_for(self.fixture.root)
            env, removed = mergegrounds.environment_for(config)
            self.assertNotIn("EXAMPLE_API_TOKEN", env)
            self.assertIn("EXAMPLE_API_TOKEN", removed)
        finally:
            if old is None:
                os.environ.pop("EXAMPLE_API_TOKEN", None)
            else:
                os.environ["EXAMPLE_API_TOKEN"] = old

    def test_security_boolean_types_fail_closed(self) -> None:
        config_path = self.fixture.root / ".mergegrounds/mergegrounds.toml"
        config_path.write_text(
            config_path.read_text(encoding="utf-8").replace("require_clean_tree = true", "require_clean_tree = 0"),
            encoding="utf-8",
        )
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.config_for(self.fixture.root)

    def test_external_profile_cannot_override_inline_stage_order(self) -> None:
        profile_directory = self.fixture.root / ".mergegrounds/profiles"
        profile_directory.mkdir()
        profile = profile_directory / "full.toml"
        inline = mergegrounds.load_toml(self.fixture.root / ".mergegrounds/mergegrounds.toml")[
            "profiles"
        ]["full"]
        reordered_stages = list(inline["stages"])
        reordered_stages[0], reordered_stages[1] = (
            reordered_stages[1],
            reordered_stages[0],
        )
        profile.write_text(
            "schema_version = 1\n"
            'id = "full"\n'
            f"stages = {json.dumps(reordered_stages)}\n"
            f"required_stages = {json.dumps(inline['required_stages'])}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "must exactly match inline"):
            mergegrounds.config_for(self.fixture.root)

        profile.write_text(
            "schema_version = 1\n"
            'id = "full"\n'
            f"stages = {json.dumps(inline['stages'])}\n"
            f"required_stages = {json.dumps(inline['required_stages'])}\n",
            encoding="utf-8",
        )
        mergegrounds.config_for(self.fixture.root)

        profile.write_text(
            "schema_version = 1\n"
            'id = "full"\n'
            f"stages = {json.dumps(reordered_stages)}\n"
            f"required_stages = {json.dumps(inline['required_stages'])}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", ".mergegrounds/profiles/full.toml"], cwd=self.fixture.root, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "mismatched external profile"],
            cwd=self.fixture.root,
            check=True,
        )
        subject = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "does not match inline policy"):
            mergegrounds.subject_evidence_context(self.fixture.root, subject, "full")

    def test_change_control_boolean_lookalikes_fail_closed(self) -> None:
        _, config = mergegrounds.config_for(self.fixture.root)
        for field, replacement in (
            ("claims_satisfy_controls", 0),
            ("require_design_in_base", 1),
        ):
            with self.subTest(field=field):
                changed = dict(config)
                changed["change_control"] = dict(config["change_control"])
                changed["change_control"][field] = replacement
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, field):
                    mergegrounds.validate_config(changed)

    def test_run_writes_passing_evidence(self) -> None:
        args = argparse.Namespace(
            root=str(self.fixture.root),
            profile="fast",
            evidence=".mergegrounds/evidence/test.json",
            fail_fast=False,
        )
        self.assertEqual(0, mergegrounds.run_profile(args))
        evidence = json.loads((self.fixture.root / ".mergegrounds/evidence/test.json").read_text())
        self.assertEqual("pass", evidence["status"])
        self.assertEqual("allow", evidence["decision"])
        self.assertEqual(["fixture"], evidence["adapters"])

    def test_normalize_attempt_accepts_complete_subject_bound_evidence(self) -> None:
        run_args = argparse.Namespace(
            root=str(self.fixture.root),
            profile="fast",
            evidence=".mergegrounds/evidence/raw.json",
            fail_fast=False,
        )
        self.assertEqual(0, mergegrounds.run_profile(run_args))
        subject = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        receipt_args = argparse.Namespace(
            root=str(self.fixture.root),
            raw=".mergegrounds/evidence/raw.json",
            output=".mergegrounds/evidence/receipt.json",
            profile="fast",
            subject_sha=subject,
            exit_code="0",
            runner_outcome="success",
        )
        self.assertEqual(0, mergegrounds.normalize_attempt(receipt_args))
        receipt = json.loads((self.fixture.root / ".mergegrounds/evidence/receipt.json").read_text())
        self.assertEqual("allow", receipt["decision"])
        self.assertTrue(receipt["raw_evidence"]["validated"])
        expected_tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        expected_policy = mergegrounds.sha256_bytes(
            subprocess.run(
                ["git", "show", "HEAD:.mergegrounds/mergegrounds.toml"],
                cwd=self.fixture.root,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
        )
        self.assertEqual(expected_tree, receipt["subject_tree"])
        self.assertEqual(expected_policy, receipt["policy_sha256"])
        self.assertEqual("local-receipt-not-external-attestation", receipt["authority"])

    def test_normalize_attempt_rejects_evidence_from_a_different_clean_checkout(self) -> None:
        run_args = argparse.Namespace(
            root=str(self.fixture.root),
            profile="fast",
            evidence=".mergegrounds/evidence/checkout-a.json",
            fail_fast=False,
        )
        self.assertEqual(0, mergegrounds.run_profile(run_args))
        subject_a = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        (self.fixture.root / "unrelated.txt").write_text("commit B\n", encoding="utf-8")
        subprocess.run(["git", "add", "unrelated.txt"], cwd=self.fixture.root, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "advance clean checkout"],
            cwd=self.fixture.root,
            check=True,
        )
        args = argparse.Namespace(
            root=str(self.fixture.root),
            raw=".mergegrounds/evidence/checkout-a.json",
            output=".mergegrounds/evidence/checkout-mismatch-receipt.json",
            profile="fast",
            subject_sha=subject_a,
            exit_code="0",
            runner_outcome="success",
        )
        self.assertEqual(1, mergegrounds.normalize_attempt(args))
        receipt = json.loads(
            (self.fixture.root / ".mergegrounds/evidence/checkout-mismatch-receipt.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("deny", receipt["decision"])
        self.assertEqual("SUBJECT_WORKTREE_MISMATCH", receipt["reason_code"])
        self.assertFalse(receipt["raw_evidence"]["validated"])

    def test_normalize_attempt_rejects_forged_tree_time_policy_and_results(self) -> None:
        run_args = argparse.Namespace(
            root=str(self.fixture.root),
            profile="fast",
            evidence=".mergegrounds/evidence/pristine.json",
            fail_fast=False,
        )
        self.assertEqual(0, mergegrounds.run_profile(run_args))
        pristine = json.loads(
            (self.fixture.root / ".mergegrounds/evidence/pristine.json").read_text(encoding="utf-8")
        )
        subject = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

        def invent_adapter(value: dict[str, object]) -> None:
            value["adapters"] = ["invented"]
            for item in value["results"]:  # type: ignore[index,union-attr]
                if item.get("adapter") != "mergegrounds":
                    item["adapter"] = "invented"

        def replace_with_minimal_results(value: dict[str, object]) -> None:
            value["results"] = [
                {"adapter": "fixture", "stage": stage, "status": "pass"}
                for stage in ("format", "lint", "typecheck", "unit")
            ] + [
                {
                    "adapter": "fixture",
                    "stage": "unit-artifacts",
                    "status": "pass",
                    "files": [],
                }
            ]
            value["artifacts"] = []
            value["tool_versions"] = {}
            value["sanitized_environment_keys"] = []

        cases = {
            "tree": (
                lambda value: value.__setitem__("git_tree", "0" * 40),
                "EVIDENCE_TREE_MISMATCH",
            ),
            "policy digest": (
                lambda value: value["config"].__setitem__("sha256", "0" * 64),
                "EVIDENCE_POLICY_MISMATCH",
            ),
            "non-canonical UTC time": (
                lambda value: value.__setitem__("started_at", "2026-01-01T00:00:00+00:00"),
                "EVIDENCE_TIME_INVALID",
            ),
            "reversed time": (
                lambda value: (
                    value.__setitem__("started_at", "2026-01-02T00:00:00Z"),
                    value.__setitem__("finished_at", "2026-01-01T00:00:00Z"),
                ),
                "EVIDENCE_TIME_ORDER",
            ),
            "non-canonical run id": (
                lambda value: value.__setitem__("run_id", "{" + str(value["run_id"]) + "}"),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            "missing required result": (
                lambda value: value.__setitem__(
                    "results",
                    [item for item in value["results"] if item.get("stage") != "lint"],
                ),
                "EVIDENCE_INCOMPLETE",
            ),
            "invented result stage": (
                lambda value: value["results"][0].__setitem__("stage", "unreviewed"),
                "EVIDENCE_RESULTS_INVALID",
            ),
            "invented adapter set": (
                invent_adapter,
                "EVIDENCE_ADAPTER_MISMATCH",
            ),
            "minimal forged pass records": (
                replace_with_minimal_results,
                "EVIDENCE_RESULTS_INVALID",
            ),
            "wrong command digest": (
                lambda value: value["results"][0].__setitem__("command_sha256", "0" * 64),
                "EVIDENCE_RESULTS_INVALID",
            ),
            "missing artifact result": (
                lambda value: value.__setitem__(
                    "results",
                    [
                        item
                        for item in value["results"]
                        if item.get("stage") != "unit-artifacts"
                    ],
                ),
                "EVIDENCE_INCOMPLETE",
            ),
            "missing artifact inventory": (
                lambda value: value.__setitem__("artifacts", []),
                "EVIDENCE_ARTIFACT_MISMATCH",
            ),
            "missing tool inventory": (
                lambda value: value.__setitem__("tool_versions", {}),
                "EVIDENCE_TOOLCHAIN_MISMATCH",
            ),
        }
        for index, (label, (mutate, expected_reason)) in enumerate(cases.items()):
            with self.subTest(label=label):
                forged = json.loads(json.dumps(pristine))
                mutate(forged)
                raw_name = f"forged-{index}.json"
                receipt_name = f"forged-{index}-receipt.json"
                (self.fixture.root / ".mergegrounds/evidence" / raw_name).write_text(
                    json.dumps(forged) + "\n",
                    encoding="utf-8",
                )
                args = argparse.Namespace(
                    root=str(self.fixture.root),
                    raw=f".mergegrounds/evidence/{raw_name}",
                    output=f".mergegrounds/evidence/{receipt_name}",
                    profile="fast",
                    subject_sha=subject,
                    exit_code="0",
                    runner_outcome="success",
                )
                self.assertEqual(1, mergegrounds.normalize_attempt(args))
                receipt = json.loads(
                    (self.fixture.root / ".mergegrounds/evidence" / receipt_name).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual("deny", receipt["decision"])
                self.assertEqual(expected_reason, receipt["reason_code"])
                self.assertFalse(receipt["raw_evidence"]["validated"])

    def test_normalize_attempt_rejects_stale_future_and_absurd_allow_times(self) -> None:
        run_args = argparse.Namespace(
            root=str(self.fixture.root),
            profile="fast",
            evidence=".mergegrounds/evidence/time-pristine.json",
            fail_fast=False,
        )
        self.assertEqual(0, mergegrounds.run_profile(run_args))
        pristine = json.loads(
            (self.fixture.root / ".mergegrounds/evidence/time-pristine.json").read_text(
                encoding="utf-8"
            )
        )
        subject_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        subject = mergegrounds.subject_evidence_context(self.fixture.root, subject_sha, "fast")
        fixed_now = mergegrounds.parse_rfc3339_utc(pristine["finished_at"])
        assert fixed_now is not None
        maximum_duration = mergegrounds.maximum_allow_run_duration(subject)

        def timestamp(value: dt.datetime) -> str:
            return value.isoformat().replace("+00:00", "Z")

        stale = fixed_now - dt.timedelta(
            seconds=mergegrounds.MAX_EVIDENCE_NORMALIZATION_DELAY_SECONDS + 1
        )
        future = fixed_now + dt.timedelta(
            seconds=mergegrounds.MAX_EVIDENCE_FUTURE_SKEW_SECONDS + 1
        )
        cases = {
            "stale": (stale, stale, "EVIDENCE_TIME_STALE"),
            "future": (future, future, "EVIDENCE_TIME_FUTURE"),
            "absurd duration": (
                fixed_now - maximum_duration - dt.timedelta(seconds=1),
                fixed_now,
                "EVIDENCE_TIME_DURATION",
            ),
        }
        for index, (label, (started, finished, expected_reason)) in enumerate(cases.items()):
            with self.subTest(label=label):
                forged = json.loads(json.dumps(pristine))
                forged["started_at"] = timestamp(started)
                forged["finished_at"] = timestamp(finished)
                raw = f".mergegrounds/evidence/time-forged-{index}.json"
                output = f".mergegrounds/evidence/time-receipt-{index}.json"
                (self.fixture.root / raw).write_text(
                    json.dumps(forged) + "\n",
                    encoding="utf-8",
                )
                args = argparse.Namespace(
                    root=str(self.fixture.root),
                    raw=raw,
                    output=output,
                    profile="fast",
                    subject_sha=subject_sha,
                    exit_code="0",
                    runner_outcome="success",
                )
                self.assertEqual(1, mergegrounds.normalize_attempt(args, now=fixed_now))
                receipt = json.loads((self.fixture.root / output).read_text(encoding="utf-8"))
                self.assertEqual("deny", receipt["decision"])
                self.assertEqual(expected_reason, receipt["reason_code"])
                self.assertFalse(receipt["raw_evidence"]["validated"])

    def test_normalize_attempt_always_records_missing_or_malformed_as_deny(self) -> None:
        subject = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        cases = (
            ("missing.json", None, "EVIDENCE_MISSING"),
            ("malformed.json", b'{"status":"pass",', "EVIDENCE_MALFORMED"),
        )
        for index, (name, body, reason) in enumerate(cases):
            with self.subTest(name=name):
                raw = self.fixture.root / ".mergegrounds/evidence" / name
                raw.parent.mkdir(parents=True, exist_ok=True)
                if body is not None:
                    raw.write_bytes(body)
                output = f".mergegrounds/evidence/receipt-{index}.json"
                args = argparse.Namespace(
                    root=str(self.fixture.root),
                    raw=f".mergegrounds/evidence/{name}",
                    output=output,
                    profile="pr",
                    subject_sha=subject,
                    exit_code="2",
                    runner_outcome="failure",
                )
                self.assertEqual(1, mergegrounds.normalize_attempt(args))
                receipt = json.loads((self.fixture.root / output).read_text())
                self.assertEqual("deny", receipt["decision"])
                self.assertEqual(reason, receipt["reason_code"])
                self.assertFalse(receipt["raw_evidence"]["validated"])

    def test_normalize_attempt_never_trusts_symlink_or_verdict_mismatch(self) -> None:
        evidence_dir = self.fixture.root / ".mergegrounds/evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        target = evidence_dir / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        symlink = evidence_dir / "symlink.json"
        symlink.symlink_to(target)
        subject = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        args = argparse.Namespace(
            root=str(self.fixture.root),
            raw=".mergegrounds/evidence/symlink.json",
            output=".mergegrounds/evidence/symlink-receipt.json",
            profile="pr",
            subject_sha=subject,
            exit_code="0",
            runner_outcome="success",
        )
        self.assertEqual(1, mergegrounds.normalize_attempt(args))
        receipt = json.loads((evidence_dir / "symlink-receipt.json").read_text())
        self.assertEqual("EVIDENCE_UNSAFE", receipt["reason_code"])
        self.assertIsNone(receipt["raw_evidence"]["sha256"])

    def test_evidence_cannot_overwrite_control_file(self) -> None:
        config_path = self.fixture.root / ".mergegrounds/mergegrounds.toml"
        original = config_path.read_bytes()
        args = argparse.Namespace(
            root=str(self.fixture.root),
            profile="fast",
            evidence=".mergegrounds/mergegrounds.toml",
            fail_fast=False,
        )
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.run_profile(args)
        self.assertEqual(original, config_path.read_bytes())

    def test_missing_declared_stage_artifact_denies(self) -> None:
        adapter = self.fixture.root / ".mergegrounds/adapters/fixture.toml"
        value = adapter.read_text(encoding="utf-8")
        value = re.sub(r'^unit = \[.*\]$', 'unit = ["python3 -c \'print(42)\'"]', value, flags=re.MULTILINE)
        adapter.write_text(value, encoding="utf-8")
        subprocess.run(["git", "add", ".mergegrounds/adapters/fixture.toml"], cwd=self.fixture.root, check=True)
        subprocess.run(["git", "commit", "-qm", "missing artifact fixture"], cwd=self.fixture.root, check=True)
        args = argparse.Namespace(
            root=str(self.fixture.root),
            profile="fast",
            evidence=".mergegrounds/evidence/missing-artifact.json",
            fail_fast=False,
        )
        self.assertEqual(1, mergegrounds.run_profile(args))
        evidence = json.loads((self.fixture.root / ".mergegrounds/evidence/missing-artifact.json").read_text())
        self.assertEqual("deny", evidence["decision"])
        self.assertIn("unit-artifacts", {result["stage"] for result in evidence["results"]})

    def test_profile_cannot_hide_a_required_stage(self) -> None:
        profiles = self.fixture.root / ".mergegrounds/profiles"
        profiles.mkdir()
        (profiles / "fast.toml").write_text(
            'schema_version = 1\nid = "fast"\nstages = []\nrequired_stages = ["unit"]\n',
            encoding="utf-8",
        )
        args = argparse.Namespace(root=str(self.fixture.root), profile="fast", evidence=None, fail_fast=False)
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.run_profile(args)

    def test_mergegrounds_rejects_nested_git_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            nested = root / "nested"
            nested.mkdir()
            with self.assertRaises(mergegrounds.MergeGroundsError):
                mergegrounds.require_git_toplevel(nested)

    def test_attestation_checkboxes_are_not_admission_evidence(self) -> None:
        event = self.fixture.root / "event.json"
        _, config = mergegrounds.config_for(self.fixture.root)
        guidance = config["pull_request_guidance"]
        self.assertIs(guidance["authoritative"], False)
        markers = guidance["informational_prompts"]
        complete = "\n".join(f"- [x] {marker}" for marker in markers)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        base = subprocess.run(
            ["git", "rev-parse", "HEAD~1"],
            cwd=self.fixture.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        event.write_text(
            json.dumps(
                {
                    "pull_request": {
                        "body": complete,
                        "base": {"sha": base},
                        "head": {"sha": head},
                    }
                }
            ),
            encoding="utf-8",
        )
        args = argparse.Namespace(root=str(self.fixture.root), event=str(event))
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "change"):
            mergegrounds.attest_pr(args)

    def test_cli_parser_exposes_every_admission_operation(self) -> None:
        parser = mergegrounds.build_parser()
        for arguments, command in (
            (["doctor"], "doctor"),
            (["verify-repo"], "verify-repo"),
            (["seal"], "seal"),
            (["run", "--profile", "fast"], "run"),
            (["verify-change", "--event", "event.json"], "verify-change"),
            (["attest-pr", "--event", "event.json"], "attest-pr"),
        ):
            with self.subTest(command=command):
                self.assertEqual(command, parser.parse_args(arguments).command)

    def test_run_profile_orchestration_is_fail_closed_across_stage_failures(self) -> None:
        config_path = self.fixture.root / ".mergegrounds/mergegrounds.toml"

        def run_case(
            adapter: dict[str, object] | None,
            *,
            stages: list[str] | None = None,
            required: list[str] | None = None,
            execution: dict[str, object] | None = None,
            command_result: dict[str, object] | None = None,
            findings: list[mergegrounds.Finding] | None = None,
            metric_result: dict[str, object] | BaseException | None = None,
            artifact_result: dict[str, object] | BaseException | None = None,
            missing_commands: list[str] | None = None,
            file_issues: list[str] | None = None,
            source_states: list[dict[str, str] | BaseException] | None = None,
            prepare_error: BaseException | None = None,
            fail_fast: bool = False,
        ) -> int:
            selected_stages = stages or ["lint"]
            selected_required = required or list(selected_stages)
            config = {
                "risk_tier": "R3",
                "thresholds": {},
                "execution": execution
                or {
                    "require_git": False,
                    "require_clean_tree": False,
                    "timeout_seconds": 10,
                    "max_output_bytes": 1024,
                    "fail_fast": False,
                },
            }
            profile = {"stages": selected_stages, "required_stages": selected_required}
            adapters = [] if adapter is None else [adapter]
            result = command_result or {
                "adapter": "fixture",
                "stage": selected_stages[0],
                "status": "pass",
                "returncode": 0,
            }
            metric_value: dict[str, object] = {
                "adapter": "fixture",
                "stage": "coverage-metrics",
                "status": "pass",
                "violations": [],
            }
            metric_error: BaseException | None = None
            if isinstance(metric_result, BaseException):
                metric_error = metric_result
            elif isinstance(metric_result, dict):
                metric_value = metric_result
            artifact_value: dict[str, object] = {
                "adapter": "fixture",
                "stage": "lint-artifacts",
                "status": "pass",
            }
            artifact_error: BaseException | None = None
            if isinstance(artifact_result, BaseException):
                artifact_error = artifact_result
            elif isinstance(artifact_result, dict):
                artifact_value = artifact_result
            args = argparse.Namespace(
                root=str(self.fixture.root),
                profile="fast",
                evidence=None,
                fail_fast=fail_fast,
            )
            with (
                mock.patch.object(mergegrounds, "resolve_root", return_value=self.fixture.root),
                mock.patch.object(mergegrounds, "config_for", return_value=(config_path, config)),
                mock.patch.object(mergegrounds, "profile_config", return_value=profile),
                mock.patch.object(mergegrounds, "detected_adapters", return_value=adapters),
                mock.patch.object(mergegrounds, "environment_for", return_value=({}, [])),
                mock.patch.object(
                    mergegrounds,
                    "missing_tools",
                    return_value=missing_commands or [],
                ),
                mock.patch.object(
                    mergegrounds,
                    "toolchain_file_issues",
                    return_value=file_issues or [],
                ),
                mock.patch.object(mergegrounds, "git_value", return_value="a" * 40),
                mock.patch.object(
                    mergegrounds,
                    "git_source_state",
                    side_effect=source_states,
                ),
                mock.patch.object(mergegrounds, "run_command", return_value=result),
                mock.patch.object(mergegrounds, "verify_repository", return_value=findings or []),
                mock.patch.object(
                    mergegrounds,
                    "validate_metric",
                    return_value=metric_value,
                    side_effect=metric_error,
                ),
                mock.patch.object(
                    mergegrounds,
                    "validate_stage_artifacts",
                    return_value=artifact_value,
                    side_effect=artifact_error,
                ),
                mock.patch.object(mergegrounds, "tool_versions", return_value={}),
                mock.patch.object(mergegrounds, "artifact_records", return_value=[]),
                mock.patch.object(
                    mergegrounds,
                    "purge_output_files",
                    side_effect=prepare_error,
                ),
            ):
                return mergegrounds.run_profile(args)

        passing_adapter: dict[str, object] = {
            "id": "fixture",
            "commands": {"lint": ["true"]},
            "toolchain": {},
        }
        self.assertEqual(0, run_case(passing_adapter))
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "no stack adapter"):
            run_case(None)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "must be positive"):
            run_case(
                passing_adapter,
                execution={
                    "require_git": False,
                    "require_clean_tree": False,
                    "timeout_seconds": 0,
                    "max_output_bytes": 1,
                },
            )

        missing_stage = {"id": "fixture", "commands": {}, "toolchain": {}}
        self.assertEqual(1, run_case(missing_stage))
        invalid_commands = {"id": "fixture", "commands": "invalid", "toolchain": {}}
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "commands must be a table"):
            run_case(invalid_commands)
        self.assertEqual(
            1,
            run_case(
                passing_adapter,
                command_result={
                    "adapter": "fixture",
                    "stage": "lint",
                    "status": "fail",
                    "returncode": 1,
                },
            ),
        )

        policy_adapter = {"id": "fixture", "commands": {}, "toolchain": {}}
        self.assertEqual(
            1,
            run_case(
                policy_adapter,
                stages=["policy"],
                findings=[mergegrounds.Finding("DENY", "error", "blocked")],
            ),
        )
        self.assertEqual(
            0,
            run_case(
                policy_adapter,
                stages=["policy"],
                findings=[mergegrounds.Finding("NOTICE", "warning", "review")],
            ),
        )

        metric_adapter: dict[str, object] = {
            "id": "fixture",
            "commands": {"coverage": ["true"]},
            "metrics": {},
            "toolchain": {},
        }
        self.assertEqual(
            1,
            run_case(
                metric_adapter,
                stages=["coverage"],
                metric_result={
                    "adapter": "fixture",
                    "stage": "coverage-metrics",
                    "status": "fail",
                    "violations": ["below threshold"],
                },
            ),
        )
        self.assertEqual(
            1,
            run_case(
                metric_adapter,
                stages=["coverage"],
                metric_result=mergegrounds.MergeGroundsError("missing report"),
            ),
        )

        artifact_adapter: dict[str, object] = {
            "id": "fixture",
            "commands": {"lint": ["true"]},
            "artifacts": {"lint": ["reports/result.json"]},
            "toolchain": {},
        }
        self.assertEqual(
            1,
            run_case(
                artifact_adapter,
                artifact_result={
                    "adapter": "fixture",
                    "stage": "lint-artifacts",
                    "status": "fail",
                    "reason": "bad artifact",
                },
            ),
        )
        self.assertEqual(
            1,
            run_case(
                artifact_adapter,
                artifact_result=mergegrounds.MergeGroundsError("missing artifact"),
            ),
        )

        self.assertEqual(
            1,
            run_case(
                passing_adapter,
                missing_commands=["missing-tool"],
                file_issues=["lockfile missing"],
                fail_fast=True,
            ),
        )
        self.assertEqual(
            1,
            run_case(
                passing_adapter,
                prepare_error=mergegrounds.MergeGroundsError("unsafe output"),
            ),
        )

        git_execution = {
            "require_git": True,
            "require_clean_tree": True,
            "timeout_seconds": 10,
            "max_output_bytes": 1024,
            "fail_fast": False,
        }
        with mock.patch.object(mergegrounds, "require_git_toplevel"):
            self.assertEqual(
                1,
                run_case(
                    passing_adapter,
                    execution=git_execution,
                    source_states=[mergegrounds.MergeGroundsError("cannot bind source")],
                ),
            )
            initial = {"commit": "a" * 40, "tree": "b" * 40, "status": ""}
            self.assertEqual(
                1,
                run_case(
                    passing_adapter,
                    execution=git_execution,
                    source_states=[initial, mergegrounds.MergeGroundsError("final read failed")],
                ),
            )
            changed = {"commit": "c" * 40, "tree": "d" * 40, "status": "dirty"}
            self.assertEqual(
                1,
                run_case(
                    passing_adapter,
                    execution=git_execution,
                    source_states=[initial, changed],
                ),
            )

    def test_toolchain_file_contract_rejects_missing_symlinked_and_nonexecutables(self) -> None:
        root = self.fixture.root
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "toolchain must be a table"):
            mergegrounds.toolchain_file_issues({"id": "fixture", "toolchain": []}, root)
        for raw in ("../escape", str(root / "absolute")):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "repository-relative"):
                    mergegrounds.validate_toolchain_path(root, raw, "fixture")

        executable = root / "tool.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        regular = root / "lock.file"
        regular.write_text("locked\n", encoding="utf-8")
        non_executable = root / "not-executable"
        non_executable.write_text("no mode\n", encoding="utf-8")
        non_executable.chmod(0o644)

        adapter = {
            "id": "fixture",
            "toolchain": {
                "required_files": ["missing.lock", "lock.file"],
                "required_any_files": ["missing-a", "missing-b"],
                "required_any_globs": ["absent/*.lock"],
            },
            "commands": {
                "lint": ["./missing-tool lint", "./not-executable check", "./tool.sh ok"]
            },
        }
        issues = mergegrounds.toolchain_file_issues(adapter, root)
        self.assertTrue(any("missing required file missing.lock" in issue for issue in issues))
        self.assertTrue(any("none of required_any" in issue for issue in issues))
        self.assertTrue(any("missing local command missing-tool" in issue for issue in issues))
        self.assertTrue(any("not executable" in issue for issue in issues))

        alternative = root / "present.lock"
        alternative.write_text("present\n", encoding="utf-8")
        adapter["toolchain"] = {
            "required_files": ["lock.file"],
            "required_any_files": ["present.lock"],
            "required_any_globs": ["*.lock"],
        }
        adapter["commands"] = {"lint": ["X=1 ./tool.sh ok"]}
        self.assertEqual([], mergegrounds.toolchain_file_issues(adapter, root))

    def test_doctor_reports_missing_inputs_tools_and_weaker_adapter_thresholds(self) -> None:
        adapter = {
            "id": "fixture",
            "thresholds": {
                "line_coverage": 89,
                "branch_coverage": 84,
                "mutation_score": 84,
            },
        }
        config = {
            "execution": {"require_git": False},
            "thresholds": {
                "line_coverage": 90,
                "branch_coverage": 85,
                "mutation_score": 85,
            },
        }
        args = argparse.Namespace(root=str(self.fixture.root))
        with (
            mock.patch.object(mergegrounds, "resolve_root", return_value=self.fixture.root),
            mock.patch.object(mergegrounds, "config_for", return_value=(Path("config"), config)),
            mock.patch.object(mergegrounds, "detected_adapters", return_value=[adapter]),
            mock.patch.object(mergegrounds, "missing_tools", return_value=["missing"]),
            mock.patch.object(mergegrounds, "toolchain_file_issues", return_value=["bad lock"]),
        ):
            self.assertEqual(1, mergegrounds.doctor(args))
        with (
            mock.patch.object(mergegrounds, "resolve_root", return_value=self.fixture.root),
            mock.patch.object(mergegrounds, "config_for", return_value=(Path("config"), config)),
            mock.patch.object(mergegrounds, "detected_adapters", return_value=[]),
        ):
            self.assertEqual(1, mergegrounds.doctor(args))

    def test_command_runner_binds_timeout_truncation_and_spawn_errors(self) -> None:
        environment = {"PATH": os.environ.get("PATH", "")}
        truncated = mergegrounds.run_command(
            "python3 -c 'print(\"0123456789\")'",
            self.fixture.root,
            environment,
            10,
            4,
            "fixture",
            "unit",
        )
        self.assertEqual("fail", truncated["status"])
        self.assertEqual(125, truncated["returncode"])
        self.assertTrue(truncated["output_truncated"])
        self.assertGreater(truncated["output_bytes"], 4)

        timed_out = mergegrounds.run_command(
            "python3 -c 'import time; time.sleep(2)'",
            self.fixture.root,
            environment,
            0,
            1024,
            "fixture",
            "unit",
        )
        self.assertEqual("fail", timed_out["status"])
        self.assertEqual(124, timed_out["returncode"])
        self.assertTrue(timed_out["timed_out"])

        with mock.patch.object(mergegrounds.subprocess, "Popen", side_effect=OSError("spawn denied")):
            with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "cannot execute command"):
                mergegrounds.run_command(
                    "true",
                    self.fixture.root,
                    environment,
                    10,
                    1024,
                    "fixture",
                    "unit",
                )

    def test_profile_resolution_seal_command_and_main_fail_closed(self) -> None:
        root = self.fixture.root
        inline = {"stages": ["lint"], "required_stages": ["lint"]}
        self.assertEqual(
            inline,
            mergegrounds.profile_config(root, {"profiles": {"fast": inline}}, "fast"),
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "unknown profile"):
            mergegrounds.profile_config(root, {"profiles": {}}, "unknown")

        profile_path = root / ".mergegrounds/profiles/fast.toml"
        profile_path.parent.mkdir(exist_ok=True)
        profile_path.write_text(
            'schema_version = 1\nid = "fast"\n'
            'stages = ["format", "lint", "typecheck", "unit"]\n'
            'required_stages = ["format", "lint", "typecheck", "unit"]\n',
            encoding="utf-8",
        )
        self.assertEqual("fast", mergegrounds.profile_config(root, {"profiles": {}}, "fast")["id"])

        config: dict[str, object] = {}
        lock_path = root / ".mergegrounds/test-control-lock.json"
        args = argparse.Namespace(root=str(root), write=True)
        with (
            mock.patch.object(mergegrounds, "resolve_root", return_value=root),
            mock.patch.object(mergegrounds, "require_git_toplevel"),
            mock.patch.object(mergegrounds, "config_for", return_value=(Path("config"), config)),
            mock.patch.object(mergegrounds, "control_lock_path", return_value=lock_path),
            mock.patch.object(
                mergegrounds,
                "seal_payload",
                return_value={"schema_version": 2, "files": {"a": {}}},
            ),
        ):
            self.assertEqual(0, mergegrounds.seal_command(args))
        self.assertTrue(lock_path.is_file())

        args.write = False
        with (
            mock.patch.object(mergegrounds, "resolve_root", return_value=root),
            mock.patch.object(mergegrounds, "require_git_toplevel"),
            mock.patch.object(mergegrounds, "config_for", return_value=(Path("config"), config)),
            mock.patch.object(mergegrounds, "control_lock_path", return_value=lock_path),
            mock.patch.object(
                mergegrounds,
                "seal_findings",
                return_value=[mergegrounds.Finding("DRIFT", "error", "changed")],
            ),
        ):
            self.assertEqual(1, mergegrounds.seal_command(args))

        parser = mock.Mock()
        parser.parse_args.return_value = argparse.Namespace(handler=lambda _args: 7)
        with mock.patch.object(mergegrounds, "build_parser", return_value=parser):
            self.assertEqual(7, mergegrounds.main([]))
        parser.parse_args.return_value = argparse.Namespace(
            handler=mock.Mock(side_effect=mergegrounds.MergeGroundsError("denied"))
        )
        with mock.patch.object(mergegrounds, "build_parser", return_value=parser):
            self.assertEqual(2, mergegrounds.main([]))
        parser.parse_args.return_value = argparse.Namespace(
            handler=mock.Mock(side_effect=KeyboardInterrupt())
        )
        with mock.patch.object(mergegrounds, "build_parser", return_value=parser):
            self.assertEqual(130, mergegrounds.main([]))

    def test_repository_verifier_keeps_defense_in_depth_for_invalid_controls(self) -> None:
        root = self.fixture.root
        missing = "missing-control.txt"
        linked = root / "linked-control.txt"
        linked.symlink_to(root / ".mergegrounds/mergegrounds.toml")
        codeowners = root / ".github/CODEOWNERS"
        codeowners.write_text(
            "invalid-rule\n"
            "* invalid-owner\n"
            "/protected/ @different\n"
            "/late-override/ @different\n",
            encoding="utf-8",
        )
        config = {
            "risk_tier": "invalid",
            "fail_closed": False,
            "policy": {
                "required_files": [missing, "linked-control.txt"],
                "required_codeowners_patterns": ["*", "/protected/"],
            },
        }
        with (
            mock.patch.object(mergegrounds, "validate_config"),
            mock.patch.object(mergegrounds, "exception_findings", return_value=[]),
            mock.patch.object(mergegrounds, "workflow_findings", return_value=[]),
            mock.patch.object(mergegrounds, "seal_findings", return_value=[]),
        ):
            findings = mergegrounds.verify_repository(root, config)
        codes = {finding.code for finding in findings}
        self.assertTrue(
            {
                "RISK_TIER_INVALID",
                "FAIL_OPEN",
                "REQUIRED_FILE_MISSING",
                "CONTROL_SYMLINK",
                "OWNERSHIP_GAP",
                "OWNERSHIP_OVERRIDE",
                "OWNER_INVALID",
            }.issubset(codes)
        )


if __name__ == "__main__":
    unittest.main()
