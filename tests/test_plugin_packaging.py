from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "manage_plugin_under_test",
    ROOT / "scripts/manage_plugin.py",
)
assert SPEC and SPEC.loader
manage_plugin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = manage_plugin
SPEC.loader.exec_module(manage_plugin)


class PluginPackagingTests(unittest.TestCase):
    def test_version_and_lifecycle_documentation_are_consistent(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        manifest = json.loads((ROOT / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], version)
        installation = (ROOT / "docs/installation.md").read_text(encoding="utf-8")
        for operation in ("install", "update", "uninstall"):
            self.assertIn(f"scripts/manage_plugin.py {operation}", installation)

    def test_repo_marketplace_resolves_to_complete_plugin_root(self) -> None:
        marketplace_path = ROOT / ".agents/plugins/marketplace.json"
        marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
        self.assertEqual("mergegrounds", marketplace["name"])
        self.assertEqual({"displayName": "MergeGrounds"}, marketplace["interface"])
        self.assertEqual(1, len(marketplace["plugins"]))

        entry = marketplace["plugins"][0]
        self.assertEqual("mergegrounds", entry["name"])
        self.assertEqual(
            {"source": "local", "path": "./"},
            entry["source"],
        )
        self.assertEqual(
            {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
            entry["policy"],
        )
        self.assertEqual("Developer Tools", entry["category"])

        plugin_root = (ROOT / entry["source"]["path"]).resolve(strict=True)
        self.assertEqual(ROOT.resolve(), plugin_root)
        manifest = json.loads(
            (plugin_root / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
        )
        self.assertEqual(entry["name"], manifest["name"])
        for required in (
            "scripts/mergegrounds.py",
            "scripts/ai_assurance.py",
            ".mergegrounds/mergegrounds.toml",
            "skills/mergegrounds/SKILL.md",
        ):
            self.assertTrue((plugin_root / required).is_file(), required)

        self.assertEqual(
            "https://github.com/ExCoder/mergegrounds",
            manifest["repository"],
        )
        self.assertEqual(
            "https://mergegrounds.chawax.chatgpt.site",
            manifest["homepage"],
        )

    def test_lifecycle_source_validation_and_dry_run_are_side_effect_free(self) -> None:
        manage_plugin.validate_source(str(ROOT))
        manage_plugin.validate_source("https://github.com/OWNER/REPOSITORY.git")
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(manage_plugin.PluginManagerError, "complete MergeGrounds"):
                manage_plugin.validate_source(raw)
        with mock.patch.object(manage_plugin.subprocess, "run") as run:
            self.assertIsNone(manage_plugin.command(["codex", "plugin", "list"], True))
        run.assert_not_called()

    def test_public_install_defaults_to_the_immutable_v1_release(self) -> None:
        self.assertEqual("https://github.com/ExCoder/mergegrounds", manage_plugin.DEFAULT_SOURCE)
        self.assertEqual("v1.0.0", manage_plugin.DEFAULT_REF)
        self.assertEqual("mergegrounds@mergegrounds", manage_plugin.SELECTOR)

    def test_lifecycle_command_parses_json_and_fails_closed_on_cli_error(self) -> None:
        success = subprocess.CompletedProcess(
            ["codex"],
            0,
            stdout='{"status":"ok"}\n',
            stderr="",
        )
        with mock.patch.object(manage_plugin.subprocess, "run", return_value=success):
            self.assertEqual(
                {"status": "ok"},
                manage_plugin.command(["codex", "plugin", "list"], False),
            )
        failure = subprocess.CompletedProcess(["codex"], 2, stdout="", stderr="denied\n")
        with mock.patch.object(manage_plugin.subprocess, "run", return_value=failure):
            with self.assertRaisesRegex(manage_plugin.PluginManagerError, "denied"):
                manage_plugin.command(["codex", "plugin", "list"], False)

    def test_status_prints_both_machine_readable_results(self) -> None:
        with (
            mock.patch.object(
                manage_plugin,
                "command",
                side_effect=[{"plugins": []}, {"marketplaces": []}],
            ) as command,
            mock.patch("builtins.print") as output,
        ):
            manage_plugin.status()
        self.assertEqual(2, command.call_count)
        rendered = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn('"plugins": []', rendered)
        self.assertIn('"marketplaces": []', rendered)


if __name__ == "__main__":
    unittest.main()
