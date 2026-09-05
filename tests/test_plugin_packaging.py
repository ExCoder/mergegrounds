from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path


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

    def test_update_rebinds_git_marketplace_to_an_explicit_immutable_ref(self) -> None:
        with mock.patch.object(manage_plugin, "command") as command:
            manage_plugin.update(
                "https://github.com/ExCoder/mergegrounds",
                "v1.1.0",
                False,
            )
        self.assertEqual(
            [
                mock.call(["codex", "plugin", "remove", "mergegrounds@mergegrounds", "--json"], False),
                mock.call(["codex", "plugin", "marketplace", "remove", "mergegrounds", "--json"], False),
                mock.call(
                    [
                        "codex",
                        "plugin",
                        "marketplace",
                        "add",
                        "https://github.com/ExCoder/mergegrounds",
                        "--ref",
                        "v1.1.0",
                        "--json",
                    ],
                    False,
                ),
                mock.call(["codex", "plugin", "add", "mergegrounds@mergegrounds", "--json"], False),
            ],
            command.call_args_list,
        )

    def test_local_update_reinstalls_without_git_marketplace_upgrade(self) -> None:
        with mock.patch.object(manage_plugin, "command") as command:
            manage_plugin.update(str(ROOT), None, False)
        flattened = [call.args[0] for call in command.call_args_list]
        self.assertNotIn(
            ["codex", "plugin", "marketplace", "upgrade", "mergegrounds", "--json"],
            flattened,
        )
        self.assertEqual(
            ["codex", "plugin", "marketplace", "add", str(ROOT), "--json"],
            flattened[2],
        )

    def test_git_update_requires_an_explicit_immutable_ref(self) -> None:
        with self.assertRaisesRegex(manage_plugin.PluginManagerError, "explicit immutable --ref"):
            manage_plugin.update(manage_plugin.DEFAULT_SOURCE, None, True)
        with self.assertRaisesRegex(manage_plugin.PluginManagerError, "immutable release tag or commit"):
            manage_plugin.update(manage_plugin.DEFAULT_SOURCE, "main", True)
        with self.assertRaisesRegex(manage_plugin.PluginManagerError, "local source does not accept"):
            manage_plugin.update(str(ROOT), "v1.1.0", True)

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

    def test_public_docs_lead_with_direct_cli_install_and_cover_status(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        installation = (ROOT / "docs/installation.md").read_text(encoding="utf-8")
        direct_marketplace = (
            "codex plugin marketplace add ExCoder/mergegrounds --ref v1.0.0 --json"
        )
        direct_plugin = "codex plugin add mergegrounds@mergegrounds --json"
        for document in (readme, installation):
            self.assertIn(direct_marketplace, document)
            self.assertIn(direct_plugin, document)
            self.assertLess(document.index(direct_marketplace), document.index("scripts/manage_plugin.py"))
        self.assertIn("scripts/manage_plugin.py status", installation)
        self.assertIn("scripts/manage_plugin.py update --ref v1.1.0", installation)
        self.assertIn("scripts/manage_plugin.py update --source .", installation)


if __name__ == "__main__":
    unittest.main()
