#!/usr/bin/env -S python3 -I
"""Install, update, inspect, or uninstall the bundled Codex plugin."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PLUGIN = "mergegrounds"
MARKETPLACE = "mergegrounds"
SELECTOR = f"{PLUGIN}@{MARKETPLACE}"
DEFAULT_SOURCE = "https://github.com/ExCoder/mergegrounds"
DEFAULT_REF = "v1.0.0"


class PluginManagerError(RuntimeError):
    """Raised when a requested plugin lifecycle operation fails."""


def validate_source(source: str) -> None:
    local = Path(source).expanduser()
    if local.exists():
        root = local.resolve(strict=True)
        manifest = root / ".codex-plugin/plugin.json"
        catalog = root / ".agents/plugins/marketplace.json"
        if not manifest.is_file() or not catalog.is_file():
            raise PluginManagerError("local source is not a complete MergeGrounds plugin repository")
        plugin = json.loads(manifest.read_text(encoding="utf-8"))
        marketplace = json.loads(catalog.read_text(encoding="utf-8"))
        if plugin.get("name") != PLUGIN or marketplace.get("name") != MARKETPLACE:
            raise PluginManagerError("local plugin or marketplace identity does not match")


def command(arguments: list[str], dry_run: bool) -> dict[str, Any] | None:
    print("+ " + " ".join(arguments))
    if dry_run:
        return None
    completed = subprocess.run(
        arguments,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise PluginManagerError(completed.stderr.strip() or completed.stdout.strip() or "Codex command failed")
    if completed.stdout.strip():
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError:
            print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
            return None
        if isinstance(value, dict):
            return value
    return None


def install(source: str, reference: str | None, dry_run: bool) -> None:
    validate_source(source)
    arguments = ["codex", "plugin", "marketplace", "add", source]
    if reference:
        arguments.extend(["--ref", reference])
    arguments.append("--json")
    command(arguments, dry_run)
    command(["codex", "plugin", "add", SELECTOR, "--json"], dry_run)


def update(dry_run: bool) -> None:
    command(["codex", "plugin", "marketplace", "upgrade", MARKETPLACE, "--json"], dry_run)
    command(["codex", "plugin", "remove", SELECTOR, "--json"], dry_run)
    command(["codex", "plugin", "add", SELECTOR, "--json"], dry_run)


def uninstall(remove_marketplace: bool, dry_run: bool) -> None:
    command(["codex", "plugin", "remove", SELECTOR, "--json"], dry_run)
    if remove_marketplace:
        command(
            ["codex", "plugin", "marketplace", "remove", MARKETPLACE, "--json"],
            dry_run,
        )


def status() -> None:
    for arguments in (
        ["codex", "plugin", "list", "--available", "--json"],
        ["codex", "plugin", "marketplace", "list", "--json"],
    ):
        value = command(arguments, False)
        if value is not None:
            print(json.dumps(value, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print mutating commands without running them")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help=f"local checkout or Git marketplace source (default: {DEFAULT_SOURCE})",
    )
    install_parser.add_argument(
        "--ref",
        help=f"immutable Git tag or commit (default for a Git source: {DEFAULT_REF})",
    )
    subparsers.add_parser("update")
    uninstall_parser = subparsers.add_parser("uninstall")
    uninstall_parser.add_argument("--keep-marketplace", action="store_true")
    subparsers.add_parser("status")
    arguments = parser.parse_args()
    if shutil.which("codex") is None:
        print("codex CLI is not available on PATH", file=sys.stderr)
        return 1
    try:
        if arguments.operation == "install":
            reference = arguments.ref
            if reference is None and not Path(arguments.source).expanduser().exists():
                reference = DEFAULT_REF
            install(arguments.source, reference, arguments.dry_run)
        elif arguments.operation == "update":
            update(arguments.dry_run)
        elif arguments.operation == "uninstall":
            uninstall(not arguments.keep_marketplace, arguments.dry_run)
        else:
            status()
    except (OSError, PluginManagerError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"plugin operation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
