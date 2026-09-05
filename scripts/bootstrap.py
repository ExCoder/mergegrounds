#!/usr/bin/env -S python3 -I
"""Preview and apply MergeGrounds controls to an existing repository."""

from __future__ import annotations

import argparse
import datetime as dt
import filecmp
import os
import secrets
import shutil
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parent.parent
CONTROL_ITEMS = (
    ".mergegrounds",
    ".github",
    "docs/decisions",
    "scripts",
    ".pre-commit-config.yaml",
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    "SECURITY.md",
)
SKIP_PARTS = {"backups", "__pycache__"}
SKIP_GENERATED_PREFIXES = {".mergegrounds/evidence/", ".mergegrounds/reports/"}
# These files make this source repository dogfood its own generic adapter. They
# must never activate that adapter in a newly bootstrapped target: the target
# remains fail-closed until its owners deliberately bind a real stack/harness.
SOURCE_ONLY_PATHS = {
    ".mergegrounds/custom.enabled",
    ".github/workflows/release.yml",
    "scripts/build_release.py",
    "scripts/manage_plugin.py",
    "scripts/self_check.py",
}
BOOTSTRAP_OVERRIDES = {
    ".github/CODEOWNERS": "templates/bootstrap/CODEOWNERS",
}
BACKUP_ROOT_ATTEMPTS = 32


class BootstrapError(RuntimeError):
    pass


@dataclass(frozen=True)
class Change:
    source: Path
    destination: Path
    status: str


def git_environment() -> dict[str, str]:
    """Return a Git environment without caller-controlled repository redirects."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def git_toplevel(path: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
            env=git_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    output = result.stdout.strip()
    if "\n" in output or "\x00" in output:
        return None
    try:
        return Path(output).resolve(strict=True)
    except OSError:
        return None


def is_git_repository(path: Path) -> bool:
    toplevel = git_toplevel(path)
    return toplevel is not None and toplevel == path.resolve()


def validate_target(raw: str, allow_non_git: bool) -> Path:
    target = Path(raw).resolve()
    if not target.is_dir():
        raise BootstrapError(f"target is not a directory: {target}")
    if target == Path(target.anchor) or target == Path.home().resolve():
        raise BootstrapError("refusing to use a filesystem root or home directory as target")
    source_root = SOURCE_ROOT.resolve()
    if target == source_root or source_root in target.parents:
        raise BootstrapError("target must not be the starter source or one of its descendants")
    enclosing_repository = git_toplevel(target)
    if enclosing_repository is not None and enclosing_repository != target:
        raise BootstrapError(
            f"target is nested inside Git worktree {enclosing_repository}; bootstrap the exact worktree root"
        )
    is_repository = enclosing_repository == target
    if not allow_non_git and not is_repository:
        raise BootstrapError("target is not a Git worktree; pass --allow-non-git only for a new empty project")
    if allow_non_git and not is_repository and any(target.iterdir()):
        raise BootstrapError("--allow-non-git is limited to a new empty project")
    return target


def destination_is_unsafe(target: Path, destination: Path) -> bool:
    try:
        parts = destination.absolute().relative_to(target.absolute()).parts
    except ValueError:
        return True
    current = target
    for part in parts:
        current = current / part
        if current.is_symlink():
            return True
    try:
        destination.resolve().relative_to(target.resolve())
    except ValueError:
        return True
    return False


def open_target_directory(target: Path, directory: Path, create: bool) -> int:
    try:
        parts = directory.absolute().relative_to(target.absolute()).parts
    except ValueError as exc:
        raise BootstrapError("target directory escaped repository root") from exc
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(target, flags)
    try:
        for part in parts:
            try:
                next_fd = os.open(part, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=directory_fd)
                next_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def open_target_file(target: Path, path: Path) -> int:
    directory_fd = open_target_directory(target, path.parent, create=False)
    try:
        return os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def copy_into_target(source: Path, destination: Path, target: Path, source_in_target: bool = False) -> None:
    """Copy through no-follow directory descriptors and atomically replace the target."""
    if os.name == "nt":  # pragma: no cover - Windows fallback
        if destination_is_unsafe(target, destination):
            raise BootstrapError(f"unsafe destination: {destination.relative_to(target)}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return
    source_fd = open_target_file(target, source) if source_in_target else os.open(
        source,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    directory_fd: int | None = None
    temporary_name: str | None = None
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise BootstrapError(f"copy source is not a regular file: {source}")
        directory_fd = open_target_directory(target, destination.parent, create=True)
        temporary_name = f".{destination.name}.{uuid.uuid4().hex}.tmp"
        destination_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            source_stat.st_mode & 0o777,
            dir_fd=directory_fd,
        )
        try:
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                offset = 0
                while offset < len(chunk):
                    offset += os.write(destination_fd, chunk[offset:])
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        os.replace(temporary_name, destination.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary_name = None
        os.fsync(directory_fd)
    except OSError as exc:
        raise BootstrapError(f"secure copy failed for {destination.relative_to(target)}: {exc}") from exc
    finally:
        if temporary_name is not None and directory_fd is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                # A concurrent cleanup may already have removed the unpublished file.
                pass
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(source_fd)


def source_files() -> list[Path]:
    values: list[Path] = []
    for item in CONTROL_ITEMS:
        path = SOURCE_ROOT / item
        if not path.exists():
            raise BootstrapError(f"starter is incomplete; missing source item: {item}")
        if path.is_symlink():
            raise BootstrapError(f"starter control item must not be a symlink: {item}")
        if path.is_file():
            values.append(path)
            continue
        for child in sorted(path.rglob("*")):
            relative_source = child.relative_to(SOURCE_ROOT)
            relative_parts = relative_source.parts
            if any(part in SKIP_PARTS for part in relative_parts):
                continue
            relative_name = relative_source.as_posix()
            if any(relative_name.startswith(prefix) for prefix in SKIP_GENERATED_PREFIXES):
                if relative_name != ".mergegrounds/evidence/.gitkeep":
                    continue
            if child.is_symlink():
                raise BootstrapError(f"starter control file must not be a symlink: {child}")
            if child.is_dir():
                continue
            if not child.is_file():
                raise BootstrapError(f"starter control item must be a regular file: {child}")
            values.append(child)
    return sorted(set(values))


def source_mappings() -> list[tuple[Path, Path]]:
    """Map reviewed source assets to target paths without leaking source bindings."""
    mappings: list[tuple[Path, Path]] = []
    for source in source_files():
        destination = source.relative_to(SOURCE_ROOT)
        destination_name = destination.as_posix()
        if destination_name in SOURCE_ONLY_PATHS:
            continue
        if destination_name in BOOTSTRAP_OVERRIDES:
            continue
        mappings.append((source, destination))

    for destination_name, source_name in sorted(BOOTSTRAP_OVERRIDES.items()):
        source = SOURCE_ROOT / source_name
        if not source.is_file() or source.is_symlink():
            raise BootstrapError(
                f"starter bootstrap override must be a regular file: {source_name}"
            )
        mappings.append((source, Path(destination_name)))
    return sorted(mappings, key=lambda item: item[1].as_posix())


def plan(target: Path) -> list[Change]:
    changes: list[Change] = []
    mappings = source_mappings()

    for source, destination_name in sorted(mappings, key=lambda item: item[1].as_posix()):
        destination = target / destination_name
        if destination_is_unsafe(target, destination):
            status = "unsafe-symlink"
        elif not destination.exists():
            status = "create"
        elif destination.is_file() and filecmp.cmp(source, destination, shallow=False):
            status = "identical"
        else:
            status = "conflict"
        changes.append(Change(source, destination, status))
    return changes


def show_plan(changes: list[Change], target: Path) -> None:
    counts: dict[str, int] = {}
    for change in changes:
        counts[change.status] = counts.get(change.status, 0) + 1
        if change.status != "identical":
            print(f"{change.status.upper():14} {change.destination.relative_to(target)}")
    summary = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
    print(f"\nPlan: {summary or 'no files'}")


def backup_conflicts(changes: list[Change], target: Path) -> Path | None:
    conflicts = [change for change in changes if change.status == "conflict"]
    if not conflicts:
        return None

    prepared: list[tuple[Change, Path]] = []
    for change in conflicts:
        if destination_is_unsafe(target, change.destination):
            raise BootstrapError(f"destination became unsafe before backup: {change.destination.relative_to(target)}")
        relative = change.destination.relative_to(target)
        if not change.destination.is_file():
            raise BootstrapError(f"cannot back up non-file conflict: {relative}")
        prepared.append((change, relative))

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_parent = target / ".mergegrounds" / "backups"
    if destination_is_unsafe(target, backup_parent):
        raise BootstrapError("backup directory traverses a symlink")

    backup_root: Path | None = None
    if os.name == "nt":  # pragma: no cover - Windows fallback
        backup_parent.mkdir(parents=True, exist_ok=True)
        for _ in range(BACKUP_ROOT_ATTEMPTS):
            candidate = backup_parent / f"bootstrap-{stamp}-{secrets.token_hex(16)}"
            try:
                candidate.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError:
                continue
            if destination_is_unsafe(target, candidate):
                raise BootstrapError("new backup root is unsafe")
            backup_root = candidate
            break
    else:
        parent_fd: int | None = None
        try:
            parent_fd = open_target_directory(target, backup_parent, create=True)
            for _ in range(BACKUP_ROOT_ATTEMPTS):
                name = f"bootstrap-{stamp}-{secrets.token_hex(16)}"
                try:
                    os.mkdir(name, mode=0o700, dir_fd=parent_fd)
                except FileExistsError:
                    continue
                os.fsync(parent_fd)
                backup_root = backup_parent / name
                break
        except OSError as exc:
            raise BootstrapError(f"could not create secure backup root: {exc}") from exc
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
    if backup_root is None:
        raise BootstrapError("could not allocate a unique backup root")

    for change, relative in prepared:
        backup = backup_root / relative
        if destination_is_unsafe(target, backup):
            raise BootstrapError(f"backup path traverses a symlink: {backup.relative_to(target)}")
        copy_into_target(change.destination, backup, target, source_in_target=True)
    return backup_root


def apply(changes: list[Change], target: Path, force: bool) -> None:
    unsafe = [change for change in changes if change.status == "unsafe-symlink"]
    if unsafe:
        names = ", ".join(str(item.destination.relative_to(target)) for item in unsafe)
        raise BootstrapError(f"refusing to replace symlink targets: {names}")
    conflicts = [change for change in changes if change.status == "conflict"]
    if conflicts and not force:
        raise BootstrapError("conflicts found; merge manually or rerun with reviewed --force (creates backups)")
    backup_root = backup_conflicts(changes, target) if force else None
    for change in changes:
        if change.status == "identical":
            continue
        if destination_is_unsafe(target, change.destination):
            raise BootstrapError(f"destination became unsafe before copy: {change.destination.relative_to(target)}")
        copy_into_target(change.source, change.destination, target)
    if backup_root:
        print(f"backups: {backup_root.relative_to(target)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=os.getcwd(), help="target repository (default: current directory)")
    parser.add_argument("--apply", action="store_true", help="apply the displayed plan")
    parser.add_argument("--force", action="store_true", help="replace conflicts after backing them up; requires --apply")
    parser.add_argument("--allow-non-git", action="store_true", help="allow a non-Git target for a new project")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.force and not args.apply:
            raise BootstrapError("--force requires --apply")
        target = validate_target(args.target, args.allow_non_git)
        changes = plan(target)
        show_plan(changes, target)
        if not args.apply:
            print("Dry run only. Review conflicts, then rerun with --apply.")
            return 0
        apply(changes, target, args.force)
        print("MergeGrounds controls applied. Review adapter commands, update CODEOWNERS, seal the control plane, then run verify-repo.")
        return 0
    except BootstrapError as exc:
        print(f"bootstrap: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
