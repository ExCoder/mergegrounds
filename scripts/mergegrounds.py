#!/usr/bin/env -S python3 -I
"""MergeGrounds: dependency-free, fail-closed repository gate runner."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import fnmatch
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - version guard
    raise SystemExit("MergeGrounds requires Python 3.11 or newer") from exc


SCHEMA_VERSION = 1
CONTROL_LOCK_SCHEMA_VERSION = 2
SENSITIVE_ENV = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIALS?|AUTH|COOKIE|SESSION|API[_-]?KEY|ACCESS[_-]?KEY)(?:_|$)",
    re.IGNORECASE,
)
ACTION_REF = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
MAX_REPORT_BYTES = 100 * 1024 * 1024
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
MAX_CODEOWNERS_BYTES = 3 * 1024 * 1024
MAX_EVENT_BYTES = 4 * 1024 * 1024
MAX_CHANGE_CONTRACT_BYTES = 128 * 1024
MAX_DESIGN_CONTRACT_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_POLICY_BYTES = 2 * 1024 * 1024
MAX_TREE_LIST_BYTES = 64 * 1024 * 1024
MAX_CONTROL_LOCK_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 4096
MAX_EVIDENCE_NODES = 250_000
MAX_JSON_STRING_BYTES = 32 * 1024
MAX_EVIDENCE_FUTURE_SKEW_SECONDS = 5 * 60
MAX_EVIDENCE_NORMALIZATION_DELAY_SECONDS = 60 * 60
MAX_EVIDENCE_RUN_OVERHEAD_SECONDS = 15 * 60
MAX_EVIDENCE_RUN_DURATION_SECONDS = 24 * 60 * 60
KNOWN_STAGES = {"policy", "format", "lint", "typecheck", "unit", "coverage", "mutation", "security", "fuzz", "build"}
TRX_NAMESPACE = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"
GO_COVER_RECORD = re.compile(
    r"^(?P<source>.+):(?P<start_line>[0-9]+)\.(?P<start_col>[0-9]+),"
    r"(?P<end_line>[0-9]+)\.(?P<end_col>[0-9]+) "
    r"(?P<statements>[0-9]+) (?P<executions>[0-9]+)$"
)
FORBIDDEN_XML_DECLARATION = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
CANONICAL_EVIDENCE_DIRECTORY = ".mergegrounds/evidence"
CANONICAL_CONTROL_LOCK = ".mergegrounds/control-plane.lock.json"
CANONICAL_CHANGE_GLOB = ".mergegrounds/changes/*.json"
CANONICAL_DESIGN_GLOB = "docs/decisions/*.json"
CHANGE_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
CONTRACT_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
SHA256_VALUE = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40,64}$")
TRUSTED_ADMISSION_WORKFLOW_SHA256 = {
    ".github/workflows/mergegrounds.yml": "5dd3aeafaf218ef0b4f6f5a97fc7e91a4952299c37595ba4648b1d019c8f0bc2",
    ".github/workflows/full-scan.yml": "bb18b0e0c38e0b57df38d6919a3faae6021ea11ff07d16c80a8d8b2de355cb78",
    ".github/workflows/codeql.yml": "64e4bc11a1209d51073267d9d9c480e573aa459ecff35246de95ec169ae41b49",
    ".github/workflows/release.yml": "9dc2d0631bfba66e56cb19772c9bedfa41cef1d386e99162d206cb16a57848bc",
}
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
RISK_ORDER = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}
ALLOWED_IMPACT_FLAGS = {
    "application_code",
    "authentication",
    "authorization",
    "business_logic",
    "control_plane",
    "cryptography",
    "data",
    "dependencies",
    "documentation",
    "infrastructure",
    "privacy",
    "ai_agent_tools",
    "ai_context",
    "ai_retrieval",
    "ai_training",
}
ACCEPTED_ORACLE_KINDS = {"test", "metric", "external_review"}
ACCEPTED_EVIDENCE_CLASSES = {"trusted_execution", "independent_human", "external_verifier"}
FORBIDDEN_EVIDENCE_CLASSES = {
    "author_assertion",
    "chain_of_thought",
    "model_confidence",
    "model_output",
    "model_reasoning",
    "self_review",
}
CONTRACT_DRAFT_PLACEHOLDER = re.compile(
    r"(?:\bEDIT[\s_-]+ME\b|\bTODO\b|\bTBD\b|"
    r"__MERGEGROUNDS_TEMPLATE(?:_DRAFT)?__|\bMERGEGROUNDS_TEMPLATE_SENTINEL\b)",
    re.IGNORECASE,
)
MINIMUM_PROFILE_STAGES = {
    "fast": {"format", "lint", "typecheck", "unit"},
    "pr": {"policy", "format", "lint", "typecheck", "unit", "coverage", "mutation", "security", "build"},
    "full": {"policy", "format", "lint", "typecheck", "unit", "coverage", "mutation", "security", "fuzz", "build"},
}
DEFAULT_INFORMATIONAL_PROMPTS = {
    "AI-assisted",
    "Tests added/updated",
    "Security impact reviewed",
    "No secrets",
    "Evidence attached",
}
# Deprecated import compatibility for v1 policy fixtures. These strings are UX
# prompts only; neither this alias nor legacy config can satisfy admission.
MINIMUM_ATTESTATION_MARKERS = DEFAULT_INFORMATIONAL_PROMPTS
MINIMUM_POLICY_MEMBERS = {
    "required_files": {
        ".mergegrounds/ai-assurance.toml",
        ".mergegrounds/LICENSE.mergegrounds",
        ".mergegrounds/README.mergegrounds.md",
        ".mergegrounds/mergegrounds.toml",
        ".mergegrounds/changes/README.md",
        ".mergegrounds/exceptions.toml",
        ".mergegrounds/schemas/ai-assurance.example.toml",
        ".github/CODEOWNERS",
        ".github/dependabot.yml",
        ".github/ISSUE_TEMPLATE/design-review.yml",
        ".github/pull_request_template.md",
        ".github/workflows/codeql.yml",
        ".github/workflows/full-scan.yml",
        ".github/workflows/mergegrounds.yml",
        ".github/workflows/scorecard.yml",
        ".gitignore",
        ".pre-commit-config.yaml",
        "scripts/apply-github-ruleset.sh",
        "scripts/ai_assurance.py",
        "scripts/mergegrounds.py",
        "scripts/scaffold_change.py",
        "docs/decisions/README.md",
        "SECURITY.md",
    },
    "required_codeowners_patterns": {
        "*",
        "/.codex-plugin/",
        "/.agents/",
        "/.github/",
        "/.mergegrounds/",
        "/.gitattributes",
        "/mergegrounds-custom",
        "/scripts/",
        "/skills/mergegrounds/",
        "/SECURITY.md",
    },
    "critical_paths": {
        ".codex-plugin/plugin.json",
        ".agents/plugins/marketplace.json",
        ".gitattributes",
        ".gitignore",
        ".pre-commit-config.yaml",
        ".mergegrounds/ai-assurance.toml",
        ".mergegrounds/LICENSE.mergegrounds",
        ".mergegrounds/README.mergegrounds.md",
        ".mergegrounds/custom.enabled",
        ".mergegrounds/mergegrounds.toml",
        ".mergegrounds/changes/README.md",
        ".mergegrounds/exceptions.toml",
        ".mergegrounds/adapters/*.toml",
        ".mergegrounds/profiles/*.toml",
        ".mergegrounds/schemas/ai-assurance.example.toml",
        ".github/CODEOWNERS",
        ".github/dependabot.yml",
        ".github/ISSUE_TEMPLATE/design-review.yml",
        ".github/pull_request_template.md",
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "GOVERNANCE.md",
        "README.md",
        "mergegrounds-custom",
        "scripts/**",
        "docs/installation.md",
        "docs/releasing.md",
        "docs/decisions/README.md",
        "skills/mergegrounds/**/*",
        "SECURITY.md",
    },
}
MINIMUM_THRESHOLDS = {
    "line_coverage": 90.0,
    "branch_coverage": 85.0,
    "mutation_score": 85.0,
    "critical_mutation_score": 100.0,
}
REQUIRED_EXECUTION_CONTROLS = {
    "sanitize_environment": True,
    "require_git": True,
    "require_clean_tree": True,
}
REQUIRED_MUTATION_CONTROLS = {
    "fail_on_survived": True,
    "fail_on_not_covered": True,
    "fail_on_timeout": True,
    "fail_on_invalid": True,
    "fail_on_unviable": True,
    "allow_ignored": False,
}
CONTROL_AUTHORITY_DOMAINS = {
    "MG-META-001": {"governance"},
    "MG-META-002": {"governance"},
    "MG-META-003": {"governance"},
    "MG-SRC-001": {"governance"},
    "MG-SRC-002": {"governance"},
    "MG-SRC-003": {"governance"},
    "MG-CTL-001": {"governance"},
    "MG-QLT-001": {"quality"},
    "MG-QLT-002": {"quality"},
    "MG-QLT-003": {"quality"},
    "MG-QLT-004": {"coverage"},
    "MG-QLT-005": {"quality"},
    "MG-QLT-006": {"quality"},
    "MG-QLT-007": {"quality"},
    "MG-QLT-008": {"quality"},
    "MG-SEC-001": {"security"},
    "MG-SEC-002": {"privacy", "security"},
    "MG-SEC-003": {"license", "security", "supply-chain"},
    "MG-SEC-004": {"privacy", "security"},
    "MG-SEC-005": {"privacy", "security"},
    "MG-SUP-001": {"supply-chain"},
    "MG-SUP-002": {"supply-chain"},
    "MG-REV-001": {"governance"},
    "MG-REV-002": {"governance"},
    "MG-OPS-001": {"reliability"},
    "MG-EXC-001": {"governance"},
    "MG-AI-001": {"governance", "privacy", "security"},
    "MG-AI-002": {"governance", "quality", "reliability"},
    "MG-AI-003": {"privacy", "quality", "security"},
    "MG-AI-004": {"quality", "reliability"},
    "MG-AI-005": {"quality", "reliability", "security", "supply-chain"},
    "MG-AI-006": {"privacy", "security", "supply-chain"},
    "MG-AI-007": {"privacy", "reliability", "security"},
    "MG-AI-008": {"governance", "reliability", "security"},
}
CONTROL_DOMAIN_CLASSES = {
    "governance": {"XQ", "XM"},
    "quality": {"XQ", "XM"},
    "coverage": {"XQ", "XM"},
    "reliability": {"XR", "XM"},
    "security": {"XS", "XM"},
    "privacy": {"XS", "XM"},
    "supply-chain": {"XS", "XM"},
    "license": {"XS", "XM"},
}
CONTROL_DOMAIN_SPECIALIST_ROLES = {
    "governance": {"platform-owner", "security-owner"},
    "quality": {"quality-owner", "testing-owner"},
    "coverage": {"quality-owner", "testing-owner"},
    "reliability": {"operations-owner", "platform-owner", "release-owner"},
    "security": {"security-owner"},
    "privacy": {"data-owner", "privacy-owner"},
    "supply-chain": {"platform-owner", "security-owner"},
    "license": {"legal-owner"},
}
EXCEPTION_ROLES = {
    "domain-owner",
    "service-owner",
    "quality-owner",
    "testing-owner",
    "security-owner",
    "platform-owner",
    "operations-owner",
    "release-owner",
    "data-owner",
    "privacy-owner",
    "legal-owner",
}


class MergeGroundsError(RuntimeError):
    """A configuration or execution error that must fail closed."""


@dataclasses.dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    path: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise MergeGroundsError(f"required TOML file is missing: {path}")
    if path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise MergeGroundsError(f"required TOML policy/data file must not be executable: {path}")
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise MergeGroundsError(f"cannot parse {path}: {exc}") from exc
    if value.get("schema_version") != SCHEMA_VERSION:
        raise MergeGroundsError(
            f"unsupported schema_version in {path}: expected {SCHEMA_VERSION}"
        )
    return value


def resolve_root(raw: str | None) -> Path:
    root = Path(raw or os.getcwd()).resolve()
    if not root.is_dir():
        raise MergeGroundsError(f"repository root is not a directory: {root}")
    return root


def relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def has_symlink_component(path: Path, root: Path) -> bool:
    """Return true when a repository-relative path traverses any symlink."""
    try:
        parts = path.absolute().relative_to(root.absolute()).parts
    except ValueError:
        return True
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def is_regular_repo_file(path: Path, root: Path) -> bool:
    return (
        path.is_file()
        and not has_symlink_component(path, root)
        and is_within(path.resolve(), root)
    )


def evidence_directory(root: Path, config: dict[str, Any]) -> Path:
    evidence = config.get("evidence", {})
    if not isinstance(evidence, dict):
        raise MergeGroundsError("evidence must be a TOML table")
    raw = evidence.get("directory", CANONICAL_EVIDENCE_DIRECTORY)
    if raw != CANONICAL_EVIDENCE_DIRECTORY:
        raise MergeGroundsError(
            f"evidence.directory must be exactly {CANONICAL_EVIDENCE_DIRECTORY!r}"
        )
    value = Path(CANONICAL_EVIDENCE_DIRECTORY)
    path = root / value
    if has_symlink_component(path, root) or not is_within(path.resolve(), root):
        raise MergeGroundsError("evidence.directory must remain inside the repository without symlinks")
    return path


def ensure_output_path(raw: str, root: Path, config: dict[str, Any]) -> Path:
    value = Path(raw)
    if value.is_absolute() or ".." in value.parts:
        raise MergeGroundsError("evidence output must be repository-relative")
    path = root / value
    directory = evidence_directory(root, config)
    try:
        path.absolute().relative_to(directory.absolute())
    except ValueError as exc:
        raise MergeGroundsError(f"evidence output must be below {relative(directory, root)}") from exc
    if path == directory or path.suffix.lower() != ".json":
        raise MergeGroundsError("evidence output must name a .json file")
    if has_symlink_component(path, root) or not is_within(path.resolve(), directory):
        raise MergeGroundsError("evidence output must remain inside the configured directory without symlinks")
    return path


def git_environment() -> dict[str, str]:
    """Return a Git environment without inherited repository-redirection state."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def git_command(*args: str) -> list[str]:
    """Build a non-interactive Git command with unsafe local accelerators disabled."""
    return [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "submodule.recurse=false",
        "-c",
        "diff.external=",
        *args,
    ]


def git_value(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            git_command(*args),
            cwd=root,
            env=git_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def git_checked(
    root: Path,
    *args: str,
    allow_empty: bool = False,
    strip_output: bool = True,
) -> str:
    try:
        result = subprocess.run(
            git_command(*args),
            cwd=root,
            env=git_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MergeGroundsError(f"Git command could not complete: git {' '.join(args)}") from exc
    output = result.stdout.strip() if strip_output else result.stdout
    if result.returncode != 0:
        detail = (result.stderr.strip().splitlines() or ["unknown Git failure"])[-1][:300]
        raise MergeGroundsError(f"Git command failed: git {' '.join(args)}: {detail}")
    if not allow_empty and not output:
        raise MergeGroundsError(f"Git command returned no value: git {' '.join(args)}")
    return output


def git_bytes_checked(root: Path, *args: str, maximum_bytes: int) -> bytes:
    try:
        result = subprocess.run(
            git_command(*args),
            cwd=root,
            env=git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MergeGroundsError(f"Git command could not complete: git {' '.join(args)}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        raise MergeGroundsError(
            f"Git command failed: git {' '.join(args)}: {(detail or ['unknown Git failure'])[-1][:300]}"
        )
    if len(result.stdout) > maximum_bytes:
        raise MergeGroundsError(f"Git command output exceeds the {maximum_bytes}-byte limit")
    return result.stdout


def validate_git_revision(root: Path, revision: str, label: str) -> str:
    if not isinstance(revision, str) or not GIT_OBJECT_ID.fullmatch(revision):
        raise MergeGroundsError(f"{label} must be a lowercase 40-64 character Git object id")
    resolved = git_checked(root, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if not GIT_OBJECT_ID.fullmatch(resolved):
        raise MergeGroundsError(f"{label} did not resolve to a commit")
    return resolved


def canonical_contract_path(raw: Any, prefix: str, identifier: str, label: str) -> str:
    path = contract_text(raw, label)
    expected = f"{prefix}/{identifier}.json"
    if path != expected:
        raise MergeGroundsError(f"{label} must be exactly {expected!r}")
    return path


def git_blob_bytes(
    root: Path,
    revision: str,
    path: str,
    label: str,
    maximum_bytes: int,
) -> bytes:
    if path.startswith("/") or ".." in Path(path).parts or "\\" in path or ":" in path:
        raise MergeGroundsError(f"{label} path is not canonical")
    entry = git_checked(root, "ls-tree", revision, "--", path, allow_empty=True)
    match = re.fullmatch(r"100644 blob ([0-9a-f]{40,64})\t(.+)", entry)
    if not match or match.group(2) != path:
        raise MergeGroundsError(f"{label} must be a non-executable regular Git blob at {revision}")
    size_raw = git_checked(root, "cat-file", "-s", f"{revision}:{path}")
    if not size_raw.isdigit():
        raise MergeGroundsError(f"{label} Git blob has an invalid size")
    size = int(size_raw)
    if size <= 0 or size > maximum_bytes:
        raise MergeGroundsError(f"{label} Git blob must be between 1 and {maximum_bytes} bytes")
    raw = git_bytes_checked(
        root,
        "cat-file",
        "blob",
        f"{revision}:{path}",
        maximum_bytes=maximum_bytes,
    )
    if len(raw) != size:
        raise MergeGroundsError(f"{label} Git blob size changed while reading")
    return raw


def git_diff_entries(root: Path, base: str, head: str) -> list[tuple[str, str]]:
    raw = git_bytes_checked(
        root,
        "diff",
        "--name-status",
        "--no-renames",
        "-z",
        base,
        head,
        "--",
        maximum_bytes=4 * 1024 * 1024,
    )
    if not raw:
        raise MergeGroundsError("pull request contains no changed paths")
    tokens = raw.split(b"\0")
    if tokens[-1] != b"" or (len(tokens) - 1) % 2:
        raise MergeGroundsError("Git returned malformed name-status data")
    result: list[tuple[str, str]] = []
    for index in range(0, len(tokens) - 1, 2):
        try:
            status = tokens[index].decode("ascii")
            path = tokens[index + 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MergeGroundsError("changed paths and statuses must be UTF-8") from exc
        if status not in {"A", "D", "M", "T", "U"}:
            raise MergeGroundsError(f"unsupported Git change status: {status!r}")
        if not path or path.startswith("/") or ".." in Path(path).parts or "\x00" in path:
            raise MergeGroundsError("Git returned a non-canonical changed path")
        result.append((status, path))
    return result


def require_git_toplevel(root: Path) -> None:
    top = Path(git_checked(root, "rev-parse", "--show-toplevel")).resolve()
    if top != root.resolve():
        raise MergeGroundsError(f"repository root must equal Git top-level: {top}")


def git_source_state(root: Path, excluded_directory: Path | None = None) -> dict[str, str]:
    # Retain the optional argument for callers of older releases, but deliberately
    # ignore it. Source identity must never be scoped by candidate-controlled
    # configuration; generated evidence belongs in the repository's ignored,
    # canonical evidence directory instead.
    _ = excluded_directory
    status = git_checked(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        ".",
        allow_empty=True,
    )
    return {
        "commit": git_checked(root, "rev-parse", "--verify", "HEAD^{commit}"),
        "tree": git_checked(root, "write-tree"),
        "status": status,
    }


def config_for(root: Path) -> tuple[Path, dict[str, Any]]:
    path = root / ".mergegrounds" / "mergegrounds.toml"
    if has_symlink_component(path, root) or not is_within(path.resolve(), root):
        raise MergeGroundsError("mergegrounds configuration must be a regular in-repository file")
    value = load_toml(path)
    validate_config(value)
    validate_external_profile_parity(root, value)
    return path, value


def as_string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise MergeGroundsError(f"{field} must be a string or an array of strings")


def strict_json_document(
    raw: bytes,
    label: str,
    maximum_bytes: int,
    *,
    maximum_nodes: int = MAX_JSON_NODES,
    maximum_string_bytes: int = MAX_JSON_STRING_BYTES,
) -> dict[str, Any]:
    """Parse bounded JSON with deterministic, closed-world semantics."""
    if not raw:
        raise MergeGroundsError(f"{label} is empty")
    if len(raw) > maximum_bytes:
        raise MergeGroundsError(f"{label} exceeds the {maximum_bytes}-byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MergeGroundsError(f"{label} must be UTF-8") from exc
    if text.startswith("\ufeff"):
        raise MergeGroundsError(f"{label} must not contain a UTF-8 byte-order mark")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def finite_float(number: str) -> float:
        value = float(number)
        if not math.isfinite(value):
            raise ValueError(f"non-finite JSON number: {number}")
        return value

    try:
        value = json.loads(
            text,
            parse_constant=reject_constant,
            parse_float=finite_float,
            object_pairs_hook=unique_object,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise MergeGroundsError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise MergeGroundsError(f"{label} root must be an object")

    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > maximum_nodes:
            raise MergeGroundsError(f"{label} exceeds the {maximum_nodes}-node limit")
        if depth > MAX_JSON_DEPTH:
            raise MergeGroundsError(f"{label} exceeds the maximum nesting depth {MAX_JSON_DEPTH}")
        if isinstance(item, str):
            try:
                string_bytes = item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise MergeGroundsError(f"{label} contains invalid Unicode text") from exc
            if len(string_bytes) > maximum_string_bytes:
                raise MergeGroundsError(
                    f"{label} contains a string larger than {maximum_string_bytes} bytes"
                )
        elif isinstance(item, dict):
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)

    visit(value, 0)
    return value


def bounded_regular_bytes(path: Path, label: str, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise MergeGroundsError(f"{label} is missing") from exc
    except OSError as exc:
        raise MergeGroundsError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise MergeGroundsError(f"{label} must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
            raise MergeGroundsError(f"{label} must be between 1 and {maximum_bytes} bytes")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise MergeGroundsError(f"{label} ended before its declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise MergeGroundsError(f"{label} grew while it was being read")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise MergeGroundsError(f"{label} changed while it was being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def exact_object(
    value: Any,
    label: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MergeGroundsError(f"{label} must be an object")
    allowed = required | (optional or set())
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing:
        raise MergeGroundsError(f"{label} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise MergeGroundsError(f"{label} contains unsupported fields: {', '.join(sorted(unknown))}")
    return value


def contract_text(value: Any, label: str, minimum: int = 1) -> str:
    if not isinstance(value, str) or value != value.strip() or len(value) < minimum:
        raise MergeGroundsError(f"{label} must be trimmed text of at least {minimum} characters")
    if "\x00" in value:
        raise MergeGroundsError(f"{label} must not contain NUL")
    if CONTRACT_DRAFT_PLACEHOLDER.search(value):
        raise MergeGroundsError(f"{label} contains an unresolved draft placeholder")
    return value


def contract_string_list(
    value: Any,
    label: str,
    *,
    minimum_items: int = 1,
    allowed: set[str] | None = None,
) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) < minimum_items
        or not all(isinstance(item, str) and item and item == item.strip() for item in value)
        or len(value) != len(set(value))
    ):
        raise MergeGroundsError(f"{label} must be a unique non-empty string array")
    for index, item in enumerate(value):
        contract_text(item, f"{label}[{index}]")
    if allowed is not None:
        unsupported = set(value) - allowed
        if unsupported:
            raise MergeGroundsError(f"{label} contains unsupported values: {', '.join(sorted(unsupported))}")
    return value


def contract_id(value: Any, label: str) -> str:
    text = contract_text(value, label)
    if not CONTRACT_ID.fullmatch(text):
        raise MergeGroundsError(f"{label} must be an uppercase stable id such as AC-1")
    return text


def validate_config(config: dict[str, Any]) -> None:
    if type(config.get("schema_version")) is not int or config["schema_version"] != SCHEMA_VERSION:
        raise MergeGroundsError(f"schema_version must be the integer {SCHEMA_VERSION}")
    if config.get("fail_closed") is not True:
        raise MergeGroundsError("fail_closed must be the TOML boolean true")
    if config.get("risk_tier") not in {"R0", "R1", "R2", "R3", "R4"}:
        raise MergeGroundsError("risk_tier must be one of R0, R1, R2, R3, or R4")
    table_names = (
        "execution",
        "evidence",
        "thresholds",
        "mutation_policy",
        "pull_request_guidance",
        # Accepted only as a deprecated v1 UX alias; never used for admission.
        "attestation",
        "change_control",
        "policy",
    )
    for name in table_names:
        value = config.get(name, {})
        if not isinstance(value, dict):
            raise MergeGroundsError(f"{name} must be a TOML table")

    evidence = config.get("evidence", {})
    if evidence.get("directory", CANONICAL_EVIDENCE_DIRECTORY) != CANONICAL_EVIDENCE_DIRECTORY:
        raise MergeGroundsError(
            f"evidence.directory must be exactly {CANONICAL_EVIDENCE_DIRECTORY!r}"
        )

    exact_change_controls = {
        "declaration_glob": CANONICAL_CHANGE_GLOB,
        "design_glob": CANONICAL_DESIGN_GLOB,
        "require_design_in_base": True,
        "allow_design_only_lane": True,
        "claims_satisfy_controls": False,
        "model_output_satisfies_controls": False,
        "self_review_satisfies_controls": False,
        "external_root_of_trust": "required-for-maximum-assurance",
    }
    # Older stack adapters/config fixtures need not declare these values: absence
    # selects the hard-coded secure policy, never a weaker policy.
    change_control = config.get("change_control") or {
        **exact_change_controls,
        "design_required_tiers": ["R0", "R1", "R2", "R3", "R4"],
    }
    unknown_change_controls = set(change_control) - (
        set(exact_change_controls) | {"design_required_tiers"}
    )
    if unknown_change_controls:
        raise MergeGroundsError(
            "change_control contains unsupported keys: "
            + ", ".join(sorted(unknown_change_controls))
        )
    for key, expected in exact_change_controls.items():
        observed = change_control.get(key)
        if (
            (type(expected) is bool and observed is not expected)
            or (type(expected) is not bool and observed != expected)
        ):
            raise MergeGroundsError(f"change_control.{key} must be {expected!r}")
    design_required_tiers = change_control.get("design_required_tiers")
    if design_required_tiers != ["R0", "R1", "R2", "R3", "R4"]:
        raise MergeGroundsError(
            "change_control.design_required_tiers must require design for every risk tier"
        )

    execution = config.get("execution", {})
    for key in ("sanitize_environment", "require_git", "require_clean_tree", "fail_fast"):
        if key in execution and type(execution[key]) is not bool:
            raise MergeGroundsError(f"execution.{key} must be a TOML boolean")
    for key in ("timeout_seconds", "max_output_bytes"):
        if key in execution and (
            isinstance(execution[key], bool)
            or not isinstance(execution[key], int)
            or execution[key] <= 0
        ):
            raise MergeGroundsError(f"execution.{key} must be a positive integer")
    if "allowed_environment" in execution:
        allowed = execution["allowed_environment"]
        if not isinstance(allowed, list) or not all(isinstance(item, str) and item for item in allowed):
            raise MergeGroundsError("execution.allowed_environment must be a string array")
        unsafe_allowed = sorted(item for item in allowed if SENSITIVE_ENV.search(item))
        if unsafe_allowed:
            raise MergeGroundsError(
                "execution.allowed_environment must not exempt sensitive names: "
                + ", ".join(unsafe_allowed)
            )
    for key, expected in REQUIRED_EXECUTION_CONTROLS.items():
        if execution.get(key) is not expected:
            raise MergeGroundsError(f"execution.{key} must remain {str(expected).lower()}")

    mutation = config.get("mutation_policy", {})
    for key in (
        "fail_on_survived",
        "fail_on_not_covered",
        "fail_on_timeout",
        "fail_on_invalid",
        "fail_on_unviable",
        "allow_ignored",
    ):
        if key in mutation and type(mutation[key]) is not bool:
            raise MergeGroundsError(f"mutation_policy.{key} must be a TOML boolean")
    for key, expected in REQUIRED_MUTATION_CONTROLS.items():
        if mutation.get(key) is not expected:
            raise MergeGroundsError(f"mutation_policy.{key} must remain {str(expected).lower()}")

    thresholds = config.get("thresholds", {})
    for key, value in thresholds.items():
        number = finite_number(value, f"thresholds.{key}")
        if not 0.0 <= number <= 100.0:
            raise MergeGroundsError(f"thresholds.{key} must be between 0 and 100")
    if "critical_mutation_score" in thresholds and "mutation_score" in thresholds:
        if float(thresholds["critical_mutation_score"]) < float(thresholds["mutation_score"]):
            raise MergeGroundsError("critical_mutation_score must not be weaker than mutation_score")
    for key, floor in MINIMUM_THRESHOLDS.items():
        if key not in thresholds or finite_number(thresholds[key], f"thresholds.{key}") < floor:
            raise MergeGroundsError(f"thresholds.{key} must be at least {floor:g}")

    profiles = config.get("profiles")
    if not isinstance(profiles, dict):
        raise MergeGroundsError("profiles must be a TOML table")
    missing_profiles = set(MINIMUM_PROFILE_STAGES) - set(profiles)
    if missing_profiles:
        raise MergeGroundsError(
            "profiles must define the secure minimum profiles: "
            + ", ".join(sorted(missing_profiles))
        )
    for profile_name, profile in profiles.items():
        validate_profile(profile, str(profile_name), f"profiles.{profile_name}")

    guidance = config.get("pull_request_guidance")
    if guidance is not None:
        exact_object(
            guidance,
            "pull_request_guidance",
            {"authoritative", "informational_prompts"},
        )
        if guidance["authoritative"] is not False:
            raise MergeGroundsError(
                "pull_request_guidance.authoritative must be false; PR prompts are not admission evidence"
            )
        prompts = guidance["informational_prompts"]
        if (
            not isinstance(prompts, list)
            or not prompts
            or not all(isinstance(prompt, str) and prompt.strip() == prompt and prompt for prompt in prompts)
            or len(prompts) != len(set(prompts))
        ):
            raise MergeGroundsError(
                "pull_request_guidance.informational_prompts must be a non-empty unique string array"
            )

    # v1 parser compatibility only. This table is absent from the v2 policy and
    # has no call path into verify-change or any admission decision.
    legacy_attestation = config.get("attestation")
    if legacy_attestation is not None:
        markers = legacy_attestation.get("required_markers")
        if (
            not isinstance(markers, list)
            or not markers
            or not all(isinstance(marker, str) and marker for marker in markers)
            or len(markers) != len(set(markers))
        ):
            raise MergeGroundsError(
                "deprecated attestation.required_markers must be a non-empty unique UX string array"
            )
        missing_markers = DEFAULT_INFORMATIONAL_PROMPTS - set(markers)
        if missing_markers:
            raise MergeGroundsError(
                "deprecated attestation.required_markers is missing default informational prompts: "
                + ", ".join(sorted(missing_markers))
            )

    policy = config.get("policy", {})
    for key, must_have in MINIMUM_POLICY_MEMBERS.items():
        values = policy.get(key)
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and value for value in values)
            or len(values) != len(set(values))
        ):
            raise MergeGroundsError(f"policy.{key} must be a non-empty unique string array")
        missing_values = must_have - set(values)
        if missing_values:
            raise MergeGroundsError(
                f"policy.{key} is missing secure minimum members: "
                + ", ".join(sorted(missing_values))
            )
    if policy.get("control_lock") != CANONICAL_CONTROL_LOCK:
        raise MergeGroundsError(f"policy.control_lock must be exactly {CANONICAL_CONTROL_LOCK!r}")


def validate_profile(profile: Any, expected_id: str, field: str) -> None:
    if not isinstance(profile, dict):
        raise MergeGroundsError(f"{field} must be a TOML table")
    if "id" in profile and profile["id"] != expected_id:
        raise MergeGroundsError(f"{field}.id must be {expected_id!r}")
    for key in ("stages", "required_stages"):
        value = profile.get(key)
        if not isinstance(value, list) or not value or not all(isinstance(item, str) and item in KNOWN_STAGES for item in value):
            raise MergeGroundsError(f"{field}.{key} must be a non-empty array of known stages")
        if len(value) != len(set(value)):
            raise MergeGroundsError(f"{field}.{key} must not contain duplicates")
    missing = set(profile["required_stages"]) - set(profile["stages"])
    if missing:
        raise MergeGroundsError(f"{field}.required_stages are absent from stages: {', '.join(sorted(missing))}")
    missing_minimum = MINIMUM_PROFILE_STAGES.get(expected_id, set()) - set(profile["required_stages"])
    if missing_minimum:
        raise MergeGroundsError(
            f"{field}.required_stages is missing secure minimum stages: "
            + ", ".join(sorted(missing_minimum))
        )


def validate_external_profile_parity(root: Path, config: dict[str, Any]) -> None:
    """Prevent an external profile file from silently overriding inline policy."""
    profiles = config.get("profiles")
    if not isinstance(profiles, dict):
        raise MergeGroundsError("profiles must be a TOML table")
    profile_directory = root / ".mergegrounds" / "profiles"
    if not profile_directory.exists():
        return
    if has_symlink_component(profile_directory, root) or not profile_directory.is_dir():
        raise MergeGroundsError(".mergegrounds/profiles must be an in-repository directory without symlinks")
    for profile_path in sorted(profile_directory.glob("*.toml")):
        if not is_regular_repo_file(profile_path, root):
            raise MergeGroundsError(f"profile must be a regular in-repository file: {profile_path}")
        profile_id = profile_path.stem
        inline = profiles.get(profile_id)
        if not isinstance(inline, dict):
            raise MergeGroundsError(
                f"external profile {profile_id!r} has no matching inline profiles.{profile_id} policy"
            )
        external = load_toml(profile_path)
        validate_profile(external, profile_id, str(profile_path))
        for key in ("stages", "required_stages"):
            if external.get(key) != inline.get(key):
                raise MergeGroundsError(
                    f"external profile {profile_id!r} {key} must exactly match inline profiles.{profile_id}.{key} order and values"
                )


def unique_contract_ids(values: Any, label: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise MergeGroundsError(f"{label} must be a non-empty array")
    result = [contract_id(item, f"{label}[{index}]") for index, item in enumerate(values)]
    if len(result) != len(set(result)):
        raise MergeGroundsError(f"{label} must not contain duplicate ids")
    return result


def validate_design_contract(value: dict[str, Any], expected_id: str) -> dict[str, Any]:
    label = "design contract"
    exact_object(
        value,
        label,
        {
            "schema_version",
            "design_id",
            "title",
            "problem",
            "goals",
            "non_goals",
            "decisions",
            "invariants",
            "trust_boundaries",
            "failure_modes",
            "rollback",
            "observability",
            "evaluation",
        },
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise MergeGroundsError("design contract schema_version must be the integer 1")
    design_id = contract_text(value["design_id"], "design contract.design_id")
    if design_id != expected_id or not CHANGE_ID.fullmatch(design_id):
        raise MergeGroundsError("design contract.design_id must match its lowercase UUID filename")
    contract_text(value["title"], "design contract.title", 8)
    contract_text(value["problem"], "design contract.problem", 20)
    contract_string_list(value["goals"], "design contract.goals")
    contract_string_list(value["non_goals"], "design contract.non_goals")

    decisions = value["decisions"]
    if not isinstance(decisions, list) or not decisions:
        raise MergeGroundsError("design contract.decisions must be a non-empty array")
    decision_ids: list[str] = []
    for index, item in enumerate(decisions):
        item_label = f"design contract.decisions[{index}]"
        exact_object(item, item_label, {"id", "choice", "alternatives", "rationale"})
        decision_ids.append(contract_id(item["id"], f"{item_label}.id"))
        contract_text(item["choice"], f"{item_label}.choice", 8)
        contract_string_list(item["alternatives"], f"{item_label}.alternatives")
        contract_text(item["rationale"], f"{item_label}.rationale", 12)
    if len(decision_ids) != len(set(decision_ids)):
        raise MergeGroundsError("design contract decision ids must be unique")

    invariants = value["invariants"]
    if not isinstance(invariants, list) or not invariants:
        raise MergeGroundsError("design contract.invariants must be a non-empty array")
    invariant_ids: list[str] = []
    for index, item in enumerate(invariants):
        item_label = f"design contract.invariants[{index}]"
        exact_object(item, item_label, {"id", "statement", "verification_ref"})
        invariant_ids.append(contract_id(item["id"], f"{item_label}.id"))
        contract_text(item["statement"], f"{item_label}.statement", 12)
        contract_id(item["verification_ref"], f"{item_label}.verification_ref")
    if len(invariant_ids) != len(set(invariant_ids)):
        raise MergeGroundsError("design contract invariant ids must be unique")

    boundaries = value["trust_boundaries"]
    if not isinstance(boundaries, list) or not boundaries:
        raise MergeGroundsError("design contract.trust_boundaries must be a non-empty array")
    boundary_ids: list[str] = []
    for index, item in enumerate(boundaries):
        item_label = f"design contract.trust_boundaries[{index}]"
        exact_object(item, item_label, {"id", "source", "target", "data", "controls"})
        boundary_ids.append(contract_id(item["id"], f"{item_label}.id"))
        for field in ("source", "target", "data"):
            contract_text(item[field], f"{item_label}.{field}", 3)
        contract_string_list(item["controls"], f"{item_label}.controls")
    if len(boundary_ids) != len(set(boundary_ids)):
        raise MergeGroundsError("design contract trust-boundary ids must be unique")

    failure_modes = value["failure_modes"]
    if not isinstance(failure_modes, list) or not failure_modes:
        raise MergeGroundsError("design contract.failure_modes must be a non-empty array")
    failure_ids: list[str] = []
    failure_definitions: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(failure_modes):
        item_label = f"design contract.failure_modes[{index}]"
        exact_object(
            item,
            item_label,
            {"id", "condition", "expected_behavior", "detection_ref", "rollback_trigger"},
        )
        failure_id = contract_id(item["id"], f"{item_label}.id")
        failure_ids.append(failure_id)
        contract_text(item["condition"], f"{item_label}.condition", 12)
        contract_text(item["expected_behavior"], f"{item_label}.expected_behavior", 12)
        contract_id(item["detection_ref"], f"{item_label}.detection_ref")
        contract_text(item["rollback_trigger"], f"{item_label}.rollback_trigger", 12)
        failure_definitions[failure_id] = item
    if len(failure_ids) != len(set(failure_ids)):
        raise MergeGroundsError("design contract failure-mode ids must be unique")

    rollback = exact_object(value["rollback"], "design contract.rollback", {"strategy", "triggers", "verification_ref"})
    contract_text(rollback["strategy"], "design contract.rollback.strategy", 12)
    contract_string_list(rollback["triggers"], "design contract.rollback.triggers")
    contract_id(rollback["verification_ref"], "design contract.rollback.verification_ref")

    observability = exact_object(value["observability"], "design contract.observability", {"signals"})
    signals = observability["signals"]
    if not isinstance(signals, list) or not signals:
        raise MergeGroundsError("design contract.observability.signals must be a non-empty array")
    signal_ids: list[str] = []
    for index, item in enumerate(signals):
        item_label = f"design contract.observability.signals[{index}]"
        exact_object(item, item_label, {"id", "name", "decision_use"})
        signal_ids.append(contract_id(item["id"], f"{item_label}.id"))
        contract_text(item["name"], f"{item_label}.name", 3)
        contract_text(item["decision_use"], f"{item_label}.decision_use", 8)
    if len(signal_ids) != len(set(signal_ids)):
        raise MergeGroundsError("design contract observability signal ids must be unique")

    evaluation = exact_object(
        value["evaluation"],
        "design contract.evaluation",
        {"acceptance_criteria", "outcome_metrics"},
    )
    design_criteria = evaluation["acceptance_criteria"]
    if not isinstance(design_criteria, list) or not design_criteria:
        raise MergeGroundsError("design contract.evaluation.acceptance_criteria must be a non-empty array")
    acceptance_ids: list[str] = []
    acceptance_definitions: dict[str, dict[str, Any]] = {}
    acceptance_oracles: dict[str, tuple[str, str]] = {}
    for index, item in enumerate(design_criteria):
        item_label = f"design contract.evaluation.acceptance_criteria[{index}]"
        exact_object(item, item_label, {"id", "class", "observable", "oracle", "failure_behavior"})
        acceptance_id = contract_id(item["id"], f"{item_label}.id")
        acceptance_ids.append(acceptance_id)
        if item["class"] not in {"positive", "negative", "adversarial", "recovery"}:
            raise MergeGroundsError(f"{item_label}.class is unsupported")
        contract_text(item["observable"], f"{item_label}.observable", 12)
        contract_text(item["failure_behavior"], f"{item_label}.failure_behavior", 12)
        oracle = exact_object(item["oracle"], f"{item_label}.oracle", {"kind", "ref", "evidence_class"})
        if oracle["kind"] not in ACCEPTED_ORACLE_KINDS:
            raise MergeGroundsError(f"{item_label}.oracle.kind is unsupported")
        oracle_ref = contract_id(oracle["ref"], f"{item_label}.oracle.ref")
        if oracle["evidence_class"] not in ACCEPTED_EVIDENCE_CLASSES:
            raise MergeGroundsError(f"{item_label}.oracle.evidence_class is not independently produced evidence")
        acceptance_oracles[acceptance_id] = (oracle_ref, item["class"])
        acceptance_definitions[acceptance_id] = item
    if len(acceptance_ids) != len(set(acceptance_ids)):
        raise MergeGroundsError("design contract acceptance criterion ids must be unique")
    if {"positive", "negative", "adversarial", "recovery"} - {
        item["class"] for item in design_criteria
    }:
        raise MergeGroundsError("design contract must define positive, negative, adversarial, and recovery criteria")
    outcome_metrics = evaluation["outcome_metrics"]
    if not isinstance(outcome_metrics, list) or not outcome_metrics:
        raise MergeGroundsError("design contract.evaluation.outcome_metrics must be a non-empty array")
    outcome_metric_ids: list[str] = []
    for index, item in enumerate(outcome_metrics):
        item_label = f"design contract.evaluation.outcome_metrics[{index}]"
        exact_object(
            item,
            item_label,
            {
                "id",
                "observable",
                "source",
                "evidence_class",
                "baseline_window",
                "observation_window",
                "direction",
                "target",
                "unit",
                "minimum_samples",
                "maximum_missing_percent",
                "promotion_blocking",
                "failure_action",
            },
        )
        outcome_metric_ids.append(contract_id(item["id"], f"{item_label}.id"))
        contract_text(item["observable"], f"{item_label}.observable", 12)
        contract_text(item["source"], f"{item_label}.source", 4)
        if item["evidence_class"] not in {"trusted_execution", "external_verifier"}:
            raise MergeGroundsError(f"{item_label}.evidence_class must be trusted telemetry evidence")
        for window in ("baseline_window", "observation_window"):
            raw_window = contract_text(item[window], f"{item_label}.{window}")
            if not re.fullmatch(r"[1-9][0-9]*(?:m|h|d|w)", raw_window):
                raise MergeGroundsError(f"{item_label}.{window} must be a positive bounded duration")
        if item["direction"] not in {"decrease", "increase", "not_regress"}:
            raise MergeGroundsError(f"{item_label}.direction is unsupported")
        finite_number(item["target"], f"{item_label}.target")
        contract_text(item["unit"], f"{item_label}.unit", 1)
        if type(item["minimum_samples"]) is not int or item["minimum_samples"] < 20:
            raise MergeGroundsError(f"{item_label}.minimum_samples must be at least 20")
        maximum_missing = finite_number(
            item["maximum_missing_percent"], f"{item_label}.maximum_missing_percent"
        )
        if not 0 <= maximum_missing <= 5:
            raise MergeGroundsError(f"{item_label}.maximum_missing_percent must be between 0 and 5")
        if item["promotion_blocking"] is not True:
            raise MergeGroundsError(f"{item_label}.promotion_blocking must be true")
        if item["failure_action"] not in {"deny_promotion", "rollback", "quarantine"}:
            raise MergeGroundsError(f"{item_label}.failure_action is unsupported")
    if len(outcome_metric_ids) != len(set(outcome_metric_ids)):
        raise MergeGroundsError("design contract outcome metric ids must be unique")
    verification_refs = {
        *(item["verification_ref"] for item in invariants),
        rollback["verification_ref"],
    }
    unknown_refs = verification_refs - set(acceptance_ids)
    if unknown_refs:
        raise MergeGroundsError(
            "design contract verification refs are absent from evaluation.acceptance_criteria: "
            + ", ".join(sorted(unknown_refs))
        )
    for failure_id, item in failure_definitions.items():
        detection_ref = item["detection_ref"]
        matching = [
            acceptance_id
            for acceptance_id, (oracle_ref, _) in acceptance_oracles.items()
            if oracle_ref == detection_ref
        ]
        if not matching or any(acceptance_oracles[item_id][1] == "positive" for item_id in matching):
            raise MergeGroundsError(
                f"design contract failure mode {failure_id} must reference a negative, adversarial, or recovery oracle"
            )
    return {
        "acceptance_ids": set(acceptance_ids),
        "failure_mode_ids": set(failure_ids),
        "outcome_metric_ids": set(outcome_metric_ids),
        "acceptance_definitions": acceptance_definitions,
        "failure_definitions": failure_definitions,
    }


def validate_change_contract(
    value: dict[str, Any],
    expected_id: str,
    config: dict[str, Any],
    changed_paths: list[str],
) -> dict[str, Any]:
    label = "change declaration"
    exact_object(
        value,
        label,
        {
            "schema_version",
            "change_id",
            "lane",
            "risk",
            "summary",
            "design",
            "acceptance_criteria",
            "failure_modes",
            "challenge_plan",
            "outcome_metric_ids",
            "evidence_policy",
            "ai_assistance",
        },
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise MergeGroundsError("change declaration schema_version must be the integer 1")
    change_id = contract_text(value["change_id"], "change declaration.change_id")
    if change_id != expected_id or not CHANGE_ID.fullmatch(change_id):
        raise MergeGroundsError("change declaration.change_id must match its lowercase UUID filename")
    if value["lane"] not in {"implementation", "design-only"}:
        raise MergeGroundsError("change declaration.lane must be implementation or design-only")

    risk = exact_object(value["risk"], "change declaration.risk", {"claimed_tier", "impact_flags", "rationale"})
    tier = risk["claimed_tier"]
    if tier not in RISK_ORDER:
        raise MergeGroundsError("change declaration.risk.claimed_tier must be R0 through R4")
    baseline = config.get("risk_tier")
    if tier not in RISK_ORDER or baseline not in RISK_ORDER or RISK_ORDER[tier] < RISK_ORDER[baseline]:
        raise MergeGroundsError(f"change declaration risk tier {tier} is below repository baseline {baseline}")
    impact_flags = contract_string_list(
        risk["impact_flags"],
        "change declaration.risk.impact_flags",
        allowed=ALLOWED_IMPACT_FLAGS,
    )
    contract_text(risk["rationale"], "change declaration.risk.rationale", 20)
    critical_patterns = as_string_list(
        config.get("policy", {}).get("critical_paths"), "policy.critical_paths"
    )
    if critical_control_paths_changed(changed_paths, critical_patterns) and tier != "R4":
        raise MergeGroundsError("changes to a critical control-plane path require risk tier R4")
    if "control_plane" in impact_flags and tier != "R4":
        raise MergeGroundsError("control_plane impact requires risk tier R4")

    summary = exact_object(value["summary"], "change declaration.summary", {"problem", "approach", "non_goals"})
    contract_text(summary["problem"], "change declaration.summary.problem", 20)
    contract_text(summary["approach"], "change declaration.summary.approach", 20)
    contract_string_list(summary["non_goals"], "change declaration.summary.non_goals")

    design = exact_object(value["design"], "change declaration.design", {"record_id", "record_path", "record_sha256"})
    record_id = contract_text(design["record_id"], "change declaration.design.record_id")
    if not CHANGE_ID.fullmatch(record_id):
        raise MergeGroundsError("change declaration.design.record_id must be a lowercase UUID")
    record_path = canonical_contract_path(
        design["record_path"], "docs/decisions", record_id, "change declaration.design.record_path"
    )
    if not isinstance(design["record_sha256"], str) or not SHA256_VALUE.fullmatch(design["record_sha256"]):
        raise MergeGroundsError("change declaration.design.record_sha256 must be sha256:<64 lowercase hex>")

    criteria = value["acceptance_criteria"]
    if not isinstance(criteria, list) or not criteria:
        raise MergeGroundsError("change declaration.acceptance_criteria must be a non-empty array")
    criterion_ids: list[str] = []
    oracle_refs: dict[str, str] = {}
    criterion_classes: dict[str, str] = {}
    acceptance_definitions: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(criteria):
        item_label = f"change declaration.acceptance_criteria[{index}]"
        exact_object(item, item_label, {"id", "class", "observable", "oracle", "failure_behavior"})
        criterion = contract_id(item["id"], f"{item_label}.id")
        criterion_ids.append(criterion)
        criterion_class = item["class"]
        if criterion_class not in {"positive", "negative", "adversarial", "recovery"}:
            raise MergeGroundsError(f"{item_label}.class is unsupported")
        criterion_classes[criterion] = criterion_class
        contract_text(item["observable"], f"{item_label}.observable", 12)
        contract_text(item["failure_behavior"], f"{item_label}.failure_behavior", 12)
        oracle = exact_object(item["oracle"], f"{item_label}.oracle", {"kind", "ref", "evidence_class"})
        if oracle["kind"] not in ACCEPTED_ORACLE_KINDS:
            raise MergeGroundsError(f"{item_label}.oracle.kind is unsupported")
        oracle_ref = contract_id(oracle["ref"], f"{item_label}.oracle.ref")
        evidence_class = oracle["evidence_class"]
        if evidence_class in FORBIDDEN_EVIDENCE_CLASSES or evidence_class not in ACCEPTED_EVIDENCE_CLASSES:
            raise MergeGroundsError(
                f"{item_label}.oracle.evidence_class must name independently produced evidence"
            )
        oracle_refs[criterion] = oracle_ref
        acceptance_definitions[criterion] = item
    if len(criterion_ids) != len(set(criterion_ids)):
        raise MergeGroundsError("change declaration acceptance criterion ids must be unique")
    required_classes = {"positive", "negative"}
    if RISK_ORDER[tier] >= RISK_ORDER["R3"]:
        required_classes |= {"adversarial", "recovery"}
    missing_classes = required_classes - set(criterion_classes.values())
    if missing_classes:
        raise MergeGroundsError(
            f"risk tier {tier} requires acceptance classes: " + ", ".join(sorted(missing_classes))
        )

    failure_modes = value["failure_modes"]
    if not isinstance(failure_modes, list) or not failure_modes:
        raise MergeGroundsError("change declaration.failure_modes must be a non-empty array")
    failure_ids: list[str] = []
    failure_definitions: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(failure_modes):
        item_label = f"change declaration.failure_modes[{index}]"
        exact_object(
            item,
            item_label,
            {"id", "condition", "expected_behavior", "detection_ref", "rollback_trigger"},
        )
        failure_id = contract_id(item["id"], f"{item_label}.id")
        failure_ids.append(failure_id)
        contract_text(item["condition"], f"{item_label}.condition", 12)
        contract_text(item["expected_behavior"], f"{item_label}.expected_behavior", 12)
        detection_ref = contract_id(item["detection_ref"], f"{item_label}.detection_ref")
        matching = [key for key, ref in oracle_refs.items() if ref == detection_ref]
        if not matching or any(criterion_classes[key] == "positive" for key in matching):
            raise MergeGroundsError(
                f"{item_label}.detection_ref must reference a negative, adversarial, or recovery oracle"
            )
        contract_text(item["rollback_trigger"], f"{item_label}.rollback_trigger", 12)
        failure_definitions[failure_id] = item
    if len(failure_ids) != len(set(failure_ids)):
        raise MergeGroundsError("change declaration failure-mode ids must be unique")

    challenges = value["challenge_plan"]
    if not isinstance(challenges, list) or not challenges:
        raise MergeGroundsError("change declaration.challenge_plan must be a non-empty array")
    challenge_ids: list[str] = []
    for index, item in enumerate(challenges):
        item_label = f"change declaration.challenge_plan[{index}]"
        exact_object(
            item,
            item_label,
            {"id", "claim_to_falsify", "attack_surface", "evaluation_ref", "required_producer"},
        )
        challenge_ids.append(contract_id(item["id"], f"{item_label}.id"))
        contract_text(item["claim_to_falsify"], f"{item_label}.claim_to_falsify", 12)
        contract_text(item["attack_surface"], f"{item_label}.attack_surface", 8)
        evaluation_ref = contract_id(item["evaluation_ref"], f"{item_label}.evaluation_ref")
        adversarial_refs = {
            oracle_refs[key]
            for key, criterion_class in criterion_classes.items()
            if criterion_class == "adversarial"
        }
        if evaluation_ref not in adversarial_refs:
            raise MergeGroundsError(f"{item_label}.evaluation_ref must reference an adversarial oracle")
        producer = item["required_producer"]
        if producer in FORBIDDEN_EVIDENCE_CLASSES or producer not in ACCEPTED_EVIDENCE_CLASSES:
            raise MergeGroundsError(f"{item_label}.required_producer is not independent evidence")
    if len(challenge_ids) != len(set(challenge_ids)):
        raise MergeGroundsError("change declaration challenge ids must be unique")

    outcome_metric_ids = unique_contract_ids(
        value["outcome_metric_ids"], "change declaration.outcome_metric_ids"
    )

    evidence_policy = exact_object(
        value["evidence_policy"],
        "change declaration.evidence_policy",
        {"author_claims_are_evidence", "model_output_is_evidence", "self_review_is_evidence"},
    )
    for field in ("author_claims_are_evidence", "model_output_is_evidence", "self_review_is_evidence"):
        if evidence_policy[field] is not False:
            raise MergeGroundsError(f"change declaration.evidence_policy.{field} must be false")

    ai = exact_object(value["ai_assistance"], "change declaration.ai_assistance", {"used", "systems", "affected_paths"})
    if type(ai["used"]) is not bool:
        raise MergeGroundsError("change declaration.ai_assistance.used must be a boolean")
    systems = ai["systems"]
    if not isinstance(systems, list):
        raise MergeGroundsError("change declaration.ai_assistance.systems must be an array")
    if ai["used"] != bool(systems):
        raise MergeGroundsError("AI systems must be listed exactly when ai_assistance.used is true")
    for index, system in enumerate(systems):
        item_label = f"change declaration.ai_assistance.systems[{index}]"
        exact_object(system, item_label, {"provider", "model", "purposes"})
        contract_text(system["provider"], f"{item_label}.provider", 2)
        contract_text(system["model"], f"{item_label}.model", 2)
        contract_string_list(system["purposes"], f"{item_label}.purposes")
    affected_paths = contract_string_list(
        ai["affected_paths"],
        "change declaration.ai_assistance.affected_paths",
        minimum_items=1 if ai["used"] else 0,
    )
    for path in affected_paths:
        if path.startswith("/") or ".." in Path(path).parts or "\\" in path:
            raise MergeGroundsError("AI-assisted paths must be canonical repository-relative patterns")

    return {
        "lane": value["lane"],
        "tier": tier,
        "record_id": record_id,
        "record_path": record_path,
        "record_sha256": design["record_sha256"],
        "acceptance_ids": set(criterion_ids),
        "failure_mode_ids": set(failure_ids),
        "acceptance_definitions": acceptance_definitions,
        "failure_definitions": failure_definitions,
        "outcome_metric_ids": set(outcome_metric_ids),
    }


def validate_change_between(
    root: Path,
    config: dict[str, Any],
    base_revision: str,
    head_revision: str,
) -> dict[str, Any]:
    base = validate_git_revision(root, base_revision, "base revision")
    head = validate_git_revision(root, head_revision, "head revision")
    try:
        git_checked(root, "merge-base", "--is-ancestor", base, head, allow_empty=True)
    except MergeGroundsError as exc:
        raise MergeGroundsError("base revision must be an ancestor of head revision") from exc
    entries = git_diff_entries(root, base, head)
    changed_paths = [path for _, path in entries]
    declarations = [
        (status, path)
        for status, path in entries
        if re.fullmatch(r"\.mergegrounds/changes/[0-9a-f-]+\.json", path)
    ]
    if len(declarations) != 1:
        raise MergeGroundsError("a pull request must add exactly one .mergegrounds/changes/<uuid>.json declaration")
    declaration_status, declaration_path = declarations[0]
    if declaration_status != "A":
        raise MergeGroundsError("change declarations are append-only and must be newly added by the pull request")
    stale_change_paths = [
        path
        for status, path in entries
        if path.startswith(".mergegrounds/changes/") and (status != "A" or path != declaration_path)
    ]
    if stale_change_paths:
        raise MergeGroundsError("existing change declarations must not be modified, removed, or replaced")
    change_id = Path(declaration_path).stem
    if not CHANGE_ID.fullmatch(change_id):
        raise MergeGroundsError("change declaration filename must be a canonical lowercase UUID")
    raw_change = git_blob_bytes(
        root,
        head,
        declaration_path,
        "change declaration",
        MAX_CHANGE_CONTRACT_BYTES,
    )
    change = strict_json_document(raw_change, "change declaration", MAX_CHANGE_CONTRACT_BYTES)
    summary = validate_change_contract(change, change_id, config, changed_paths)

    record_revision = head if summary["lane"] == "design-only" else base
    raw_design = git_blob_bytes(
        root,
        record_revision,
        summary["record_path"],
        "design contract",
        MAX_DESIGN_CONTRACT_BYTES,
    )
    observed_design_digest = f"sha256:{sha256_bytes(raw_design)}"
    if observed_design_digest != summary["record_sha256"]:
        raise MergeGroundsError("design contract digest does not match change declaration")
    design = strict_json_document(raw_design, "design contract", MAX_DESIGN_CONTRACT_BYTES)
    design_summary = validate_design_contract(design, summary["record_id"])
    if summary["acceptance_ids"] != design_summary["acceptance_ids"]:
        raise MergeGroundsError(
            "change acceptance criterion ids must exactly match the reviewed design"
        )
    if summary["failure_mode_ids"] != design_summary["failure_mode_ids"]:
        raise MergeGroundsError(
            "change failure-mode ids must exactly match the reviewed design"
        )
    if summary["outcome_metric_ids"] != design_summary["outcome_metric_ids"]:
        raise MergeGroundsError(
            "change outcome metric ids must exactly match the reviewed design"
        )
    for acceptance_id in sorted(summary["acceptance_ids"]):
        if summary["acceptance_definitions"][acceptance_id] != design_summary["acceptance_definitions"][acceptance_id]:
            raise MergeGroundsError(
                f"change acceptance criterion {acceptance_id} changes semantics from the reviewed design"
            )
    for failure_id in sorted(summary["failure_mode_ids"]):
        if summary["failure_definitions"][failure_id] != design_summary["failure_definitions"][failure_id]:
            raise MergeGroundsError(
                f"change failure mode {failure_id} changes semantics from the reviewed design"
            )

    if summary["lane"] == "design-only":
        expected_paths = {declaration_path, summary["record_path"]}
        if set(changed_paths) != expected_paths or any(status != "A" for status, _ in entries):
            raise MergeGroundsError(
                "design-only lane may add only its change declaration and one design contract"
            )
    else:
        changed_design_records = [
            path
            for path in changed_paths
            if re.fullmatch(r"docs/decisions/[0-9a-f-]+\.json", path)
        ]
        if changed_design_records:
            raise MergeGroundsError(
                "implementation lane cannot add, modify, or remove design contracts; use a design-only PR"
            )

    return {
        "base_sha": base,
        "head_sha": head,
        "change_id": change_id,
        "change_path": declaration_path,
        "change_sha256": f"sha256:{sha256_bytes(raw_change)}",
        "lane": summary["lane"],
        "risk_tier": summary["tier"],
        "design_id": summary["record_id"],
        "design_path": summary["record_path"],
        "design_sha256": observed_design_digest,
        "authority": "declaration-validated-not-admission-evidence",
        "external_root_of_trust": "required-for-maximum-assurance",
    }


def adapter_paths(root: Path) -> list[Path]:
    directory = root / ".mergegrounds" / "adapters"
    return sorted(directory.glob("*.toml")) if directory.is_dir() else []


def load_adapters(root: Path) -> list[dict[str, Any]]:
    adapters: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in adapter_paths(root):
        if not is_regular_repo_file(path, root):
            raise MergeGroundsError(f"adapter must be a regular in-repository file: {path}")
        value = load_toml(path)
        adapter_id = value.get("id")
        if not isinstance(adapter_id, str) or not adapter_id.strip():
            raise MergeGroundsError(f"adapter has no non-empty id: {path}")
        if adapter_id in seen:
            raise MergeGroundsError(f"duplicate adapter id: {adapter_id}")
        artifacts = value.get("artifacts", {})
        if not isinstance(artifacts, dict) or any(key not in KNOWN_STAGES for key in artifacts):
            raise MergeGroundsError(f"adapter {adapter_id} artifacts must use only known stage keys")
        seen.add(adapter_id)
        value["_path"] = path
        adapters.append(value)
    return sorted(adapters, key=lambda item: (-int(item.get("priority", 0)), item["id"]))


def has_glob(root: Path, pattern: str) -> bool:
    return any(is_regular_repo_file(path, root) for path in root.glob(pattern))


def detects(adapter: dict[str, Any], root: Path) -> bool:
    detect = adapter.get("detect", {})
    if not isinstance(detect, dict):
        raise MergeGroundsError(f"adapter {adapter['id']} detect must be a table")
    all_files = as_string_list(detect.get("all_files"), "detect.all_files")
    any_files = as_string_list(detect.get("any_files"), "detect.any_files")
    any_globs = as_string_list(detect.get("any_globs"), "detect.any_globs")
    if not (all_files or any_files or any_globs):
        return False
    if all_files and not all(is_regular_repo_file(root / item, root) for item in all_files):
        return False
    alternatives = [is_regular_repo_file(root / item, root) for item in any_files]
    alternatives.extend(has_glob(root, item) for item in any_globs)
    return not alternatives or any(alternatives)


def detected_adapters(root: Path) -> list[dict[str, Any]]:
    matched = [adapter for adapter in load_adapters(root) if detects(adapter, root)]
    selected: dict[str, dict[str, Any]] = {}
    for adapter in matched:
        ecosystem = adapter.get("ecosystem")
        if not isinstance(ecosystem, str) or not ecosystem:
            raise MergeGroundsError(f"adapter {adapter['id']} has no ecosystem")
        current = selected.get(ecosystem)
        if current is None:
            selected[ecosystem] = adapter
        elif int(current.get("priority", 0)) == int(adapter.get("priority", 0)):
            raise MergeGroundsError(f"ambiguous adapters for ecosystem {ecosystem}: {current['id']}, {adapter['id']}")
    return sorted(selected.values(), key=lambda item: (-int(item.get("priority", 0)), item["id"]))


def environment_for(config: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    execution = config.get("execution", {})
    if not execution.get("sanitize_environment", True):
        return dict(os.environ), []
    allowed = set(as_string_list(execution.get("allowed_environment"), "allowed_environment"))
    result: dict[str, str] = {}
    removed: list[str] = []
    for key, value in os.environ.items():
        if SENSITIVE_ENV.search(key) and key not in allowed:
            removed.append(key)
        else:
            result[key] = value
    result.setdefault("CI", "true")
    result.setdefault("NO_COLOR", "1")
    return result, sorted(removed)


def shell_argv(command: str) -> list[str]:
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", command]
    bash = shutil.which("bash")
    if bash:
        return [bash, "-euo", "pipefail", "-c", command]
    return ["/bin/sh", "-eu", "-c", command]


def run_command(
    command: str,
    root: Path,
    env: dict[str, str],
    timeout: int,
    output_limit: int,
    adapter_id: str,
    stage: str,
) -> dict[str, Any]:
    print(f"\n[{adapter_id}:{stage}] $ {command}", flush=True)
    started = time.monotonic()
    output_digest = hashlib.sha256()
    output_size = 0
    output_buffer = bytearray()
    output_lock = threading.Lock()
    timed_out = False
    process: subprocess.Popen[bytes] | None = None

    def consume(stream: Any) -> None:
        nonlocal output_size
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            output_digest.update(chunk)
            with output_lock:
                output_size += len(chunk)
                remaining = max(0, output_limit - len(output_buffer))
                if remaining:
                    output_buffer.extend(chunk[:remaining])

    try:
        popen_kwargs: dict[str, Any] = {"start_new_session": True} if os.name != "nt" else {}
        process = subprocess.Popen(
            shell_argv(command),
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            **popen_kwargs,
        )
        assert process.stdout is not None
        reader = threading.Thread(target=consume, args=(process.stdout,), daemon=True)
        reader.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:  # pragma: no cover - exercised on Windows CI
                process.kill()
            process.wait(timeout=10)
        if os.name != "nt" and not timed_out:
            try:
                # A successful shell must not leave background descendants racing
                # evidence collection or the final source-state check.
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                # The process group exited before the best-effort descendant cleanup.
                pass
        reader.join(timeout=10)
        if reader.is_alive():
            process.stdout.close()
            reader.join(timeout=1)
            raise MergeGroundsError("failed to drain command output after process exit")
        process.stdout.close()
        output = bytes(output_buffer).decode("utf-8", errors="replace")
        if output:
            print(output, end="" if output.endswith("\n") else "\n")
        truncated = output_size > output_limit
        if truncated:
            print(f"command output exceeded the {output_limit}-byte evidence limit", file=sys.stderr)
            returncode = 125
        if timed_out:
            print(f"command timed out after {timeout}s", file=sys.stderr)
            returncode = 124
        status = "pass" if returncode == 0 else "fail"
    except OSError as exc:
        if process is not None and process.poll() is None:
            process.kill()
        if process is not None and process.stdout is not None:
            process.stdout.close()
        raise MergeGroundsError(f"cannot execute command: {exc}") from exc
    return {
        "adapter": adapter_id,
        "stage": stage,
        "status": status,
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "command_sha256": sha256_bytes(command.encode("utf-8")),
        "output_sha256": output_digest.hexdigest(),
        "output_bytes": output_size,
        "output_truncated": output_size > output_limit,
    }


def required_tools(adapter: dict[str, Any]) -> list[str]:
    toolchain = adapter.get("toolchain", {})
    if not isinstance(toolchain, dict):
        raise MergeGroundsError(f"adapter {adapter['id']} toolchain must be a table")
    values = as_string_list(toolchain.get("required_commands"), "required_commands")
    if any(
        not value
        or value != value.strip()
        or len(value) > 512
        or "\x00" in value
        for value in values
    ):
        raise MergeGroundsError("required_commands entries must be trimmed non-empty names of at most 512 characters")
    return values


def missing_tools(adapter: dict[str, Any]) -> list[str]:
    return [name for name in required_tools(adapter) if shutil.which(name) is None]


def validate_toolchain_path(root: Path, raw: str, field: str) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise MergeGroundsError(f"{field} path must remain repository-relative: {raw}")
    path = root / candidate
    if has_symlink_component(path, root) or not is_within(path.resolve(), root):
        raise MergeGroundsError(f"{field} path must be a regular in-repository file: {raw}")
    return path


def toolchain_file_issues(adapter: dict[str, Any], root: Path) -> list[str]:
    toolchain = adapter.get("toolchain", {})
    if not isinstance(toolchain, dict):
        raise MergeGroundsError(f"adapter {adapter['id']} toolchain must be a table")
    issues: list[str] = []
    for raw in as_string_list(toolchain.get("required_files"), "toolchain.required_files"):
        path = validate_toolchain_path(root, raw, "required_files")
        if not is_regular_repo_file(path, root):
            issues.append(f"missing required file {raw}")
    alternatives: list[Path] = []
    for raw in as_string_list(toolchain.get("required_any_files"), "toolchain.required_any_files"):
        alternatives.append(validate_toolchain_path(root, raw, "required_any_files"))
    matched_alternatives = [path for path in alternatives if is_regular_repo_file(path, root)]
    for pattern in as_string_list(toolchain.get("required_any_globs"), "toolchain.required_any_globs"):
        validate_report_pattern(pattern)
        for path in root.glob(pattern):
            if is_regular_repo_file(path, root):
                matched_alternatives.append(path)
    if (alternatives or toolchain.get("required_any_globs")) and not matched_alternatives:
        issues.append("none of required_any_files/required_any_globs matched a regular file")
    commands = adapter.get("commands", {})
    if isinstance(commands, dict) and os.name != "nt":
        local_commands: set[str] = set()
        for stage_commands in commands.values():
            for command in as_string_list(stage_commands, "commands"):
                match = re.match(r"^(?:[A-Za-z_][A-Za-z0-9_]*=[^ ]+\s+)*\./([^\s]+)", command)
                if match:
                    local_commands.add(match.group(1))
        for raw in sorted(local_commands):
            path = validate_toolchain_path(root, raw, "local command")
            if not is_regular_repo_file(path, root):
                issues.append(f"missing local command {raw}")
            elif not os.access(path, os.X_OK):
                issues.append(f"local command is not executable: {raw}")
    return issues


def tool_versions(adapters: Iterable[dict[str, Any]], root: Path, env: dict[str, str]) -> dict[str, str]:
    """Record no-execution tool discovery; never invoke adapter-declared paths."""
    del root  # Discovery deliberately does not execute anything in the repository.
    versions: dict[str, str] = {"python": f"{platform.python_version()} (running verifier)"}
    for tool in sorted({name for adapter in adapters for name in required_tools(adapter)}):
        resolved = shutil.which(tool, path=env.get("PATH"))
        if resolved is None:
            versions[tool] = "missing"
        else:
            versions[tool] = f"present:{resolved}; version-not-executed"
    return versions


def artifact_file_record(path: Path, root: Path, label: str) -> dict[str, Any]:
    size = path.stat().st_size
    if size <= 0:
        raise MergeGroundsError(f"{label} is empty: {relative(path, root)}")
    if size > MAX_ARTIFACT_BYTES:
        raise MergeGroundsError(
            f"{label} exceeds the {MAX_ARTIFACT_BYTES}-byte artifact limit: {relative(path, root)}"
        )
    return {"path": relative(path, root), "sha256": sha256_file(path), "bytes": size}


def xml_local_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def xml_namespace(element: ET.Element) -> str | None:
    if not element.tag.startswith("{") or "}" not in element.tag:
        return None
    return element.tag[1:].split("}", 1)[0]


def xml_count_attribute(
    element: ET.Element,
    name: str,
    label: str,
    *,
    required: bool = True,
) -> int:
    value = element.attrib.get(name)
    if value is None:
        if required:
            raise MergeGroundsError(f"{label} lacks the {name!r} counter")
        return 0
    if not re.fullmatch(r"[0-9]+", value):
        raise MergeGroundsError(f"{label}.{name} must be a non-negative integer")
    try:
        return int(value)
    except ValueError as exc:
        raise MergeGroundsError(f"{label}.{name} is too large to parse safely") from exc


def parse_test_result_xml(path: Path) -> ET.Element:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise MergeGroundsError(f"cannot read test-result artifact {path}: {exc}") from exc
    try:
        document = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise MergeGroundsError(f"test-result artifact must be UTF-8 XML: {path}") from exc
    if FORBIDDEN_XML_DECLARATION.search(document):
        raise MergeGroundsError(f"test-result artifact must not contain a DTD or entity declaration: {path}")
    try:
        return ET.fromstring(document)
    except ET.ParseError as exc:
        raise MergeGroundsError(f"invalid XML test-result artifact {path}: {exc}") from exc


def junit_artifact_semantics(root: ET.Element, path: Path) -> dict[str, Any]:
    suites = [element for element in root.iter() if xml_local_name(element) == "testsuite"]
    if not suites:
        raise MergeGroundsError(f"JUnit artifact contains no testsuite: {path}")

    counters: dict[int, dict[str, int]] = {}
    for suite in suites:
        label = f"JUnit testsuite {suite.attrib.get('name', '<unnamed>')!r}"
        values = {
            "tests": xml_count_attribute(suite, "tests", label),
            "failures": xml_count_attribute(suite, "failures", label),
            "errors": xml_count_attribute(suite, "errors", label),
            "skipped": xml_count_attribute(suite, "skipped", label, required=False),
            "disabled": xml_count_attribute(suite, "disabled", label, required=False),
        }
        if values["failures"] or values["errors"]:
            raise MergeGroundsError(f"{label} reports failures or errors")
        excluded = values["failures"] + values["errors"] + values["skipped"] + values["disabled"]
        if excluded > values["tests"]:
            raise MergeGroundsError(f"{label} outcome counters exceed its tests counter")
        counters[id(suite)] = values

    testcases = [element for element in root.iter() if xml_local_name(element) == "testcase"]
    executed_cases = 0
    for case in testcases:
        name = case.attrib.get("name")
        if not isinstance(name, str) or not name:
            raise MergeGroundsError(f"JUnit testcase has no non-empty name: {path}")
        outcomes = {xml_local_name(child).lower() for child in list(case)}
        if "failure" in outcomes or "error" in outcomes:
            raise MergeGroundsError(f"JUnit testcase {name!r} reports a failure or error")
        status = case.attrib.get("status", "").strip().lower()
        if status in {"error", "failed", "failure"}:
            raise MergeGroundsError(f"JUnit testcase {name!r} has an adverse status")
        if "skipped" not in outcomes and status not in {"disabled", "notrun", "not-run", "skipped"}:
            executed_cases += 1

    root_name = xml_local_name(root)
    if root_name == "testsuite":
        summary_suites = [root]
    else:
        root_counter_names = {"tests", "failures", "errors"}
        if root_counter_names & set(root.attrib):
            if not root_counter_names <= set(root.attrib):
                raise MergeGroundsError("JUnit testsuites root has an incomplete counter set")
            root_label = "JUnit testsuites root"
            root_values = {
                "tests": xml_count_attribute(root, "tests", root_label),
                "failures": xml_count_attribute(root, "failures", root_label),
                "errors": xml_count_attribute(root, "errors", root_label),
                "skipped": xml_count_attribute(root, "skipped", root_label, required=False),
                "disabled": xml_count_attribute(root, "disabled", root_label, required=False),
            }
            if root_values["failures"] or root_values["errors"]:
                raise MergeGroundsError("JUnit testsuites root reports failures or errors")
            if sum(root_values[key] for key in ("failures", "errors", "skipped", "disabled")) > root_values["tests"]:
                raise MergeGroundsError("JUnit testsuites root outcome counters exceed its tests counter")
            summary_suites = []
        else:
            root_values = None
            summary_suites = [element for element in list(root) if xml_local_name(element) == "testsuite"]
            if not summary_suites:
                raise MergeGroundsError("JUnit testsuites root contains no direct testsuite summary")

    if root_name != "testsuite" and root_values is not None:
        summary = root_values
        direct_suites = [element for element in list(root) if xml_local_name(element) == "testsuite"]
        if not direct_suites:
            raise MergeGroundsError("JUnit testsuites root contains no direct testsuite summary")
        direct_summary = {
            key: sum(counters[id(suite)][key] for suite in direct_suites)
            for key in ("tests", "failures", "errors", "skipped", "disabled")
        }
        if direct_summary != summary:
            raise MergeGroundsError("JUnit testsuites root counters disagree with direct testsuite summaries")
    else:
        summary = {
            key: sum(counters[id(suite)][key] for suite in summary_suites)
            for key in ("tests", "failures", "errors", "skipped", "disabled")
        }
    executed = summary["tests"] - summary["skipped"] - summary["disabled"]
    if summary["tests"] <= 0 or executed <= 0:
        raise MergeGroundsError(f"JUnit artifact has no executed tests: {path}")
    if testcases and executed_cases <= 0:
        raise MergeGroundsError(f"JUnit artifact has no executed testcase: {path}")
    if testcases and len(testcases) != summary["tests"]:
        raise MergeGroundsError("JUnit testcase detail disagrees with the declared tests counter")
    if testcases and executed_cases != executed:
        raise MergeGroundsError("JUnit testcase outcomes disagree with the declared executed count")
    return {
        "format": "junit",
        "tests": summary["tests"],
        "executed": executed,
        "passed": executed,
        "failures": 0,
        "errors": 0,
        "skipped": summary["skipped"] + summary["disabled"],
    }


def trx_artifact_semantics(root: ET.Element, path: Path) -> dict[str, Any]:
    if xml_namespace(root) != TRX_NAMESPACE:
        raise MergeGroundsError(f"TRX artifact uses an unsupported or absent namespace: {path}")
    summaries = [element for element in root.iter() if xml_local_name(element) == "ResultSummary"]
    counters_elements = [element for element in root.iter() if xml_local_name(element) == "Counters"]
    if len(summaries) != 1 or len(counters_elements) != 1:
        raise MergeGroundsError("TRX artifact must contain exactly one ResultSummary and Counters element")
    if summaries[0].attrib.get("outcome") != "Completed":
        raise MergeGroundsError("TRX ResultSummary outcome must be Completed")
    if any(xml_namespace(element) != TRX_NAMESPACE for element in (*summaries, *counters_elements)):
        raise MergeGroundsError("TRX summary elements must use the official TeamTest namespace")

    counters_element = counters_elements[0]
    label = "TRX Counters"
    counters = {
        key: xml_count_attribute(counters_element, key, label)
        for key in ("total", "executed", "passed", "failed", "error")
    }
    adverse_names = (
        "timeout",
        "aborted",
        "inconclusive",
        "passedButRunAborted",
        "notRunnable",
        "disconnected",
        "warning",
        "inProgress",
        "pending",
    )
    adverse = {key: xml_count_attribute(counters_element, key, label, required=False) for key in adverse_names}
    if counters["failed"] or counters["error"] or any(adverse.values()):
        raise MergeGroundsError("TRX Counters reports a failed, error, or inconclusive outcome")
    if counters["total"] < counters["executed"] or counters["passed"] != counters["executed"]:
        raise MergeGroundsError("TRX Counters has inconsistent total/executed/passed values")
    if counters["executed"] <= 0:
        raise MergeGroundsError(f"TRX artifact has no executed tests: {path}")

    results = [element for element in root.iter() if xml_local_name(element) == "UnitTestResult"]
    if not results:
        raise MergeGroundsError("TRX artifact contains no UnitTestResult detail")
    if any(xml_namespace(result) != TRX_NAMESPACE for result in results):
        raise MergeGroundsError("TRX result elements must use the official TeamTest namespace")
    execution_ids: set[str] = set()
    passed_results = 0
    for result in results:
        execution_id = result.attrib.get("executionId")
        if not execution_id or execution_id in execution_ids:
            raise MergeGroundsError("TRX UnitTestResult executionId is absent or duplicated")
        execution_ids.add(execution_id)
        outcome = result.attrib.get("outcome")
        if outcome == "Passed":
            passed_results += 1
        elif outcome != "NotExecuted":
            raise MergeGroundsError(f"TRX UnitTestResult has adverse or unknown outcome: {outcome!r}")
    if len(results) != counters["total"]:
        raise MergeGroundsError("TRX result detail disagrees with the total counter")
    if passed_results != counters["passed"]:
        raise MergeGroundsError("TRX passed result detail disagrees with the Counters summary")
    return {
        "format": "trx",
        "tests": counters["total"],
        "executed": counters["executed"],
        "passed": counters["passed"],
        "failures": 0,
        "errors": 0,
        "skipped": counters["total"] - counters["executed"],
    }


def test_artifact_semantics(path: Path) -> dict[str, Any] | None:
    suffix = path.suffix.lower()
    if suffix not in {".xml", ".trx"}:
        return None
    root = parse_test_result_xml(path)
    root_name = xml_local_name(root)
    if root_name in {"testsuite", "testsuites"}:
        return junit_artifact_semantics(root, path)
    if root_name == "TestRun":
        return trx_artifact_semantics(root, path)
    if suffix == ".trx":
        raise MergeGroundsError(f"TRX artifact has an unsupported root element: {root_name!r}")
    return None


def artifact_records(root: Path, adapters: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    patterns: set[str] = set()
    for adapter in adapters:
        artifacts = adapter.get("artifacts", {})
        if not isinstance(artifacts, dict):
            continue
        for value in artifacts.values():
            patterns.update(as_string_list(value, "artifacts"))
    selected: set[Path] = set()
    for pattern in sorted(patterns):
        for path in sorted(root.glob(pattern)):
            if is_regular_repo_file(path, root):
                selected.add(path)
    return [artifact_file_record(path, root, "artifact") for path in sorted(selected)]


def artifact_patterns(adapter: dict[str, Any], stage: str) -> list[str]:
    artifacts = adapter.get("artifacts", {})
    if not isinstance(artifacts, dict):
        raise MergeGroundsError(f"adapter {adapter['id']} artifacts must be a table")
    return as_string_list(artifacts.get(stage), f"{adapter['id']}.artifacts.{stage}")


def pattern_files(root: Path, patterns: Iterable[str], label: str) -> list[Path]:
    selected: set[Path] = set()
    for pattern in patterns:
        validate_report_pattern(pattern)
        for path in root.glob(pattern):
            if path.is_dir() and not path.is_symlink():
                continue
            if not is_regular_repo_file(path, root):
                raise MergeGroundsError(f"{label} path must be a regular in-repository file: {path}")
            selected.add(path)
    return sorted(selected)


def protected_output_reason(path: Path, root: Path, git_directory: Path | None = None) -> str | None:
    """Explain why an adapter-controlled output path must never be deleted."""
    try:
        parts = path.absolute().relative_to(root.absolute()).parts
    except ValueError:
        return "outside the repository"
    if not parts:
        return "the repository root"
    first = parts[0].casefold()
    if first == ".git":
        return "Git metadata"
    if git_directory is not None and is_within(path.resolve(), git_directory):
        return "Git metadata"
    if first in {".github", "scripts"}:
        return "the MergeGrounds control plane"
    if first == ".mergegrounds" and (
        len(parts) == 1 or parts[1].casefold() not in {"evidence", "reports"}
    ):
        return "the MergeGrounds control plane"
    current = path if path.is_dir() else path.parent
    while current.absolute() != root.absolute():
        marker = current / ".git"
        try:
            marker.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            return "an unverifiable nested Git worktree"
        else:
            return "a nested Git worktree"
        current = current.parent
    return None


def validate_output_pattern_scope(root: Path, pattern: str, label: str) -> None:
    """Reject patterns whose non-glob prefix already enters protected state."""
    validate_report_pattern(pattern)
    prefix: list[str] = []
    for part in Path(pattern).parts:
        if any(character in part for character in "*?["):
            break
        prefix.append(part)
    if not prefix:
        return
    reason = protected_output_reason(root.joinpath(*prefix), root)
    if reason:
        raise MergeGroundsError(f"refusing {label} output pattern in {reason}: {pattern}")


def purge_output_files(root: Path, patterns: Iterable[str], label: str) -> set[str]:
    """Preflight every match, then remove only untracked generated outputs."""
    configured_patterns = list(patterns)
    for pattern in configured_patterns:
        validate_output_pattern_scope(root, pattern, label)
    files = pattern_files(root, configured_patterns, label)
    if not files:
        return set()

    # These queries are security decisions: inability to prove the repository or
    # tracking state is a denial, never an assumption that a path is untracked.
    require_git_toplevel(root)
    raw_git_directory = git_checked(root, "rev-parse", "--absolute-git-dir")
    git_directory = Path(raw_git_directory)
    if not git_directory.is_absolute():
        git_directory = root / git_directory
    git_directory = git_directory.resolve()

    relative_paths: list[str] = []
    identities: dict[Path, tuple[int, int, int]] = {}
    for path in files:
        rel = relative(path, root)
        reason = protected_output_reason(path, root, git_directory)
        if reason:
            raise MergeGroundsError(f"refusing to purge {label} in {reason}: {rel}")
        try:
            stat_result = path.lstat()
        except OSError as exc:
            raise MergeGroundsError(f"cannot preflight {label}: {rel}: {exc}") from exc
        identities[path] = (stat_result.st_dev, stat_result.st_ino, stat_result.st_mode)
        relative_paths.append(rel)

    # Git tracks files, not directories. Query only the preflighted file paths:
    # adding their directory prefixes would make `git ls-files .mergegrounds` report
    # unrelated control files and prevent safe cleanup below
    # `.mergegrounds/reports`. Ancestor symlinks and non-directories have already
    # been rejected by `pattern_files` and the filesystem preflight above.
    literal_pathspecs = [f":(literal){path}" for path in sorted(relative_paths)]
    tracked_output = git_checked(
        root,
        "ls-files",
        "-z",
        "--",
        *literal_pathspecs,
        allow_empty=True,
        strip_output=False,
    )
    tracked = sorted(path for path in tracked_output.split("\0") if path)
    if tracked:
        raise MergeGroundsError(f"refusing to purge tracked {label}: {', '.join(tracked)}")

    # Recheck every candidate before the first unlink so a validation error cannot
    # cause a partial purge. This is not a substitute for filesystem isolation,
    # but closes ordinary path replacement between discovery and deletion.
    for path in files:
        rel = relative(path, root)
        if not is_regular_repo_file(path, root):
            raise MergeGroundsError(f"{label} changed during purge preflight: {rel}")
        stat_result = path.lstat()
        if identities[path] != (stat_result.st_dev, stat_result.st_ino, stat_result.st_mode):
            raise MergeGroundsError(f"{label} changed during purge preflight: {rel}")

    removed: set[str] = set()
    for path, rel in zip(files, relative_paths, strict=True):
        try:
            path.unlink()
        except OSError as exc:
            raise MergeGroundsError(f"cannot purge {label}: {rel}: {exc}") from exc
        removed.add(rel)
    return removed


def validate_stage_artifacts(root: Path, adapter: dict[str, Any], stage: str) -> dict[str, Any] | None:
    patterns = artifact_patterns(adapter, stage)
    if not patterns:
        return None
    files = pattern_files(root, patterns, f"{adapter['id']}:{stage} artifact")
    if not files:
        raise MergeGroundsError(f"{adapter['id']}:{stage} did not produce any declared artifact")
    records: list[dict[str, Any]] = []
    recognized_test_reports = 0
    for path in files:
        record = artifact_file_record(path, root, f"{adapter['id']}:{stage} artifact")
        if stage == "unit":
            semantics = test_artifact_semantics(path)
            if semantics is None:
                record["semantic_validation"] = "unavailable"
            else:
                record["test_results"] = semantics
                recognized_test_reports += 1
        records.append(record)
    if stage == "unit" and recognized_test_reports == 0:
        raise MergeGroundsError(
            f"{adapter['id']}:{stage} artifacts contain no supported positive JUnit or TRX test result"
        )
    return {
        "adapter": adapter["id"],
        "stage": f"{stage}-artifacts",
        "status": "pass",
        "files": records,
    }


def strict_json(path: Path) -> Any:
    if path.stat().st_size <= 0:
        raise MergeGroundsError(f"metric report is empty: {path}")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise MergeGroundsError(f"metric report exceeds {MAX_REPORT_BYTES} bytes: {path}")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise MergeGroundsError(f"invalid JSON metric report {path}: {exc}") from exc


def finite_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MergeGroundsError(f"{field} must be a JSON/TOML number")
    number = float(value)
    if not math.isfinite(number):
        raise MergeGroundsError(f"{field} must be finite")
    return number


def count(value: Any, field: str) -> int:
    number = finite_number(value, field)
    if number < 0 or not number.is_integer():
        raise MergeGroundsError(f"{field} must be a non-negative integer")
    return int(number)


def text_count(value: Any, field: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
        raise MergeGroundsError(f"{field} must be a non-negative integer string")
    return int(value)


def percentage(value: Any, field: str) -> float:
    number = finite_number(value, field)
    if not 0.0 <= number <= 100.0:
        raise MergeGroundsError(f"{field} must be between 0 and 100")
    return number


def ratio(covered: int, total: int, field: str) -> float:
    if total <= 0:
        raise MergeGroundsError(f"{field} denominator must be positive")
    if covered < 0 or covered > total:
        raise MergeGroundsError(f"{field} numerator is outside its denominator")
    return 100.0 * covered / total


def descriptor_for(adapter: dict[str, Any], kind: str) -> dict[str, Any] | None:
    metrics = adapter.get("metrics", {})
    if not isinstance(metrics, dict):
        raise MergeGroundsError(f"adapter {adapter['id']} metrics must be a table")
    descriptor = metrics.get(kind)
    if descriptor is None:
        return None
    if not isinstance(descriptor, dict):
        raise MergeGroundsError(f"adapter {adapter['id']} metrics.{kind} must be a table")
    return descriptor


def validate_report_pattern(pattern: str) -> None:
    if not isinstance(pattern, str) or not pattern or "\x00" in pattern or pattern == ".":
        raise MergeGroundsError(f"metric report glob must be a non-empty relative pattern: {pattern!r}")
    candidate = Path(pattern)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise MergeGroundsError(f"metric report glob must remain relative: {pattern}")


def select_report_files(root: Path, descriptor: dict[str, Any]) -> list[Path]:
    patterns = as_string_list(descriptor.get("paths"), "metrics.paths")
    if not patterns:
        raise MergeGroundsError("metric descriptor has no report paths")
    selected: list[Path] = []
    for pattern in patterns:
        validate_report_pattern(pattern)
        matches = sorted({path for path in root.glob(pattern) if path.is_file() or path.is_symlink()})
        if matches:
            selected = matches
            break
    if not selected:
        raise MergeGroundsError("required metric report did not match any configured path")
    seen_real: set[Path] = set()
    for path in selected:
        resolved = path.resolve()
        if not is_regular_repo_file(path, root):
            raise MergeGroundsError(f"metric report must be a regular in-repository file: {path}")
        if resolved in seen_real:
            raise MergeGroundsError(f"metric report is duplicated through path aliases: {path}")
        seen_real.add(resolved)
        if path.stat().st_size <= 0:
            raise MergeGroundsError(f"metric report is empty: {path}")
        if path.stat().st_size > MAX_REPORT_BYTES:
            raise MergeGroundsError(f"metric report exceeds {MAX_REPORT_BYTES} bytes: {path}")
    return selected


def report_snapshot(root: Path, descriptor: dict[str, Any] | None) -> dict[str, tuple[int, int, str]]:
    if descriptor is None:
        return {}
    result: dict[str, tuple[int, int, str]] = {}
    for pattern in as_string_list(descriptor.get("paths"), "metrics.paths"):
        validate_report_pattern(pattern)
        for path in root.glob(pattern):
            if is_regular_repo_file(path, root):
                stat_result = path.stat()
                result[relative(path, root)] = (
                    stat_result.st_mtime_ns,
                    stat_result.st_size,
                    sha256_file(path),
                )
    return result


def purge_metric_reports(root: Path, descriptor: dict[str, Any] | None) -> set[str]:
    """Remove only configured, untracked report files so a stage cannot replay them."""
    if descriptor is None:
        return set()
    patterns = as_string_list(descriptor.get("paths"), "metrics.paths")
    return purge_output_files(root, patterns, "metric report")


def require_fresh_reports(
    root: Path,
    files: list[Path],
    before: dict[str, tuple[int, int, str]],
    purged: set[str] | None = None,
) -> None:
    purged = purged or set()
    for path in files:
        rel = relative(path, root)
        if rel in purged:
            continue
        stat_result = path.stat()
        old = before.get(rel)
        current = (stat_result.st_mtime_ns, stat_result.st_size, sha256_file(path))
        if old is not None and old[2] == current[2]:
            raise MergeGroundsError(f"metric report was not recreated with new content by this stage: {rel}")


def coverage_json_counts(path: Path) -> dict[str, int | None]:
    data = strict_json(path)
    if not isinstance(data, dict):
        raise MergeGroundsError("coverage JSON root must be an object")
    if isinstance(data.get("totals"), dict):
        totals = data["totals"]
        line_covered = count(totals.get("covered_lines"), "totals.covered_lines")
        line_total = count(totals.get("num_statements"), "totals.num_statements")
        if ("num_branches" in totals) != ("covered_branches" in totals):
            raise MergeGroundsError("coverage.py totals has an incomplete branch counter pair")
        branch_total = count(totals.get("num_branches", 0), "totals.num_branches")
        branch_covered = count(totals.get("covered_branches", 0), "totals.covered_branches")
    elif isinstance(data.get("total"), dict):
        totals = data["total"]
        lines = totals.get("lines")
        branches = totals.get("branches")
        if not isinstance(lines, dict) or not isinstance(branches, dict):
            raise MergeGroundsError("Istanbul summary lacks total.lines or total.branches")
        line_covered = count(lines.get("covered"), "total.lines.covered")
        line_total = count(lines.get("total"), "total.lines.total")
        branch_covered = count(branches.get("covered"), "total.branches.covered")
        branch_total = count(branches.get("total"), "total.branches.total")
    else:
        raise MergeGroundsError("unsupported coverage JSON schema; require coverage.py totals or Istanbul total summary")
    if line_covered > line_total or branch_covered > branch_total:
        raise MergeGroundsError("coverage JSON covered counters exceed their per-report totals")
    return {
        "line_covered": line_covered,
        "line_total": line_total,
        "branch_covered": branch_covered,
        "branch_total": branch_total,
    }


def parse_xml(path: Path) -> ET.Element:
    size = path.stat().st_size
    if size <= 0:
        raise MergeGroundsError(f"XML metric report is empty: {path}")
    if size > MAX_REPORT_BYTES:
        raise MergeGroundsError(f"XML report exceeds {MAX_REPORT_BYTES} bytes: {path}")
    try:
        document = path.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise MergeGroundsError(f"XML metric report must be UTF-8: {path}: {exc}") from exc
    if FORBIDDEN_XML_DECLARATION.search(document):
        raise MergeGroundsError(f"XML metric report must not contain a DTD or entity declaration: {path}")
    try:
        return ET.fromstring(document)
    except ET.ParseError as exc:
        raise MergeGroundsError(f"invalid XML metric report {path}: {exc}") from exc


def cobertura_counts(path: Path) -> dict[str, int | None]:
    root = parse_xml(path)
    required = ("lines-covered", "lines-valid")
    if not all(name in root.attrib for name in required):
        raise MergeGroundsError("Cobertura root must expose lines-covered and lines-valid counts")
    if ("branches-covered" in root.attrib) != ("branches-valid" in root.attrib):
        raise MergeGroundsError("Cobertura root has an incomplete branch counter pair")
    line_covered = text_count(root.attrib["lines-covered"], "lines-covered")
    line_total = text_count(root.attrib["lines-valid"], "lines-valid")
    branch_covered = text_count(root.attrib.get("branches-covered", "0"), "branches-covered")
    branch_total = text_count(root.attrib.get("branches-valid", "0"), "branches-valid")
    if line_covered > line_total or branch_covered > branch_total:
        raise MergeGroundsError("Cobertura covered counters exceed their per-report totals")
    return {
        "line_covered": line_covered,
        "line_total": line_total,
        "branch_covered": branch_covered,
        "branch_total": branch_total,
    }


def jacoco_counts(path: Path) -> dict[str, int | None]:
    root = parse_xml(path)
    values: dict[str, tuple[int, int]] = {}
    for element in list(root):
        if element.tag.rsplit("}", 1)[-1] != "counter":
            continue
        counter_type = element.attrib.get("type")
        if counter_type in {"LINE", "BRANCH"}:
            missed = text_count(element.attrib.get("missed"), f"{counter_type}.missed")
            covered = text_count(element.attrib.get("covered"), f"{counter_type}.covered")
            if counter_type in values:
                raise MergeGroundsError(f"duplicate JaCoCo root counter: {counter_type}")
            values[counter_type] = (covered, covered + missed)
    if "LINE" not in values:
        raise MergeGroundsError("JaCoCo report lacks a root LINE counter")
    line_covered, line_total = values["LINE"]
    branch_covered, branch_total = values.get("BRANCH", (0, 0))
    return {
        "line_covered": line_covered,
        "line_total": line_total,
        "branch_covered": branch_covered,
        "branch_total": branch_total,
    }


def lcov_counts(path: Path) -> dict[str, int | None]:
    records: dict[str, tuple[int, int, int, int]] = {}
    current: dict[str, int | str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line:
            continue
        if raw_line.startswith("SF:"):
            if current:
                raise MergeGroundsError("LCOV record is missing end_of_record")
            current = {"source": raw_line[3:]}
        elif raw_line == "end_of_record":
            source = current.get("source")
            if not isinstance(source, str) or not source:
                raise MergeGroundsError("LCOV record has no source")
            if source in records:
                raise MergeGroundsError(f"duplicate LCOV source record: {source}")
            if "LH" not in current or "LF" not in current:
                raise MergeGroundsError(f"LCOV record lacks LH/LF counters: {source}")
            if ("BRH" in current) != ("BRF" in current):
                raise MergeGroundsError(f"LCOV record has an incomplete branch counter pair: {source}")
            try:
                lh = count(int(current["LH"]), f"LCOV {source} LH")
                lf = count(int(current["LF"]), f"LCOV {source} LF")
                brh = count(int(current.get("BRH", 0)), f"LCOV {source} BRH")
                brf = count(int(current.get("BRF", 0)), f"LCOV {source} BRF")
            except (TypeError, ValueError) as exc:
                raise MergeGroundsError(f"invalid LCOV counters for {source}") from exc
            if lh > lf or brh > brf:
                raise MergeGroundsError(f"LCOV covered counters exceed totals for {source}")
            records[source] = (lh, lf, brh, brf)
            current = {}
        elif ":" in raw_line:
            key, value = raw_line.split(":", 1)
            if key in {"LH", "LF", "BRH", "BRF"}:
                if key in current:
                    raise MergeGroundsError(f"duplicate LCOV {key} counter in one source record")
                current[key] = value
    if current:
        raise MergeGroundsError("LCOV final record is missing end_of_record")
    if not records:
        raise MergeGroundsError("LCOV report contains no source records")
    line_covered = sum(value[0] for value in records.values())
    line_total = sum(value[1] for value in records.values())
    branch_covered = sum(value[2] for value in records.values())
    branch_total = sum(value[3] for value in records.values())
    return {
        "line_covered": count(line_covered, "LCOV.LH"),
        "line_total": count(line_total, "LCOV.LF"),
        "branch_covered": count(branch_covered, "LCOV.BRH"),
        "branch_total": count(branch_total, "LCOV.BRF"),
    }


def go_cover_counts(path: Path) -> dict[str, int | None]:
    size = path.stat().st_size
    if size <= 0:
        raise MergeGroundsError("Go coverage report is empty")
    if size > MAX_REPORT_BYTES:
        raise MergeGroundsError(f"Go coverage report exceeds {MAX_REPORT_BYTES} bytes")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise MergeGroundsError(f"cannot read Go coverage report {path}: {exc}") from exc
    if not lines or lines[0] not in {"mode: set", "mode: count", "mode: atomic"}:
        raise MergeGroundsError("Go coverage mode must be exactly set, count, or atomic")
    mode = lines[0][len("mode: ") :]
    if len(lines) == 1:
        raise MergeGroundsError("Go coverage report contains no block records")

    total = 0
    covered = 0
    identities: set[tuple[str, int, int, int, int]] = set()
    blocks_by_source: dict[str, list[tuple[tuple[int, int], tuple[int, int]]]] = {}
    for index, line in enumerate(lines[1:], start=2):
        match = GO_COVER_RECORD.fullmatch(line)
        if match is None:
            raise MergeGroundsError(f"invalid Go coverage record on line {index}")
        source = match.group("source")
        parts = source.split("/")
        if (
            source != source.strip()
            or source.startswith("/")
            or "\\" in source
            or ":" in source
            or any(not part or part in {".", ".."} for part in parts)
            or not parts[-1].endswith(".go")
            or any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in source)
        ):
            raise MergeGroundsError(f"Go coverage source is not a canonical module-relative path on line {index}")
        start_line = text_count(match.group("start_line"), f"go-cover line {index} start line")
        start_col = text_count(match.group("start_col"), f"go-cover line {index} start column")
        end_line = text_count(match.group("end_line"), f"go-cover line {index} end line")
        end_col = text_count(match.group("end_col"), f"go-cover line {index} end column")
        if min(start_line, start_col, end_line, end_col) <= 0:
            raise MergeGroundsError(f"Go coverage coordinates must be positive on line {index}")
        start = (start_line, start_col)
        end = (end_line, end_col)
        if end <= start:
            raise MergeGroundsError(f"Go coverage block must have a positive ordered range on line {index}")
        identity = (source, start_line, start_col, end_line, end_col)
        if identity in identities:
            raise MergeGroundsError(f"duplicate Go coverage block on line {index}")
        identities.add(identity)
        blocks_by_source.setdefault(source, []).append((start, end))

        statements = text_count(match.group("statements"), f"go-cover line {index} statements")
        executions = text_count(match.group("executions"), f"go-cover line {index} executions")
        if mode == "set" and executions not in {0, 1}:
            raise MergeGroundsError(f"Go set-mode execution counter must be 0 or 1 on line {index}")
        total += statements
        if executions > 0:
            covered += statements

    for source, blocks in blocks_by_source.items():
        previous_end: tuple[int, int] | None = None
        for start, end in sorted(blocks):
            if previous_end is not None and start < previous_end:
                raise MergeGroundsError(f"overlapping Go coverage blocks for {source}")
            previous_end = end
    return {"line_covered": covered, "line_total": total, "branch_covered": None, "branch_total": None}


def mergegrounds_metrics(path: Path) -> dict[str, float]:
    data = strict_json(path)
    required = {"line_coverage", "branch_coverage", "mutation_score"}
    if not isinstance(data, dict) or set(data) != required:
        raise MergeGroundsError("mergegrounds-json must contain exactly line_coverage, branch_coverage, and mutation_score")
    return {key: percentage(data[key], key) for key in sorted(required)}


def parse_coverage_report(report_format: str, path: Path) -> dict[str, int | None] | dict[str, float]:
    if report_format == "coverage-json":
        return coverage_json_counts(path)
    if report_format == "cobertura":
        return cobertura_counts(path)
    if report_format == "jacoco":
        return jacoco_counts(path)
    if report_format == "lcov":
        return lcov_counts(path)
    if report_format == "go-cover":
        return go_cover_counts(path)
    if report_format == "mergegrounds-json":
        return mergegrounds_metrics(path)
    raise MergeGroundsError(f"unsupported coverage metric format: {report_format}")


MUTATION_STATUS = {
    "KILLED": "killed",
    "CAUGHT": "killed",
    "SURVIVED": "survived",
    "MISSED": "survived",
    "LIVED": "survived",
    "NO_COVERAGE": "not_covered",
    "NOCOVERAGE": "not_covered",
    "NOT COVERED": "not_covered",
    "NOT_COVERED": "not_covered",
    "TIMEOUT": "timeout",
    "TIMED_OUT": "timeout",
    "TIMEDOUT": "timeout",
    "TIMED OUT": "timeout",
    "RUNTIMEERROR": "invalid",
    "RUN_ERROR": "invalid",
    "MEMORY_ERROR": "invalid",
    "PENDING": "invalid",
    "SUSPICIOUS": "invalid",
    "INTERRUPTED": "invalid",
    "RUNNABLE": "invalid",
    "COMPILEERROR": "unviable",
    "NON_VIABLE": "unviable",
    "NOT VIABLE": "unviable",
    "UNVIABLE": "unviable",
    "IGNORED": "ignored",
    "SKIPPED": "ignored",
}


def empty_mutation_counts() -> dict[str, int]:
    return {key: 0 for key in ("killed", "survived", "not_covered", "timeout", "invalid", "unviable", "ignored")}


def add_status(target: dict[str, int], raw: Any, field: str) -> None:
    if not isinstance(raw, str) or not raw.strip():
        raise MergeGroundsError(f"{field} mutation status must be text")
    normalized = raw.strip().upper().replace("-", "_")
    category = MUTATION_STATUS.get(normalized)
    if category is None:
        raise MergeGroundsError(f"unknown mutation status {raw!r} in {field}")
    target[category] += 1


def stryker_counts(path: Path) -> dict[str, int]:
    data = strict_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("files"), (dict, list)):
        raise MergeGroundsError("Stryker JSON must contain files")
    files = data["files"].items() if isinstance(data["files"], dict) else enumerate(data["files"])
    counts = empty_mutation_counts()
    identities: set[str] = set()
    for file_name, file_data in files:
        if not isinstance(file_data, dict) or not isinstance(file_data.get("mutants"), list):
            raise MergeGroundsError(f"Stryker file {file_name!r} lacks mutants")
        for index, mutant in enumerate(file_data["mutants"]):
            if not isinstance(mutant, dict):
                raise MergeGroundsError("Stryker mutant must be an object")
            identity = f"{file_name}:{mutant.get('id', index)}"
            if identity in identities:
                raise MergeGroundsError(f"duplicate Stryker mutant id: {identity}")
            identities.add(identity)
            add_status(counts, mutant.get("status"), identity)
    if not identities:
        raise MergeGroundsError("Stryker report contains zero mutants")
    return counts


def pit_counts(path: Path) -> dict[str, int]:
    root = parse_xml(path)
    counts = empty_mutation_counts()
    total = 0
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "mutation":
            continue
        total += 1
        status = element.attrib.get("status")
        add_status(counts, status, f"PIT mutation {total}")
        detected = element.attrib.get("detected")
        if detected not in {"true", "false"}:
            raise MergeGroundsError("PIT mutation detected attribute must be true or false")
        should_detect = str(status).upper() == "KILLED"
        if (detected == "true") != should_detect:
            raise MergeGroundsError(f"PIT detected/status mismatch for mutation {total}")
    if total == 0:
        raise MergeGroundsError("PIT report contains zero mutants")
    return counts


def gremlins_counts(path: Path) -> dict[str, int]:
    data = strict_json(path)
    if not isinstance(data, dict):
        raise MergeGroundsError("Gremlins JSON root must be an object")
    counts = empty_mutation_counts()
    counts["killed"] = count(data.get("mutants_killed"), "mutants_killed")
    counts["survived"] = count(data.get("mutants_lived"), "mutants_lived")
    counts["not_covered"] = count(data.get("mutants_not_covered"), "mutants_not_covered")
    counts["unviable"] = count(data.get("mutants_not_viable", 0), "mutants_not_viable")
    files = data.get("files", [])
    if not isinstance(files, list) or not files:
        raise MergeGroundsError("Gremlins files must be a non-empty array")
    observed = empty_mutation_counts()
    observed_total = 0
    identities: set[tuple[str, int, int, str]] = set()
    for file_data in files:
        if not isinstance(file_data, dict) or not isinstance(file_data.get("mutations"), list):
            raise MergeGroundsError("Gremlins file record lacks mutations")
        file_name = file_data.get("file_name")
        if not isinstance(file_name, str) or not file_name:
            raise MergeGroundsError("Gremlins file record lacks file_name")
        for mutation in file_data["mutations"]:
            if not isinstance(mutation, dict):
                raise MergeGroundsError("Gremlins mutation must be an object")
            line = mutation.get("line")
            column = mutation.get("column")
            mutation_type = mutation.get("type")
            if not isinstance(line, int) or isinstance(line, bool) or line <= 0:
                raise MergeGroundsError("Gremlins mutation line must be a positive integer")
            if not isinstance(column, int) or isinstance(column, bool) or column <= 0:
                raise MergeGroundsError("Gremlins mutation column must be a positive integer")
            if not isinstance(mutation_type, str) or not mutation_type:
                raise MergeGroundsError("Gremlins mutation type must be a non-empty string")
            identity = (file_name, line, column, mutation_type)
            if identity in identities:
                raise MergeGroundsError(f"duplicate Gremlins mutation identity: {identity}")
            identities.add(identity)
            add_status(observed, mutation.get("status"), "Gremlins mutation")
            observed_total += 1
    for key in ("killed", "survived", "not_covered", "unviable"):
        if observed[key] != counts[key]:
            raise MergeGroundsError(f"Gremlins summary/detail mismatch for {key}")
    counts["timeout"] = observed["timeout"]
    counts["invalid"] = observed["invalid"]
    counts["ignored"] = observed["ignored"]
    total = count(data.get("mutants_total"), "mutants_total")
    native_total = counts["killed"] + counts["survived"] + counts["unviable"]
    if total <= 0 or native_total != total:
        raise MergeGroundsError("Gremlins mutants_total is inconsistent with its native summary formula")
    if observed_total != total + counts["not_covered"] + counts["timeout"] + counts["invalid"] + counts["ignored"]:
        raise MergeGroundsError("Gremlins detail count disagrees with summary counters")
    efficacy = ratio(counts["killed"], counts["killed"] + counts["survived"], "Gremlins efficacy")
    mutation_coverage = ratio(
        counts["killed"] + counts["survived"],
        counts["killed"] + counts["survived"] + counts["not_covered"],
        "Gremlins mutation coverage",
    )
    if abs(percentage(data.get("test_efficacy"), "test_efficacy") - efficacy) > 0.01:
        raise MergeGroundsError("Gremlins test_efficacy disagrees with recomputed value")
    if abs(percentage(data.get("mutations_coverage"), "mutations_coverage") - mutation_coverage) > 0.01:
        raise MergeGroundsError("Gremlins mutations_coverage disagrees with recomputed value")
    return counts


def mutmut_counts(path: Path) -> dict[str, int]:
    data = strict_json(path)
    if not isinstance(data, dict):
        raise MergeGroundsError("mutmut CI stats root must be an object")
    required = ("killed", "survived", "total", "no_tests", "skipped", "suspicious", "timeout", "check_was_interrupted_by_user", "segfault")
    values = {key: count(data.get(key), key) for key in required}
    if values["total"] <= 0:
        raise MergeGroundsError("mutmut generated zero mutants")
    known = sum(values[key] for key in required if key != "total")
    if known != values["total"]:
        raise MergeGroundsError("mutmut counters do not explain total mutants")
    counts = empty_mutation_counts()
    counts["killed"] = values["killed"]
    counts["survived"] = values["survived"]
    counts["not_covered"] = values["no_tests"]
    counts["timeout"] = values["timeout"]
    counts["ignored"] = values["skipped"]
    counts["invalid"] = values["suspicious"] + values["check_was_interrupted_by_user"] + values["segfault"]
    return counts


def infection_counts(path: Path) -> tuple[dict[str, int], float]:
    data = strict_json(path)
    stats = data.get("stats") if isinstance(data, dict) else None
    if not isinstance(stats, dict):
        raise MergeGroundsError("Infection summary must contain stats")
    total = count(stats.get("totalMutantsCount"), "stats.totalMutantsCount")
    if total <= 0:
        raise MergeGroundsError("Infection generated zero mutants")
    counts = empty_mutation_counts()
    counts["killed"] = count(stats.get("killedCount"), "stats.killedCount")
    counts["survived"] = count(stats.get("escapedCount", 0), "stats.escapedCount")
    counts["not_covered"] = count(stats.get("notCoveredCount", 0), "stats.notCoveredCount")
    counts["timeout"] = count(stats.get("timeOutCount", 0), "stats.timeOutCount")
    counts["invalid"] = count(stats.get("errorCount", 0), "stats.errorCount")
    counts["unviable"] = count(stats.get("syntaxErrorCount", 0), "stats.syntaxErrorCount")
    counts["ignored"] = count(stats.get("skippedCount", 0), "stats.skippedCount") + count(stats.get("ignoredCount", 0), "stats.ignoredCount")
    if sum(counts.values()) != total:
        raise MergeGroundsError("Infection counters do not explain totalMutantsCount")
    tested = total - counts["ignored"]
    if tested <= 0:
        raise MergeGroundsError("Infection has no non-ignored mutants")
    computed_msi = ratio(counts["killed"], tested, "Infection MSI")
    native_score = percentage(stats.get("msi"), "stats.msi")
    if abs(native_score - computed_msi) > 0.01:
        raise MergeGroundsError("Infection msi disagrees with recomputed value")
    code_coverage = ratio(tested - counts["not_covered"], tested, "Infection mutation code coverage")
    covered_total = tested - counts["not_covered"]
    covered_msi = ratio(counts["killed"], covered_total, "Infection covered code MSI")
    if abs(percentage(stats.get("mutationCodeCoverage"), "stats.mutationCodeCoverage") - code_coverage) > 0.01:
        raise MergeGroundsError("Infection mutationCodeCoverage disagrees with recomputed value")
    if abs(percentage(stats.get("coveredCodeMsi"), "stats.coveredCodeMsi") - covered_msi) > 0.01:
        raise MergeGroundsError("Infection coveredCodeMsi disagrees with recomputed value")
    return counts, native_score


def cargo_mutants_counts(path: Path) -> dict[str, int]:
    data = strict_json(path)
    if not isinstance(data, dict):
        raise MergeGroundsError("cargo-mutants outcomes root must be an object")
    counts = empty_mutation_counts()
    counts["killed"] = count(data.get("caught"), "caught")
    counts["survived"] = count(data.get("missed"), "missed")
    counts["timeout"] = count(data.get("timeout"), "timeout")
    counts["unviable"] = count(data.get("unviable"), "unviable")
    counts["invalid"] = count(data.get("success", 0), "success")
    total = count(data.get("total_mutants"), "total_mutants")
    if total <= 0 or sum(counts.values()) != total:
        raise MergeGroundsError("cargo-mutants summary is empty or inconsistent")
    outcomes = data.get("outcomes")
    if not isinstance(outcomes, list):
        raise MergeGroundsError("cargo-mutants report lacks outcomes")
    if data.get("end_time") is None:
        raise MergeGroundsError("cargo-mutants report is incomplete: end_time is missing")
    detail = {"CaughtMutant": 0, "MissedMutant": 0, "Timeout": 0, "Unviable": 0, "Success": 0}
    baseline_success = False
    for item in outcomes:
        if not isinstance(item, dict):
            raise MergeGroundsError("cargo-mutants outcome must be an object")
        scenario = item.get("scenario")
        summary = item.get("summary")
        if scenario == "Baseline":
            if summary != "Success" or baseline_success:
                raise MergeGroundsError("cargo-mutants baseline is absent, duplicated, or failed")
            baseline_success = True
            continue
        if not isinstance(scenario, dict) or "Mutant" not in scenario:
            raise MergeGroundsError("cargo-mutants outcome has an unknown scenario")
        if summary not in detail:
            raise MergeGroundsError(f"cargo-mutants has unknown/adverse summary: {summary!r}")
        detail[summary] += 1
    if not baseline_success:
        raise MergeGroundsError("cargo-mutants report has no successful baseline")
    expected = {
        "caught": detail["CaughtMutant"],
        "missed": detail["MissedMutant"],
        "timeout": detail["Timeout"],
        "unviable": detail["Unviable"],
        "success": detail["Success"],
    }
    for key, value in expected.items():
        if count(data.get(key, 0), key) != value:
            raise MergeGroundsError(f"cargo-mutants summary/detail mismatch for {key}")
    return counts


def parse_mutation_report(report_format: str, path: Path) -> tuple[dict[str, int] | None, float | None]:
    if report_format == "mergegrounds-json":
        return None, mergegrounds_metrics(path)["mutation_score"]
    if report_format == "stryker-json":
        return stryker_counts(path), None
    if report_format == "pit-xml":
        return pit_counts(path), None
    if report_format == "gremlins-json":
        return gremlins_counts(path), None
    if report_format == "mutmut-json":
        return mutmut_counts(path), None
    if report_format == "infection-json":
        return infection_counts(path)
    if report_format == "cargo-mutants":
        return cargo_mutants_counts(path), None
    raise MergeGroundsError(f"unsupported mutation metric format: {report_format}")


def aggregate_coverage(report_format: str, files: list[Path], branch_required: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    if report_format == "mergegrounds-json":
        if len(files) != 1:
            raise MergeGroundsError("mergegrounds-json requires exactly one metric report")
        values = mergegrounds_metrics(files[0])
        return {"line_coverage": values["line_coverage"], "branch_coverage": values["branch_coverage"]}, {}
    aggregate = {"line_covered": 0, "line_total": 0, "branch_covered": 0, "branch_total": 0}
    for path in files:
        parsed = parse_coverage_report(report_format, path)
        for key in aggregate:
            value = parsed.get(key)
            if value is not None:
                aggregate[key] += count(value, key)
    line_score = ratio(aggregate["line_covered"], aggregate["line_total"], "line coverage")
    if branch_required:
        branch_score: float | None = ratio(aggregate["branch_covered"], aggregate["branch_total"], "branch coverage")
    else:
        branch_score = None
    return {"line_coverage": line_score, "branch_coverage": branch_score}, aggregate


def aggregate_mutation(report_format: str, files: list[Path]) -> tuple[float, dict[str, int]]:
    if report_format == "mergegrounds-json":
        if len(files) != 1:
            raise MergeGroundsError("mergegrounds-json requires exactly one metric report")
        return mergegrounds_metrics(files[0])["mutation_score"], {}
    aggregate = empty_mutation_counts()
    native_scores: list[float] = []
    for path in files:
        parsed, native_score = parse_mutation_report(report_format, path)
        if parsed is None:
            raise MergeGroundsError(f"{report_format} did not provide mutation counts")
        for key in aggregate:
            aggregate[key] += parsed[key]
        if native_score is not None:
            native_scores.append(native_score)
    denominator = aggregate["killed"] + aggregate["survived"] + aggregate["not_covered"] + aggregate["timeout"] + aggregate["invalid"]
    score = ratio(aggregate["killed"], denominator, "mutation score")
    if native_scores and (len(native_scores) != 1 or abs(native_scores[0] - score) > 0.01):
        raise MergeGroundsError("native mutation score disagrees with recomputed value")
    return score, aggregate


def configured_threshold(config: dict[str, Any], adapter: dict[str, Any], key: str) -> float:
    global_value = finite_number(config.get("thresholds", {}).get(key), f"thresholds.{key}")
    adapter_value = finite_number(adapter.get("thresholds", {}).get(key), f"{adapter['id']}.thresholds.{key}")
    return max(global_value, adapter_value)


def validate_metric(
    root: Path,
    config: dict[str, Any],
    adapter: dict[str, Any],
    kind: str,
    before: dict[str, tuple[int, int, str]],
    purged: set[str] | None = None,
) -> dict[str, Any]:
    descriptor = descriptor_for(adapter, kind)
    if descriptor is None:
        raise MergeGroundsError(f"adapter {adapter['id']} has no metrics.{kind} descriptor")
    report_format = descriptor.get("format")
    if not isinstance(report_format, str) or not report_format:
        raise MergeGroundsError(f"adapter {adapter['id']} metrics.{kind}.format is missing")
    files = select_report_files(root, descriptor)
    require_fresh_reports(root, files, before, purged)
    for path in files:
        if not is_regular_repo_file(path, root):
            raise MergeGroundsError(f"metric report changed into an unsafe path before parsing: {path}")
    report_records = [
        {"path": relative(path, root), "sha256": sha256_file(path), "bytes": path.stat().st_size}
        for path in files
    ]
    violations: list[str] = []
    if kind == "coverage":
        branch_required = descriptor.get("branch_required") is not False
        observed, counts = aggregate_coverage(report_format, files, branch_required)
        line_floor = configured_threshold(config, adapter, "line_coverage")
        branch_floor = configured_threshold(config, adapter, "branch_coverage")
        if observed["line_coverage"] < line_floor:
            violations.append(f"line coverage {observed['line_coverage']:.4f} < {line_floor:.4f}")
        if branch_required and observed["branch_coverage"] < branch_floor:
            violations.append(f"branch coverage {observed['branch_coverage']:.4f} < {branch_floor:.4f}")
        thresholds = {"line_coverage": line_floor, "branch_coverage": branch_floor if branch_required else None}
        metric_counts = counts
    else:
        score, metric_counts = aggregate_mutation(report_format, files)
        floor = configured_threshold(config, adapter, "mutation_score")
        if config.get("risk_tier") == "R4":
            critical_floor = finite_number(
                config.get("thresholds", {}).get("critical_mutation_score"),
                "thresholds.critical_mutation_score",
            )
            floor = max(floor, critical_floor)
        observed = {"mutation_score": score}
        thresholds = {"mutation_score": floor}
        if score < floor:
            violations.append(f"mutation score {score:.4f} < {floor:.4f}")
        policy = config.get("mutation_policy", {})
        if metric_counts:
            checks = {
                "survived": "fail_on_survived",
                "not_covered": "fail_on_not_covered",
                "timeout": "fail_on_timeout",
                "invalid": "fail_on_invalid",
                "unviable": "fail_on_unviable",
            }
            for category, setting in checks.items():
                if policy.get(setting, True) and metric_counts[category] > 0:
                    violations.append(f"{category} mutants: {metric_counts[category]}")
            if not policy.get("allow_ignored", False) and metric_counts["ignored"] > 0:
                violations.append(f"ignored mutants lack reviewed exclusions: {metric_counts['ignored']}")
        elif policy.get("fail_on_survived", True) and score < 100.0:
            violations.append("generic mutation metric cannot prove zero survivors below 100%")
    return {
        "adapter": adapter["id"],
        "stage": f"{kind}-metrics",
        "status": "fail" if violations else "pass",
        "format": report_format,
        "reports": report_records,
        "observed": observed,
        "counts": metric_counts,
        "thresholds": thresholds,
        "violations": violations,
    }


def write_json_atomic(path: Path, payload: dict[str, Any], root: Path) -> None:
    """Atomically write JSON without following repository-relative symlinks."""
    try:
        relative_path = path.absolute().relative_to(root.absolute())
    except ValueError as exc:
        raise MergeGroundsError("JSON output path must remain in the repository") from exc
    if not relative_path.parts or relative_path.name in {"", ".", ".."}:
        raise MergeGroundsError("JSON output path must name a repository file")
    body = (json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")

    if os.name == "nt":  # pragma: no cover - Windows fallback; CI policy uses Linux
        if has_symlink_component(path.parent, root) or not is_within(path.parent.resolve(), root):
            raise MergeGroundsError("JSON output parent must not traverse a symlink")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        with temporary.open("xb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        return

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(root, directory_flags)
    try:
        for part in relative_path.parent.parts:
            try:
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=directory_fd)
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        temporary_name = f".{relative_path.name}.{uuid.uuid4().hex}.tmp"
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(temporary_name, file_flags, 0o600, dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(body):
                offset += os.write(file_fd, body[offset:])
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        try:
            os.replace(
                temporary_name,
                relative_path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        except Exception:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                # A successful replace can remove the temporary name before fsync fails.
                pass
            raise
    except OSError as exc:
        raise MergeGroundsError(f"cannot securely write JSON output {relative_path}: {exc}") from exc
    finally:
        os.close(directory_fd)


def yaml_without_comment(line: str) -> str:
    """Strip YAML comments while preserving # characters inside quoted scalars."""
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if quote == '"' and escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if quote is None and character in {"'", '"'}:
            quote = character
            continue
        if quote == character:
            quote = None
            continue
        if quote is None and character == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line.rstrip()


def yaml_structure_lines(lines: list[str]) -> list[str]:
    """Mask block-scalar bodies so embedded scripts are not parsed as YAML keys."""
    result: list[str] = []
    block_indent: int | None = None
    block_header = re.compile(
        r"^\s*(?P<dash>-\s+)?[A-Za-z0-9_-]+\s*:\s*[>|](?:[+-]?[1-9]?|[1-9][+-]?)?\s*$"
    )
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None and (not line.strip() or indent > block_indent):
            result.append("")
            continue
        block_indent = None
        result.append(line)
        match = block_header.match(line)
        if match:
            block_indent = indent + len(match.group("dash") or "")
    return result


def workflow_expression_sink_values(lines: list[str]) -> list[str]:
    """Collect execution-affecting scalar values without claiming to parse YAML.

    PR data is dangerous anywhere it can select a runner, container, command
    interpreter, working directory, matrix, or command input.  Container-style
    keys intentionally taint every nested scalar because GitHub's schema allows
    execution controls several levels below services/strategy/defaults.
    """
    values: list[list[str]] = []
    container_indents: list[int] = []
    continuation_indent: int | None = None
    continuation_index: int | None = None

    scalar_keys = {
        "cancel-in-progress",
        "container",
        "continue-on-error",
        "environment",
        "group",
        "if",
        "run",
        "runs-on",
        "shell",
        "timeout-minutes",
        "working-directory",
    }
    container_keys = {
        "concurrency",
        "container",
        "defaults",
        "env",
        "outputs",
        "services",
        "strategy",
        "with",
    }
    keys = "|".join(sorted(scalar_keys | container_keys, key=len, reverse=True))
    sink_key = re.compile(
        rf"^(?P<dash>-\s+)?(?P<key>{keys})\s*:\s*(?P<value>.*)$"
    )
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if continuation_index is not None:
            if not stripped or indent > (continuation_indent or 0):
                values[continuation_index].append(line)
                continue
            continuation_indent = None
            continuation_index = None

        if not stripped:
            continue

        while container_indents and indent <= container_indents[-1]:
            container_indents.pop()

        # Everything nested below a container-style mapping is an execution input.
        # Keeping it as a scalar chunk also covers block and folded continuations;
        # unsupported mapping tricks remain blocked by the canonical YAML checks.
        if container_indents:
            values.append([line])
            continuation_indent = indent
            continuation_index = len(values) - 1
            continue

        match = sink_key.match(stripped)
        if not match:
            continue
        logical_indent = indent + len(match.group("dash") or "")
        key = match.group("key")
        value = match.group("value")
        if key in container_keys and not value:
            container_indents.append(logical_indent)
            continue

        values.append([value])
        continuation_indent = logical_indent
        continuation_index = len(values) - 1

    return ["\n".join(parts) for parts in values]


def encoded_yaml_double_scalar(value: str) -> bool:
    """Detect character escapes that could hide an Actions expression from raw scanning."""
    stripped = value.lstrip()
    scalar = re.match(r'(?:[A-Za-z_][A-Za-z0-9_-]*\s*:\s*)?(".*)', stripped, re.DOTALL)
    return bool(
        scalar
        and re.search(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})", scalar.group(1))
    )


def actions_expression_bodies(value: str) -> tuple[list[str], bool]:
    """Extract ${{ ... }} bodies while ignoring closing braces inside strings."""
    bodies: list[str] = []
    malformed = False
    cursor = 0
    while True:
        start = value.find("${{", cursor)
        if start < 0:
            break
        index = start + 3
        quote: str | None = None
        closed = False
        while index < len(value):
            character = value[index]
            if quote == "'":
                if character == "'" and index + 1 < len(value) and value[index + 1] == "'":
                    index += 2
                    continue
                if character == "'":
                    quote = None
                index += 1
                continue
            if quote == '"':
                if character == "\\" and index + 1 < len(value):
                    index += 2
                    continue
                if character == '"':
                    quote = None
                index += 1
                continue
            if character in {"'", '"'}:
                quote = character
                index += 1
                continue
            if value.startswith("${{", index):
                malformed = True
            if value.startswith("}}", index):
                bodies.append(value[start + 3 : index])
                cursor = index + 2
                closed = True
                break
            index += 1
        if not closed:
            bodies.append(value[start + 3 :])
            malformed = True
            break
    return bodies, malformed


def actions_expression_tokens(expression: str) -> tuple[list[tuple[str, str]], bool]:
    """Tokenize only the property-access subset needed for context hardening."""
    tokens: list[tuple[str, str]] = []
    malformed = False
    index = 0
    while index < len(expression):
        character = expression[index]
        if character.isspace():
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            decoded: list[str] = []
            dynamic = False
            closed = False
            while index < len(expression):
                current = expression[index]
                if quote == "'" and current == "'" and index + 1 < len(expression) and expression[index + 1] == "'":
                    decoded.append("'")
                    index += 2
                    continue
                if current == "\\":
                    # GitHub expression strings and an enclosing YAML scalar have
                    # different escape rules. Treat any escape as dynamic rather
                    # than trying to emulate both grammars.
                    dynamic = True
                    if index + 1 < len(expression):
                        decoded.append(expression[index + 1])
                        index += 2
                    else:
                        index += 1
                    continue
                if current == quote:
                    index += 1
                    closed = True
                    break
                decoded.append(current)
                index += 1
            if not closed:
                malformed = True
            tokens.append(("DYNAMIC_STRING" if dynamic else "STRING", "".join(decoded)))
            continue
        identifier = re.match(r"[A-Za-z_][A-Za-z0-9_]*", expression[index:])
        if identifier:
            value = identifier.group(0)
            tokens.append(("IDENT", value))
            index += len(value)
            continue
        punctuation = {
            ".": "DOT",
            "[": "LBRACKET",
            "]": "RBRACKET",
            "*": "STAR",
            "(": "LPAREN",
            ")": "RPAREN",
        }
        if character in punctuation:
            tokens.append((punctuation[character], character))
        else:
            if character == "\\":
                malformed = True
            tokens.append(("OTHER", character))
        index += 1
    return tokens, malformed


def github_expression_risks(expression: str) -> tuple[bool, bool, bool]:
    """Return implicit-token, untrusted-PR-data, and malformed-expression risks."""
    tokens, malformed = actions_expression_tokens(expression)
    token_risk = False
    pr_data_risk = False
    safe_pull_request_scalars = {
        ("id",),
        ("node_id",),
        ("number",),
        ("merge_commit_sha",),
        ("base", "sha"),
        ("head", "sha"),
    }

    for position, (kind, value) in enumerate(tokens):
        if kind != "IDENT" or value.casefold() != "github":
            continue
        if position > 0 and tokens[position - 1][0] == "DOT":
            continue

        segments: list[str] = []
        dynamic_access = False
        cursor = position + 1
        while cursor < len(tokens):
            token_kind, _ = tokens[cursor]
            if token_kind == "DOT":
                if cursor + 1 >= len(tokens) or tokens[cursor + 1][0] != "IDENT":
                    dynamic_access = True
                    break
                segments.append(tokens[cursor + 1][1].casefold())
                cursor += 2
                continue
            if token_kind == "LBRACKET":
                if (
                    cursor + 2 < len(tokens)
                    and tokens[cursor + 1][0] == "STRING"
                    and tokens[cursor + 2][0] == "RBRACKET"
                ):
                    segments.append(tokens[cursor + 1][1].casefold())
                    cursor += 3
                    continue
                dynamic_access = True
            break

        normalized = tuple(segments)
        if not normalized:
            # A bare/serialized github object contains both github.token and the
            # complete pull-request event. A dynamic root index can select either.
            token_risk = True
            pr_data_risk = True
            continue
        if normalized[0] == "token":
            token_risk = True
        if normalized[0] == "head_ref":
            pr_data_risk = True
        if normalized[0] == "event":
            if len(normalized) == 1 or dynamic_access:
                pr_data_risk = True
            elif normalized[1] == "pull_request":
                pull_request_path = normalized[2:]
                if dynamic_access or pull_request_path not in safe_pull_request_scalars:
                    pr_data_risk = True
            elif normalized not in {
                ("event", "repository", "default_branch"),
                ("event", "repository", "private"),
            }:
                # Issue/comment/review/discussion/call/dispatch payloads and
                # future event fields are attacker-controlled unless a tiny
                # typed scalar is explicitly proven safe above.
                pr_data_risk = True

    return token_risk, pr_data_risk, malformed


def workflow_output_expression_risk(expression: str, workflow_path: str) -> bool:
    """Reject cross-step/job output dataflow except audited starter plumbing."""
    tokens, malformed = actions_expression_tokens(expression)
    if malformed:
        return True
    output_reference = False
    for position, (kind, value) in enumerate(tokens):
        if kind != "IDENT" or value.casefold() not in {"steps", "needs"}:
            continue
        if position > 0 and tokens[position - 1][0] == "DOT":
            continue
        segments: list[str] = []
        dynamic = False
        cursor = position + 1
        while cursor < len(tokens):
            token_kind, _ = tokens[cursor]
            if token_kind == "DOT":
                if cursor + 1 >= len(tokens) or tokens[cursor + 1][0] != "IDENT":
                    dynamic = True
                    break
                segments.append(tokens[cursor + 1][1])
                cursor += 2
                continue
            if token_kind == "LBRACKET":
                if (
                    cursor + 2 < len(tokens)
                    and tokens[cursor + 1][0] == "STRING"
                    and tokens[cursor + 2][0] == "RBRACKET"
                ):
                    segments.append(tokens[cursor + 1][1])
                    cursor += 3
                    continue
                dynamic = True
            break
        if dynamic or not segments:
            return True
        if any(segment.casefold() == "outputs" for segment in segments):
            output_reference = True
    if not output_reference:
        return False

    # These exact references are the starter's reviewed, type-checked plumbing:
    # MergeGrounds's shell exit code is range-checked before use; CodeQL's matrix is
    # produced by the fixed, bounded language detector and consumed as JSON.
    allowed = {
        ".github/workflows/mergegrounds.yml": {
            "steps.mergegrounds_pr.outputs.exit_code",
        },
        ".github/workflows/full-scan.yml": {
            "steps.mergegrounds_full.outputs.exit_code",
        },
        ".github/workflows/codeql.yml": {
            "steps.languages.outputs.matrix",
            "fromJSON(needs.detect.outputs.matrix)",
        },
    }
    canonical = re.sub(r"\s+", "", expression)
    return canonical not in allowed.get(workflow_path, set())


def workflow_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflow_dir = root / ".github" / "workflows"
    for path in sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")]):
        try:
            rel = path.absolute().relative_to(root.absolute()).as_posix()
        except ValueError:
            rel = str(path)
        if not is_regular_repo_file(path, root):
            findings.append(Finding("CONTROL_SYMLINK", "error", "workflow must be a regular in-repository file", rel))
            continue
        text = path.read_text(encoding="utf-8")
        workflow_digest = sha256_bytes(text.encode("utf-8"))
        trusted_workflow_digest = TRUSTED_ADMISSION_WORKFLOW_SHA256.get(rel)
        if (
            trusted_workflow_digest is not None
            and workflow_digest != trusted_workflow_digest
        ):
            findings.append(
                Finding(
                    "WORKFLOW_TOPOLOGY",
                    "error",
                    "the shipped security workflow differs from its reviewed fail-closed topology",
                    rel,
                )
            )
        if "\t" in text:
            findings.append(Finding("WORKFLOW_SYNTAX", "error", "tabs are forbidden in workflow YAML", rel))
        expression_lines = [yaml_without_comment(line) for line in text.splitlines()]
        code_lines = yaml_structure_lines(expression_lines)
        entries = [
            (index, len(line) - len(line.lstrip(" ")), line.lstrip(" "))
            for index, line in enumerate(code_lines)
            if line.strip()
        ]
        code = "\n".join(code_lines)
        expressions = "\n".join(expression_lines)

        control_invocation = re.compile(
            r"\bpython3(?P<options>(?:[ \t]+-[A-Za-z]+)*)[ \t]+"
            r"scripts/(?:mergegrounds|ai_assurance)\.py\b"
        )
        for invocation in control_invocation.finditer(expressions):
            if "-I" not in invocation.group("options").split():
                findings.append(
                    Finding(
                        "PYTHON_ISOLATION",
                        "error",
                        "Python control-plane scripts must be invoked with canonical python3 -I isolation",
                        rel,
                    )
                )

        for line in code_lines:
            content = line.strip()
            if re.match(r"^(?:-\s*)?['\"][^'\"]+['\"]\s*:", content):
                findings.append(Finding("WORKFLOW_SYNTAX", "error", "quoted YAML keys are forbidden in the canonical workflow subset", rel))
            if re.match(r"^-?\s*\{", content):
                findings.append(Finding("WORKFLOW_SYNTAX", "error", "flow-style mappings are forbidden in workflows", rel))
            if re.match(r"^<<\s*:", content) or re.search(r"(?:^|\s)[&*][A-Za-z_][A-Za-z0-9_-]*", content):
                findings.append(Finding("WORKFLOW_SYNTAX", "error", "YAML anchors, aliases, and merge keys are forbidden", rel))
            if re.match(r"^(?:-\s*)?(?:\?|:\s|!)", content):
                findings.append(Finding("WORKFLOW_SYNTAX", "error", "complex YAML keys and explicit tags are forbidden", rel))
            flow_collection = re.match(
                r"^(?:-\s*)?(?P<key>[A-Za-z0-9_-]+)\s*:\s*(?P<value>[\[{].*)$",
                content,
            )
            if flow_collection:
                key = flow_collection.group("key")
                value = flow_collection.group("value")
                safe_scalar_sequence = key in {"on", "types"} and re.fullmatch(
                    r"\[[A-Za-z_][A-Za-z0-9_-]*(?:, [A-Za-z_][A-Za-z0-9_-]*)*\]",
                    value,
                )
                if not safe_scalar_sequence:
                    findings.append(
                        Finding(
                            "WORKFLOW_SYNTAX",
                            "error",
                            "workflow structure must not use unparsed flow-style collections",
                            rel,
                        )
                    )

        if re.search(r"\bpull_request_target\b", code):
            findings.append(Finding("UNTRUSTED_TRIGGER", "error", "pull_request_target is forbidden", rel))
        top_keys: dict[str, list[tuple[int, str]]] = {
            "on": [],
            "permissions": [],
            "concurrency": [],
            "jobs": [],
        }
        for index, indent, content in entries:
            if indent != 0:
                continue
            match = re.match(r"^(on|permissions|concurrency|jobs)\s*:\s*(.*)$", content)
            if match:
                top_keys[match.group(1)].append((index, match.group(2)))
        for key in ("on", "jobs"):
            if len(top_keys[key]) != 1:
                findings.append(Finding("WORKFLOW_SYNTAX", "error", f"workflow must have exactly one canonical top-level {key}: key", rel))
        if len(top_keys["permissions"]) != 1:
            findings.append(Finding("PERMISSIONS_MISSING", "error", "workflow lacks top-level permissions", rel))

        pull_request = False
        protected_source_event = False
        untrusted_input_event = True
        if len(top_keys["on"]) == 1:
            on_index, on_value = top_keys["on"][0]
            trigger_names: set[str] = set()
            if not on_value:
                child_lines: list[str] = []
                for index in range(on_index + 1, len(code_lines)):
                    line = code_lines[index]
                    if not line.strip():
                        continue
                    indent = len(line) - len(line.lstrip(" "))
                    if indent == 0:
                        break
                    child_lines.append(line.strip())
                    if indent == 2:
                        event_match = re.match(
                            r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:",
                            line.strip(),
                        )
                        if event_match:
                            trigger_names.add(event_match.group(1))
            elif on_value.startswith("["):
                trigger_names.update(
                    re.findall(r"[A-Za-z_][A-Za-z0-9_-]*", on_value)
                )
            elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", on_value):
                trigger_names.add(on_value)
            pull_request = "pull_request" in trigger_names
            protected_source_event = bool(
                trigger_names
                & {"pull_request", "push", "merge_group", "workflow_dispatch"}
            )
            # Only a pure scheduled default-branch workflow lacks candidate or
            # external event input. Unknown/new triggers fail into the tainted set.
            untrusted_input_event = trigger_names != {"schedule"}
            if on_value and not (
                on_value.startswith("[")
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", on_value)
            ):
                findings.append(Finding("WORKFLOW_SYNTAX", "error", "non-canonical inline workflow triggers are forbidden", rel))

        if protected_source_event:
            concurrency_entries = top_keys["concurrency"]
            nested_concurrency = [
                (index, indent, content)
                for index, indent, content in entries
                if indent != 0 and re.match(r"^concurrency\s*:", content)
            ]
            # A job-level concurrency group shares the repository-wide namespace
            # and can cancel another security run.  The portable subset therefore
            # permits only the single reviewed workflow-level block below.
            concurrency_valid = len(concurrency_entries) == 1 and not nested_concurrency
            group_value: str | None = None
            cancel_value: str | None = None
            if concurrency_valid:
                concurrency_index, concurrency_scalar = concurrency_entries[0]
                concurrency_valid = not concurrency_scalar
                children: list[tuple[int, str]] = []
                if concurrency_valid:
                    for child_index in range(concurrency_index + 1, len(code_lines)):
                        child = code_lines[child_index]
                        if not child.strip():
                            continue
                        child_indent = len(child) - len(child.lstrip(" "))
                        if child_indent == 0:
                            break
                        children.append((child_indent, child.strip()))
                if len(children) != 2 or any(indent != 2 for indent, _ in children):
                    concurrency_valid = False
                else:
                    parsed_children: dict[str, str] = {}
                    for _, child in children:
                        match = re.fullmatch(
                            r"(group|cancel-in-progress)\s*:\s*(.+?)\s*",
                            child,
                        )
                        if not match or match.group(1) in parsed_children:
                            concurrency_valid = False
                            break
                        parsed_children[match.group(1)] = match.group(2)
                    group_value = parsed_children.get("group")
                    cancel_value = parsed_children.get("cancel-in-progress")
                    concurrency_valid = concurrency_valid and set(parsed_children) == {
                        "group",
                        "cancel-in-progress",
                    }
            if concurrency_valid:
                safe_group_expression = (
                    r"(?:github\.(?:ref|sha|run_id|run_attempt)|"
                    r"github\.event\.pull_request\.number(?:\s*\|\|\s*github\.ref)?)"
                )
                concurrency_valid = (
                    isinstance(group_value, str)
                    and len(group_value.encode("utf-8")) <= 256
                    and re.fullmatch(
                        rf"(?:[A-Za-z0-9_.-]{{1,128}}|"
                        rf"[A-Za-z0-9_.-]{{0,128}}\$\{{\{{\s*{safe_group_expression}\s*\}}\}})",
                        group_value,
                    )
                    is not None
                    and cancel_value == "false"
                )
            if not concurrency_valid:
                findings.append(
                    Finding(
                        "CONCURRENCY_INVALID",
                        "error",
                        "protected-source workflows require one canonical concurrency block with a bounded safe group and cancel-in-progress: false",
                        rel,
                    )
                )

        if protected_source_event:
            dynamic_runner = False
            for start, indent, content in entries:
                runner_match = re.match(r"^runs-on\s*:\s*(.*)$", content)
                if not runner_match:
                    continue
                runner_value = runner_match.group(1)
                if not runner_value:
                    nested_runner_lines: list[str] = []
                    for child_index in range(start + 1, len(code_lines)):
                        child = code_lines[child_index]
                        if not child.strip():
                            continue
                        child_indent = len(child) - len(child.lstrip(" "))
                        if child_indent <= indent:
                            break
                        nested_runner_lines.append(child.strip())
                    runner_value = "\n".join(nested_runner_lines)
                dynamic_runner = dynamic_runner or "${{" in runner_value
            allow_reviewed_dynamic_runner = (
                rel == ".github/workflows/codeql.yml"
                and workflow_digest
                == TRUSTED_ADMISSION_WORKFLOW_SHA256[".github/workflows/codeql.yml"]
            )
            if dynamic_runner and not allow_reviewed_dynamic_runner:
                findings.append(
                    Finding(
                        "DYNAMIC_EXECUTION_CONTROL",
                        "error",
                        "protected-source workflows must not select runners from dynamic expressions",
                        rel,
                    )
                )
            for line in code_lines:
                content = line.strip()
                image_match = re.match(
                    r"^(?:-\s*)?(?:image|container)\s*:\s*(.+?)\s*$",
                    content,
                )
                if not image_match:
                    continue
                image_value = image_match.group(1).strip()
                if len(image_value) >= 2 and image_value[0] == image_value[-1] and image_value[0] in {"'", '"'}:
                    image_value = image_value[1:-1]
                if re.fullmatch(r"[^@\s]+@sha256:[0-9a-fA-F]{64}", image_value) is None:
                    findings.append(
                        Finding(
                            "MUTABLE_CONTAINER_IMAGE",
                            "error",
                            "job and service container images must be pinned to an immutable sha256 digest",
                            rel,
                        )
                    )

        permission_blocks: list[tuple[int, int, str]] = []
        for index, indent, content in entries:
            match = re.match(r"^permissions\s*:\s*(.*)$", content)
            if match:
                permission_blocks.append((index, indent, match.group(1)))
        for start, indent, scalar in permission_blocks:
            if scalar == "write-all":
                findings.append(Finding("WRITE_ALL", "error", "workflow grants write-all", rel))
            elif scalar == "read-all":
                findings.append(Finding("READ_ALL", "warning", "prefer explicit least-privilege scopes over read-all", rel))
            elif scalar:
                if re.search(r"(?:^|[,{]\s*)[A-Za-z0-9_-]+\s*:\s*write(?:\s*[,}]|$)", scalar):
                    findings.append(Finding("PR_WRITE_PERMISSION" if pull_request else "WRITE_PERMISSION", "error", "inline write permissions are forbidden", rel))
                else:
                    findings.append(Finding("WORKFLOW_SYNTAX", "error", "permissions must use an explicit block mapping", rel))
                continue
            for index in range(start + 1, len(code_lines)):
                line = code_lines[index]
                if not line.strip():
                    continue
                child_indent = len(line) - len(line.lstrip(" "))
                if child_indent <= indent:
                    break
                match = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(read|write|none)\s*$", line.strip())
                if not match:
                    findings.append(Finding("WORKFLOW_SYNTAX", "error", "permissions entries must be canonical scope: read|write|none pairs", rel))
                    continue
                scope, access = match.groups()
                if access == "write" and protected_source_event:
                    reviewed_release_attestation_scope = (
                        rel == ".github/workflows/release.yml"
                        and workflow_digest
                        == TRUSTED_ADMISSION_WORKFLOW_SHA256[
                            ".github/workflows/release.yml"
                        ]
                        and scope in {"artifact-metadata", "attestations", "id-token"}
                    )
                    if not reviewed_release_attestation_scope:
                        code = "PR_WRITE_PERMISSION" if pull_request else "WRITE_PERMISSION"
                        findings.append(
                            Finding(
                                code,
                                "error",
                                f"protected-source workflow grants {scope}: write",
                                rel,
                            )
                        )

        if re.search(r"\bself-hosted\b", code, re.IGNORECASE):
            findings.append(Finding("SELF_HOSTED_PR", "error", "portable baseline forbids self-hosted runners for untrusted code", rel))
        if untrusted_input_event and re.search(r"\$\{\{[^}]*\bsecrets\b", expressions, re.IGNORECASE):
            findings.append(Finding("PR_SECRET", "error", "repository workflow references a secret in candidate-executable YAML", rel))
        if untrusted_input_event and any(
            re.match(r"^secrets\s*:", content, re.IGNORECASE)
            for _, _, content in entries
        ):
            findings.append(
                Finding(
                    "PR_SECRET",
                    "error",
                    "protected-source workflows must not declare or inherit reusable-workflow secrets",
                    rel,
                )
            )
        if protected_source_event and any(
            re.match(r"^continue-on-error\s*:", content, re.IGNORECASE)
            for _, _, content in entries
        ):
            allow_reviewed_continue_on_error = (
                rel
                in {
                    ".github/workflows/mergegrounds.yml",
                    ".github/workflows/full-scan.yml",
                }
                and workflow_digest == TRUSTED_ADMISSION_WORKFLOW_SHA256[rel]
            )
            if not allow_reviewed_continue_on_error:
                findings.append(
                    Finding(
                        "CONTINUE_ON_ERROR",
                        "error",
                        "continue-on-error is forbidden outside the exact reviewed fail-closed admission workflows",
                        rel,
                    )
                )
        # Event payloads, tokens, and cross-step outputs stay tainted for every
        # candidate/external trigger; new event names fail into this branch.
        if untrusted_input_event:
            token_risk = False
            pr_data_risk = False
            output_risk = False
            malformed_expression = False
            for sink_value in workflow_expression_sink_values(expression_lines):
                malformed_expression = malformed_expression or encoded_yaml_double_scalar(sink_value)
                bodies, malformed_delimiters = actions_expression_bodies(sink_value)
                malformed_expression = malformed_expression or malformed_delimiters
                for body in bodies:
                    body_token_risk, body_pr_data_risk, malformed_tokens = github_expression_risks(body)
                    token_risk = token_risk or body_token_risk
                    pr_data_risk = pr_data_risk or body_pr_data_risk
                    output_risk = output_risk or workflow_output_expression_risk(body, rel)
                    malformed_expression = malformed_expression or malformed_tokens
            if malformed_expression:
                findings.append(
                    Finding(
                        "WORKFLOW_SYNTAX",
                        "error",
                        "an execution-affecting workflow field contains an unsupported or malformed Actions expression",
                        rel,
                    )
                )
            if token_risk:
                findings.append(
                    Finding(
                        "PR_TOKEN",
                        "error",
                        "protected-source workflow exposes or dynamically indexes the GitHub context/token",
                        rel,
                    )
                )
            if pr_data_risk:
                findings.append(
                    Finding(
                        "SCRIPT_INJECTION",
                        "error",
                        "untrusted source-event context is interpolated into an execution-affecting workflow field",
                        rel,
                    )
                )
            if output_risk:
                findings.append(
                    Finding(
                        "WORKFLOW_OUTPUT_TAINT",
                        "error",
                        "step/job outputs must not influence protected-source execution controls outside audited typed plumbing",
                        rel,
                    )
                )
        for index, line in enumerate(code_lines):
            if not line.strip():
                continue
            match = re.match(r"^(\s*)(?:-\s*)?uses\s*:\s*(.+?)\s*$", line)
            if re.search(r"\buses\s*:", line) and not match:
                findings.append(Finding("WORKFLOW_SYNTAX", "error", "uses must be a standalone YAML key", rel))
                continue
            if not match:
                continue
            use = match.group(2).strip()
            if len(use) >= 2 and use[0] == use[-1] and use[0] in {"'", '"'}:
                use = use[1:-1]
            if not use or any(character.isspace() for character in use):
                findings.append(Finding("WORKFLOW_SYNTAX", "error", "uses value must be one immutable reference", rel))
                continue
            if use.startswith("./"):
                if protected_source_event:
                    findings.append(
                        Finding(
                            "CANDIDATE_LOCAL_ACTION",
                            "error",
                            "pull-request/push/merge-group/manual workflows must not execute candidate-local actions or reusable workflows",
                            rel,
                        )
                    )
                continue
            if use.startswith("docker://"):
                if not re.fullmatch(r"docker://[^@\s]+@sha256:[0-9a-fA-F]{64}", use):
                    findings.append(Finding("MUTABLE_ACTION", "error", f"container action is not digest-pinned: {use}", rel))
                continue
            if "@" not in use or not FULL_SHA.fullmatch(use.rsplit("@", 1)[1]):
                findings.append(Finding("MUTABLE_ACTION", "error", f"action is not pinned to a full commit SHA: {use}", rel))
            if use.lower().startswith("actions/checkout@"):
                uses_indent = len(match.group(1))
                step_indent = uses_indent if line.lstrip().startswith("-") else max(0, uses_indent - 2)
                with_indent: int | None = None
                persist_values: list[str] = []
                for child in code_lines[index + 1 :]:
                    if not child.strip():
                        continue
                    child_indent = len(child) - len(child.lstrip(" "))
                    child_content = child.strip()
                    if child_indent <= step_indent:
                        break
                    if re.fullmatch(r"with\s*:\s*", child_content):
                        with_indent = child_indent
                        continue
                    if with_indent is not None and child_indent <= with_indent:
                        with_indent = None
                    if with_indent is not None:
                        persist = re.fullmatch(r"persist-credentials\s*:\s*(.+?)\s*", child_content)
                        if persist:
                            persist_values.append(persist.group(1).strip("'\""))
                if persist_values != ["false"]:
                    findings.append(Finding("CHECKOUT_CREDENTIALS", "error", "checkout must set persist-credentials: false", rel))
    return findings


def exception_findings(root: Path) -> list[Finding]:
    path = root / ".mergegrounds" / "exceptions.toml"
    if not is_regular_repo_file(path, root):
        return [Finding("EXCEPTIONS_MISSING", "error", "exception registry is missing", relative(path, root))]
    try:
        data = load_toml(path)
    except MergeGroundsError as exc:
        return [Finding("EXCEPTIONS_INVALID", "error", str(exc), relative(path, root))]
    values = data.get("exceptions", [])
    if not isinstance(values, list):
        return [Finding("EXCEPTIONS_INVALID", "error", "exceptions must be an array", relative(path, root))]
    findings: list[Finding] = []
    required = {
        "schema",
        "exception_id",
        "class",
        "control_id",
        "control_domain",
        "underlying_evidence_digest",
        "subject",
        "affected_object",
        "risk_tier",
        "blast_radius",
        "reason",
        "residual_risk",
        "compensating_controls",
        "validation_evidence",
        "owner",
        "issued_at",
        "expires_at",
        "must_fix_by",
        "allowed_actions",
        "allowed_environments",
        "max_uses",
        "uses",
        "points",
        "remediation_issue",
        "remediation_change",
        "renewals",
    }
    class_policy = {
        "XQ": {"ttl": 14, "remediation": 30, "weight": 1},
        "XR": {"ttl": 7, "remediation": 14, "weight": 2},
        "XS": {"ttl": 3, "remediation": 7, "weight": 4},
        "XM": {"ttl": 30, "remediation": 30, "weight": 3},
    }
    risk_multiplier = {"R0": 1, "R1": 1, "R2": 2, "R3": 4, "R4": 8}
    blast_multiplier = {"component": 1, "service/team": 2, "multi-service/customer": 3, "organization/critical": 4}
    now = utc_now()
    ids: set[str] = set()
    active_points = 0
    active_xs = 0

    def add(code: str, message: str) -> None:
        findings.append(Finding(code, "error", message, relative(path, root)))

    def parse_time(value: Any, field: str, label: str) -> dt.datetime | None:
        parsed: dt.datetime | None
        if isinstance(value, dt.datetime):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                parsed = None
        else:
            parsed = None
        if parsed is None or parsed.tzinfo is None:
            add("EXCEPTION_TIME", f"{label}.{field} must be an offset-aware ISO timestamp")
            return None
        return parsed.astimezone(dt.timezone.utc)

    def string_array(item: dict[str, Any], key: str, label: str) -> list[str]:
        value = item.get(key)
        if (
            not isinstance(value, list)
            or not value
            or not all(
                isinstance(entry, str)
                and entry == entry.strip()
                and 0 < len(entry) <= 1024
                and "\x00" not in entry
                for entry in value
            )
        ):
            add("EXCEPTION_INCOMPLETE", f"{label}.{key} must be a non-empty string array")
            return []
        return value

    digest_pattern = re.compile(r"^sha256:[0-9a-f]{64}$")
    identity_pattern = re.compile(r"^user:[A-Za-z0-9][A-Za-z0-9._@:+/=~-]{2,253}$")
    scoped_token_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{1,511}$")

    def valid_human(value: Any) -> bool:
        return isinstance(value, str) and identity_pattern.fullmatch(value) is not None

    def role_seats_satisfied(roles: list[str], seats: list[tuple[str, set[str]]]) -> tuple[bool, list[str]]:
        """Require a distinct human for each documented approval-authority seat."""

        def assign(seat_index: int, used: set[int]) -> bool:
            if seat_index == len(seats):
                return True
            allowed = seats[seat_index][1]
            for role_index, role in enumerate(roles):
                if role_index not in used and role in allowed and assign(seat_index + 1, used | {role_index}):
                    return True
            return False

        if assign(0, set()):
            return True, []
        missing = [name for name, allowed in seats if not any(role in allowed for role in roles)]
        return False, missing or ["distinct approver for each authority seat"]

    for index, item in enumerate(values):
        label = f"exceptions[{index}]"
        if not isinstance(item, dict):
            add("EXCEPTION_INVALID", f"{label} must be a table")
            continue
        missing = sorted(key for key in required if item.get(key) in (None, "", []))
        if missing:
            add("EXCEPTION_INCOMPLETE", f"{label} lacks: {', '.join(missing)}")
        if item.get("schema") != "mergegrounds/exception/v1":
            add("EXCEPTION_SCHEMA", f"{label} has an unsupported schema")
        exception_id = item.get("exception_id")
        if not isinstance(exception_id, str) or not re.fullmatch(r"EXC-[0-9]{4}-[0-9]{4,}", exception_id):
            add("EXCEPTION_ID", f"{label}.exception_id must match EXC-YYYY-NNNN")
        elif exception_id in ids:
            add("EXCEPTION_DUPLICATE", f"duplicate exception id: {exception_id}")
        else:
            ids.add(exception_id)

        exception_class = item.get("class")
        control_id = item.get("control_id")
        control_domain = item.get("control_domain")
        risk_tier = item.get("risk_tier")
        blast = item.get("blast_radius")
        if exception_class not in class_policy:
            add("EXCEPTION_CLASS", f"{label}.class is invalid")
        if risk_tier not in risk_multiplier:
            add("EXCEPTION_RISK", f"{label}.risk_tier is invalid")
        if blast not in blast_multiplier:
            add("EXCEPTION_BLAST", f"{label}.blast_radius is invalid")
        if risk_tier == "R4":
            add("EXCEPTION_R4", f"{label}: ordinary exceptions are prohibited for R4")

        mapped_control_domain: str | None = None
        if (
            not isinstance(control_domain, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{1,31}", control_domain) is None
            or control_domain not in CONTROL_DOMAIN_CLASSES
        ):
            add("EXCEPTION_CONTROL_DOMAIN", f"{label}.control_domain is not a supported authority domain")
        allowed_domains = CONTROL_AUTHORITY_DOMAINS.get(control_id) if isinstance(control_id, str) else None
        if allowed_domains is None:
            add("EXCEPTION_CONTROL_UNMAPPED", f"{label}.control_id has no reviewed authority mapping")
        elif not isinstance(control_domain, str) or control_domain not in allowed_domains:
            add(
                "EXCEPTION_CONTROL_DOMAIN",
                f"{label}.control_domain is not permitted for {control_id}",
            )
        else:
            mapped_control_domain = control_domain
            if exception_class in class_policy and exception_class not in CONTROL_DOMAIN_CLASSES[control_domain]:
                add(
                    "EXCEPTION_CONTROL_DOMAIN",
                    f"{label}.{exception_class} cannot waive the {control_domain} control domain",
                )

        scalar_rules = {
            "control_id": (re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){2,}$"), 3),
            "reason": (None, 20),
            "residual_risk": (None, 20),
            "remediation_issue": (re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{1,255}$"), 2),
            "remediation_change": (re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{1,255}$"), 2),
        }
        for key, (pattern, minimum) in scalar_rules.items():
            value = item.get(key)
            if (
                not isinstance(value, str)
                or value != value.strip()
                or not minimum <= len(value) <= 4096
                or "\x00" in value
                or (pattern is not None and pattern.fullmatch(value) is None)
            ):
                add("EXCEPTION_FIELD", f"{label}.{key} is not a canonical non-empty string")

        evidence_digest = item.get("underlying_evidence_digest")
        if not isinstance(evidence_digest, str) or not digest_pattern.fullmatch(evidence_digest):
            add("EXCEPTION_EVIDENCE", f"{label}.underlying_evidence_digest must be sha256:<64 lowercase hex>")
        for evidence in string_array(item, "validation_evidence", label):
            if not digest_pattern.fullmatch(evidence):
                add("EXCEPTION_EVIDENCE", f"{label}.validation_evidence contains an invalid digest")

        subject = item.get("subject")
        subject_fields = {"repository", "candidate_commit", "base_commit", "diff_digest"}
        if not isinstance(subject, dict) or any(not subject.get(key) for key in subject_fields):
            add("EXCEPTION_SCOPE", f"{label}.subject must bind repository, candidate_commit, base_commit, and diff_digest")
        elif (
            not isinstance(subject["repository"], str)
            or scoped_token_pattern.fullmatch(subject["repository"]) is None
            or not isinstance(subject["candidate_commit"], str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", subject["candidate_commit"]) is None
            or not isinstance(subject["base_commit"], str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", subject["base_commit"]) is None
            or not isinstance(subject["diff_digest"], str)
            or digest_pattern.fullmatch(subject["diff_digest"]) is None
        ):
            add("EXCEPTION_SCOPE", f"{label}.subject contains an invalid commit or diff digest")
        affected = item.get("affected_object")
        if (
            not isinstance(affected, dict)
            or not isinstance(affected.get("finding_fingerprint"), str)
            or scoped_token_pattern.fullmatch(affected["finding_fingerprint"]) is None
        ):
            add("EXCEPTION_SCOPE", f"{label}.affected_object needs a finding_fingerprint")
        elif (
            not isinstance(affected.get("paths"), list)
            or not affected["paths"]
            or not all(
                isinstance(entry, str)
                and entry == entry.strip()
                and entry
                and not entry.startswith("/")
                and "\\" not in entry
                and not any(part in {"", ".", ".."} for part in entry.split("/"))
                and not any(character in entry for character in "*?[]\x00")
                for entry in affected["paths"]
            )
        ):
            add("EXCEPTION_SCOPE", f"{label}.affected_object.paths must be non-empty")

        string_array(item, "compensating_controls", label)
        allowed_actions = string_array(item, "allowed_actions", label)
        allowed_environments = string_array(item, "allowed_environments", label)
        canonical_scope = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
        if any(canonical_scope.fullmatch(value) is None for value in allowed_actions):
            add("EXCEPTION_SCOPE", f"{label}.allowed_actions contains a non-canonical action")
        if any(canonical_scope.fullmatch(value) is None for value in allowed_environments):
            add("EXCEPTION_SCOPE", f"{label}.allowed_environments contains a non-canonical environment")
        owner = item.get("owner")
        if (
            not isinstance(owner, dict)
            or not valid_human(owner.get("identity"))
            or not isinstance(owner.get("role"), str)
        ):
            add("EXCEPTION_OWNER", f"{label}.owner needs identity and role")
            owner_identity = None
        else:
            owner_identity = owner["identity"]
            if owner.get("role") not in EXCEPTION_ROLES:
                add("EXCEPTION_OWNER", f"{label} has an unrecognized owner role")
        approvers = item.get("approvers")
        if approvers is None and isinstance(item.get("approver"), dict):
            approvers = [item["approver"]]
        if not isinstance(approvers, list):
            approvers = []
        approver_ids: list[str] = []
        approver_roles: list[str] = []
        for approver in approvers:
            if (
                not isinstance(approver, dict)
                or not valid_human(approver.get("identity"))
                or not isinstance(approver.get("role"), str)
            ):
                add("EXCEPTION_APPROVER", f"{label} has an invalid approver record")
            else:
                if approver.get("role") not in EXCEPTION_ROLES:
                    add("EXCEPTION_APPROVER", f"{label} has an unrecognized approver role")
                else:
                    approver_roles.append(approver["role"])
                approver_ids.append(approver["identity"])
        required_approvers = 1
        if exception_class == "XM" or risk_tier == "R3":
            required_approvers = 3
        elif exception_class == "XS" or risk_tier == "R2" or exception_class == "XR":
            required_approvers = 2
        if len(set(approver_ids)) < required_approvers:
            add("EXCEPTION_QUORUM", f"{label} needs {required_approvers} distinct approvers")
        if len(set(approver_ids)) != len(approver_ids) or owner_identity in approver_ids:
            add("EXCEPTION_INDEPENDENCE", f"{label} owner and approvers must all be distinct")

        domain_roles = {"domain-owner", "service-owner"}
        operations_roles = {"operations-owner", "release-owner", "platform-owner"}
        seats: list[tuple[str, set[str]]] = []
        if mapped_control_domain is None:
            seats = []
        elif exception_class == "XM":
            seats = [
                ("domain owner", domain_roles),
                ("security owner", {"security-owner"}),
                ("platform owner", {"platform-owner"}),
            ]
            if mapped_control_domain == "license":
                seats.append(("legal owner for license scope", {"legal-owner"}))
        elif exception_class == "XS":
            contextual_roles = {
                "security": domain_roles,
                "privacy": {"data-owner", "privacy-owner"},
                "supply-chain": {"platform-owner"},
                "license": domain_roles,
            }.get(mapped_control_domain, set())
            seats = [
                ("security owner", {"security-owner"}),
                (f"{mapped_control_domain} contextual owner", contextual_roles),
            ]
            if blast == "multi-service/customer" and mapped_control_domain != "privacy":
                seats.append(("data or privacy owner for customer scope", {"data-owner", "privacy-owner"}))
            elif risk_tier == "R3":
                seats.append(("operations/release/platform owner for R3", operations_roles))
            if mapped_control_domain == "license":
                seats.append(("legal owner for license scope", {"legal-owner"}))
        elif risk_tier == "R3":
            seats = [
                ("domain owner", domain_roles),
                ("security owner", {"security-owner"}),
                ("operations/release/platform owner", operations_roles),
            ]
        elif exception_class == "XR":
            seats = [
                ("domain owner", domain_roles),
                (
                    f"{mapped_control_domain} specialist",
                    CONTROL_DOMAIN_SPECIALIST_ROLES[mapped_control_domain],
                ),
            ]
        elif exception_class == "XQ" and risk_tier == "R2":
            seats = [
                ("domain owner", domain_roles),
                (
                    f"{mapped_control_domain} specialist",
                    CONTROL_DOMAIN_SPECIALIST_ROLES[mapped_control_domain],
                ),
            ]
        elif exception_class == "XQ":
            seats = [("domain owner", domain_roles)]
        if seats:
            role_ok, missing_roles = role_seats_satisfied(approver_roles, seats)
            if not role_ok:
                add("EXCEPTION_AUTHORITY", f"{label} lacks required authority: {', '.join(missing_roles)}")

        issued = parse_time(item.get("issued_at"), "issued_at", label)
        expires = parse_time(item.get("expires_at"), "expires_at", label)
        must_fix = parse_time(item.get("must_fix_by"), "must_fix_by", label)
        if issued and expires and must_fix and exception_class in class_policy:
            policy = class_policy[exception_class]
            if issued > now:
                add("EXCEPTION_TIME", f"{label}.issued_at is in the future")
            if not issued < expires <= issued + dt.timedelta(days=policy["ttl"]):
                add("EXCEPTION_TTL", f"{label} exceeds the {policy['ttl']}-day admission TTL")
            if not issued < must_fix <= issued + dt.timedelta(days=policy["remediation"]):
                add("EXCEPTION_REMEDIATION", f"{label} exceeds the {policy['remediation']}-day remediation deadline")
            if expires <= now:
                add("EXCEPTION_EXPIRED", f"{label} expired at {expires.isoformat()}")
            if must_fix <= now:
                add("EXCEPTION_OVERDUE", f"{label} remediation deadline passed at {must_fix.isoformat()}")

        try:
            max_uses = count(item.get("max_uses"), f"{label}.max_uses")
            uses = count(item.get("uses"), f"{label}.uses")
            renewals = count(item.get("renewals"), f"{label}.renewals")
            points = count(item.get("points"), f"{label}.points")
        except MergeGroundsError as exc:
            add("EXCEPTION_COUNTER", str(exc))
            continue
        if max_uses <= 0 or uses >= max_uses:
            add("EXCEPTION_USES", f"{label} has no remaining authorized use")
        if renewals != 0:
            add("EXCEPTION_RENEWAL", f"{label}: this local registry cannot prove renewal ledger integrity; issue a new centrally signed record")
        if exception_class in class_policy and risk_tier in risk_multiplier and blast in blast_multiplier:
            expected_points = class_policy[exception_class]["weight"] * risk_multiplier[risk_tier] * blast_multiplier[blast]
            if points != expected_points:
                add("EXCEPTION_POINTS", f"{label}.points {points} != computed {expected_points}")
            if points > 8:
                add("EXCEPTION_BUDGET", f"{label} exceeds the per-change 8-point cap")
            active_points += points * (2 if must_fix and must_fix <= now else 1)
            if exception_class == "XS":
                active_xs += 1

    if active_points > 12:
        add("EXCEPTION_BUDGET", f"repository active exception budget {active_points} exceeds 12")
    if active_xs > 1:
        add("EXCEPTION_BUDGET", "more than one active XS exception exists")
    return findings


def git_path_is_ignored(root: Path, path: Path) -> bool:
    try:
        name = path.absolute().relative_to(root.absolute()).as_posix()
    except ValueError as exc:
        raise MergeGroundsError(f"critical path escapes the repository: {path}") from exc
    try:
        result = subprocess.run(
            git_command("check-ignore", "-q", "--", name),
            cwd=root,
            env=git_environment(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MergeGroundsError(f"cannot evaluate Git ignore policy for critical path: {name}") from exc
    if result.returncode not in {0, 1}:
        detail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        raise MergeGroundsError(
            f"Git ignore policy failed for {name}: {(detail or ['unknown Git failure'])[-1][:300]}"
        )
    return result.returncode == 0


def expand_critical_paths(root: Path, config: dict[str, Any]) -> list[Path]:
    policy = config.get("policy", {})
    patterns = as_string_list(policy.get("critical_paths"), "policy.critical_paths")
    paths: set[Path] = set()
    for pattern in patterns:
        # Python 3.11's Path.glob("directory/**") yields only directories while
        # newer runtimes yield descendants too. Normalize the terminal ** to an
        # explicit child selector so the protected file set is version-stable.
        filesystem_pattern = pattern + "/*" if pattern.endswith("/**") else pattern
        for path in root.glob(filesystem_pattern):
            if (path.is_file() or path.is_symlink()) and not git_path_is_ignored(root, path):
                paths.add(path)
    return sorted(paths)


def canonical_regular_mode(path: Path) -> str:
    """Return the Git-relevant regular-file mode, including executable drift."""
    executable = path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return "100755" if executable else "100644"


def repository_glob_match(path: str, pattern: str) -> bool:
    """Match a repository path using pathlib-style segment-aware ** globs."""
    path_parts = PurePosixPath(path).parts
    pattern_parts = PurePosixPath(pattern).parts
    memo: dict[tuple[int, int], bool] = {}

    def match(pattern_index: int, path_index: int) -> bool:
        key = (pattern_index, path_index)
        if key in memo:
            return memo[key]
        if pattern_index == len(pattern_parts):
            result = path_index == len(path_parts)
        elif pattern_parts[pattern_index] == "**":
            result = match(pattern_index + 1, path_index) or (
                path_index < len(path_parts)
                and match(pattern_index, path_index + 1)
            )
        else:
            result = (
                path_index < len(path_parts)
                and fnmatch.fnmatchcase(path_parts[path_index], pattern_parts[pattern_index])
                and match(pattern_index + 1, path_index + 1)
            )
        memo[key] = result
        return result

    return match(0, 0)


def critical_control_paths_changed(
    changed_paths: Iterable[str],
    patterns: Iterable[str],
) -> bool:
    return any(
        repository_glob_match(path, pattern)
        for path in changed_paths
        for pattern in patterns
    )


def critical_path_patterns(config: dict[str, Any]) -> list[str]:
    return as_string_list(
        config.get("policy", {}).get("critical_paths"),
        "policy.critical_paths",
    )


def selected_control_path(path: str, patterns: list[str]) -> bool:
    return any(repository_glob_match(path, pattern) for pattern in patterns)


def parse_git_control_entries(
    raw: bytes,
    patterns: list[str],
    *,
    index: bool,
) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for raw_entry in raw.split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        if not separator:
            raise MergeGroundsError("Git returned a malformed control-plane tree entry")
        path = os.fsdecode(raw_path)
        if not selected_control_path(path, patterns):
            continue
        try:
            path.encode("utf-8")
            fields = metadata.decode("ascii").split()
        except (UnicodeEncodeError, UnicodeDecodeError) as exc:
            raise MergeGroundsError("critical control-plane Git paths must be canonical UTF-8") from exc
        if index:
            if len(fields) != 3 or fields[2] != "0":
                raise MergeGroundsError(f"critical control-plane index entry is unresolved: {path}")
            mode, object_id = fields[:2]
        else:
            if len(fields) != 3 or fields[1] != "blob":
                raise MergeGroundsError(f"critical control-plane path is not a Git blob: {path}")
            mode, _, object_id = fields
        if mode not in {"100644", "100755"} or GIT_OBJECT_ID.fullmatch(object_id) is None:
            raise MergeGroundsError(f"critical control-plane path has an unsafe Git mode/type: {path}")
        if path in entries:
            raise MergeGroundsError(f"critical control-plane Git path is duplicated: {path}")
        entries[path] = (mode, object_id)
    return entries


def git_revision_control_entries(
    root: Path,
    revision: str,
    config: dict[str, Any],
) -> dict[str, tuple[str, str]]:
    raw = git_bytes_checked(
        root,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        revision,
        maximum_bytes=MAX_TREE_LIST_BYTES,
    )
    return parse_git_control_entries(
        raw,
        critical_path_patterns(config),
        index=False,
    )


def git_index_control_entries(
    root: Path,
    config: dict[str, Any],
) -> dict[str, tuple[str, str]]:
    raw = git_bytes_checked(
        root,
        "ls-files",
        "--stage",
        "-z",
        maximum_bytes=MAX_TREE_LIST_BYTES,
    )
    return parse_git_control_entries(
        raw,
        critical_path_patterns(config),
        index=True,
    )


def git_control_records(
    root: Path,
    entries: dict[str, tuple[str, str]],
) -> dict[str, dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    for path, (mode, object_id) in sorted(entries.items()):
        raw = git_bytes_checked(
            root,
            "cat-file",
            "blob",
            object_id,
            maximum_bytes=MAX_ARTIFACT_BYTES,
        )
        records[path] = {"sha256": sha256_bytes(raw), "mode": mode}
    return records


def worktree_control_records(
    root: Path,
    config: dict[str, Any],
) -> dict[str, dict[str, str]]:
    files: dict[str, dict[str, str]] = {}
    for path in expand_critical_paths(root, config):
        if not is_regular_repo_file(path, root):
            raise MergeGroundsError(
                f"critical path must be a regular in-repository file: {relative(path, root)}"
            )
        files[relative(path, root)] = {
            "sha256": sha256_file(path),
            "mode": canonical_regular_mode(path),
        }
    return files


def seal_payload(root: Path, config: dict[str, Any]) -> dict[str, Any]:
    commit = validate_git_revision(
        root,
        git_checked(root, "rev-parse", "--verify", "HEAD^{commit}"),
        "control-plane seal commit",
    )
    committed_entries = git_revision_control_entries(root, commit, config)
    index_entries = git_index_control_entries(root, config)
    if index_entries != committed_entries:
        raise MergeGroundsError(
            "critical controls in the Git index differ from HEAD; commit them before sealing"
        )
    files = git_control_records(root, committed_entries)
    if worktree_control_records(root, config) != files:
        raise MergeGroundsError(
            "critical control worktree files differ from HEAD; commit them before sealing"
        )
    return {
        "schema_version": CONTROL_LOCK_SCHEMA_VERSION,
        "generated_at": iso_now(),
        "git_commit": commit,
        "files": files,
    }


def control_lock_path(root: Path, config: dict[str, Any]) -> Path:
    raw = config.get("policy", {}).get("control_lock", ".mergegrounds/control-plane.lock.json")
    if not isinstance(raw, str):
        raise MergeGroundsError("policy.control_lock must be a string")
    candidate = root / raw
    if Path(raw).is_absolute() or ".." in Path(raw).parts:
        raise MergeGroundsError("policy.control_lock must be a repository-relative path")
    if has_symlink_component(candidate, root) or not is_within(candidate.resolve(), root):
        raise MergeGroundsError("policy.control_lock must remain inside the repository")
    return candidate


def seal_findings(root: Path, config: dict[str, Any]) -> list[Finding]:
    path = control_lock_path(root, config)
    if not path.exists():
        return [Finding("CONTROL_LOCK_MISSING", "error", "control-plane integrity lock is missing", relative(path, root))]
    if not is_regular_repo_file(path, root):
        return [Finding("CONTROL_LOCK_INVALID", "error", "control lock must be a regular in-repository file", relative(path, root))]
    if canonical_regular_mode(path) != "100644":
        return [Finding("CONTROL_LOCK_INVALID", "error", "control lock data file must not be executable", relative(path, root))]
    try:
        lock = strict_json_document(
            bounded_regular_bytes(path, "control lock", MAX_CONTROL_LOCK_BYTES),
            "control lock",
            MAX_CONTROL_LOCK_BYTES,
            maximum_nodes=250_000,
        )
    except MergeGroundsError as exc:
        return [Finding("CONTROL_LOCK_INVALID", "error", f"cannot parse control lock: {exc}", relative(path, root))]
    expected = lock.get("files")
    if (
        set(lock) != {"schema_version", "generated_at", "git_commit", "files"}
        or lock.get("schema_version") != CONTROL_LOCK_SCHEMA_VERSION
        or parse_rfc3339_utc(lock.get("generated_at")) is None
        or not isinstance(lock.get("git_commit"), str)
        or GIT_OBJECT_ID.fullmatch(lock["git_commit"]) is None
        or not isinstance(expected, dict)
    ):
        return [
            Finding(
                "CONTROL_LOCK_INVALID",
                "error",
                "control lock must be regenerated with schema 2 content-and-mode bindings",
                relative(path, root),
            )
        ]
    for name, record in expected.items():
        if (
            not isinstance(name, str)
            or not isinstance(record, dict)
            or set(record) != {"sha256", "mode"}
            or not isinstance(record.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            or record.get("mode") not in {"100644", "100755"}
        ):
            return [
                Finding(
                    "CONTROL_LOCK_INVALID",
                    "error",
                    "control lock contains an invalid file content/mode record",
                    relative(path, root),
                )
            ]
    try:
        sealed_commit = validate_git_revision(
            root,
            lock["git_commit"],
            "control lock git_commit",
        )
        current_head = validate_git_revision(
            root,
            git_checked(root, "rev-parse", "--verify", "HEAD^{commit}"),
            "current HEAD",
        )
        git_checked(
            root,
            "merge-base",
            "--is-ancestor",
            sealed_commit,
            current_head,
            allow_empty=True,
        )
        sealed_entries = git_revision_control_entries(root, sealed_commit, config)
        sealed_records = git_control_records(root, sealed_entries)
        head_entries = git_revision_control_entries(root, current_head, config)
        head_records = git_control_records(root, head_entries)
        index_entries = git_index_control_entries(root, config)
        current = worktree_control_records(root, config)
    except MergeGroundsError as exc:
        return [
            Finding(
                "CONTROL_LOCK_INVALID",
                "error",
                f"control lock Git provenance cannot be verified: {exc}",
                relative(path, root),
            )
        ]
    if sealed_records != expected:
        return [
            Finding(
                "CONTROL_LOCK_INVALID",
                "error",
                "control lock records do not match the declared committed Git tree",
                relative(path, root),
            )
        ]
    findings: list[Finding] = []
    if head_records != expected:
        findings.append(
            Finding(
                "CONTROL_COMMIT_DRIFT",
                "error",
                "current HEAD control files differ from the reviewed seal commit",
                relative(path, root),
            )
        )
    if index_entries != head_entries:
        findings.append(
            Finding(
                "CONTROL_INDEX_DRIFT",
                "error",
                "Git index control files differ from current HEAD",
                relative(path, root),
            )
        )
    for name in sorted(set(expected) | set(current)):
        if name not in expected:
            findings.append(Finding("CONTROL_FILE_UNSEALED", "error", "critical file is not in the control lock", name))
        elif name not in current:
            findings.append(Finding("CONTROL_FILE_MISSING", "error", "sealed critical file is missing", name))
        elif expected[name]["sha256"] != current[name]["sha256"]:
            findings.append(Finding("CONTROL_FILE_DRIFT", "error", "critical file hash differs from the reviewed lock", name))
        elif expected[name]["mode"] != current[name]["mode"]:
            findings.append(Finding("CONTROL_FILE_MODE", "error", "critical file executable mode differs from the reviewed lock", name))
    return findings


def verify_repository(root: Path, config: dict[str, Any]) -> list[Finding]:
    try:
        validate_config(config)
    except MergeGroundsError as exc:
        return [
            Finding(
                "CONFIG_INVALID",
                "error",
                str(exc),
                ".mergegrounds/mergegrounds.toml",
            )
        ]
    findings: list[Finding] = []
    risk_tier = config.get("risk_tier")
    if risk_tier not in {"R0", "R1", "R2", "R3", "R4"}:
        findings.append(Finding("RISK_TIER_INVALID", "error", "risk_tier must be one of R0, R1, R2, R3, or R4", ".mergegrounds/mergegrounds.toml"))
    if config.get("fail_closed") is not True:
        findings.append(Finding("FAIL_OPEN", "error", "fail_closed must be true", ".mergegrounds/mergegrounds.toml"))
    policy = config.get("policy", {})
    for raw in as_string_list(policy.get("required_files"), "policy.required_files"):
        path = root / raw
        if not path.is_file():
            findings.append(Finding("REQUIRED_FILE_MISSING", "error", "required control file is missing", raw))
        elif not is_regular_repo_file(path, root):
            findings.append(Finding("CONTROL_SYMLINK", "error", "control file must be a regular in-repository file", raw))
    codeowners = root / ".github" / "CODEOWNERS"
    codeowners_usable = is_regular_repo_file(codeowners, root)
    if codeowners_usable and codeowners.stat().st_size >= MAX_CODEOWNERS_BYTES:
        findings.append(Finding("CODEOWNERS_TOO_LARGE", "error", "CODEOWNERS must remain below GitHub's 3 MiB processing limit", relative(codeowners, root)))
        codeowners_usable = False
    if codeowners_usable:
        owners_text = codeowners.read_text(encoding="utf-8")
        if "@org/security-team" in owners_text:
            findings.append(Finding("OWNER_PLACEHOLDER", "error", "replace @org/security-team with a real GitHub owner before activation", relative(codeowners, root)))
        rules = [
            (parts[0], tuple(parts[1:]))
            for line in owners_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#") and len(parts := line.split()) >= 2
        ]
        required_patterns = as_string_list(policy.get("required_codeowners_patterns"), "required_codeowners_patterns")
        if not rules or rules[0][0] != "*" or not rules[0][1]:
            findings.append(Finding("OWNERSHIP_GAP", "error", "CODEOWNERS must begin with a repository-wide * owner rule", relative(codeowners, root)))
        protected = [pattern for pattern in required_patterns if pattern != "*"]
        suffix = rules[-len(protected) :] if protected else []
        if [pattern for pattern, _ in suffix] != protected:
            findings.append(Finding("OWNERSHIP_OVERRIDE", "error", "protected CODEOWNERS rules must form the canonical final block", relative(codeowners, root)))
        trusted_owners = rules[0][1] if rules and rules[0][0] == "*" else ()
        for pattern, owners in suffix:
            if owners != trusted_owners:
                findings.append(Finding("OWNERSHIP_GAP", "error", f"{pattern} must use the repository-wide trusted owners", relative(codeowners, root)))
        owner_pattern = re.compile(r"^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9](?:[A-Za-z0-9_-]{0,99}))?$")
        for owner in trusted_owners:
            if not owner_pattern.fullmatch(owner):
                findings.append(Finding("OWNER_INVALID", "error", f"CODEOWNER is not a canonical GitHub user/team: {owner}", relative(codeowners, root)))
    findings.extend(exception_findings(root))
    findings.extend(workflow_findings(root))
    findings.extend(seal_findings(root, config))
    return findings


def print_findings(findings: Iterable[Finding]) -> None:
    values = list(findings)
    if not values:
        print("MergeGrounds repository policy: PASS")
        return
    for finding in values:
        location = f" ({finding.path})" if finding.path else ""
        print(f"{finding.severity.upper():7} {finding.code}: {finding.message}{location}")


def profile_config(root: Path, config: dict[str, Any], name: str) -> dict[str, Any]:
    profile_path = root / ".mergegrounds" / "profiles" / f"{name}.toml"
    if profile_path.is_file():
        if not is_regular_repo_file(profile_path, root):
            raise MergeGroundsError(f"profile must be a regular in-repository file: {profile_path}")
        external_profile = load_toml(profile_path)
        validate_profile(external_profile, name, str(profile_path))
        return external_profile
    profiles = config.get("profiles", {})
    inline_profile = profiles.get(name) if isinstance(profiles, dict) else None
    if not isinstance(inline_profile, dict):
        raise MergeGroundsError(f"unknown profile: {name}")
    return inline_profile


def run_profile(args: argparse.Namespace) -> int:
    root = resolve_root(args.root)
    config_path, config = config_for(root)
    profile = profile_config(root, config, args.profile)
    stages = as_string_list(profile.get("stages"), f"profiles.{args.profile}.stages")
    required = set(as_string_list(profile.get("required_stages"), f"profiles.{args.profile}.required_stages"))
    if not stages or not required:
        raise MergeGroundsError("a gate profile must contain stages and at least one required stage")
    if len(stages) != len(set(stages)):
        raise MergeGroundsError("a gate profile must not contain duplicate stages")
    missing_required = sorted(required - set(stages))
    if missing_required:
        raise MergeGroundsError("required_stages are absent from stages: " + ", ".join(missing_required))
    evidence_path = ensure_output_path(args.evidence, root, config) if args.evidence else None
    evidence_root = evidence_directory(root, config)
    adapters = detected_adapters(root)
    if not adapters:
        raise MergeGroundsError("no stack adapter detected; configure .mergegrounds/adapters or a custom marker")
    env, removed_env = environment_for(config)
    execution = config.get("execution", {})
    timeout = int(execution.get("timeout_seconds", 1800))
    output_limit = int(execution.get("max_output_bytes", 2 * 1024 * 1024))
    if timeout <= 0 or output_limit <= 0:
        raise MergeGroundsError("execution timeout_seconds and max_output_bytes must be positive")
    fail_fast = bool(args.fail_fast or execution.get("fail_fast", False))
    results: list[dict[str, Any]] = []
    started_at = iso_now()
    failed = False
    initial_source: dict[str, str] | None = None
    require_git = bool(execution.get("require_git", True))
    require_clean = bool(execution.get("require_clean_tree", True))
    if require_git or require_clean:
        require_git_toplevel(root)
        try:
            initial_source = git_source_state(root, evidence_root)
        except MergeGroundsError as exc:
            print(f"mergegrounds: {exc}", file=sys.stderr)
            results.append({"adapter": "mergegrounds", "stage": "source", "status": "not_evaluated", "reason": str(exc)})
            failed = True
    git_commit = initial_source["commit"] if initial_source else git_value(root, "rev-parse", "HEAD")
    git_tree = initial_source["tree"] if initial_source else git_value(root, "write-tree")
    if require_clean and initial_source and initial_source["status"]:
        print("mergegrounds: source/index or untracked files are dirty before validation", file=sys.stderr)
        results.append({"adapter": "mergegrounds", "stage": "source", "status": "fail", "reason": "repository is dirty before validation"})
        failed = True
    source_blocked = (require_git or require_clean) and (
        initial_source is None or (require_clean and bool(initial_source["status"]))
    )

    for adapter in adapters:
        missing = missing_tools(adapter)
        file_issues = toolchain_file_issues(adapter, root)
        if missing or file_issues:
            hint = adapter.get("toolchain", {}).get("setup_hint", "install the pinned development toolchain")
            details = []
            if missing:
                details.append("missing commands: " + ", ".join(missing))
            details.extend(file_issues)
            print(f"{adapter['id']}: {'; '.join(details)}; {hint}", file=sys.stderr)
            results.append(
                {
                    "adapter": adapter["id"],
                    "stage": "toolchain",
                    "status": "not_evaluated",
                    "missing_commands": missing,
                    "file_issues": file_issues,
                }
            )
            failed = True
    if source_blocked or (failed and fail_fast):
        stages = []

    for stage in stages:
        if fail_fast and failed:
            break
        if stage == "policy":
            findings = verify_repository(root, config)
            print_findings(findings)
            status = "fail" if any(item.severity == "error" for item in findings) else "pass"
            results.append({"adapter": "mergegrounds", "stage": stage, "status": status, "findings": [item.as_dict() for item in findings]})
            failed = failed or status == "fail"
            continue
        ran = False
        for adapter in adapters:
            commands_table = adapter.get("commands", {})
            if not isinstance(commands_table, dict):
                raise MergeGroundsError(f"adapter {adapter['id']} commands must be a table")
            commands = as_string_list(commands_table.get(stage), f"{adapter['id']}.commands.{stage}")
            if not commands:
                if stage in required:
                    results.append({"adapter": adapter["id"], "stage": stage, "status": "not_evaluated", "reason": "required stage is not configured"})
                    print(f"{adapter['id']}:{stage}: required stage is not configured", file=sys.stderr)
                    failed = True
                continue
            ran = True
            metric_before: dict[str, tuple[int, int, str]] = {}
            purged_reports: set[str] = set()
            declared_artifacts = artifact_patterns(adapter, stage)
            try:
                if stage in {"coverage", "mutation"}:
                    descriptor = descriptor_for(adapter, stage)
                    metric_before = report_snapshot(root, descriptor)
                    purged_reports = purge_metric_reports(root, descriptor)
                purge_output_files(root, declared_artifacts, f"{adapter['id']}:{stage} artifact")
            except MergeGroundsError as exc:
                results.append({"adapter": adapter["id"], "stage": f"{stage}-prepare", "status": "not_evaluated", "reason": str(exc)})
                print(f"{adapter['id']}:{stage}-prepare: {exc}", file=sys.stderr)
                failed = True
                if fail_fast:
                    break
                continue
            adapter_stage_failed = False
            for command in commands:
                result = run_command(command, root, env, timeout, output_limit, adapter["id"], stage)
                results.append(result)
                if result["status"] != "pass":
                    failed = True
                    adapter_stage_failed = True
                    break
            if not adapter_stage_failed and stage in {"coverage", "mutation"}:
                try:
                    metric_result = validate_metric(root, config, adapter, stage, metric_before, purged_reports)
                except MergeGroundsError as exc:
                    metric_result = {
                        "adapter": adapter["id"],
                        "stage": f"{stage}-metrics",
                        "status": "not_evaluated",
                        "reason": str(exc),
                    }
                results.append(metric_result)
                if metric_result["status"] != "pass":
                    failed = True
                    print(f"{adapter['id']}:{stage}-metrics: {metric_result.get('reason') or '; '.join(metric_result.get('violations', []))}", file=sys.stderr)
            if not adapter_stage_failed and declared_artifacts:
                try:
                    artifact_result = validate_stage_artifacts(root, adapter, stage)
                except MergeGroundsError as exc:
                    artifact_result = {
                        "adapter": adapter["id"],
                        "stage": f"{stage}-artifacts",
                        "status": "not_evaluated",
                        "reason": str(exc),
                    }
                if artifact_result is None:
                    raise MergeGroundsError(
                        f"{adapter['id']}:{stage} declared artifacts but produced no validation result"
                    )
                results.append(artifact_result)
                if artifact_result["status"] != "pass":
                    failed = True
                    print(f"{adapter['id']}:{stage}-artifacts: {artifact_result.get('reason')}", file=sys.stderr)
            if fail_fast and failed:
                break
        if not ran and stage in required:
            print(f"{stage}: no detected adapter supplied this required stage", file=sys.stderr)
            failed = True

    versions = tool_versions(adapters, root, env)
    if initial_source is not None:
        try:
            final_source = git_source_state(root, evidence_root)
        except MergeGroundsError as exc:
            final_source = None
            print(f"mergegrounds: source state cannot be revalidated: {exc}", file=sys.stderr)
            results.append({"adapter": "mergegrounds", "stage": "source-final", "status": "not_evaluated", "reason": str(exc)})
            failed = True
        if final_source is not None:
            changes: list[str] = []
            if final_source["commit"] != initial_source["commit"]:
                changes.append("HEAD changed")
            if final_source["tree"] != initial_source["tree"]:
                changes.append("index tree changed")
            if final_source["status"] != initial_source["status"]:
                changes.append("worktree/index status changed")
            if require_clean and final_source["status"]:
                changes.append("repository is dirty after validation")
            if changes:
                reason = "; ".join(dict.fromkeys(changes))
                results.append({"adapter": "mergegrounds", "stage": "source-final", "status": "fail", "reason": reason})
                print(f"mergegrounds: {reason}", file=sys.stderr)
                failed = True

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "run_id": str(uuid.uuid4()),
        "started_at": started_at,
        "finished_at": iso_now(),
        "status": "fail" if failed else "pass",
        "decision": "deny" if failed else "allow",
        "profile": args.profile,
        "risk_tier": config.get("risk_tier"),
        "git_commit": git_commit,
        "git_tree": git_tree,
        "config": {"path": relative(config_path, root), "sha256": sha256_file(config_path)},
        "adapters": [adapter["id"] for adapter in adapters],
        "sanitized_environment_keys": removed_env,
        "tool_versions": versions,
        "thresholds": config.get("thresholds", {}),
        "results": results,
        "artifacts": artifact_records(root, adapters),
    }
    if evidence_path is not None:
        # Candidate commands may have attempted to replace the output directory.
        evidence_path = ensure_output_path(args.evidence, root, config)
        write_json_atomic(evidence_path, evidence, root)
        print(f"evidence: {relative(evidence_path, root)} sha256={sha256_file(evidence_path)}")
    return 1 if failed else 0


def doctor(args: argparse.Namespace) -> int:
    root = resolve_root(args.root)
    _, config = config_for(root)
    if config.get("execution", {}).get("require_git", True):
        require_git_toplevel(root)
    adapters = detected_adapters(root)
    if not adapters:
        print("ERROR   NO_ADAPTER: no stack adapter detected")
        return 1
    print("detected adapters: " + ", ".join(adapter["id"] for adapter in adapters))
    failed = False
    global_thresholds = config.get("thresholds", {})
    for adapter in adapters:
        missing = missing_tools(adapter)
        file_issues = toolchain_file_issues(adapter, root)
        if missing:
            failed = True
            print(f"ERROR   TOOL_MISSING [{adapter['id']}]: {', '.join(missing)}")
        if file_issues:
            failed = True
            for issue in file_issues:
                print(f"ERROR   INPUT_MISSING [{adapter['id']}]: {issue}")
        if not missing and not file_issues:
            print(f"PASS    TOOLCHAIN [{adapter['id']}]")
        local_thresholds = adapter.get("thresholds", {})
        for key in ("line_coverage", "branch_coverage", "mutation_score"):
            global_value = global_thresholds.get(key)
            local_value = local_thresholds.get(key) if isinstance(local_thresholds, dict) else None
            if global_value is not None and local_value is not None and float(local_value) < float(global_value):
                failed = True
                print(f"ERROR   WEAK_THRESHOLD [{adapter['id']}]: {key} {local_value} < {global_value}")
    return 1 if failed else 0


def verify_repo_command(args: argparse.Namespace) -> int:
    root = resolve_root(args.root)
    require_git_toplevel(root)
    _, config = config_for(root)
    findings = verify_repository(root, config)
    print_findings(findings)
    severities = {"error"} | ({"warning"} if args.strict else set())
    return 1 if any(item.severity in severities for item in findings) else 0


def seal_command(args: argparse.Namespace) -> int:
    root = resolve_root(args.root)
    require_git_toplevel(root)
    _, config = config_for(root)
    path = control_lock_path(root, config)
    if args.write:
        write_json_atomic(path, seal_payload(root, config), root)
        print(f"wrote {relative(path, root)} ({len(json.loads(path.read_text())['files'])} files)")
        return 0
    findings = seal_findings(root, config)
    print_findings(findings)
    return 1 if findings else 0


def pull_request_revisions(event_path: Path) -> tuple[str, str]:
    raw = bounded_regular_bytes(event_path, "GitHub event", MAX_EVENT_BYTES)
    event = strict_json_document(
        raw,
        "GitHub event",
        MAX_EVENT_BYTES,
        maximum_nodes=50_000,
        maximum_string_bytes=128 * 1024,
    )
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        raise MergeGroundsError("event does not contain a pull_request object")
    base = pull_request.get("base")
    head = pull_request.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise MergeGroundsError("pull_request event lacks base/head objects")
    base_sha = base.get("sha")
    head_sha = head.get("sha")
    if not isinstance(base_sha, str) or not GIT_OBJECT_ID.fullmatch(base_sha):
        raise MergeGroundsError("pull_request.base.sha is not a canonical Git object id")
    if not isinstance(head_sha, str) or not GIT_OBJECT_ID.fullmatch(head_sha):
        raise MergeGroundsError("pull_request.head.sha is not a canonical Git object id")
    if base_sha == head_sha:
        raise MergeGroundsError("pull-request base and head revisions must differ")
    return base_sha, head_sha


def verify_change_command(args: argparse.Namespace) -> int:
    root = resolve_root(args.root)
    require_git_toplevel(root)
    _, config = config_for(root)
    event_path = Path(args.event).absolute()
    base_sha, head_sha = pull_request_revisions(event_path)
    result = validate_change_between(root, config, base_sha, head_sha)
    print("MergeGrounds structured change contract: PASS")
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0


def attest_pr(args: argparse.Namespace) -> int:
    """Compatibility alias; checkbox prose is deliberately not admission evidence."""
    print("MergeGrounds: attest-pr now validates the structured change contract; PR checkboxes are informational only")
    return verify_change_command(args)


def canonical_attempt_path(root: Path, raw: str, label: str) -> Path:
    value = Path(raw)
    if (
        value.is_absolute()
        or ".." in value.parts
        or len(value.parts) != 3
        or value.parts[:2] != (".mergegrounds", "evidence")
        or value.suffix.lower() != ".json"
    ):
        raise MergeGroundsError(f"{label} must be a direct .json child of .mergegrounds/evidence")
    return root / value


def parse_rfc3339_utc(value: Any) -> dt.datetime | None:
    """Parse the one canonical UTC representation emitted by MergeGrounds."""
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        return None
    return parsed.astimezone(dt.timezone.utc)


def subject_regular_paths(root: Path, revision: str) -> set[str]:
    """Return regular blob paths from an immutable tree using NUL-safe parsing."""
    raw = git_bytes_checked(
        root,
        "ls-tree",
        "-r",
        "-z",
        revision,
        "--",
        maximum_bytes=MAX_TREE_LIST_BYTES,
    )
    paths: set[str] = set()
    records = raw.split(b"\0")
    if records[-1:] != [b""]:
        raise MergeGroundsError("subject Git tree returned a malformed record stream")
    for record in records[:-1]:
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise MergeGroundsError("subject Git tree contains a malformed entry") from exc
        if GIT_OBJECT_ID.fullmatch(object_id) is None:
            raise MergeGroundsError("subject Git tree contains an invalid object id")
        if (
            not path
            or path.startswith("/")
            or ".." in Path(path).parts
            or len(path.encode("utf-8")) > 4096
        ):
            raise MergeGroundsError("subject Git tree contains a non-canonical path")
        if object_type == "blob" and mode in {"100644", "100755"}:
            paths.add(path)
    return paths


def rooted_git_glob_match(path: str, pattern: str) -> bool:
    """Match repository-rooted POSIX paths with Path.glob-style ** zero depth."""
    variants = {pattern}
    pending = [pattern]
    while pending:
        current = pending.pop()
        cursor = current.find("**/")
        while cursor >= 0:
            reduced = current[:cursor] + current[cursor + 3 :]
            if reduced not in variants:
                variants.add(reduced)
                pending.append(reduced)
            cursor = current.find("**/", cursor + 3)
    candidate = PurePosixPath("/" + path)
    return any(candidate.match("/" + value) for value in variants)


def subject_detected_adapters(
    root: Path,
    revision: str,
    regular_paths: set[str],
) -> list[dict[str, Any]]:
    """Reproduce adapter selection from committed configs and detection inputs."""
    adapter_paths = sorted(
        path
        for path in regular_paths
        if re.fullmatch(r"\.mergegrounds/adapters/[^/]+\.toml", path)
    )
    adapters: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for path in adapter_paths:
        raw = git_blob_bytes(
            root,
            revision,
            path,
            "subject MergeGrounds adapter",
            MAX_POLICY_BYTES,
        )
        try:
            adapter = tomllib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise MergeGroundsError(f"subject MergeGrounds adapter is invalid TOML: {path}: {exc}") from exc
        if adapter.get("schema_version") != SCHEMA_VERSION:
            raise MergeGroundsError(f"subject MergeGrounds adapter has an unsupported schema: {path}")
        adapter_id = adapter.get("id")
        ecosystem = adapter.get("ecosystem")
        priority = adapter.get("priority", 0)
        if (
            not isinstance(adapter_id, str)
            or not adapter_id
            or adapter_id != adapter_id.strip()
            or adapter_id in seen_ids
            or not isinstance(ecosystem, str)
            or not ecosystem
            or type(priority) is not int
        ):
            raise MergeGroundsError(f"subject MergeGrounds adapter identity is invalid or duplicated: {path}")
        artifacts = adapter.get("artifacts", {})
        if not isinstance(artifacts, dict) or any(key not in KNOWN_STAGES for key in artifacts):
            raise MergeGroundsError(f"subject MergeGrounds adapter artifacts are invalid: {path}")
        detect = adapter.get("detect", {})
        if not isinstance(detect, dict):
            raise MergeGroundsError(f"subject MergeGrounds adapter detect table is invalid: {path}")
        all_files = as_string_list(detect.get("all_files"), f"{path}.detect.all_files")
        any_files = as_string_list(detect.get("any_files"), f"{path}.detect.any_files")
        any_globs = as_string_list(detect.get("any_globs"), f"{path}.detect.any_globs")
        if not (all_files or any_files or any_globs):
            matched = False
        elif all_files and not all(item in regular_paths for item in all_files):
            matched = False
        else:
            alternatives = [item in regular_paths for item in any_files]
            for pattern in any_globs:
                validate_report_pattern(pattern)
                alternatives.append(
                    any(
                        rooted_git_glob_match(candidate, pattern)
                        for candidate in regular_paths
                    )
                )
            matched = not alternatives or any(alternatives)
        seen_ids.add(adapter_id)
        adapter["_matched"] = matched
        adapters.append(adapter)

    ordered = sorted(adapters, key=lambda item: (-item.get("priority", 0), item["id"]))
    selected: dict[str, dict[str, Any]] = {}
    for adapter in (item for item in ordered if item["_matched"]):
        ecosystem = adapter["ecosystem"]
        current = selected.get(ecosystem)
        if current is None:
            selected[ecosystem] = adapter
        elif current.get("priority", 0) == adapter.get("priority", 0):
            raise MergeGroundsError(
                f"ambiguous subject adapters for ecosystem {ecosystem}: "
                f"{current['id']}, {adapter['id']}"
            )
    result: list[dict[str, Any]] = []
    for adapter in sorted(
        selected.values(),
        key=lambda item: (-item.get("priority", 0), item["id"]),
    ):
        result.append({key: value for key, value in adapter.items() if key != "_matched"})
    return result


def subject_detected_adapter_ids(
    root: Path,
    revision: str,
    regular_paths: set[str],
) -> list[str]:
    """Compatibility helper returning immutable selected adapter identities."""
    return [
        adapter["id"]
        for adapter in subject_detected_adapters(root, revision, regular_paths)
    ]


def subject_evidence_context(root: Path, subject_sha: str, profile: str) -> dict[str, Any]:
    """Resolve receipt expectations exclusively from immutable subject blobs."""
    if (
        not isinstance(profile, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile) is None
    ):
        raise MergeGroundsError("receipt profile is not a canonical profile id")
    resolved = validate_git_revision(root, subject_sha, "receipt subject SHA")
    if resolved != subject_sha:
        raise MergeGroundsError("receipt subject SHA must be the complete commit id")
    tree = git_checked(root, "rev-parse", "--verify", f"{resolved}^{{tree}}")
    if GIT_OBJECT_ID.fullmatch(tree) is None:
        raise MergeGroundsError("receipt subject tree did not resolve to a Git tree")
    regular_paths = subject_regular_paths(root, resolved)

    raw_config = git_blob_bytes(
        root,
        resolved,
        ".mergegrounds/mergegrounds.toml",
        "subject MergeGrounds policy",
        MAX_POLICY_BYTES,
    )
    try:
        config = tomllib.loads(raw_config.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise MergeGroundsError(f"subject MergeGrounds policy is invalid TOML: {exc}") from exc
    if not isinstance(config, dict):
        raise MergeGroundsError("subject MergeGrounds policy must be a TOML document")
    validate_config(config)

    profile_path = f".mergegrounds/profiles/{profile}.toml"
    profiles = config.get("profiles")
    inline_profile = profiles.get(profile) if isinstance(profiles, dict) else None
    profile_entry = git_checked(
        root,
        "ls-tree",
        resolved,
        "--",
        profile_path,
        allow_empty=True,
    )
    profile_value: dict[str, Any] | None
    if profile_entry:
        raw_profile = git_blob_bytes(
            root,
            resolved,
            profile_path,
            "subject MergeGrounds profile",
            MAX_POLICY_BYTES,
        )
        try:
            profile_value = tomllib.loads(raw_profile.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise MergeGroundsError(f"subject MergeGrounds profile is invalid TOML: {exc}") from exc
        if profile_value.get("schema_version") != SCHEMA_VERSION:
            raise MergeGroundsError("subject MergeGrounds profile has an unsupported schema_version")
        if not isinstance(inline_profile, dict):
            raise MergeGroundsError("subject external profile has no matching inline policy")
        for key in ("stages", "required_stages"):
            if profile_value.get(key) != inline_profile.get(key):
                raise MergeGroundsError(
                    f"subject external profile {key} does not match inline policy order and values"
                )
    else:
        profile_value = inline_profile
    validate_profile(profile_value, profile, f"subject profiles.{profile}")
    assert isinstance(profile_value, dict)

    adapter_values = subject_detected_adapters(root, resolved, regular_paths)
    return {
        "root": root,
        "commit": resolved,
        "tree": tree,
        "policy_sha256": sha256_bytes(raw_config),
        "risk_tier": config.get("risk_tier"),
        "thresholds": config.get("thresholds", {}),
        "config": config,
        "profile": profile_value,
        "adapters": [adapter["id"] for adapter in adapter_values],
        "adapter_values": adapter_values,
    }


def same_json_value(left: Any, right: Any) -> bool:
    """Compare JSON-compatible values without bool/int equality confusion."""
    try:
        return json.dumps(
            left,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ) == json.dumps(
            right,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return False


def expected_allow_result_manifest(subject: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Derive the exact successful run shape from immutable policy and adapters."""
    profile_value = subject["profile"]
    stages = as_string_list(profile_value.get("stages"), "receipt profile stages")
    required_stages = set(
        as_string_list(profile_value.get("required_stages"), "receipt required profile stages")
    )
    manifest: list[dict[str, Any]] = []
    for stage in stages:
        if stage == "policy":
            manifest.append({"kind": "policy", "adapter": None, "stage": stage})
            continue
        ran = False
        for adapter in subject["adapter_values"]:
            commands_table = adapter.get("commands", {})
            if not isinstance(commands_table, dict):
                raise MergeGroundsError(f"subject adapter {adapter['id']} commands must be a table")
            commands = as_string_list(
                commands_table.get(stage),
                f"subject {adapter['id']}.commands.{stage}",
            )
            if not commands:
                if stage in required_stages:
                    return None
                continue
            ran = True
            for command in commands:
                manifest.append(
                    {
                        "kind": "command",
                        "adapter": adapter,
                        "stage": stage,
                        "command_sha256": sha256_bytes(command.encode("utf-8")),
                    }
                )
            if stage in {"coverage", "mutation"}:
                if descriptor_for(adapter, stage) is None:
                    return None
                manifest.append(
                    {"kind": "metric", "adapter": adapter, "stage": stage}
                )
            if artifact_patterns(adapter, stage):
                manifest.append(
                    {"kind": "artifact", "adapter": adapter, "stage": stage}
                )
        if stage in required_stages and not ran:
            return None
    return manifest


def maximum_allow_run_duration(subject: dict[str, Any]) -> dt.timedelta:
    """Bound an ALLOW run by immutable command count and per-command timeout."""
    manifest = expected_allow_result_manifest(subject)
    if manifest is None:
        raise MergeGroundsError("subject policy cannot produce a complete ALLOW result manifest")
    command_count = sum(item["kind"] == "command" for item in manifest)
    execution = subject["config"].get("execution", {})
    timeout = execution.get("timeout_seconds", 1800) if isinstance(execution, dict) else None
    if type(timeout) is not int or timeout <= 0:
        raise MergeGroundsError("subject execution timeout is invalid")
    derived_seconds = timeout * command_count + MAX_EVIDENCE_RUN_OVERHEAD_SECONDS
    return dt.timedelta(seconds=min(derived_seconds, MAX_EVIDENCE_RUN_DURATION_SECONDS))


def allow_evidence_time_reason(
    started_at: dt.datetime,
    finished_at: dt.datetime,
    subject: dict[str, Any],
    now: dt.datetime,
) -> str | None:
    """Return the fail-closed reason for an implausible or replayed ALLOW clock."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise MergeGroundsError("evidence validation clock must be timezone-aware")
    validation_time = now.astimezone(dt.timezone.utc)
    try:
        maximum_duration = maximum_allow_run_duration(subject)
    except MergeGroundsError:
        return "EVIDENCE_RESULTS_INVALID"
    if finished_at - started_at > maximum_duration:
        return "EVIDENCE_TIME_DURATION"
    if finished_at > validation_time + dt.timedelta(seconds=MAX_EVIDENCE_FUTURE_SKEW_SECONDS):
        return "EVIDENCE_TIME_FUTURE"
    if validation_time - finished_at > dt.timedelta(
        seconds=MAX_EVIDENCE_NORMALIZATION_DELAY_SECONDS
    ):
        return "EVIDENCE_TIME_STALE"
    return None


def valid_finding_record(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"code", "severity", "message", "path"}:
        return False
    return (
        isinstance(value.get("code"), str)
        and bool(value["code"])
        and value.get("severity") in {"info", "warning", "error"}
        and isinstance(value.get("message"), str)
        and bool(value["message"])
        and (value.get("path") is None or isinstance(value.get("path"), str))
    )


def valid_successful_command_result(value: Any, expected: dict[str, Any]) -> bool:
    required = {
        "adapter",
        "stage",
        "status",
        "returncode",
        "timed_out",
        "duration_seconds",
        "command_sha256",
        "output_sha256",
        "output_bytes",
        "output_truncated",
    }
    if not isinstance(value, dict) or set(value) != required:
        return False
    duration = value.get("duration_seconds")
    output_bytes = value.get("output_bytes")
    output_sha256 = value.get("output_sha256")
    if (
        value.get("adapter") != expected["adapter"]["id"]
        or value.get("stage") != expected["stage"]
        or value.get("status") != "pass"
        or type(value.get("returncode")) is not int
        or value.get("returncode") != 0
        or value.get("timed_out") is not False
        or isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(float(duration))
        or duration < 0
        or value.get("command_sha256") != expected["command_sha256"]
        or not isinstance(output_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", output_sha256) is None
        or type(output_bytes) is not int
        or output_bytes < 0
        or value.get("output_truncated") is not False
    ):
        return False
    return output_bytes != 0 or output_sha256 == sha256_bytes(b"")


def successful_result_matches(
    root: Path,
    subject: dict[str, Any],
    value: Any,
    expected: dict[str, Any],
) -> bool:
    """Validate one ALLOW result, re-reading every referenced report/artifact."""
    kind = expected["kind"]
    if kind == "command":
        return valid_successful_command_result(value, expected)
    if kind == "policy":
        if (
            not isinstance(value, dict)
            or set(value) != {"adapter", "stage", "status", "findings"}
            or value.get("adapter") != "mergegrounds"
            or value.get("stage") != "policy"
            or value.get("status") != "pass"
            or not isinstance(value.get("findings"), list)
            or not all(valid_finding_record(item) for item in value["findings"])
            or any(item["severity"] == "error" for item in value["findings"])
        ):
            return False
        observed_findings = [item.as_dict() for item in verify_repository(root, subject["config"])]
        return same_json_value(value["findings"], observed_findings)

    adapter = expected["adapter"]
    stage = expected["stage"]
    if kind == "metric":
        observed_metric = validate_metric(root, subject["config"], adapter, stage, {})
        return same_json_value(value, observed_metric) and observed_metric.get("status") == "pass"
    if kind == "artifact":
        observed_artifact = validate_stage_artifacts(root, adapter, stage)
        return observed_artifact is not None and same_json_value(value, observed_artifact)
    return False


def raw_result_reason(
    root: Path,
    results: Any,
    subject: dict[str, Any],
    expect_allow: bool,
) -> str | None:
    """Validate result identities and exact successful-run completeness."""
    if not isinstance(results, list) or not results:
        return "EVIDENCE_INCOMPLETE"
    adapters = subject["adapters"]
    profile_value = subject["profile"]

    if expect_allow:
        try:
            manifest = expected_allow_result_manifest(subject)
        except MergeGroundsError:
            return "EVIDENCE_RESULTS_INVALID"
        if manifest is None:
            return "EVIDENCE_INCOMPLETE"
        if len(results) != len(manifest):
            return "EVIDENCE_INCOMPLETE" if len(results) < len(manifest) else "EVIDENCE_RESULTS_INVALID"
        try:
            matches = all(
                successful_result_matches(root, subject, value, expected)
                for value, expected in zip(results, manifest, strict=True)
            )
        except (MergeGroundsError, OSError, ValueError, TypeError):
            return "EVIDENCE_RESULTS_INVALID"
        return None if matches else "EVIDENCE_RESULTS_INVALID"

    profile_stages = set(as_string_list(profile_value.get("stages"), "receipt profile stages"))
    observed: set[tuple[str, str]] = set()
    statuses: list[str] = []
    auxiliary_suffixes = {"artifacts", "metrics", "prepare"}
    special_stages = {"source", "source-final", "toolchain"}

    for item in results:
        if not isinstance(item, dict):
            return "EVIDENCE_RESULTS_INVALID"
        adapter = item.get("adapter")
        stage = item.get("stage")
        status_value = item.get("status")
        if (
            not isinstance(adapter, str)
            or not adapter
            or not isinstance(stage, str)
            or not stage
            or status_value not in {"pass", "fail", "not_evaluated"}
        ):
            return "EVIDENCE_RESULTS_INVALID"
        statuses.append(status_value)

        if stage in special_stages:
            if stage in {"source", "source-final"} and adapter != "mergegrounds":
                return "EVIDENCE_RESULTS_INVALID"
            if stage == "toolchain" and adapter not in adapters:
                return "EVIDENCE_RESULTS_INVALID"
            continue

        base_stage = stage
        suffix: str | None = None
        if "-" in stage:
            candidate_base, candidate_suffix = stage.rsplit("-", 1)
            if candidate_suffix in auxiliary_suffixes:
                base_stage, suffix = candidate_base, candidate_suffix
        if base_stage not in KNOWN_STAGES or base_stage not in profile_stages:
            return "EVIDENCE_RESULTS_INVALID"
        if suffix == "metrics" and base_stage not in {"coverage", "mutation"}:
            return "EVIDENCE_RESULTS_INVALID"
        if base_stage == "policy":
            if adapter != "mergegrounds" or suffix is not None:
                return "EVIDENCE_RESULTS_INVALID"
        elif adapter not in adapters:
            return "EVIDENCE_RESULTS_INVALID"
        if suffix is None:
            observed.add((adapter, base_stage))

    if all(status == "pass" for status in statuses):
        return "EVIDENCE_VERDICT_MISMATCH"
    return None


def validate_raw_run_evidence(
    value: dict[str, Any],
    profile: str,
    subject: dict[str, Any],
    exit_code: int,
    runner_outcome: str,
    *,
    now: dt.datetime | None = None,
) -> tuple[bool, str]:
    required = {
        "schema_version",
        "run_id",
        "started_at",
        "finished_at",
        "status",
        "decision",
        "profile",
        "risk_tier",
        "git_commit",
        "git_tree",
        "config",
        "adapters",
        "sanitized_environment_keys",
        "tool_versions",
        "thresholds",
        "results",
        "artifacts",
    }
    if set(value) != required:
        return False, "EVIDENCE_SCHEMA_INVALID"
    if value.get("schema_version") != SCHEMA_VERSION or value.get("profile") != profile:
        return False, "EVIDENCE_SCHEMA_INVALID"
    if value.get("risk_tier") not in RISK_ORDER:
        return False, "EVIDENCE_SCHEMA_INVALID"
    run_id = value.get("run_id")
    try:
        parsed_run_id = uuid.UUID(run_id) if isinstance(run_id, str) else None
    except (ValueError, TypeError, AttributeError):
        return False, "EVIDENCE_SCHEMA_INVALID"
    if parsed_run_id is None or parsed_run_id.version != 4 or str(parsed_run_id) != run_id:
        return False, "EVIDENCE_SCHEMA_INVALID"
    started_at = parse_rfc3339_utc(value.get("started_at"))
    finished_at = parse_rfc3339_utc(value.get("finished_at"))
    if started_at is None or finished_at is None:
        return False, "EVIDENCE_TIME_INVALID"
    if finished_at < started_at:
        return False, "EVIDENCE_TIME_ORDER"
    if exit_code == 0:
        time_reason = allow_evidence_time_reason(
            started_at,
            finished_at,
            subject,
            now or utc_now(),
        )
        if time_reason is not None:
            return False, time_reason
    if value.get("git_commit") != subject["commit"]:
        return False, "EVIDENCE_SUBJECT_MISMATCH"
    if not isinstance(value.get("git_tree"), str) or not GIT_OBJECT_ID.fullmatch(value["git_tree"]):
        return False, "EVIDENCE_SCHEMA_INVALID"
    if value["git_tree"] != subject["tree"]:
        return False, "EVIDENCE_TREE_MISMATCH"
    config = value.get("config")
    if (
        not isinstance(config, dict)
        or set(config) != {"path", "sha256"}
        or config.get("path") != ".mergegrounds/mergegrounds.toml"
        or not isinstance(config.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", config["sha256"])
    ):
        return False, "EVIDENCE_SCHEMA_INVALID"
    if config["sha256"] != subject["policy_sha256"]:
        return False, "EVIDENCE_POLICY_MISMATCH"
    if value.get("risk_tier") != subject["risk_tier"]:
        return False, "EVIDENCE_POLICY_MISMATCH"
    if not same_json_value(value.get("thresholds"), subject["thresholds"]):
        return False, "EVIDENCE_POLICY_MISMATCH"
    adapters = value.get("adapters")
    if (
        not isinstance(adapters, list)
        or not adapters
        or not all(isinstance(item, str) and item for item in adapters)
        or len(adapters) != len(set(adapters))
    ):
        return False, "EVIDENCE_SCHEMA_INVALID"
    if adapters != subject["adapters"]:
        return False, "EVIDENCE_ADAPTER_MISMATCH"
    result_reason = raw_result_reason(
        subject["root"],
        value.get("results"),
        subject,
        exit_code == 0,
    )
    if result_reason is not None:
        return False, result_reason
    sanitized = value.get("sanitized_environment_keys")
    if (
        not isinstance(sanitized, list)
        or any(not isinstance(item, str) or not item or "\x00" in item for item in sanitized)
        or sanitized != sorted(set(sanitized))
    ):
        return False, "EVIDENCE_SCHEMA_INVALID"
    tool_version_values = value.get("tool_versions")
    if not isinstance(tool_version_values, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in tool_version_values.items()
    ):
        return False, "EVIDENCE_SCHEMA_INVALID"
    if not isinstance(value.get("thresholds"), dict) or not isinstance(value.get("artifacts"), list):
        return False, "EVIDENCE_SCHEMA_INVALID"
    if exit_code == 0:
        try:
            expected_environment, expected_sanitized = environment_for(subject["config"])
            expected_versions = tool_versions(
                subject["adapter_values"],
                subject["root"],
                expected_environment,
            )
            expected_artifacts = artifact_records(subject["root"], subject["adapter_values"])
        except (MergeGroundsError, OSError, ValueError, TypeError):
            return False, "EVIDENCE_RESULTS_INVALID"
        if sanitized != expected_sanitized or not same_json_value(tool_version_values, expected_versions):
            return False, "EVIDENCE_TOOLCHAIN_MISMATCH"
        if not same_json_value(value["artifacts"], expected_artifacts):
            return False, "EVIDENCE_ARTIFACT_MISMATCH"
    expected = ("pass", "allow") if exit_code == 0 else ("fail", "deny")
    if (value.get("status"), value.get("decision")) != expected:
        return False, "EVIDENCE_VERDICT_MISMATCH"
    if exit_code == 0 and runner_outcome != "success":
        return False, "EVIDENCE_VERDICT_MISMATCH"
    if exit_code != 0 and runner_outcome != "failure":
        return False, "EVIDENCE_VERDICT_MISMATCH"
    return True, "EVIDENCE_VALID"


def subject_worktree_matches(root: Path, subject: dict[str, Any]) -> bool:
    """Bind local revalidation to one clean checkout of the immutable subject."""
    try:
        require_git_toplevel(root)
        state = git_source_state(root)
    except MergeGroundsError:
        return False
    return (
        state["commit"] == subject.get("commit")
        and state["tree"] == subject.get("tree")
        and state["status"] == ""
    )


def normalize_attempt(args: argparse.Namespace, *, now: dt.datetime | None = None) -> int:
    """Create an inert receipt even when candidate evidence is absent or malformed."""
    root = resolve_root(args.root)
    raw_path = canonical_attempt_path(root, args.raw, "raw evidence path")
    output_path = canonical_attempt_path(root, args.output, "receipt output path")
    if raw_path == output_path:
        raise MergeGroundsError("receipt output path must differ from raw evidence path")
    subject_sha = args.subject_sha if isinstance(args.subject_sha, str) and GIT_OBJECT_ID.fullmatch(args.subject_sha) else None
    subject_context: dict[str, Any] | None = None
    subject_error: str | None = None
    if subject_sha is not None:
        try:
            subject_context = subject_evidence_context(root, subject_sha, args.profile)
        except MergeGroundsError as exc:
            subject_error = str(exc)
    initial_subject_checkout = bool(
        subject_context is not None
        and subject_worktree_matches(root, subject_context)
    )
    exit_code: int | None = None
    if isinstance(args.exit_code, str) and re.fullmatch(r"[0-9]{1,3}", args.exit_code):
        parsed = int(args.exit_code)
        if 0 <= parsed <= 255:
            exit_code = parsed
    runner_outcome = args.runner_outcome if args.runner_outcome in {"success", "failure", "cancelled", "skipped"} else "unknown"
    raw_bytes: bytes | None = None
    raw_error: str | None = None
    try:
        raw_bytes = bounded_regular_bytes(raw_path, "raw MergeGrounds evidence", MAX_EVIDENCE_BYTES)
    except MergeGroundsError as exc:
        raw_error = str(exc)

    raw_digest = sha256_bytes(raw_bytes) if raw_bytes is not None else None
    raw_size = len(raw_bytes) if raw_bytes is not None else None
    validated = False
    reason_code = "EVIDENCE_MISSING" if raw_error and "missing" in raw_error else "EVIDENCE_UNSAFE"
    if exit_code is None:
        reason_code = "RUNNER_EXIT_INVALID"
    elif runner_outcome in {"unknown", "cancelled", "skipped"}:
        reason_code = "RUNNER_OUTCOME_INVALID"
    elif subject_context is None:
        reason_code = "SUBJECT_CONTEXT_INVALID"
    elif not initial_subject_checkout:
        reason_code = "SUBJECT_WORKTREE_MISMATCH"
    elif raw_bytes is not None:
        try:
            document = strict_json_document(
                raw_bytes,
                "raw MergeGrounds evidence",
                MAX_EVIDENCE_BYTES,
                maximum_nodes=MAX_EVIDENCE_NODES,
            )
        except MergeGroundsError:
            reason_code = "EVIDENCE_MALFORMED"
        else:
            validated, reason_code = validate_raw_run_evidence(
                document,
                args.profile,
                subject_context,
                exit_code,
                runner_outcome,
                now=now,
            )
    if subject_sha is None:
        validated = False
        reason_code = "SUBJECT_INVALID"
    elif subject_context is None:
        validated = False
        reason_code = "SUBJECT_CONTEXT_INVALID"
    if validated and subject_context is not None and not subject_worktree_matches(root, subject_context):
        validated = False
        reason_code = "SUBJECT_WORKTREE_MISMATCH"
    allow = validated and exit_code == 0 and runner_outcome == "success"
    if validated and not allow:
        reason_code = "RUNNER_DENIED"
    receipt = {
        "schema_version": 1,
        "receipt_id": str(uuid.uuid4()),
        "created_at": iso_now(),
        "profile": args.profile,
        "status": "pass" if allow else "fail",
        "decision": "allow" if allow else "deny",
        "reason_code": "NONE" if allow else reason_code,
        "subject_sha": subject_sha,
        "subject_tree": subject_context.get("tree") if subject_context else None,
        "policy_sha256": subject_context.get("policy_sha256") if subject_context else None,
        "run": {
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "runner_outcome": runner_outcome,
            "exit_code": exit_code,
        },
        "raw_evidence": {
            "path": args.raw,
            "regular_bounded_file": raw_bytes is not None,
            "validated": validated,
            "sha256": raw_digest,
            "bytes": raw_size,
        },
        "subject_context_error": subject_error,
        "authority": "local-receipt-not-external-attestation",
        "external_root_of_trust": "required-for-maximum-assurance",
    }
    write_json_atomic(output_path, receipt, root)
    print(f"attempt receipt: {relative(output_path, root)} decision={receipt['decision']} reason={receipt['reason_code']}")
    return 0 if allow else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="repository root (defaults to current directory)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="run a configured gate profile")
    run.add_argument("--profile", required=True, help="profile id from .mergegrounds/profiles or mergegrounds.toml")
    run.add_argument("--evidence", help="write machine-readable evidence inside the repository")
    run.add_argument("--fail-fast", action="store_true", help="stop after the first failure")
    run.set_defaults(handler=run_profile)

    check = subparsers.add_parser("verify-repo", help="verify repository policy and control-plane integrity")
    check.add_argument("--strict", action="store_true", help="treat warnings as failures")
    check.set_defaults(handler=verify_repo_command)

    diagnose = subparsers.add_parser("doctor", help="detect stacks and required toolchains")
    diagnose.set_defaults(handler=doctor)

    seal = subparsers.add_parser("seal", help="check or explicitly update the control-plane integrity lock")
    seal.add_argument("--write", action="store_true", help="write the reviewed control-plane lock")
    seal.set_defaults(handler=seal_command)

    change = subparsers.add_parser(
        "verify-change",
        help="validate a structured change declaration and its pre-existing design contract",
    )
    change.add_argument("--event", required=True, help="path to the GitHub pull_request event JSON")
    change.set_defaults(handler=verify_change_command)

    attestation = subparsers.add_parser(
        "attest-pr",
        help="compatibility alias for verify-change; checkboxes are not admission evidence",
    )
    attestation.add_argument("--event", required=True, help="path to the GitHub event JSON")
    attestation.set_defaults(handler=attest_pr)

    receipt = subparsers.add_parser(
        "normalize-attempt",
        help="write a fail-closed receipt for present, missing, or malformed run evidence",
    )
    receipt.add_argument("--raw", required=True, help="raw evidence path below .mergegrounds/evidence")
    receipt.add_argument("--output", required=True, help="receipt path below .mergegrounds/evidence")
    receipt.add_argument("--profile", required=True, help="expected MergeGrounds profile")
    receipt.add_argument("--subject-sha", required=True, help="tested Git commit")
    receipt.add_argument("--exit-code", required=True, help="raw runner exit code, possibly empty")
    receipt.add_argument("--runner-outcome", required=True, help="GitHub step outcome")
    receipt.set_defaults(handler=normalize_attempt)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except MergeGroundsError as exc:
        print(f"mergegrounds: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("mergegrounds: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
