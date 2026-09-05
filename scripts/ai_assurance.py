#!/usr/bin/env -S python3 -I
"""Fail-closed, dependency-free assurance gate for products that ship AI behavior.

The module intentionally validates only observable, typed evidence.  Model
reasoning, confidence, author assertions, and same-session self-review are not
accepted as admission evidence.

Public API:

* ``load_policy(root)`` raises ``AIAssuranceError`` on an invalid policy.
* ``validate_repository_policy(root)`` returns a structured ``Decision``.
* ``evaluate_repository(root)`` validates the configured report and returns a
  structured ``Decision`` suitable for a surrounding repository gate.
* CLI ``evaluate --output .mergegrounds/evidence/ai-decision.json`` materializes
  that decision through a no-follow atomic replacement; shell redirection is
  not a safe evidence writer.

An ``allow`` here is local conformance, not proof that a producer was really
independent, a provider honored its contract, or a holdout stayed hidden.  A
protected CI identity and external trust services must establish those facts.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - explicit version guard
    raise SystemExit("AI assurance requires Python 3.11 or newer") from exc


SCHEMA_VERSION = 2
CANONICAL_CONFIG = ".mergegrounds/ai-assurance.toml"
CANONICAL_DECISION_OUTPUT = ".mergegrounds/evidence/ai-decision.json"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 100_000
MAX_JSON_STRING_BYTES = 256 * 1024
MAX_FUTURE_SKEW_SECONDS = 300

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{1,255}$")
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9._:/\-]{1,127}$")
METRIC_ID = re.compile(r"^[a-z][a-z0-9._:/\-]{1,127}$")
SLICE_ID = re.compile(r"^[a-z][a-z0-9._:/\-]{1,127}$")

# These values are emitted by the fail-closed example or are common copy/paste
# sentinels.  A syntactically valid identifier is not a materialized product
# identity merely because its digest fields were replaced.
PLACEHOLDER_VALUES = frozenset(
    {
        "change-me",
        "change_me",
        "changeme",
        "example",
        "placeholder",
        "replace",
        "tbd",
        "todo",
    }
)
PLACEHOLDER_PREFIXES = (
    "change-me-",
    "change_me_",
    "changeme-",
    "example-",
    "example:",
    "example/",
    "placeholder-",
    "placeholder:",
    "placeholder/",
    "replace-",
    "replace:",
    "replace/",
    "tbd-",
    "todo-",
    "your-",
    "your_",
)

CAPABILITIES = {
    "inference",
    "retrieval",
    "long_context",
    "fine_tuning",
    "agent_tools",
}
CASE_CLASSES = {"positive", "negative", "adversarial", "regression", "recovery"}
AUTHORITATIVE_PRODUCERS = {"trusted_execution", "external_verifier", "independent_human"}
ADVISORY_PRODUCERS = {"model", "self_review", "author"}
ALL_PRODUCERS = AUTHORITATIVE_PRODUCERS | ADVISORY_PRODUCERS
ORACLE_CLASSES = {"deterministic", "trusted_system", "independent_human"}
TERMINAL_CASE_STATUSES = {
    "passed",
    "failed",
    "skipped",
    "error",
    "partial",
    "stale",
    "inconclusive",
}
DENY_CASE_STATUSES = TERMINAL_CASE_STATUSES - {"passed"}
THRESHOLD_OPERATORS = {"gte", "lte", "eq"}
SAMPLE_COUNT_MODES = {"exact", "minimum"}
REGRESSION_DIRECTIONS = {"higher_is_better", "lower_is_better"}
MAX_SAMPLE_COUNT = 1_000_000_000

COMPONENT_FIELDS: dict[str, tuple[str, ...]] = {
    "inference": (
        "provider_id",
        "endpoint_id",
        "model_id",
        "model_revision",
        "runtime_digest",
        "prompt_digest",
        "inference_parameters_digest",
        "safety_policy_digest",
        "output_validator_digest",
    ),
    "retrieval": (
        "corpus_snapshot_id",
        "corpus_digest",
        "acl_policy_digest",
        "embedding_model_digest",
        "chunker_digest",
        "index_digest",
        "retriever_digest",
        "reranker_digest",
        "context_builder_digest",
    ),
    "long_context": (
        "tokenizer_digest",
        "context_builder_digest",
        "truncation_policy_digest",
        "ordered_context_manifest_digest",
    ),
    "fine_tuning": (
        "base_model_digest",
        "production_baseline_digest",
        "tokenizer_digest",
        "training_dataset_digest",
        "training_recipe_digest",
        "training_code_digest",
        "training_parameters_digest",
        "training_runtime_digest",
        "artifact_digest",
        "rollback_target_digest",
    ),
    "agent_tools": (
        "tool_catalog_digest",
        "authorization_policy_digest",
        "sandbox_profile_digest",
        "egress_policy_digest",
        "confirmation_policy_digest",
        "resource_budget_digest",
        "audit_policy_digest",
    ),
}
COMPONENT_ID_FIELDS = {
    "provider_id",
    "endpoint_id",
    "model_id",
    "corpus_snapshot_id",
}

# Every listed behavior must have at least one critical, product-specific case.
# The policy chooses thresholds and concrete inputs; these names impose no
# universal score or vendor benchmark.
REQUIRED_REQUIREMENTS: dict[str, frozenset[str]] = {
    "inference": frozenset(
        {
            "inference_expected",
            "inference_refusal",
            "inference_prompt_injection",
            "inference_regression",
            "inference_recovery",
        }
    ),
    "retrieval": frozenset(
        {
            "rag_acl_leak",
            "rag_unsupported_claim",
            "rag_abstention",
            "rag_position_beginning",
            "rag_position_middle",
            "rag_position_end",
            "rag_overflow",
            "rag_stale_source",
            "rag_conflicting_source",
            "rag_retrieved_instruction",
        }
    ),
    "long_context": frozenset(
        {
            "context_position_beginning",
            "context_position_middle",
            "context_position_end",
            "context_paraphrase",
            "context_multifact",
            "context_distractor",
            "context_conflict",
            "context_overflow",
        }
    ),
    "fine_tuning": frozenset(
        {
            "finetune_target",
            "finetune_general_capability",
            "finetune_safety",
            "finetune_privacy",
            "finetune_refusal",
            "finetune_tool_use",
            "finetune_latency",
            "finetune_cost",
            "finetune_rollback",
        }
    ),
    "agent_tools": frozenset(
        {
            "agent_sandbox_escape",
            "agent_egress_denied",
            "agent_tool_authorization",
            "agent_human_confirmation",
            "agent_resource_limit",
            "agent_credential_isolation",
            "agent_retrieval_cannot_expand_authority",
        }
    ),
}
KNOWN_REQUIREMENTS = {"product_specific"} | set().union(*REQUIRED_REQUIREMENTS.values())
REQUIREMENT_ALLOWED_CLASSES: dict[str, frozenset[str]] = {
    "inference_expected": frozenset({"positive"}),
    "inference_refusal": frozenset({"negative"}),
    "inference_prompt_injection": frozenset({"adversarial"}),
    "inference_regression": frozenset({"regression"}),
    "inference_recovery": frozenset({"recovery"}),
    "rag_acl_leak": frozenset({"negative", "adversarial"}),
    "rag_unsupported_claim": frozenset({"negative", "adversarial"}),
    "rag_abstention": frozenset({"negative"}),
    "rag_position_beginning": frozenset({"positive"}),
    "rag_position_middle": frozenset({"regression"}),
    "rag_position_end": frozenset({"positive"}),
    "rag_overflow": frozenset({"recovery"}),
    "rag_stale_source": frozenset({"regression", "negative"}),
    "rag_conflicting_source": frozenset({"adversarial"}),
    "rag_retrieved_instruction": frozenset({"adversarial"}),
    "context_position_beginning": frozenset({"positive"}),
    "context_position_middle": frozenset({"regression"}),
    "context_position_end": frozenset({"positive"}),
    "context_paraphrase": frozenset({"positive", "regression"}),
    "context_multifact": frozenset({"positive", "regression"}),
    "context_distractor": frozenset({"adversarial"}),
    "context_conflict": frozenset({"negative", "adversarial"}),
    "context_overflow": frozenset({"recovery"}),
    "finetune_target": frozenset({"positive"}),
    "finetune_general_capability": frozenset({"regression"}),
    "finetune_safety": frozenset({"adversarial", "regression"}),
    "finetune_privacy": frozenset({"adversarial", "regression"}),
    "finetune_refusal": frozenset({"negative", "regression"}),
    "finetune_tool_use": frozenset({"adversarial", "regression"}),
    "finetune_latency": frozenset({"regression"}),
    "finetune_cost": frozenset({"regression"}),
    "finetune_rollback": frozenset({"recovery"}),
    "agent_sandbox_escape": frozenset({"adversarial"}),
    "agent_egress_denied": frozenset({"negative", "adversarial"}),
    "agent_tool_authorization": frozenset({"negative", "adversarial"}),
    "agent_human_confirmation": frozenset({"negative"}),
    "agent_resource_limit": frozenset({"negative", "adversarial"}),
    "agent_credential_isolation": frozenset({"adversarial"}),
    "agent_retrieval_cannot_expand_authority": frozenset({"adversarial"}),
}

LOCAL_LIMITATIONS = (
    "A local product_ai declaration does not prove that AI behavior was completely "
    "discovered; protected applicability review remains required.",
    "Local report validation does not authenticate the producer or prove its independence.",
    "A matching provider-policy digest does not prove provider contract performance, "
    "retention, deletion, residency, or subprocessors.",
    "A matching evaluation-policy digest does not prove that a holdout remained private or uncontaminated.",
    "Finite cases establish conformance only for the bound revision and enumerated "
    "scope; model reasoning and self-review are advisory.",
)


class AIAssuranceError(ValueError):
    """A validation problem that must produce a deny decision."""

    def __init__(self, code: str, message: str, path: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.path = path


@dataclasses.dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    path: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Decision:
    decision: str
    product_ai: bool
    capabilities: tuple[str, ...]
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]
    report_path: str | None = None
    source_commit: str | None = None
    source_tree: str | None = None
    config_digest: str | None = None
    report_digest: str | None = None
    expected_case_set_digest: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "decision": self.decision,
            "local_conformance": self.allowed,
            "authority": "local-validation-only",
            "product_ai": self.product_ai,
            "capabilities": list(self.capabilities),
            "report_path": self.report_path,
            "source_commit": self.source_commit,
            "source_tree": self.source_tree,
            "config_digest": self.config_digest,
            "report_digest": self.report_digest,
            "expected_case_set_digest": self.expected_case_set_digest,
            "findings": [finding.as_dict() for finding in self.findings],
            "limitations": list(self.limitations),
        }


@dataclasses.dataclass(frozen=True)
class Policy:
    root: Path
    raw: Mapping[str, Any]
    config_digest: str
    source_commit: str
    source_tree: str
    product_ai: bool
    capabilities: tuple[str, ...]
    components: Mapping[str, Mapping[str, str]]
    protected_policies: Mapping[str, Mapping[str, str]]
    evaluation: Mapping[str, Any] | None


def _deny(error: AIAssuranceError, product_ai: bool = True) -> Decision:
    return Decision(
        decision="deny",
        product_ai=product_ai,
        capabilities=(),
        findings=(Finding(error.code, "error", str(error), error.path),),
        limitations=LOCAL_LIMITATIONS,
    )


def _git_environment() -> dict[str, str]:
    """Return a minimal Git environment without caller-controlled repository indirection."""

    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment


def _repository_root(root: str | os.PathLike[str]) -> Path:
    candidate = Path(root)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise AIAssuranceError("AI_PATH_ROOT", f"repository root is unavailable: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise AIAssuranceError("AI_PATH_ROOT_SYMLINK", "repository root must not be a symlink")
    if not stat.S_ISDIR(info.st_mode):
        raise AIAssuranceError("AI_PATH_ROOT", "repository root must be a directory")
    resolved = candidate.resolve(strict=True)
    try:
        completed = subprocess.run(
            ["git", "-C", str(resolved), "rev-parse", "--show-toplevel"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AIAssuranceError("AI_GIT_UNAVAILABLE", f"cannot locate Git top-level: {exc}") from exc
    raw_top = completed.stdout.strip()
    if completed.returncode != 0 or not raw_top:
        raise AIAssuranceError("AI_GIT_TOPLEVEL", "repository root must be an initialized Git worktree")
    try:
        top = Path(raw_top).resolve(strict=True)
    except OSError as exc:
        raise AIAssuranceError("AI_GIT_TOPLEVEL", f"Git top-level is unavailable: {exc}") from exc
    if top != resolved:
        raise AIAssuranceError(
            "AI_GIT_NESTED_ROOT",
            f"repository root must exactly equal Git top-level {top}",
        )
    return resolved


def _safe_repo_path(raw: str | os.PathLike[str], *, prefix: str | None = None) -> str:
    value = os.fspath(raw)
    if not isinstance(value, str) or not value:
        raise AIAssuranceError("AI_PATH_INVALID", "path must be a non-empty string")
    if "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise AIAssuranceError("AI_PATH_INVALID", f"unsafe path syntax: {value!r}", value)
    parts = value.split("/")
    if value.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise AIAssuranceError("AI_PATH_INVALID", f"path must be canonical and repository-relative: {value!r}", value)
    parsed = PurePosixPath(value)
    if parsed.as_posix() != value:
        raise AIAssuranceError("AI_PATH_INVALID", f"path is not canonical: {value!r}", value)
    if prefix is not None and not value.startswith(prefix.rstrip("/") + "/"):
        raise AIAssuranceError("AI_PATH_SCOPE", f"path must be below {prefix}/: {value!r}", value)
    return value


def _read_repo_file(root: Path, relative: str, maximum: int) -> bytes:
    relative = _safe_repo_path(relative)
    if not hasattr(os, "O_NOFOLLOW") or os.open not in getattr(os, "supports_dir_fd", set()):
        raise AIAssuranceError(
            "AI_PLATFORM_UNSAFE",
            "this platform cannot provide no-follow, directory-relative input reads",
            relative,
        )
    flags_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    root_fd = -1
    directory_fd = -1
    file_fd = -1
    try:
        root_fd = os.open(root, flags_dir | nofollow)
        directory_fd = root_fd
        parts = relative.split("/")
        for component in parts[:-1]:
            next_fd = os.open(component, flags_dir | nofollow, dir_fd=directory_fd)
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | nofollow,
            dir_fd=directory_fd,
        )
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise AIAssuranceError("AI_PATH_NOT_REGULAR", "required input is not a regular file", relative)
        if before.st_mode & 0o111:
            raise AIAssuranceError(
                "AI_PATH_EXECUTABLE",
                "policy, evidence, and decision data must be non-executable regular files",
                relative,
            )
        if before.st_size > maximum:
            raise AIAssuranceError("AI_FILE_TOO_LARGE", f"input exceeds {maximum} bytes", relative)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise AIAssuranceError("AI_FILE_TOO_LARGE", f"input exceeds {maximum} bytes", relative)
        after = os.fstat(file_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise AIAssuranceError("AI_FILE_CHANGED", "input changed while it was read", relative)
        data = b"".join(chunks)
        if len(data) != after.st_size:
            raise AIAssuranceError("AI_FILE_CHANGED", "input size changed while it was read", relative)
        if not data:
            raise AIAssuranceError("AI_FILE_EMPTY", "required input must not be empty", relative)
        return data
    except AIAssuranceError:
        raise
    except OSError as exc:
        raise AIAssuranceError("AI_PATH_UNSAFE", f"cannot securely read input: {exc}", relative) from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0 and directory_fd != root_fd:
            os.close(directory_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _read_head_bound_control(
    root: Path,
    relative: str,
    maximum: int,
    *,
    expected_identity: tuple[str, str] | None = None,
) -> tuple[bytes, tuple[str, str]]:
    """Read a control as an exact regular blob from one immutable HEAD tree.

    The worktree copy must byte-for-byte equal that blob. This deliberately
    denies staged, unstaged, untracked, symlinked, or concurrently switched
    controls instead of combining an immutable report subject with mutable
    local policy.
    """

    relative = _safe_repo_path(relative)
    identity = _git_identity(root)
    if expected_identity is not None and identity != expected_identity:
        raise AIAssuranceError(
            "AI_GIT_CHANGED",
            "repository HEAD changed while assurance controls were loaded",
            relative,
        )
    commit, _ = identity
    try:
        listing = subprocess.run(
            ["git", "-C", str(root), "ls-tree", "-z", "--full-tree", commit, "--", relative],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AIAssuranceError("AI_GIT_UNAVAILABLE", f"cannot inspect control blob: {exc}", relative) from exc
    records = [record for record in listing.stdout.split(b"\0") if record]
    if listing.returncode != 0 or len(records) != 1:
        raise AIAssuranceError(
            "AI_CONTROL_UNTRACKED",
            "assurance control must exist exactly once in the immutable HEAD tree",
            relative,
        )
    try:
        header, encoded_path = records[0].split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        listed_path = encoded_path.decode("utf-8", errors="strict")
    except (ValueError, UnicodeError) as exc:
        raise AIAssuranceError("AI_CONTROL_GIT_ENTRY", "invalid Git tree entry", relative) from exc
    if listed_path != relative or object_type != "blob" or mode != "100644":
        raise AIAssuranceError(
            "AI_CONTROL_GIT_MODE",
            "assurance control must be an exact non-executable regular Git blob (100644)",
            relative,
        )
    try:
        size_result = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-s", object_id],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=_git_environment(),
        )
        blob_size = int(size_result.stdout.strip())
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise AIAssuranceError("AI_CONTROL_GIT_BLOB", f"cannot size control blob: {exc}", relative) from exc
    if size_result.returncode != 0 or blob_size <= 0:
        raise AIAssuranceError("AI_CONTROL_GIT_BLOB", "control blob must be non-empty", relative)
    if blob_size > maximum:
        raise AIAssuranceError("AI_FILE_TOO_LARGE", f"input exceeds {maximum} bytes", relative)
    try:
        content_result = subprocess.run(
            ["git", "-C", str(root), "cat-file", "blob", object_id],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AIAssuranceError("AI_CONTROL_GIT_BLOB", f"cannot read control blob: {exc}", relative) from exc
    blob = content_result.stdout
    if content_result.returncode != 0 or len(blob) != blob_size:
        raise AIAssuranceError("AI_CONTROL_GIT_BLOB", "control blob changed or could not be read", relative)
    worktree = _read_repo_file(root, relative, maximum)
    if worktree != blob:
        raise AIAssuranceError(
            "AI_CONTROL_DIRTY",
            "worktree control must byte-for-byte match its immutable HEAD blob",
            relative,
        )
    return blob, identity


def _write_decision_output(
    root: str | os.PathLike[str], relative: str | os.PathLike[str], data: bytes
) -> None:
    """Atomically replace the canonical ignored decision output without following links."""

    repository = _repository_root(root)
    selected = _safe_repo_path(relative, prefix=".mergegrounds/evidence")
    if selected != CANONICAL_DECISION_OUTPUT:
        raise AIAssuranceError(
            "AI_DECISION_PATH",
            f"decision output must be exactly {CANONICAL_DECISION_OUTPUT}",
            selected,
        )
    if not data or len(data) > MAX_CONFIG_BYTES:
        raise AIAssuranceError(
            "AI_DECISION_SIZE",
            "decision output must be non-empty and bounded",
            selected,
        )
    try:
        tracked = subprocess.run(
            ["git", "-C", str(repository), "ls-files", "--error-unmatch", "--", selected],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env=_git_environment(),
        )
        ignored = subprocess.run(
            ["git", "-C", str(repository), "check-ignore", "-q", "--", selected],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AIAssuranceError(
            "AI_GIT_UNAVAILABLE",
            f"cannot validate decision output isolation: {exc}",
            selected,
        ) from exc
    if tracked.returncode == 0:
        raise AIAssuranceError(
            "AI_DECISION_TRACKED",
            "decision output must not be tracked in the candidate tree",
            selected,
        )
    if ignored.returncode != 0:
        raise AIAssuranceError(
            "AI_DECISION_NOT_IGNORED",
            "decision output must be ignored by repository policy",
            selected,
        )

    flags_directory = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow or os.open not in getattr(os, "supports_dir_fd", set()):
        raise AIAssuranceError(
            "AI_PLATFORM_UNSAFE",
            "this platform cannot safely materialize decision output",
            selected,
        )
    root_fd = -1
    directory_fd = -1
    temporary_fd = -1
    temporary_name = f".ai-decision.tmp.{os.urandom(16).hex()}"
    try:
        root_fd = os.open(repository, flags_directory | nofollow)
        directory_fd = root_fd
        parts = selected.split("/")
        for component in parts[:-1]:
            next_fd = os.open(component, flags_directory | nofollow, dir_fd=directory_fd)
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | nofollow,
            0o600,
            dir_fd=directory_fd,
        )
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(temporary_fd, view[written:])
            if count <= 0:
                raise OSError("short write while materializing decision")
            written += count
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(
            temporary_name,
            parts[-1],
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except AIAssuranceError:
        raise
    except OSError as exc:
        raise AIAssuranceError(
            "AI_DECISION_WRITE",
            f"cannot safely materialize decision output: {exc}",
            selected,
        ) from exc
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if directory_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_fd >= 0 and directory_fd != root_fd:
            os.close(directory_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _decode_utf8(data: bytes, path: str) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        raise AIAssuranceError("AI_UTF8_BOM", "UTF-8 BOM is forbidden", path)
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AIAssuranceError("AI_UTF8_INVALID", f"input is not strict UTF-8: {exc}", path) from exc


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _expect_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise AIAssuranceError("AI_SCHEMA_TYPE", f"{label} must be a table/object")
    return value


def _exact_keys(value: Mapping[str, Any], required: Iterable[str], label: str) -> None:
    expected = set(required)
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unknown:
            details.append("unknown=" + ",".join(unknown))
        raise AIAssuranceError("AI_SCHEMA_KEYS", f"{label} has an invalid closed schema ({'; '.join(details)})")


def _strict_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise AIAssuranceError("AI_SCHEMA_TYPE", f"{label} must be a boolean")
    return value


def _strict_int(value: Any, label: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        limit = f"..{maximum}" if maximum is not None else " or greater"
        raise AIAssuranceError("AI_SCHEMA_TYPE", f"{label} must be an integer in {minimum}{limit}")
    return value


def _finite_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AIAssuranceError("AI_SCHEMA_TYPE", f"{label} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise AIAssuranceError("AI_SCHEMA_NUMBER", f"{label} must be finite")
    return number


def _unit_interval(value: Any, label: str) -> float:
    number = _finite_number(value, label)
    if number < 0 or number > 1:
        raise AIAssuranceError("AI_METRIC_RANGE", f"{label} must be normalized to the range 0..1")
    return number


def _string(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_JSON_STRING_BYTES:
        raise AIAssuranceError("AI_SCHEMA_TYPE", f"{label} must be a non-empty bounded string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise AIAssuranceError("AI_SCHEMA_VALUE", f"{label} has an invalid value: {value!r}")
    return value


def _materialized_string(
    value: Any,
    label: str,
    pattern: re.Pattern[str] | None = None,
) -> str:
    """Validate an identifier and reject known template/copy-paste sentinels."""

    result = _string(value, label, pattern)
    normalized = result.casefold()
    if normalized in PLACEHOLDER_VALUES or normalized.startswith(PLACEHOLDER_PREFIXES):
        raise AIAssuranceError(
            "AI_IDENTITY_PLACEHOLDER",
            f"{label} is an unresolved template placeholder: {result!r}",
        )
    return result


def _string_list(
    value: Any,
    label: str,
    *,
    allowed: set[str] | frozenset[str] | None = None,
    pattern: re.Pattern[str] | None = None,
    nonempty: bool = True,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AIAssuranceError("AI_SCHEMA_TYPE", f"{label} must be an array")
    if nonempty and not value:
        raise AIAssuranceError("AI_SCHEMA_EMPTY", f"{label} must not be empty")
    result: list[str] = []
    for index, item in enumerate(value):
        text = _string(item, f"{label}[{index}]", pattern)
        if allowed is not None and text not in allowed:
            raise AIAssuranceError("AI_SCHEMA_VALUE", f"{label}[{index}] is unsupported: {text!r}")
        result.append(text)
    if len(set(result)) != len(result):
        raise AIAssuranceError("AI_SCHEMA_DUPLICATE", f"{label} must contain unique values")
    return tuple(result)


def _materialized_string_list(
    value: Any,
    label: str,
    *,
    allowed: set[str] | frozenset[str] | None = None,
    pattern: re.Pattern[str] | None = None,
    nonempty: bool = True,
) -> tuple[str, ...]:
    result = _string_list(
        value,
        label,
        allowed=allowed,
        pattern=pattern,
        nonempty=nonempty,
    )
    for index, item in enumerate(result):
        _materialized_string(item, f"{label}[{index}]", pattern)
    return result


def _digest(value: Any, label: str) -> str:
    result = _string(value, label, SHA256)
    if result == "sha256:" + "0" * 64:
        raise AIAssuranceError(
            "AI_DIGEST_PLACEHOLDER",
            f"{label} is an unresolved all-zero digest placeholder",
        )
    return result


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return _sha256(encoded)


def _validate_sample_requirement(
    mode_value: Any,
    count_value: Any,
    label: str,
) -> tuple[str, int]:
    mode = _string(mode_value, f"{label}.sample_count_mode")
    if mode not in SAMPLE_COUNT_MODES:
        raise AIAssuranceError(
            "AI_SAMPLE_MODE",
            f"{label}.sample_count_mode must be one of {sorted(SAMPLE_COUNT_MODES)}",
        )
    count = _strict_int(
        count_value,
        f"{label}.sample_count",
        minimum=1,
        maximum=MAX_SAMPLE_COUNT,
    )
    return mode, count


def _validate_authoritative_producers(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise AIAssuranceError(
            "AI_PRODUCER_POLICY_EMPTY",
            "evaluation.authoritative_producers must be a non-empty array of exact class/ID pairs",
        )
    normalized: list[dict[str, str]] = []
    pairs: set[tuple[str, str]] = set()
    ids: set[str] = set()
    for index, item in enumerate(value):
        label = f"evaluation.authoritative_producers[{index}]"
        producer = _expect_mapping(item, label)
        _exact_keys(producer, {"class", "id"}, label)
        producer_class = _string(producer["class"], f"{label}.class")
        if producer_class not in AUTHORITATIVE_PRODUCERS:
            raise AIAssuranceError(
                "AI_PRODUCER_POLICY_CLASS",
                f"{label}.class is not authoritative",
            )
        producer_id = _materialized_string(producer["id"], f"{label}.id", IDENTIFIER)
        pair = (producer_class, producer_id)
        if pair in pairs or producer_id in ids:
            raise AIAssuranceError(
                "AI_PRODUCER_POLICY_DUPLICATE",
                "authoritative producer pairs and IDs must be unique",
            )
        pairs.add(pair)
        ids.add(producer_id)
        normalized.append({"class": producer_class, "id": producer_id})
    return normalized


def _enforce_sample_requirement(actual: int, mode: str, expected: int, label: str) -> None:
    if (mode == "exact" and actual != expected) or (mode == "minimum" and actual < expected):
        relation = "exactly" if mode == "exact" else "at least"
        raise AIAssuranceError(
            "AI_SAMPLE_COUNT",
            f"{label} must contain {relation} {expected} samples; got {actual}",
        )


def _validate_component(capability: str, value: Any, label: str) -> dict[str, str]:
    component = _expect_mapping(value, label)
    fields = COMPONENT_FIELDS[capability]
    _exact_keys(component, fields, label)
    normalized: dict[str, str] = {}
    for field in fields:
        if field in COMPONENT_ID_FIELDS:
            normalized[field] = _materialized_string(
                component[field], f"{label}.{field}", IDENTIFIER
            )
        else:
            normalized[field] = _digest(component[field], f"{label}.{field}")
    return normalized


def _validate_case(value: Any, index: int, capabilities: tuple[str, ...]) -> dict[str, Any]:
    label = f"evaluation.cases[{index}]"
    case = _expect_mapping(value, label)
    fields = {
        "id",
        "class",
        "requirement",
        "capabilities",
        "slices",
        "critical",
        "input_digest",
        "expectation_digest",
        "sample_count_mode",
        "sample_count",
    }
    _exact_keys(case, fields, label)
    case_id = _materialized_string(case["id"], f"{label}.id", CASE_ID)
    case_class = _string(case["class"], f"{label}.class")
    if case_class not in CASE_CLASSES:
        raise AIAssuranceError("AI_CASE_CLASS", f"{label}.class is unsupported: {case_class!r}")
    requirement = _string(case["requirement"], f"{label}.requirement")
    if requirement not in KNOWN_REQUIREMENTS:
        raise AIAssuranceError("AI_CASE_REQUIREMENT", f"{label}.requirement is unsupported: {requirement!r}")
    allowed_classes = REQUIREMENT_ALLOWED_CLASSES.get(requirement)
    if allowed_classes is not None and case_class not in allowed_classes:
        raise AIAssuranceError(
            "AI_CASE_SEMANTICS",
            f"{label} requirement {requirement!r} requires one of classes {sorted(allowed_classes)}",
        )
    case_capabilities = _string_list(
        case["capabilities"], f"{label}.capabilities", allowed=set(capabilities)
    )
    slices = _materialized_string_list(
        case["slices"], f"{label}.slices", pattern=SLICE_ID
    )
    critical = _strict_bool(case["critical"], f"{label}.critical")
    input_digest = _digest(case["input_digest"], f"{label}.input_digest")
    expectation_digest = _digest(case["expectation_digest"], f"{label}.expectation_digest")
    sample_count_mode, sample_count = _validate_sample_requirement(
        case["sample_count_mode"], case["sample_count"], label
    )
    owners = {cap for cap, requirements in REQUIRED_REQUIREMENTS.items() if requirement in requirements}
    if owners and not owners.issubset(set(case_capabilities)):
        raise AIAssuranceError(
            "AI_CASE_CAPABILITY",
            f"{label} requirement {requirement!r} must name capabilities {sorted(owners)}",
        )
    return {
        "id": case_id,
        "class": case_class,
        "requirement": requirement,
        "capabilities": list(case_capabilities),
        "slices": list(slices),
        "critical": critical,
        "input_digest": input_digest,
        "expectation_digest": expectation_digest,
        "sample_count_mode": sample_count_mode,
        "sample_count": sample_count,
    }


def _validate_threshold(
    value: Any,
    index: int,
    critical_slices: tuple[str, ...],
    cases: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    label = f"evaluation.thresholds[{index}]"
    threshold = _expect_mapping(value, label)
    _exact_keys(
        threshold,
        {
            "metric",
            "scope",
            "operator",
            "value",
            "case_ids",
            "sample_count_mode",
            "sample_count",
        },
        label,
    )
    metric = _materialized_string(threshold["metric"], f"{label}.metric", METRIC_ID)
    scope = _string(threshold["scope"], f"{label}.scope")
    if scope != "aggregate" and scope not in critical_slices:
        raise AIAssuranceError(
            "AI_THRESHOLD_SCOPE",
            f"{label}.scope must be aggregate or a declared critical slice",
        )
    operator = _string(threshold["operator"], f"{label}.operator")
    if operator not in THRESHOLD_OPERATORS:
        raise AIAssuranceError("AI_THRESHOLD_OPERATOR", f"{label}.operator is unsupported")
    number = _unit_interval(threshold["value"], f"{label}.value")
    case_ids = _string_list(threshold["case_ids"], f"{label}.case_ids", pattern=CASE_ID)
    expected_scope_ids = {
        case["id"]
        for case in cases
        if scope == "aggregate" or scope in case["slices"]
    }
    if set(case_ids) != expected_scope_ids:
        raise AIAssuranceError(
            "AI_THRESHOLD_CASE_BINDING",
            f"{label}.case_ids must exactly equal the policy case membership for scope {scope!r}",
        )
    sample_mode, sample_count = _validate_sample_requirement(
        threshold["sample_count_mode"], threshold["sample_count"], label
    )
    minimum_from_cases = sum(
        int(case["sample_count"]) for case in cases if case["id"] in expected_scope_ids
    )
    if sample_count < minimum_from_cases:
        raise AIAssuranceError(
            "AI_THRESHOLD_SAMPLE_BINDING",
            f"{label}.sample_count cannot be lower than the bound cases' required total "
            f"{minimum_from_cases}",
        )
    return {
        "metric": metric,
        "scope": scope,
        "operator": operator,
        "value": number,
        "case_ids": list(case_ids),
        "sample_count_mode": sample_mode,
        "sample_count": sample_count,
    }


def _comparison_input_manifest_digest(
    cases: Sequence[Mapping[str, Any]], case_ids: Iterable[str]
) -> str:
    selected = set(case_ids)
    material = [
        {
            "id": case["id"],
            "input_digest": case["input_digest"],
            "expectation_digest": case["expectation_digest"],
            "sample_count_mode": case["sample_count_mode"],
            "sample_count": case["sample_count"],
        }
        for case in sorted(cases, key=lambda item: item["id"])
        if case["id"] in selected
    ]
    return _canonical_digest({"domain": "ai-comparison-input-manifest/v1", "cases": material})


def _validate_comparison_metric_policy(
    value: Any,
    label: str,
    comparison_case_ids: tuple[str, ...],
    cases: Sequence[Mapping[str, Any]],
    thresholds: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    metric = _expect_mapping(value, label)
    _exact_keys(
        metric,
        {
            "metric",
            "scope",
            "case_ids",
            "sample_count_mode",
            "sample_count",
            "direction",
            "max_regression",
        },
        label,
    )
    metric_id = _materialized_string(metric["metric"], f"{label}.metric", METRIC_ID)
    scope = _string(metric["scope"], f"{label}.scope")
    key = (metric_id, scope)
    thresholds_by_key = {(item["metric"], item["scope"]): item for item in thresholds}
    if key not in thresholds_by_key:
        raise AIAssuranceError(
            "AI_COMPARISON_METRIC_BINDING",
            f"{label} must reference a configured candidate threshold",
        )
    case_ids = _string_list(metric["case_ids"], f"{label}.case_ids", pattern=CASE_ID)
    expected_for_scope = {
        case["id"]
        for case in cases
        if case["id"] in set(comparison_case_ids)
        and (scope == "aggregate" or scope in case["slices"])
    }
    if set(case_ids) != expected_for_scope or set(case_ids) != set(
        thresholds_by_key[key]["case_ids"]
    ):
        raise AIAssuranceError(
            "AI_COMPARISON_METRIC_CASES",
            f"{label}.case_ids must exactly bind the comparable cases and candidate metric",
        )
    sample_mode, sample_count = _validate_sample_requirement(
        metric["sample_count_mode"], metric["sample_count"], label
    )
    threshold = thresholds_by_key[key]
    if (sample_mode, sample_count) != (
        threshold["sample_count_mode"],
        threshold["sample_count"],
    ):
        raise AIAssuranceError(
            "AI_COMPARISON_METRIC_SAMPLES",
            f"{label} must use the candidate threshold's exact sample requirement",
        )
    direction = _string(metric["direction"], f"{label}.direction")
    if direction not in REGRESSION_DIRECTIONS:
        raise AIAssuranceError(
            "AI_COMPARISON_DIRECTION",
            f"{label}.direction must be one of {sorted(REGRESSION_DIRECTIONS)}",
        )
    max_regression = _unit_interval(metric["max_regression"], f"{label}.max_regression")
    return {
        "metric": metric_id,
        "scope": scope,
        "case_ids": list(case_ids),
        "sample_count_mode": sample_mode,
        "sample_count": sample_count,
        "direction": direction,
        "max_regression": max_regression,
    }


def _validate_comparison_policies(
    value: Any,
    capabilities: tuple[str, ...],
    components: Mapping[str, Mapping[str, str]],
    cases: Sequence[Mapping[str, Any]],
    thresholds: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise AIAssuranceError("AI_SCHEMA_TYPE", "evaluation.comparison_policies must be an array")
    if "fine_tuning" not in capabilities:
        if value:
            raise AIAssuranceError(
                "AI_COMPARISON_POLICY_UNEXPECTED",
                "evaluation.comparison_policies must be empty without fine_tuning",
            )
        return []
    if not value:
        raise AIAssuranceError(
            "AI_COMPARISON_POLICY_MISSING",
            "fine_tuning requires base-model and production comparison policies",
        )
    fine_tune_case_ids = tuple(
        case["id"] for case in cases if case["requirement"].startswith("finetune_")
    )
    expected_baselines = {
        "base_model": components["fine_tuning"]["base_model_digest"],
        "production": components["fine_tuning"]["production_baseline_digest"],
    }
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw_policy in enumerate(value):
        label = f"evaluation.comparison_policies[{index}]"
        comparison = _expect_mapping(raw_policy, label)
        _exact_keys(
            comparison,
            {"kind", "baseline_digest", "case_ids", "input_manifest_digest", "metrics"},
            label,
        )
        kind = _string(comparison["kind"], f"{label}.kind")
        if kind not in expected_baselines or kind in seen:
            raise AIAssuranceError("AI_COMPARISON_POLICY_SET", f"invalid comparison kind {kind!r}")
        baseline_digest = _digest(comparison["baseline_digest"], f"{label}.baseline_digest")
        if baseline_digest != expected_baselines[kind]:
            raise AIAssuranceError(
                "AI_COMPARISON_POLICY_BASELINE",
                f"{label}.baseline_digest does not match the typed component inventory",
            )
        case_ids = _string_list(comparison["case_ids"], f"{label}.case_ids", pattern=CASE_ID)
        if set(case_ids) != set(fine_tune_case_ids):
            raise AIAssuranceError(
                "AI_COMPARISON_POLICY_CASES",
                f"{label}.case_ids must exactly cover every fine-tuning regression case",
            )
        input_manifest_digest = _digest(
            comparison["input_manifest_digest"], f"{label}.input_manifest_digest"
        )
        expected_manifest = _comparison_input_manifest_digest(cases, case_ids)
        if input_manifest_digest != expected_manifest:
            raise AIAssuranceError(
                "AI_COMPARISON_INPUT_MANIFEST",
                f"{label}.input_manifest_digest does not match the exact case inputs",
            )
        metric_values = comparison["metrics"]
        if not isinstance(metric_values, list) or not metric_values:
            raise AIAssuranceError(
                "AI_COMPARISON_METRIC_MISSING",
                f"{label}.metrics must contain at least one protected regression metric",
            )
        metrics = [
            _validate_comparison_metric_policy(
                item,
                f"{label}.metrics[{metric_index}]",
                case_ids,
                cases,
                thresholds,
            )
            for metric_index, item in enumerate(metric_values)
        ]
        metric_keys = [(item["metric"], item["scope"]) for item in metrics]
        if len(set(metric_keys)) != len(metric_keys):
            raise AIAssuranceError(
                "AI_COMPARISON_METRIC_DUPLICATE",
                f"{label}.metrics contains duplicate metric/scope pairs",
            )
        normalized.append(
            {
                "kind": kind,
                "baseline_digest": baseline_digest,
                "case_ids": list(case_ids),
                "input_manifest_digest": input_manifest_digest,
                "metrics": metrics,
            }
        )
        seen.add(kind)
    if seen != set(expected_baselines):
        raise AIAssuranceError(
            "AI_COMPARISON_POLICY_SET",
            "fine_tuning requires exactly base_model and production comparison policies",
        )
    return normalized


def _validate_true_policy(
    root: Path,
    raw: Mapping[str, Any],
    config_digest: str,
    source_identity: tuple[str, str],
) -> Policy:
    _exact_keys(
        raw,
        {
            "schema_version",
            "product_ai",
            "fail_closed",
            "capabilities",
            "inventory",
            "components",
            "protected_policies",
            "evaluation",
        },
        "policy",
    )
    capabilities = _string_list(raw["capabilities"], "capabilities", allowed=CAPABILITIES)

    inventory = _expect_mapping(raw["inventory"], "inventory")
    _exact_keys(inventory, {"product_id", "repository_id"}, "inventory")
    _materialized_string(inventory["product_id"], "inventory.product_id", IDENTIFIER)
    _materialized_string(inventory["repository_id"], "inventory.repository_id", IDENTIFIER)

    component_table = _expect_mapping(raw["components"], "components")
    _exact_keys(component_table, set(capabilities), "components")
    components = {
        capability: _validate_component(capability, component_table[capability], f"components.{capability}")
        for capability in capabilities
    }

    protected_table = _expect_mapping(raw["protected_policies"], "protected_policies")
    _exact_keys(protected_table, {"evaluation", "provider", "sandbox"}, "protected_policies")
    protected: dict[str, dict[str, str]] = {}
    for name in ("evaluation", "provider", "sandbox"):
        label = f"protected_policies.{name}"
        reference = _expect_mapping(protected_table[name], label)
        _exact_keys(reference, {"path", "sha256"}, label)
        path = _safe_repo_path(_string(reference["path"], f"{label}.path"), prefix=".mergegrounds/policies")
        if PurePosixPath(path).suffix not in {".json", ".toml"}:
            raise AIAssuranceError("AI_POLICY_FORMAT", f"{label}.path must end in .json or .toml", path)
        expected_digest = _digest(reference["sha256"], f"{label}.sha256")
        content, _ = _read_head_bound_control(
            root,
            path,
            MAX_POLICY_BYTES,
            expected_identity=source_identity,
        )
        actual_digest = _sha256(content)
        if actual_digest != expected_digest:
            raise AIAssuranceError(
                "AI_POLICY_DIGEST",
                f"{label} digest mismatch: expected {expected_digest}, got {actual_digest}",
                path,
            )
        protected[name] = {"path": path, "sha256": expected_digest}

    evaluation = _expect_mapping(raw["evaluation"], "evaluation")
    _exact_keys(
        evaluation,
        {
            "report_path",
            "harness_digest",
            "dataset_digest",
            "max_report_age_seconds",
            "authoritative_producers",
            "expected_case_ids",
            "critical_slices",
            "cases",
            "thresholds",
            "comparison_policies",
        },
        "evaluation",
    )
    report_path = _safe_repo_path(
        _string(evaluation["report_path"], "evaluation.report_path"), prefix=".mergegrounds/evidence"
    )
    if PurePosixPath(report_path).suffix != ".json":
        raise AIAssuranceError("AI_REPORT_FORMAT", "evaluation.report_path must end in .json", report_path)
    if report_path == CANONICAL_DECISION_OUTPUT:
        raise AIAssuranceError(
            "AI_REPORT_OUTPUT_COLLISION",
            "evaluation.report_path must not equal the canonical decision output path",
            report_path,
        )
    harness_digest = _digest(evaluation["harness_digest"], "evaluation.harness_digest")
    dataset_digest = _digest(evaluation["dataset_digest"], "evaluation.dataset_digest")
    max_age = _strict_int(
        evaluation["max_report_age_seconds"],
        "evaluation.max_report_age_seconds",
        minimum=1,
        maximum=31 * 24 * 60 * 60,
    )
    authoritative_producers = _validate_authoritative_producers(
        evaluation["authoritative_producers"]
    )
    expected_ids = _materialized_string_list(
        evaluation["expected_case_ids"], "evaluation.expected_case_ids", pattern=CASE_ID
    )
    critical_slices = _materialized_string_list(
        evaluation["critical_slices"], "evaluation.critical_slices", pattern=SLICE_ID
    )
    case_values = evaluation["cases"]
    if not isinstance(case_values, list) or not case_values:
        raise AIAssuranceError("AI_SCHEMA_EMPTY", "evaluation.cases must be a non-empty array of tables")
    cases = [_validate_case(value, index, capabilities) for index, value in enumerate(case_values)]
    case_ids = [case["id"] for case in cases]
    if len(set(case_ids)) != len(case_ids):
        raise AIAssuranceError("AI_CASE_DUPLICATE", "evaluation.cases contains duplicate IDs")
    if set(case_ids) != set(expected_ids):
        raise AIAssuranceError(
            "AI_CASE_MANIFEST",
            "evaluation.expected_case_ids must exactly equal evaluation.cases IDs",
        )
    represented_classes = {case["class"] for case in cases}
    if represented_classes != CASE_CLASSES:
        raise AIAssuranceError(
            "AI_CASE_CLASSES_INCOMPLETE",
            f"evaluation.cases must cover every case class; missing={sorted(CASE_CLASSES - represented_classes)}",
        )
    all_slices = {item for case in cases for item in case["slices"]}
    if not set(critical_slices).issubset(all_slices):
        raise AIAssuranceError("AI_CRITICAL_SLICE_MISSING", "every critical slice must be represented by a case")
    for capability in capabilities:
        for requirement in REQUIRED_REQUIREMENTS[capability]:
            matching = [case for case in cases if case["requirement"] == requirement]
            if not matching:
                raise AIAssuranceError(
                    "AI_REQUIRED_CASE_MISSING",
                    f"capability {capability!r} requires a {requirement!r} case",
                )
            if not any(case["critical"] and set(case["slices"]) & set(critical_slices) for case in matching):
                raise AIAssuranceError(
                    "AI_REQUIRED_CASE_NOT_CRITICAL",
                    f"requirement {requirement!r} needs a critical case in a critical slice",
                )

    threshold_values = evaluation["thresholds"]
    if not isinstance(threshold_values, list) or not threshold_values:
        raise AIAssuranceError("AI_SCHEMA_EMPTY", "evaluation.thresholds must be a non-empty array of tables")
    thresholds = [
        _validate_threshold(value, index, critical_slices, cases)
        for index, value in enumerate(threshold_values)
    ]
    threshold_keys = [(item["metric"], item["scope"]) for item in thresholds]
    if len(set(threshold_keys)) != len(threshold_keys):
        raise AIAssuranceError("AI_THRESHOLD_DUPLICATE", "metric/scope threshold pairs must be unique")
    scopes = {item["scope"] for item in thresholds}
    required_scopes = {"aggregate", *critical_slices}
    if not required_scopes.issubset(scopes):
        raise AIAssuranceError(
            "AI_THRESHOLD_COVERAGE",
            f"thresholds must cover aggregate and every critical slice; missing={sorted(required_scopes - scopes)}",
        )

    comparison_policies = _validate_comparison_policies(
        evaluation["comparison_policies"],
        capabilities,
        components,
        cases,
        thresholds,
    )

    normalized_evaluation: dict[str, Any] = {
        "report_path": report_path,
        "harness_digest": harness_digest,
        "dataset_digest": dataset_digest,
        "max_report_age_seconds": max_age,
        "authoritative_producers": authoritative_producers,
        "expected_case_ids": list(expected_ids),
        "critical_slices": list(critical_slices),
        "cases": cases,
        "thresholds": thresholds,
        "comparison_policies": comparison_policies,
    }
    return Policy(
        root=root,
        raw=raw,
        config_digest=config_digest,
        source_commit=source_identity[0],
        source_tree=source_identity[1],
        product_ai=True,
        capabilities=capabilities,
        components=components,
        protected_policies=protected,
        evaluation=normalized_evaluation,
    )


def load_policy(
    root: str | os.PathLike[str], config_path: str | os.PathLike[str] = CANONICAL_CONFIG
) -> Policy:
    """Load and strictly validate the repository's AI applicability policy."""

    repository = _repository_root(root)
    relative = _safe_repo_path(config_path)
    if relative != CANONICAL_CONFIG:
        raise AIAssuranceError(
            "AI_CONFIG_CANONICAL", f"AI assurance config must be {CANONICAL_CONFIG}", relative
        )
    data, source_identity = _read_head_bound_control(repository, relative, MAX_CONFIG_BYTES)
    text = _decode_utf8(data, relative)
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise AIAssuranceError("AI_TOML_INVALID", f"invalid TOML: {exc}", relative) from exc
    policy = _expect_mapping(raw, "policy")
    for required in ("schema_version", "product_ai", "fail_closed", "capabilities"):
        if required not in policy:
            raise AIAssuranceError("AI_SCHEMA_KEYS", f"policy is missing required key {required!r}")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != SCHEMA_VERSION:
        raise AIAssuranceError("AI_SCHEMA_VERSION", f"schema_version must equal {SCHEMA_VERSION}")
    product_ai = _strict_bool(policy["product_ai"], "product_ai")
    if not _strict_bool(policy["fail_closed"], "fail_closed"):
        raise AIAssuranceError("AI_FAIL_OPEN", "fail_closed must be true")
    config_digest = _sha256(data)
    if not product_ai:
        _exact_keys(policy, {"schema_version", "product_ai", "fail_closed", "capabilities"}, "policy")
        capabilities = _string_list(
            policy["capabilities"], "capabilities", allowed=CAPABILITIES, nonempty=False
        )
        if capabilities:
            raise AIAssuranceError("AI_APPLICABILITY_CONFLICT", "product_ai=false requires capabilities=[]")
        return Policy(
            root=repository,
            raw=policy,
            config_digest=config_digest,
            source_commit=source_identity[0],
            source_tree=source_identity[1],
            product_ai=False,
            capabilities=(),
            components={},
            protected_policies={},
            evaluation=None,
        )
    return _validate_true_policy(repository, policy, config_digest, source_identity)


def case_set_digest(policy: Policy) -> str:
    """Return the deterministic digest bound into reports for the case manifest."""

    if not policy.product_ai or policy.evaluation is None:
        raise AIAssuranceError("AI_NOT_APPLICABLE", "product_ai=false has no evaluation case set")
    material = {
        "expected_case_ids": policy.evaluation["expected_case_ids"],
        "critical_slices": policy.evaluation["critical_slices"],
        "cases": policy.evaluation["cases"],
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return _sha256(encoded)


def render_policy_example(capabilities: Sequence[str] = ("inference",)) -> str:
    """Render a complete, deliberately non-runnable product_ai=true template.

    All-zero digests are explicit placeholders rejected by schema validation.
    The generated document therefore fails closed until every identity, digest,
    case, slice, producer, and threshold has been deliberately materialized.
    """

    selected = tuple(capabilities)
    if not selected or len(set(selected)) != len(selected) or not set(selected).issubset(CAPABILITIES):
        raise AIAssuranceError("AI_EXAMPLE_CAPABILITIES", "example capabilities must be unique and supported")
    placeholder = "sha256:" + "0" * 64
    cases: list[dict[str, Any]] = []
    for capability in selected:
        for requirement in sorted(REQUIRED_REQUIREMENTS[capability]):
            slices = ["replace-critical-slice"]
            if capability == "fine_tuning":
                slices.append("replace-finetune-comparison")
            cases.append(
                {
                    "id": f"replace-{capability.replace('_', '-')}-{requirement.replace('_', '-')}",
                    "class": sorted(REQUIREMENT_ALLOWED_CLASSES[requirement])[0],
                    "requirement": requirement,
                    "capabilities": [capability],
                    "slices": slices,
                    "critical": True,
                    "input_digest": placeholder,
                    "expectation_digest": placeholder,
                    "sample_count_mode": "minimum",
                    "sample_count": 5,
                }
            )
    represented = {case["class"] for case in cases}
    for missing in sorted(CASE_CLASSES - represented):
        cases.append(
            {
                "id": f"replace-product-{missing}",
                "class": missing,
                "requirement": "product_specific",
                "capabilities": [selected[0]],
                "slices": ["replace-critical-slice"],
                "critical": True,
                "input_digest": placeholder,
                "expectation_digest": placeholder,
                "sample_count_mode": "minimum",
                "sample_count": 5,
            }
        )

    def quote(value: str) -> str:
        return json.dumps(value, ensure_ascii=True)

    def strings(values: Sequence[str]) -> str:
        return "[" + ", ".join(quote(value) for value in values) + "]"
    lines = [
        "# Generated fail-closed template. Replace every replace-* identity,",
        "# all-zero digest, case definition, producer, slice, and threshold.",
        f"schema_version = {SCHEMA_VERSION}",
        "product_ai = true",
        "fail_closed = true",
        f"capabilities = {strings(list(selected))}",
        "",
        "[inventory]",
        'product_id = "replace-product-id"',
        'repository_id = "replace-owner/repository"',
    ]
    for capability in selected:
        lines.extend(("", f"[components.{capability}]"))
        for field in COMPONENT_FIELDS[capability]:
            value = f"replace:{capability}:{field}:v1" if field in COMPONENT_ID_FIELDS else placeholder
            lines.append(f"{field} = {quote(value)}")
    for name in ("evaluation", "provider", "sandbox"):
        lines.extend(
            (
                "",
                f"[protected_policies.{name}]",
                f'path = ".mergegrounds/policies/ai-{name}.json"',
                f"sha256 = {quote(placeholder)}",
            )
        )
    lines.extend(
        (
            "",
            "[evaluation]",
            'report_path = ".mergegrounds/evidence/ai-assurance.json"',
            f"harness_digest = {quote(placeholder)}",
            f"dataset_digest = {quote(placeholder)}",
            "max_report_age_seconds = 3600",
            f"expected_case_ids = {strings([case['id'] for case in cases])}",
            "critical_slices = "
            + strings(
                ["replace-critical-slice"]
                + (["replace-finetune-comparison"] if "fine_tuning" in selected else [])
            ),
            *(('comparison_policies = []',) if "fine_tuning" not in selected else ()),
        )
    )
    lines.extend(
        (
            "",
            "[[evaluation.authoritative_producers]]",
            'class = "trusted_execution"',
            'id = "replace-independent-evaluator-v1"',
        )
    )
    for case in cases:
        lines.extend(
            (
                "",
                "[[evaluation.cases]]",
                f"id = {quote(case['id'])}",
                f"class = {quote(case['class'])}",
                f"requirement = {quote(case['requirement'])}",
                f"capabilities = {strings(case['capabilities'])}",
                f"slices = {strings(case['slices'])}",
                "critical = true",
                f"input_digest = {quote(case['input_digest'])}",
                f"expectation_digest = {quote(case['expectation_digest'])}",
                f"sample_count_mode = {quote(case['sample_count_mode'])}",
                f"sample_count = {case['sample_count']}",
            )
        )
    lines.extend(
        (
            "",
            "# Conservative illustrative values, not universal quality claims.",
            "# Replace them with thresholds approved for this product and risk.",
            "[[evaluation.thresholds]]",
            'metric = "replace-product-pass-rate"',
            'scope = "aggregate"',
            'operator = "gte"',
            "value = 1.0",
            f"case_ids = {strings([case['id'] for case in cases])}",
            'sample_count_mode = "minimum"',
            f"sample_count = {sum(case['sample_count'] for case in cases)}",
            "",
            "[[evaluation.thresholds]]",
            'metric = "replace-product-pass-rate"',
            'scope = "replace-critical-slice"',
            'operator = "gte"',
            "value = 1.0",
            f"case_ids = {strings([case['id'] for case in cases])}",
            'sample_count_mode = "minimum"',
            f"sample_count = {sum(case['sample_count'] for case in cases)}",
        )
    )
    if "fine_tuning" in selected:
        fine_cases = [
            case for case in cases if case["requirement"].startswith("finetune_")
        ]
        fine_ids = [case["id"] for case in fine_cases]
        fine_samples = sum(case["sample_count"] for case in fine_cases)
        lines.extend(
            (
                "",
                "[[evaluation.thresholds]]",
                'metric = "replace-product-pass-rate"',
                'scope = "replace-finetune-comparison"',
                'operator = "gte"',
                "value = 1.0",
                f"case_ids = {strings(fine_ids)}",
                'sample_count_mode = "minimum"',
                f"sample_count = {fine_samples}",
            )
        )
        manifest = _comparison_input_manifest_digest(fine_cases, fine_ids)
        for kind in ("base_model", "production"):
            baseline = placeholder
            lines.extend(
                (
                    "",
                    "[[evaluation.comparison_policies]]",
                    f"kind = {quote(kind)}",
                    f"baseline_digest = {quote(baseline)}",
                    f"case_ids = {strings(fine_ids)}",
                    f"input_manifest_digest = {quote(manifest)}",
                    "",
                    "[[evaluation.comparison_policies.metrics]]",
                    'metric = "replace-product-pass-rate"',
                    'scope = "replace-finetune-comparison"',
                    f"case_ids = {strings(fine_ids)}",
                    'sample_count_mode = "minimum"',
                    f"sample_count = {fine_samples}",
                    'direction = "higher_is_better"',
                    "max_regression = 0.0",
                )
            )
    return "\n".join(lines) + "\n"


def _json_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AIAssuranceError("AI_JSON_DUPLICATE_KEY", f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise AIAssuranceError("AI_JSON_NONFINITE", f"non-finite JSON number is forbidden: {value}")


def _validate_json_limits(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise AIAssuranceError("AI_JSON_NODES", f"JSON exceeds {MAX_JSON_NODES} nodes")
        if depth > MAX_JSON_DEPTH:
            raise AIAssuranceError("AI_JSON_DEPTH", f"JSON exceeds depth {MAX_JSON_DEPTH}")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise AIAssuranceError("AI_JSON_STRING", "JSON string exceeds the byte limit")
        elif isinstance(current, dict):
            for key, item in current.items():
                if len(key.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                    raise AIAssuranceError("AI_JSON_STRING", "JSON object key exceeds the byte limit")
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise AIAssuranceError("AI_JSON_NONFINITE", "JSON contains a non-finite number")


def _load_report(
    policy: Policy, report_path: str | os.PathLike[str] | None
) -> tuple[Mapping[str, Any], str]:
    assert policy.evaluation is not None
    configured = policy.evaluation["report_path"]
    selected = configured if report_path is None else _safe_repo_path(report_path)
    if selected != configured:
        raise AIAssuranceError(
            "AI_REPORT_CANONICAL", f"report path must match configured path {configured!r}", selected
        )
    try:
        tracked = subprocess.run(
            ["git", "-C", str(policy.root), "ls-files", "--error-unmatch", "--", selected],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env=_git_environment(),
        )
        ignored = subprocess.run(
            ["git", "-C", str(policy.root), "check-ignore", "-q", "--", selected],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AIAssuranceError(
            "AI_GIT_UNAVAILABLE", f"cannot validate report output isolation: {exc}", selected
        ) from exc
    if tracked.returncode == 0:
        raise AIAssuranceError(
            "AI_REPORT_TRACKED",
            "the mutable evaluation report must not be tracked in the candidate tree",
            selected,
        )
    if ignored.returncode != 0:
        raise AIAssuranceError(
            "AI_REPORT_NOT_IGNORED",
            "the canonical evaluation report must be an ignored evidence output",
            selected,
        )
    data = _read_repo_file(policy.root, selected, MAX_REPORT_BYTES)
    text = _decode_utf8(data, selected)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_constant=_invalid_constant,
        )
    except AIAssuranceError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise AIAssuranceError("AI_JSON_INVALID", f"invalid report JSON: {exc}", selected) from exc
    _validate_json_limits(parsed)
    return _expect_mapping(parsed, "report"), _sha256(data)


def _git_identity(root: Path) -> tuple[str, str]:
    def run(spec: str) -> str:
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--verify", spec],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                env=_git_environment(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AIAssuranceError("AI_GIT_UNAVAILABLE", f"cannot resolve git identity: {exc}") from exc
        value = completed.stdout.strip()
        if completed.returncode != 0 or GIT_OBJECT_ID.fullmatch(value) is None:
            raise AIAssuranceError("AI_GIT_IDENTITY", f"cannot resolve immutable git object {spec!r}")
        return value

    commit = run("HEAD^{commit}")
    tree = run(f"{commit}^{{tree}}")
    if run("HEAD^{commit}") != commit:
        raise AIAssuranceError("AI_GIT_CHANGED", "repository HEAD changed during identity resolution")
    return commit, tree


def _timestamp(value: Any, label: str) -> dt.datetime:
    text = _string(value, label)
    if not text.endswith("Z"):
        raise AIAssuranceError("AI_TIMESTAMP", f"{label} must use UTC Z notation")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise AIAssuranceError("AI_TIMESTAMP", f"{label} is not RFC 3339 UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise AIAssuranceError("AI_TIMESTAMP", f"{label} must be UTC")
    return parsed


def _validate_report_case(
    value: Any, expected: Mapping[str, Any], index: int
) -> dict[str, Any]:
    label = f"report.cases[{index}]"
    case = _expect_mapping(value, label)
    _exact_keys(
        case,
        {
            "id",
            "class",
            "requirement",
            "capabilities",
            "slices",
            "critical",
            "status",
            "attempts",
            "oracle",
            "input_digest",
            "expectation_digest",
            "observations_digest",
            "sample_count",
        },
        label,
    )
    case_id = _string(case["id"], f"{label}.id", CASE_ID)
    if case_id != expected["id"]:
        raise AIAssuranceError("AI_CASE_BINDING", f"{label}.id does not match the expected case")
    for field in ("class", "requirement"):
        if _string(case[field], f"{label}.{field}") != expected[field]:
            raise AIAssuranceError("AI_CASE_BINDING", f"{label}.{field} does not match policy")
    capabilities = _string_list(
        case["capabilities"], f"{label}.capabilities", allowed=set(expected["capabilities"])
    )
    if set(capabilities) != set(expected["capabilities"]):
        raise AIAssuranceError("AI_CASE_BINDING", f"{label}.capabilities does not match policy")
    slices = _string_list(case["slices"], f"{label}.slices", pattern=SLICE_ID)
    if set(slices) != set(expected["slices"]):
        raise AIAssuranceError("AI_CASE_BINDING", f"{label}.slices does not match policy")
    if _strict_bool(case["critical"], f"{label}.critical") != expected["critical"]:
        raise AIAssuranceError("AI_CASE_BINDING", f"{label}.critical does not match policy")
    status_value = _string(case["status"], f"{label}.status")
    if status_value not in TERMINAL_CASE_STATUSES:
        raise AIAssuranceError("AI_CASE_STATUS", f"{label}.status is unsupported")
    if status_value in DENY_CASE_STATUSES:
        raise AIAssuranceError("AI_CASE_FAILED", f"case {case_id!r} has denying status {status_value!r}")
    attempts = _strict_int(case["attempts"], f"{label}.attempts", minimum=1, maximum=1)
    if attempts != 1:  # defensive: maximum above already rejects this
        raise AIAssuranceError("AI_CASE_RETRY", f"case {case_id!r} was retried")
    oracle = _string(case["oracle"], f"{label}.oracle")
    if oracle not in ORACLE_CLASSES:
        raise AIAssuranceError(
            "AI_ORACLE_ADVISORY", f"case {case_id!r} uses a non-authoritative oracle {oracle!r}"
        )
    input_digest = _digest(case["input_digest"], f"{label}.input_digest")
    if input_digest != expected["input_digest"]:
        raise AIAssuranceError("AI_CASE_INPUT_BINDING", f"case {case_id!r} input digest does not match policy")
    expectation_digest = _digest(case["expectation_digest"], f"{label}.expectation_digest")
    if expectation_digest != expected["expectation_digest"]:
        raise AIAssuranceError(
            "AI_CASE_EXPECTATION_BINDING",
            f"case {case_id!r} expected-observation digest does not match policy",
        )
    observations_digest = _digest(case["observations_digest"], f"{label}.observations_digest")
    sample_count = _strict_int(
        case["sample_count"],
        f"{label}.sample_count",
        minimum=1,
        maximum=MAX_SAMPLE_COUNT,
    )
    _enforce_sample_requirement(
        sample_count,
        expected["sample_count_mode"],
        expected["sample_count"],
        f"case {case_id!r}",
    )
    return {
        "id": case_id,
        "status": status_value,
        "slices": slices,
        "input_digest": input_digest,
        "expectation_digest": expectation_digest,
        "observations_digest": observations_digest,
        "sample_count": sample_count,
    }


def _observation_set_digest(
    case_ids: Iterable[str],
    report_cases: Mapping[str, Mapping[str, Any]],
    *,
    role: str = "candidate",
) -> str:
    selected = sorted(set(case_ids))
    material = [
        {
            "id": case_id,
            "input_digest": report_cases[case_id]["input_digest"],
            "expectation_digest": report_cases[case_id]["expectation_digest"],
            "observations_digest": report_cases[case_id]["observations_digest"],
            "sample_count": report_cases[case_id]["sample_count"],
        }
        for case_id in selected
    ]
    return _canonical_digest(
        {"domain": "ai-observation-set/v1", "role": role, "cases": material}
    )


def _metric_key(value: Mapping[str, Any], label: str) -> tuple[str, str]:
    metric = _string(value["metric"], f"{label}.metric", METRIC_ID)
    scope = _string(value["scope"], f"{label}.scope")
    return metric, scope


def _threshold_passes(operator: str, actual: float, expected: float) -> bool:
    if operator == "gte":
        return actual >= expected
    if operator == "lte":
        return actual <= expected
    return math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12)


def _comparison_result_digest(
    role: str,
    kind: str,
    baseline_digest: str,
    input_manifest_digest: str,
    case_ids: Iterable[str],
    case_results: Mapping[str, Mapping[str, Any]],
    metric_results: Mapping[tuple[str, str], Mapping[str, Any]],
) -> str:
    if role not in {"candidate", "baseline"}:
        raise AIAssuranceError("AI_INTERNAL_ROLE", "comparison role must be candidate or baseline")
    cases_material = [
        {
            "id": case_id,
            "input_digest": case_results[case_id]["input_digest"],
            "expectation_digest": case_results[case_id]["expectation_digest"],
            "observations_digest": case_results[case_id][f"{role}_observations_digest"],
            "sample_count": case_results[case_id]["sample_count"],
        }
        for case_id in sorted(set(case_ids))
    ]
    metric_material = [
        {
            "metric": key[0],
            "scope": key[1],
            "value": metric_results[key][f"{role}_value"],
            "case_ids": sorted(metric_results[key]["case_ids"]),
            "sample_count": metric_results[key]["sample_count"],
            "observation_set_digest": metric_results[key][f"{role}_observation_set_digest"],
        }
        for key in sorted(metric_results)
    ]
    return _canonical_digest(
        {
            "domain": "ai-finetune-comparison-result/v1",
            "role": role,
            "kind": kind,
            "baseline_digest": baseline_digest,
            "input_manifest_digest": input_manifest_digest,
            "cases": cases_material,
            "metrics": metric_material,
        }
    )


def _comparison_binding_digest(
    *,
    kind: str,
    baseline_digest: str,
    input_manifest_digest: str,
    candidate_report_digest: str,
    baseline_report_digest: str,
    candidate_result_digest: str,
    baseline_result_digest: str,
) -> str:
    return _canonical_digest(
        {
            "domain": "ai-finetune-comparison-binding/v1",
            "kind": kind,
            "baseline_digest": baseline_digest,
            "input_manifest_digest": input_manifest_digest,
            "candidate_report_digest": candidate_report_digest,
            "baseline_report_digest": baseline_report_digest,
            "candidate_result_digest": candidate_result_digest,
            "baseline_result_digest": baseline_result_digest,
        }
    )


def _validate_report(policy: Policy, report: Mapping[str, Any], now: dt.datetime) -> None:
    assert policy.evaluation is not None
    evaluation = policy.evaluation
    _exact_keys(
        report,
        {
            "schema_version",
            "generated_at",
            "completeness",
            "producer",
            "subject",
            "cases",
            "slice_results",
            "metrics",
            "summary",
            "comparisons",
        },
        "report",
    )
    if type(report["schema_version"]) is not int or report["schema_version"] != SCHEMA_VERSION:
        raise AIAssuranceError("AI_REPORT_VERSION", f"report.schema_version must equal {SCHEMA_VERSION}")
    if _string(report["completeness"], "report.completeness") != "complete":
        raise AIAssuranceError("AI_REPORT_INCOMPLETE", "report.completeness must be 'complete'")
    generated_at = _timestamp(report["generated_at"], "report.generated_at")
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    now = now.astimezone(dt.timezone.utc)
    age = (now - generated_at).total_seconds()
    if age < -MAX_FUTURE_SKEW_SECONDS:
        raise AIAssuranceError("AI_REPORT_FUTURE", "report timestamp is too far in the future")
    if age > evaluation["max_report_age_seconds"]:
        raise AIAssuranceError("AI_REPORT_STALE", "report is stale under project policy")

    producer = _expect_mapping(report["producer"], "report.producer")
    _exact_keys(producer, {"class", "id", "run_id", "attestation_digest"}, "report.producer")
    producer_class = _string(producer["class"], "report.producer.class")
    if producer_class not in ALL_PRODUCERS:
        raise AIAssuranceError("AI_PRODUCER_CLASS", "report producer class is unsupported")
    if producer_class in ADVISORY_PRODUCERS:
        raise AIAssuranceError(
            "AI_PRODUCER_ADVISORY",
            f"producer class {producer_class!r} is advisory and cannot authorize admission",
        )
    producer_id = _string(producer["id"], "report.producer.id", IDENTIFIER)
    authorized_pairs = {
        (item["class"], item["id"]) for item in evaluation["authoritative_producers"]
    }
    if (producer_class, producer_id) not in authorized_pairs:
        raise AIAssuranceError(
            "AI_PRODUCER_UNAUTHORIZED",
            "producer class/ID pair is not allowed by project policy",
        )
    _string(producer["run_id"], "report.producer.run_id", IDENTIFIER)
    _digest(producer["attestation_digest"], "report.producer.attestation_digest")

    subject = _expect_mapping(report["subject"], "report.subject")
    _exact_keys(
        subject,
        {
            "source_commit",
            "source_tree",
            "config_digest",
            "harness_digest",
            "dataset_digest",
            "case_set_digest",
            "components",
            "protected_policies",
        },
        "report.subject",
    )
    source_commit = _string(subject["source_commit"], "report.subject.source_commit", GIT_OBJECT_ID)
    source_tree = _string(subject["source_tree"], "report.subject.source_tree", GIT_OBJECT_ID)
    actual_commit, actual_tree = _git_identity(policy.root)
    if (actual_commit, actual_tree) != (policy.source_commit, policy.source_tree):
        raise AIAssuranceError("AI_GIT_CHANGED", "repository HEAD changed after policy loading")
    if (source_commit, source_tree) != (policy.source_commit, policy.source_tree):
        raise AIAssuranceError("AI_SOURCE_BINDING", "report does not match repository HEAD commit and tree")
    expected_subject_digests = {
        "config_digest": policy.config_digest,
        "harness_digest": evaluation["harness_digest"],
        "dataset_digest": evaluation["dataset_digest"],
        "case_set_digest": case_set_digest(policy),
    }
    for field, expected in expected_subject_digests.items():
        if _digest(subject[field], f"report.subject.{field}") != expected:
            raise AIAssuranceError("AI_SUBJECT_BINDING", f"report.subject.{field} does not match policy")
    report_components = _expect_mapping(subject["components"], "report.subject.components")
    _exact_keys(report_components, set(policy.capabilities), "report.subject.components")
    for capability in policy.capabilities:
        component = _validate_component(
            capability,
            report_components[capability],
            f"report.subject.components.{capability}",
        )
        if component != policy.components[capability]:
            raise AIAssuranceError(
                "AI_COMPONENT_BINDING",
                f"report component {capability!r} does not exactly match the typed inventory",
            )
    report_policies = _expect_mapping(subject["protected_policies"], "report.subject.protected_policies")
    _exact_keys(report_policies, set(policy.protected_policies), "report.subject.protected_policies")
    for name, reference in policy.protected_policies.items():
        if _digest(report_policies[name], f"report.subject.protected_policies.{name}") != reference["sha256"]:
            raise AIAssuranceError("AI_POLICY_BINDING", f"report does not bind protected {name} policy")

    case_values = report["cases"]
    if not isinstance(case_values, list) or not case_values:
        raise AIAssuranceError("AI_REPORT_ZERO_CASES", "report.cases must contain every expected case")
    report_case_ids: list[str] = []
    report_cases_by_id: dict[str, dict[str, Any]] = {}
    expected_by_id = {case["id"]: case for case in evaluation["cases"]}
    for index, value in enumerate(case_values):
        mapping = _expect_mapping(value, f"report.cases[{index}]")
        raw_id = mapping.get("id")
        if not isinstance(raw_id, str) or raw_id not in expected_by_id:
            raise AIAssuranceError("AI_CASE_SET", f"unexpected or invalid report case ID at index {index}")
        normalized_case = _validate_report_case(mapping, expected_by_id[raw_id], index)
        case_id = normalized_case["id"]
        report_case_ids.append(case_id)
        report_cases_by_id[case_id] = normalized_case
    if len(set(report_case_ids)) != len(report_case_ids):
        raise AIAssuranceError("AI_CASE_DUPLICATE", "report contains duplicate case IDs")
    if set(report_case_ids) != set(evaluation["expected_case_ids"]):
        raise AIAssuranceError("AI_CASE_SET", "report case set does not exactly match expected case IDs")

    all_slices = sorted(
        {item for case in report_cases_by_id.values() for item in case["slices"]}
    )
    slice_values = report["slice_results"]
    if not isinstance(slice_values, list):
        raise AIAssuranceError("AI_SCHEMA_TYPE", "report.slice_results must be an array")
    seen_slices: list[str] = []
    for index, value in enumerate(slice_values):
        label = f"report.slice_results[{index}]"
        result = _expect_mapping(value, label)
        _exact_keys(
            result,
            {"id", "status", "case_ids", "sample_count", "observation_set_digest"},
            label,
        )
        slice_id = _string(result["id"], f"{label}.id", SLICE_ID)
        status_value = _string(result["status"], f"{label}.status")
        if status_value != "passed":
            raise AIAssuranceError(
                "AI_CRITICAL_SLICE_FAILED" if slice_id in evaluation["critical_slices"] else "AI_SLICE_FAILED",
                f"slice {slice_id!r} did not pass",
            )
        case_ids = _string_list(result["case_ids"], f"{label}.case_ids", pattern=CASE_ID)
        expected_slice_cases = {
            case_id
            for case_id, case in report_cases_by_id.items()
            if slice_id in case["slices"]
        }
        if set(case_ids) != expected_slice_cases:
            raise AIAssuranceError("AI_SLICE_BINDING", f"slice {slice_id!r} has an incorrect case set")
        sample_count = _strict_int(
            result["sample_count"],
            f"{label}.sample_count",
            minimum=1,
            maximum=MAX_SAMPLE_COUNT,
        )
        expected_sample_count = sum(
            report_cases_by_id[case_id]["sample_count"] for case_id in expected_slice_cases
        )
        if sample_count != expected_sample_count:
            raise AIAssuranceError(
                "AI_SLICE_SAMPLE_BINDING",
                f"slice {slice_id!r} sample_count must equal its exact case observations",
            )
        observed_digest = _digest(
            result["observation_set_digest"], f"{label}.observation_set_digest"
        )
        expected_observed_digest = _observation_set_digest(
            expected_slice_cases, report_cases_by_id
        )
        if observed_digest != expected_observed_digest:
            raise AIAssuranceError(
                "AI_SLICE_OBSERVATION_BINDING",
                f"slice {slice_id!r} does not bind its exact case observations",
            )
        seen_slices.append(slice_id)
    if len(set(seen_slices)) != len(seen_slices) or set(seen_slices) != set(all_slices):
        raise AIAssuranceError("AI_SLICE_SET", "slice result set must exactly cover all case slices")

    metric_values = report["metrics"]
    if not isinstance(metric_values, list):
        raise AIAssuranceError("AI_SCHEMA_TYPE", "report.metrics must be an array")
    thresholds = {
        (item["metric"], item["scope"]): item for item in evaluation["thresholds"]
    }
    seen_metrics: list[tuple[str, str]] = []
    report_metrics_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for index, value in enumerate(metric_values):
        label = f"report.metrics[{index}]"
        metric = _expect_mapping(value, label)
        _exact_keys(
            metric,
            {
                "metric",
                "scope",
                "value",
                "numerator",
                "denominator",
                "case_ids",
                "sample_count",
                "observation_set_digest",
            },
            label,
        )
        key = _metric_key(metric, label)
        if key not in thresholds:
            raise AIAssuranceError("AI_METRIC_SET", f"unexpected metric/scope pair {key!r}")
        threshold = thresholds[key]
        case_ids = _string_list(metric["case_ids"], f"{label}.case_ids", pattern=CASE_ID)
        if set(case_ids) != set(threshold["case_ids"]):
            raise AIAssuranceError(
                "AI_METRIC_CASE_BINDING",
                f"metric {key!r} does not bind the exact policy case membership",
            )
        sample_count = _strict_int(
            metric["sample_count"],
            f"{label}.sample_count",
            minimum=1,
            maximum=MAX_SAMPLE_COUNT,
        )
        expected_observed_count = sum(
            report_cases_by_id[case_id]["sample_count"] for case_id in case_ids
        )
        if sample_count != expected_observed_count:
            raise AIAssuranceError(
                "AI_METRIC_SAMPLE_BINDING",
                f"metric {key!r} sample_count does not equal its exact case observations",
            )
        _enforce_sample_requirement(
            sample_count,
            threshold["sample_count_mode"],
            threshold["sample_count"],
            f"metric {key!r}",
        )
        observed_digest = _digest(
            metric["observation_set_digest"], f"{label}.observation_set_digest"
        )
        if observed_digest != _observation_set_digest(case_ids, report_cases_by_id):
            raise AIAssuranceError(
                "AI_METRIC_OBSERVATION_BINDING",
                f"metric {key!r} does not bind its exact case observations",
            )
        actual = _unit_interval(metric["value"], f"{label}.value")
        numerator = _finite_number(metric["numerator"], f"{label}.numerator")
        denominator = _finite_number(metric["denominator"], f"{label}.denominator")
        if numerator < 0 or denominator <= 0:
            raise AIAssuranceError("AI_METRIC_DENOMINATOR", f"{label} has an invalid numerator/denominator")
        if numerator > denominator:
            raise AIAssuranceError(
                "AI_METRIC_RANGE",
                f"{label}.numerator must not exceed its denominator",
            )
        ratio = numerator / denominator
        if not math.isclose(actual, ratio, rel_tol=1e-12, abs_tol=1e-12):
            raise AIAssuranceError("AI_METRIC_ARITHMETIC", f"{label}.value does not equal numerator/denominator")
        if not math.isclose(denominator, float(sample_count), rel_tol=0.0, abs_tol=0.0):
            raise AIAssuranceError(
                "AI_METRIC_DENOMINATOR_BINDING",
                f"{label}.denominator must equal the exact bound sample_count",
            )
        if not _threshold_passes(threshold["operator"], actual, threshold["value"]):
            code = "AI_CRITICAL_THRESHOLD" if key[1] in evaluation["critical_slices"] else "AI_THRESHOLD"
            raise AIAssuranceError(code, f"metric {key!r} violates project policy")
        report_metrics_by_key[key] = {
            "metric": key[0],
            "scope": key[1],
            "value": actual,
            "case_ids": list(case_ids),
            "sample_count": sample_count,
            "observation_set_digest": observed_digest,
        }
        seen_metrics.append(key)
    if len(set(seen_metrics)) != len(seen_metrics) or set(seen_metrics) != set(thresholds):
        raise AIAssuranceError("AI_METRIC_SET", "report metrics must exactly match configured thresholds")

    summary = _expect_mapping(report["summary"], "report.summary")
    _exact_keys(
        summary,
        {"total", "passed", "failed", "skipped", "errors", "partial", "stale", "inconclusive", "retries"},
        "report.summary",
    )
    total = len(report_case_ids)
    expected_summary = {
        "total": total,
        "passed": total,
        "failed": 0,
        "skipped": 0,
        "errors": 0,
        "partial": 0,
        "stale": 0,
        "inconclusive": 0,
        "retries": 0,
    }
    for field, expected in expected_summary.items():
        if _strict_int(summary[field], f"report.summary.{field}", minimum=0) != expected:
            raise AIAssuranceError("AI_SUMMARY_INVALID", f"report.summary.{field} must equal {expected}")

    comparisons = report["comparisons"]
    if not isinstance(comparisons, list):
        raise AIAssuranceError("AI_SCHEMA_TYPE", "report.comparisons must be an array")
    if "fine_tuning" not in policy.capabilities:
        if comparisons:
            raise AIAssuranceError("AI_COMPARISON_UNEXPECTED", "comparisons must be empty without fine_tuning")
        return
    expected_comparisons = {
        item["kind"]: item for item in evaluation["comparison_policies"]
    }
    seen_comparisons: set[str] = set()
    seen_baseline_report_digests: set[str] = set()
    seen_baseline_result_digests: set[str] = set()
    seen_baseline_payloads: dict[str, tuple[str, str]] = {}
    for index, value in enumerate(comparisons):
        label = f"report.comparisons[{index}]"
        comparison = _expect_mapping(value, label)
        _exact_keys(
            comparison,
            {
                "kind",
                "baseline_digest",
                "status",
                "case_ids",
                "input_manifest_digest",
                "candidate_report_digest",
                "baseline_report_digest",
                "candidate_result_digest",
                "baseline_result_digest",
                "comparison_binding_digest",
                "case_results",
                "metric_deltas",
            },
            label,
        )
        kind = _string(comparison["kind"], f"{label}.kind")
        if kind not in expected_comparisons or kind in seen_comparisons:
            raise AIAssuranceError("AI_COMPARISON_SET", f"invalid comparison kind {kind!r}")
        expected_comparison = expected_comparisons[kind]
        if (
            _digest(comparison["baseline_digest"], f"{label}.baseline_digest")
            != expected_comparison["baseline_digest"]
        ):
            raise AIAssuranceError("AI_COMPARISON_BINDING", f"comparison {kind!r} has the wrong baseline")
        if _string(comparison["status"], f"{label}.status") != "passed":
            raise AIAssuranceError("AI_COMPARISON_FAILED", f"comparison {kind!r} did not pass")
        ids = _string_list(comparison["case_ids"], f"{label}.case_ids", pattern=CASE_ID)
        if set(ids) != set(expected_comparison["case_ids"]):
            raise AIAssuranceError(
                "AI_COMPARISON_CASES",
                f"comparison {kind!r} lacks the exact broad regression case set",
            )
        input_manifest_digest = _digest(
            comparison["input_manifest_digest"], f"{label}.input_manifest_digest"
        )
        if input_manifest_digest != expected_comparison["input_manifest_digest"]:
            raise AIAssuranceError(
                "AI_COMPARISON_INPUT_MANIFEST",
                f"comparison {kind!r} does not bind the protected input manifest",
            )
        digest_fields = {
            field: _digest(comparison[field], f"{label}.{field}")
            for field in (
                "candidate_report_digest",
                "baseline_report_digest",
                "candidate_result_digest",
                "baseline_result_digest",
            )
        }
        if len(set(digest_fields.values())) != len(digest_fields):
            raise AIAssuranceError(
                "AI_COMPARISON_DIGEST_ALIAS",
                f"comparison {kind!r} candidate/baseline result/report digests must be distinct",
            )
        if digest_fields["baseline_report_digest"] in seen_baseline_report_digests:
            raise AIAssuranceError(
                "AI_COMPARISON_CROSS_KIND_REPLAY",
                "a baseline report digest cannot be reused across comparison kinds",
            )
        if digest_fields["baseline_result_digest"] in seen_baseline_result_digests:
            raise AIAssuranceError(
                "AI_COMPARISON_CROSS_KIND_REPLAY",
                "a baseline result digest cannot be reused across comparison kinds",
            )

        case_result_values = comparison["case_results"]
        if not isinstance(case_result_values, list) or not case_result_values:
            raise AIAssuranceError(
                "AI_COMPARISON_CASE_RESULTS",
                f"comparison {kind!r} must include every comparable case result",
            )
        normalized_case_results: dict[str, dict[str, Any]] = {}
        for case_index, case_value in enumerate(case_result_values):
            case_label = f"{label}.case_results[{case_index}]"
            result = _expect_mapping(case_value, case_label)
            _exact_keys(
                result,
                {
                    "id",
                    "candidate_input_digest",
                    "baseline_input_digest",
                    "expectation_digest",
                    "candidate_observations_digest",
                    "baseline_observations_digest",
                    "candidate_sample_count",
                    "baseline_sample_count",
                },
                case_label,
            )
            case_id = _string(result["id"], f"{case_label}.id", CASE_ID)
            if case_id not in set(ids) or case_id in normalized_case_results:
                raise AIAssuranceError(
                    "AI_COMPARISON_CASE_RESULTS",
                    f"comparison {kind!r} has an unexpected or duplicate case result {case_id!r}",
                )
            candidate_input = _digest(
                result["candidate_input_digest"], f"{case_label}.candidate_input_digest"
            )
            baseline_input = _digest(
                result["baseline_input_digest"], f"{case_label}.baseline_input_digest"
            )
            expected_case = expected_by_id[case_id]
            if candidate_input != baseline_input or candidate_input != expected_case["input_digest"]:
                raise AIAssuranceError(
                    "AI_COMPARISON_INPUT_EQUIVALENCE",
                    f"comparison {kind!r} case {case_id!r} did not use the exact same protected input",
                )
            expectation_digest = _digest(
                result["expectation_digest"], f"{case_label}.expectation_digest"
            )
            if expectation_digest != expected_case["expectation_digest"]:
                raise AIAssuranceError(
                    "AI_COMPARISON_EXPECTATION_BINDING",
                    f"comparison {kind!r} case {case_id!r} uses a different oracle expectation",
                )
            candidate_observations = _digest(
                result["candidate_observations_digest"],
                f"{case_label}.candidate_observations_digest",
            )
            baseline_observations = _digest(
                result["baseline_observations_digest"],
                f"{case_label}.baseline_observations_digest",
            )
            if candidate_observations != report_cases_by_id[case_id]["observations_digest"]:
                raise AIAssuranceError(
                    "AI_COMPARISON_CANDIDATE_BINDING",
                    f"comparison {kind!r} case {case_id!r} is not bound to the candidate report",
                )
            candidate_samples = _strict_int(
                result["candidate_sample_count"],
                f"{case_label}.candidate_sample_count",
                minimum=1,
                maximum=MAX_SAMPLE_COUNT,
            )
            baseline_samples = _strict_int(
                result["baseline_sample_count"],
                f"{case_label}.baseline_sample_count",
                minimum=1,
                maximum=MAX_SAMPLE_COUNT,
            )
            if (
                candidate_samples != baseline_samples
                or candidate_samples != report_cases_by_id[case_id]["sample_count"]
            ):
                raise AIAssuranceError(
                    "AI_COMPARISON_SAMPLE_EQUIVALENCE",
                    f"comparison {kind!r} case {case_id!r} used unequal samples",
                )
            normalized_case_results[case_id] = {
                "id": case_id,
                "input_digest": candidate_input,
                "expectation_digest": expectation_digest,
                "candidate_observations_digest": candidate_observations,
                "baseline_observations_digest": baseline_observations,
                "sample_count": candidate_samples,
            }
        if set(normalized_case_results) != set(ids):
            raise AIAssuranceError(
                "AI_COMPARISON_CASE_RESULTS",
                f"comparison {kind!r} case result set is incomplete",
            )

        metric_delta_values = comparison["metric_deltas"]
        if not isinstance(metric_delta_values, list) or not metric_delta_values:
            raise AIAssuranceError(
                "AI_COMPARISON_METRIC_SET",
                f"comparison {kind!r} must contain protected per-metric deltas",
            )
        expected_metric_policies = {
            (item["metric"], item["scope"]): item
            for item in expected_comparison["metrics"]
        }
        normalized_metric_results: dict[tuple[str, str], dict[str, Any]] = {}
        for metric_index, metric_value in enumerate(metric_delta_values):
            metric_label = f"{label}.metric_deltas[{metric_index}]"
            delta_result = _expect_mapping(metric_value, metric_label)
            _exact_keys(
                delta_result,
                {
                    "metric",
                    "scope",
                    "case_ids",
                    "sample_count",
                    "candidate_observation_set_digest",
                    "baseline_observation_set_digest",
                    "candidate_value",
                    "baseline_value",
                    "delta",
                    "regression",
                },
                metric_label,
            )
            key = _metric_key(delta_result, metric_label)
            if key not in expected_metric_policies or key in normalized_metric_results:
                raise AIAssuranceError(
                    "AI_COMPARISON_METRIC_SET",
                    f"comparison {kind!r} has an unexpected or duplicate metric {key!r}",
                )
            metric_policy = expected_metric_policies[key]
            metric_case_ids = _string_list(
                delta_result["case_ids"], f"{metric_label}.case_ids", pattern=CASE_ID
            )
            if set(metric_case_ids) != set(metric_policy["case_ids"]):
                raise AIAssuranceError(
                    "AI_COMPARISON_METRIC_CASES",
                    f"comparison metric {key!r} does not bind its exact cases",
                )
            sample_count = _strict_int(
                delta_result["sample_count"],
                f"{metric_label}.sample_count",
                minimum=1,
                maximum=MAX_SAMPLE_COUNT,
            )
            expected_samples = sum(
                normalized_case_results[case_id]["sample_count"] for case_id in metric_case_ids
            )
            if sample_count != expected_samples:
                raise AIAssuranceError(
                    "AI_COMPARISON_METRIC_SAMPLES",
                    f"comparison metric {key!r} sample count does not match exact case results",
                )
            _enforce_sample_requirement(
                sample_count,
                metric_policy["sample_count_mode"],
                metric_policy["sample_count"],
                f"comparison metric {key!r}",
            )
            candidate_observation_set = _digest(
                delta_result["candidate_observation_set_digest"],
                f"{metric_label}.candidate_observation_set_digest",
            )
            expected_candidate_observation_set = _observation_set_digest(
                metric_case_ids, report_cases_by_id, role="candidate"
            )
            if candidate_observation_set != expected_candidate_observation_set:
                raise AIAssuranceError(
                    "AI_COMPARISON_CANDIDATE_BINDING",
                    f"comparison metric {key!r} is not bound to candidate observations",
                )
            baseline_case_view = {
                case_id: {
                    "input_digest": normalized_case_results[case_id]["input_digest"],
                    "expectation_digest": normalized_case_results[case_id]["expectation_digest"],
                    "observations_digest": normalized_case_results[case_id][
                        "baseline_observations_digest"
                    ],
                    "sample_count": normalized_case_results[case_id]["sample_count"],
                }
                for case_id in metric_case_ids
            }
            baseline_observation_set = _digest(
                delta_result["baseline_observation_set_digest"],
                f"{metric_label}.baseline_observation_set_digest",
            )
            expected_baseline_observation_set = _observation_set_digest(
                metric_case_ids, baseline_case_view, role="baseline"
            )
            if baseline_observation_set != expected_baseline_observation_set:
                raise AIAssuranceError(
                    "AI_COMPARISON_BASELINE_BINDING",
                    f"comparison metric {key!r} is not bound to baseline observations",
                )
            candidate_value = _unit_interval(
                delta_result["candidate_value"], f"{metric_label}.candidate_value"
            )
            baseline_value = _unit_interval(
                delta_result["baseline_value"], f"{metric_label}.baseline_value"
            )
            if not math.isclose(
                candidate_value,
                report_metrics_by_key[key]["value"],
                rel_tol=1e-12,
                abs_tol=1e-12,
            ):
                raise AIAssuranceError(
                    "AI_COMPARISON_CANDIDATE_BINDING",
                    f"comparison metric {key!r} candidate value differs from the admitted report",
                )
            delta = _finite_number(delta_result["delta"], f"{metric_label}.delta")
            expected_delta = candidate_value - baseline_value
            if not math.isclose(delta, expected_delta, rel_tol=1e-12, abs_tol=1e-12):
                raise AIAssuranceError(
                    "AI_COMPARISON_DELTA_ARITHMETIC",
                    f"comparison metric {key!r} delta is inconsistent",
                )
            expected_regression = max(
                0.0,
                baseline_value - candidate_value
                if metric_policy["direction"] == "higher_is_better"
                else candidate_value - baseline_value,
            )
            regression = _unit_interval(
                delta_result["regression"], f"{metric_label}.regression"
            )
            if not math.isclose(
                regression, expected_regression, rel_tol=1e-12, abs_tol=1e-12
            ):
                raise AIAssuranceError(
                    "AI_COMPARISON_REGRESSION_ARITHMETIC",
                    f"comparison metric {key!r} regression is inconsistent",
                )
            if regression > metric_policy["max_regression"] and not math.isclose(
                regression,
                metric_policy["max_regression"],
                rel_tol=1e-12,
                abs_tol=1e-12,
            ):
                raise AIAssuranceError(
                    "AI_COMPARISON_REGRESSION",
                    f"comparison metric {key!r} exceeds the protected regression budget",
                )
            normalized_metric_results[key] = {
                "metric": key[0],
                "scope": key[1],
                "case_ids": list(metric_case_ids),
                "sample_count": sample_count,
                "candidate_observation_set_digest": candidate_observation_set,
                "baseline_observation_set_digest": baseline_observation_set,
                "candidate_value": candidate_value,
                "baseline_value": baseline_value,
            }
        if set(normalized_metric_results) != set(expected_metric_policies):
            raise AIAssuranceError(
                "AI_COMPARISON_METRIC_SET",
                f"comparison {kind!r} metric delta set is incomplete",
            )

        expected_candidate_result = _comparison_result_digest(
            "candidate",
            kind,
            expected_comparison["baseline_digest"],
            input_manifest_digest,
            ids,
            normalized_case_results,
            normalized_metric_results,
        )
        expected_baseline_result = _comparison_result_digest(
            "baseline",
            kind,
            expected_comparison["baseline_digest"],
            input_manifest_digest,
            ids,
            normalized_case_results,
            normalized_metric_results,
        )
        if digest_fields["candidate_result_digest"] != expected_candidate_result:
            raise AIAssuranceError(
                "AI_COMPARISON_RESULT_BINDING",
                f"comparison {kind!r} candidate result digest is inconsistent",
            )
        if digest_fields["baseline_result_digest"] != expected_baseline_result:
            raise AIAssuranceError(
                "AI_COMPARISON_RESULT_BINDING",
                f"comparison {kind!r} baseline result digest is inconsistent",
            )
        binding_digest = _digest(
            comparison["comparison_binding_digest"], f"{label}.comparison_binding_digest"
        )
        expected_binding_digest = _comparison_binding_digest(
            kind=kind,
            baseline_digest=expected_comparison["baseline_digest"],
            input_manifest_digest=input_manifest_digest,
            candidate_report_digest=digest_fields["candidate_report_digest"],
            baseline_report_digest=digest_fields["baseline_report_digest"],
            candidate_result_digest=digest_fields["candidate_result_digest"],
            baseline_result_digest=digest_fields["baseline_result_digest"],
        )
        if binding_digest != expected_binding_digest:
            raise AIAssuranceError(
                "AI_COMPARISON_ATTESTATION_BINDING",
                f"comparison {kind!r} report/result binding digest is inconsistent",
            )
        baseline_payload_digest = _comparison_result_digest(
            "baseline",
            "cross-kind-payload",
            "sha256:" + "0" * 64,
            input_manifest_digest,
            ids,
            normalized_case_results,
            normalized_metric_results,
        )
        prior_payload = seen_baseline_payloads.get(baseline_payload_digest)
        if (
            prior_payload is not None
            and prior_payload[1] != expected_comparison["baseline_digest"]
        ):
            raise AIAssuranceError(
                "AI_COMPARISON_CROSS_KIND_REPLAY",
                f"comparison {kind!r} reuses baseline observations from {prior_payload[0]!r}",
            )
        seen_baseline_report_digests.add(digest_fields["baseline_report_digest"])
        seen_baseline_result_digests.add(digest_fields["baseline_result_digest"])
        seen_baseline_payloads[baseline_payload_digest] = (
            kind,
            expected_comparison["baseline_digest"],
        )
        seen_comparisons.add(kind)
    if seen_comparisons != set(expected_comparisons):
        raise AIAssuranceError("AI_COMPARISON_SET", "both base-model and production comparisons are required")


def validate_repository_policy(
    root: str | os.PathLike[str], config_path: str | os.PathLike[str] = CANONICAL_CONFIG
) -> Decision:
    """Return a structured local decision for the policy itself."""

    try:
        policy = load_policy(root, config_path)
    except AIAssuranceError as exc:
        return _deny(exc)
    except Exception as exc:  # pragma: no cover - last-resort fail-closed boundary
        return _deny(AIAssuranceError("AI_INTERNAL_ERROR", f"unexpected policy failure: {type(exc).__name__}: {exc}"))
    message = (
        "AI product assurance is explicitly not applicable"
        if not policy.product_ai
        else "AI product assurance policy and protected references are locally valid"
    )
    return Decision(
        decision="allow",
        product_ai=policy.product_ai,
        capabilities=policy.capabilities,
        findings=(Finding("AI_POLICY_VALID", "info", message, CANONICAL_CONFIG),),
        limitations=LOCAL_LIMITATIONS,
        source_commit=policy.source_commit,
        source_tree=policy.source_tree,
        config_digest=policy.config_digest,
        expected_case_set_digest=(case_set_digest(policy) if policy.product_ai else None),
    )


def evaluate_repository(
    root: str | os.PathLike[str],
    config_path: str | os.PathLike[str] = CANONICAL_CONFIG,
    report_path: str | os.PathLike[str] | None = None,
    *,
    now: dt.datetime | None = None,
) -> Decision:
    """Validate the complete conditional AI assurance report, failing closed."""

    try:
        policy = load_policy(root, config_path)
        if not policy.product_ai:
            return Decision(
                decision="allow",
                product_ai=False,
                capabilities=(),
                findings=(
                    Finding(
                        "AI_NOT_APPLICABLE",
                        "info",
                        "product_ai=false is explicit; no AI evaluation report is materialized",
                        CANONICAL_CONFIG,
                    ),
                ),
                limitations=LOCAL_LIMITATIONS,
                source_commit=policy.source_commit,
                source_tree=policy.source_tree,
                config_digest=policy.config_digest,
            )
        report, report_digest = _load_report(policy, report_path)
        _validate_report(policy, report, now or dt.datetime.now(dt.timezone.utc))
    except AIAssuranceError as exc:
        decision = _deny(exc)
        try:
            if "policy" in locals():
                return dataclasses.replace(
                    decision,
                    product_ai=policy.product_ai,
                    capabilities=policy.capabilities,
                    report_path=(policy.evaluation or {}).get("report_path"),
                    source_commit=policy.source_commit,
                    source_tree=policy.source_tree,
                    config_digest=policy.config_digest,
                    report_digest=(report_digest if "report_digest" in locals() else None),
                    expected_case_set_digest=(
                        case_set_digest(policy) if policy.product_ai else None
                    ),
                )
        except Exception:
            pass
        return decision
    except Exception as exc:  # pragma: no cover - last-resort fail-closed boundary
        return _deny(
            AIAssuranceError(
                "AI_INTERNAL_ERROR",
                f"unexpected evaluation failure: {type(exc).__name__}: {exc}",
            )
        )
    assert policy.evaluation is not None
    return Decision(
        decision="allow",
        product_ai=True,
        capabilities=policy.capabilities,
        report_path=policy.evaluation["report_path"],
        source_commit=policy.source_commit,
        source_tree=policy.source_tree,
        config_digest=policy.config_digest,
        report_digest=report_digest,
        expected_case_set_digest=case_set_digest(policy),
        findings=(
            Finding(
                "AI_REPORT_CONFORMANT",
                "info",
                "the exact local report, subject, cases, slices, and project thresholds conform",
                policy.evaluation["report_path"],
            ),
            Finding(
                "AI_EXTERNAL_TRUST_REQUIRED",
                "warning",
                "admission remains dependent on protected CI identity and external producer/provider/holdout trust",
            ),
        ),
        limitations=LOCAL_LIMITATIONS,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root (must not be a symlink)")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("validate-policy", help="validate applicability, inventory, and protected policy refs")
    evaluate = subcommands.add_parser("evaluate", help="validate the configured AI evaluation report")
    evaluate.add_argument("--report", help="must exactly match evaluation.report_path")
    evaluate.add_argument(
        "--output",
        help=f"atomically write the decision (must be {CANONICAL_DECISION_OUTPUT})",
    )
    subcommands.add_parser("case-set-digest", help="print the canonical expected-case digest")
    example = subcommands.add_parser(
        "print-example", help="print a complete fail-closed product_ai=true TOML template"
    )
    example.add_argument(
        "--capability",
        action="append",
        choices=sorted(CAPABILITIES),
        help="repeat to select capabilities; defaults to inference",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "validate-policy":
        decision = validate_repository_policy(args.root)
        print(json.dumps(decision.as_dict(), sort_keys=True, indent=2))
        return 0 if decision.allowed else 1
    if args.command == "evaluate":
        decision = evaluate_repository(args.root, report_path=args.report)
        rendered = (json.dumps(decision.as_dict(), sort_keys=True, indent=2) + "\n").encode("utf-8")
        if args.output:
            try:
                _write_decision_output(args.root, args.output, rendered)
            except AIAssuranceError as exc:
                print(json.dumps(_deny(exc).as_dict(), sort_keys=True, indent=2), file=sys.stderr)
                return 1
        else:
            print(rendered.decode("utf-8"), end="")
        return 0 if decision.allowed else 1
    if args.command == "print-example":
        print(render_policy_example(tuple(args.capability or ("inference",))), end="")
        return 0
    try:
        print(case_set_digest(load_policy(args.root)))
        return 0
    except AIAssuranceError as exc:
        print(json.dumps(_deny(exc).as_dict(), sort_keys=True, indent=2))
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
