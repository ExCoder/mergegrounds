#!/usr/bin/env -S python3 -I
"""Create strict, editable design and implementation contract skeletons safely."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
MERGEGROUNDS_PATH = SCRIPT_DIRECTORY / "mergegrounds.py"
MERGEGROUNDS_SPEC = importlib.util.spec_from_file_location("mergegrounds_scaffold_schema", MERGEGROUNDS_PATH)
if MERGEGROUNDS_SPEC is None or MERGEGROUNDS_SPEC.loader is None:  # pragma: no cover - import boundary
    raise SystemExit(f"cannot load MergeGrounds schema authority from {MERGEGROUNDS_PATH}")
mergegrounds = importlib.util.module_from_spec(MERGEGROUNDS_SPEC)
sys.modules[MERGEGROUNDS_SPEC.name] = mergegrounds
MERGEGROUNDS_SPEC.loader.exec_module(mergegrounds)


class ScaffoldError(RuntimeError):
    """An unsafe or invalid scaffold request."""


DESIGN_DIRECTORY = ("docs", "decisions")
CHANGE_DIRECTORY = (".mergegrounds", "changes")
PLACEHOLDER_NOTICE = (
    "DRAFT ONLY: MergeGrounds denies admission until every EDIT ME placeholder is replaced; "
    "claims are never evidence."
)


def canonical_uuid(raw: str, label: str) -> str:
    """Return a canonical lowercase RFC 4122 UUID accepted by MergeGrounds."""
    if not isinstance(raw, str) or not mergegrounds.CHANGE_ID.fullmatch(raw):
        raise ScaffoldError(f"{label} must be a canonical lowercase UUID")
    try:
        parsed = uuid.UUID(raw)
    except ValueError as exc:
        raise ScaffoldError(f"{label} must be a canonical lowercase UUID") from exc
    if str(parsed) != raw or parsed.version not in {1, 2, 3, 4, 5}:
        raise ScaffoldError(f"{label} must be a canonical lowercase UUID")
    return raw


def canonical_relative(raw: str, label: str) -> str:
    """Reject alternate spellings, traversal, absolute paths, and NULs."""
    if not isinstance(raw, str) or not raw or "\x00" in raw or "\\" in raw:
        raise ScaffoldError(f"{label} must be a canonical repository-relative path")
    if raw.startswith("/") or any(part in {"", ".", ".."} for part in raw.split("/")):
        raise ScaffoldError(f"{label} must be a canonical repository-relative path")
    if Path(raw).is_absolute() or Path(raw).as_posix() != raw:
        raise ScaffoldError(f"{label} must be a canonical repository-relative path")
    return raw


def canonical_contract_path(
    raw: str,
    directory: tuple[str, str],
    contract_id: str,
    label: str,
) -> str:
    relative = canonical_relative(raw, label)
    expected = "/".join((*directory, f"{contract_id}.json"))
    if relative != expected:
        raise ScaffoldError(f"{label} must be exactly {expected}")
    return relative


def id_and_output(
    explicit_id: str | None,
    raw_output: str | None,
    directory: tuple[str, str],
    id_label: str,
    output_label: str,
) -> tuple[str, str]:
    """Resolve an explicit/inferred id, or generate one with its matching path."""
    if explicit_id is not None:
        contract_id = canonical_uuid(explicit_id, id_label)
    elif raw_output is not None:
        relative = canonical_relative(raw_output, output_label)
        parts = relative.split("/")
        if len(parts) != 3 or tuple(parts[:2]) != directory or not parts[2].endswith(".json"):
            expected = "/".join((*directory, "<uuid>.json"))
            raise ScaffoldError(f"{output_label} must match {expected}")
        contract_id = canonical_uuid(parts[2][:-5], f"UUID in {output_label}")
    else:
        contract_id = str(uuid.uuid4())

    output = raw_output or "/".join((*directory, f"{contract_id}.json"))
    return contract_id, canonical_contract_path(output, directory, contract_id, output_label)


def discover_repository(raw: str) -> Path:
    """Resolve a Git working-tree top level; non-repositories fail closed."""
    start = Path(raw)
    if start.is_symlink():
        raise ScaffoldError("repository target must not be a symlink")
    try:
        resolved_start = start.resolve(strict=True)
    except OSError as exc:
        raise ScaffoldError(f"repository target cannot be resolved safely: {exc}") from exc
    if not resolved_start.is_dir():
        raise ScaffoldError("repository target must be a directory")
    git_environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    git_environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    try:
        result = subprocess.run(
            [
                "git",
                "-c", "core.fsmonitor=false",
                "-c", "core.untrackedCache=false",
                "-c", f"core.hooksPath={os.devnull}",
                "-C", os.fspath(resolved_start),
                "rev-parse", "--show-toplevel",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            env=git_environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScaffoldError(f"cannot locate Git repository: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or "not a Git working tree"
        raise ScaffoldError(f"cannot locate Git repository: {detail}")
    output = result.stdout.strip()
    if not output or "\n" in output or "\x00" in output:
        raise ScaffoldError("Git returned an invalid repository root")
    try:
        root = Path(output).resolve(strict=True)
    except OSError as exc:
        raise ScaffoldError(f"repository root cannot be resolved safely: {exc}") from exc
    if not root.is_dir():
        raise ScaffoldError("repository root is not a directory")
    if resolved_start != root and root not in resolved_start.parents:
        raise ScaffoldError(
            "Git resolved a worktree outside the explicitly selected repository target"
        )
    return root


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ScaffoldError("this platform lacks required no-follow directory operations")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def open_repository_directory(root: Path, parts: Sequence[str]) -> int:
    """Open a repository directory component-by-component without following links."""
    flags = _directory_flags()
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise ScaffoldError(f"cannot open repository root safely: {exc}") from exc
    try:
        for part in parts:
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ScaffoldError(
                    f"required repository directory {'/'.join(parts)} is missing or unsafe: {exc}"
                ) from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_repository_file(root: Path, relative: str, maximum_bytes: int) -> bytes:
    """Read a bounded regular repository file through pinned no-follow descriptors."""
    parts = canonical_relative(relative, "input path").split("/")
    directory = open_repository_directory(root, parts[:-1])
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(parts[-1], flags, dir_fd=directory)
        except OSError as exc:
            raise ScaffoldError(f"input file is missing or unsafe: {relative}: {exc}") from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ScaffoldError(f"input file must be regular: {relative}")
        if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
            raise ScaffoldError(
                f"input file must be between 1 and {maximum_bytes} bytes: {relative}"
            )
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ScaffoldError(f"input file ended before its declared size: {relative}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ScaffoldError(f"input file grew while it was read: {relative}")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise ScaffoldError(f"input file changed while it was read: {relative}")
        return b"".join(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def write_repository_file_atomic(root: Path, relative: str, payload: bytes) -> None:
    """Publish a complete file atomically without overwriting any existing entry."""
    parts = canonical_relative(relative, "output path").split("/")
    directory = open_repository_directory(root, parts[:-1])
    target_name = parts[-1]
    temporary_name = f".{target_name}.tmp-{uuid.uuid4().hex}"
    temporary_created = False
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory)
            temporary_created = True
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise ScaffoldError("atomic output write made no progress")
                offset += written
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)
                descriptor = None

        try:
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise ScaffoldError(f"refusing to overwrite existing output: {relative}") from exc
        except OSError as exc:
            raise ScaffoldError(f"cannot publish output safely: {relative}: {exc}") from exc
        os.fsync(directory)
    except OSError as exc:
        raise ScaffoldError(f"cannot write output safely: {relative}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=directory)
                os.fsync(directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def design_document(design_id: str) -> dict[str, Any]:
    """Return a strict R3 design skeleton with four observable evaluation classes."""
    value: dict[str, Any] = {
        "schema_version": 1,
        "design_id": canonical_uuid(design_id, "design id"),
        "title": "EDIT ME: reviewed change design title",
        "problem": (
            "EDIT ME: describe the externally observable problem, affected users, and current harm."
        ),
        "goals": [
            "EDIT ME: state a measurable user or system outcome that this design must deliver."
        ],
        "non_goals": [
            "EDIT ME: state one adjacent behavior that this change deliberately will not alter."
        ],
        "decisions": [
            {
                "id": "DEC-PRIMARY",
                "choice": "EDIT ME: state the chosen implementation-independent design decision.",
                "alternatives": [
                    "EDIT ME: record a materially different option considered during review."
                ],
                "rationale": (
                    "EDIT ME: explain tradeoffs and why the observable constraints "
                    "favor this choice."
                ),
            }
        ],
        "invariants": [
            {
                "id": "INV-FAIL-CLOSED",
                "statement": (
                    "EDIT ME: define the safety or business invariant that must hold on every path."
                ),
                "verification_ref": "AC-NEGATIVE",
            }
        ],
        "trust_boundaries": [
            {
                "id": "TB-PRIMARY",
                "source": "EDIT ME: untrusted source",
                "target": "EDIT ME: protected component",
                "data": "EDIT ME: classified data crossing this boundary",
                "controls": [
                    "EDIT ME: name validation, authorization, isolation, and audit controls."
                ],
            }
        ],
        "failure_modes": [
            {
                "id": "FM-UNSAFE-INPUT",
                "condition": (
                    "EDIT ME: malformed, unauthorized, stale, or conflicting input "
                    "reaches the boundary."
                ),
                "expected_behavior": (
                    "EDIT ME: deny safely, preserve state, and emit a bounded diagnostic signal."
                ),
                "detection_ref": "TEST-NEGATIVE",
                "rollback_trigger": (
                    "EDIT ME: trigger rollback when the negative-path oracle fails "
                    "or evidence is missing."
                ),
            }
        ],
        "rollback": {
            "strategy": (
                "EDIT ME: restore the last verified artifact or disable the change "
                "without data loss."
            ),
            "triggers": [
                "EDIT ME: a safety invariant, recovery objective, or outcome guardrail is breached."
            ],
            "verification_ref": "AC-RECOVERY",
        },
        "observability": {
            "signals": [
                {
                    "id": "SIG-OUTCOME",
                    "name": "EDIT ME: end-to-end outcome and failure signal",
                    "decision_use": (
                        "EDIT ME: block promotion or trigger rollback when the verified "
                        "bound is breached."
                    ),
                }
            ]
        },
        "evaluation": {
            "acceptance_criteria": [
                {
                    "id": "AC-POSITIVE",
                    "class": "positive",
                    "observable": (
                        "EDIT ME: the intended externally visible result occurs within "
                        "a measurable bound."
                    ),
                    "oracle": {
                        "kind": "test",
                        "ref": "TEST-POSITIVE",
                        "evidence_class": "trusted_execution",
                    },
                    "failure_behavior": (
                        "A failed, skipped, invalid, or missing positive observation "
                        "denies promotion."
                    ),
                },
                {
                    "id": "AC-NEGATIVE",
                    "class": "negative",
                    "observable": (
                        "EDIT ME: invalid or unauthorized input is rejected without "
                        "protected state change."
                    ),
                    "oracle": {
                        "kind": "test",
                        "ref": "TEST-NEGATIVE",
                        "evidence_class": "trusted_execution",
                    },
                    "failure_behavior": (
                        "Acceptance, ambiguous handling, or missing evidence denies promotion."
                    ),
                },
                {
                    "id": "AC-ADVERSARIAL",
                    "class": "adversarial",
                    "observable": (
                        "EDIT ME: an independent challenger cannot violate the stated "
                        "trust-boundary invariant."
                    ),
                    "oracle": {
                        "kind": "external_review",
                        "ref": "REVIEW-ADVERSARIAL",
                        "evidence_class": "independent_human",
                    },
                    "failure_behavior": (
                        "Any unresolved counterexample or absent independent challenge "
                        "denies promotion."
                    ),
                },
                {
                    "id": "AC-RECOVERY",
                    "class": "recovery",
                    "observable": (
                        "EDIT ME: rollback restores the last verified behavior and "
                        "preserves protected data."
                    ),
                    "oracle": {
                        "kind": "test",
                        "ref": "TEST-RECOVERY",
                        "evidence_class": "trusted_execution",
                    },
                    "failure_behavior": (
                        "Recovery timeout, state corruption, or missing recovery evidence "
                        "denies promotion."
                    ),
                },
            ],
            "outcome_metrics": [
                {
                    "id": "OUTCOME-DELIVERY-QUALITY",
                    "observable": (
                        "EDIT ME: end-to-end delivery quality does not regress after "
                        "verified release."
                    ),
                    "source": (
                        "EDIT ME: independently administered deployment, rework, "
                        "and incident telemetry"
                    ),
                    "evidence_class": "external_verifier",
                    "baseline_window": "4w",
                    "observation_window": "4w",
                    "direction": "not_regress",
                    "target": 0,
                    "unit": "percent change from reviewed baseline",
                    "minimum_samples": 20,
                    "maximum_missing_percent": 5,
                    "promotion_blocking": True,
                    "failure_action": "deny_promotion",
                }
            ],
        },
    }
    return value


def change_document(
    change_id: str,
    design_id: str,
    design_path: str,
    design_digest: str,
    design: dict[str, Any],
    risk_tier: str,
    lane: str,
) -> dict[str, Any]:
    """Bind a change declaration to the design's exact semantics."""
    if lane not in {"design-only", "implementation"}:
        raise ScaffoldError("change lane must be design-only or implementation")
    criteria = copy.deepcopy(design["evaluation"]["acceptance_criteria"])
    failure_modes = copy.deepcopy(design["failure_modes"])
    adversarial = next(item for item in criteria if item["class"] == "adversarial")
    return {
        "schema_version": 1,
        "change_id": canonical_uuid(change_id, "change id"),
        "lane": lane,
        "risk": {
            "claimed_tier": risk_tier,
            "impact_flags": ["documentation" if lane == "design-only" else "application_code"],
            "rationale": (
                "EDIT ME: justify this tier from data, privilege, blast radius, "
                "and rollback constraints."
            ),
        },
        "summary": {
            "problem": design["problem"],
            "approach": (
                "EDIT ME: explain how the change realizes the reviewed decisions "
                "and invariants."
            ),
            "non_goals": copy.deepcopy(design["non_goals"]),
        },
        "design": {
            "record_id": design_id,
            "record_path": design_path,
            "record_sha256": design_digest,
        },
        "acceptance_criteria": criteria,
        "failure_modes": failure_modes,
        "challenge_plan": [
            {
                "id": "CH-INDEPENDENT",
                "claim_to_falsify": (
                    "EDIT ME: attempt to violate the reviewed invariant without "
                    "relying on author assertions."
                ),
                "attack_surface": (
                    "EDIT ME: trust boundary, abuse case, concurrency edge, and recovery path."
                ),
                "evaluation_ref": adversarial["oracle"]["ref"],
                "required_producer": "independent_human",
            }
        ],
        "outcome_metric_ids": [
            item["id"] for item in design["evaluation"]["outcome_metrics"]
        ],
        "evidence_policy": {
            "author_claims_are_evidence": False,
            "model_output_is_evidence": False,
            "self_review_is_evidence": False,
        },
        "ai_assistance": {
            "used": False,
            "systems": [],
            "affected_paths": [],
        },
    }


def implementation_document(
    change_id: str,
    design_id: str,
    design_path: str,
    design_digest: str,
    design: dict[str, Any],
    risk_tier: str,
) -> dict[str, Any]:
    """Backward-compatible helper for an implementation-lane draft."""
    return change_document(
        change_id,
        design_id,
        design_path,
        design_digest,
        design,
        risk_tier,
        "implementation",
    )


def render_json(value: dict[str, Any]) -> bytes:
    """Produce stable, human-editable UTF-8 JSON."""
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def scaffold_design(args: argparse.Namespace) -> tuple[str, bytes]:
    root = discover_repository(args.repo)
    design_id, output = id_and_output(
        args.design_id,
        args.output,
        DESIGN_DIRECTORY,
        "design id",
        "design output",
    )
    payload = render_json(design_document(design_id))
    if args.write:
        write_repository_file_atomic(root, output, payload)
    return output, payload


def load_design(
    root: Path,
    raw_design_path: str,
) -> tuple[str, str, bytes, dict[str, Any]]:
    """Load and semantically validate a completed design contract."""
    design_input = canonical_relative(raw_design_path, "design input")
    design_parts = design_input.split("/")
    if (
        len(design_parts) != 3
        or tuple(design_parts[:2]) != DESIGN_DIRECTORY
        or not design_parts[2].endswith(".json")
    ):
        raise ScaffoldError("design input must be exactly docs/decisions/<uuid>.json")
    design_id = canonical_uuid(design_parts[2][:-5], "design input UUID")
    design_path = canonical_contract_path(
        design_input,
        DESIGN_DIRECTORY,
        design_id,
        "design input",
    )
    raw_design = read_repository_file(root, design_path, mergegrounds.MAX_DESIGN_CONTRACT_BYTES)
    design = mergegrounds.strict_json_document(
        raw_design,
        "design contract",
        mergegrounds.MAX_DESIGN_CONTRACT_BYTES,
    )
    mergegrounds.validate_design_contract(design, design_id)
    return design_id, design_path, raw_design, design


def scaffold_design_change(args: argparse.Namespace) -> tuple[str, bytes]:
    root = discover_repository(args.repo)
    design_id, design_path, raw_design, design = load_design(root, args.design)
    change_id, output = id_and_output(
        args.change_id,
        args.output,
        CHANGE_DIRECTORY,
        "change id",
        "design-change output",
    )
    value = change_document(
        change_id,
        design_id,
        design_path,
        f"sha256:{hashlib.sha256(raw_design).hexdigest()}",
        design,
        args.risk_tier,
        "design-only",
    )
    payload = render_json(value)
    if args.write:
        write_repository_file_atomic(root, output, payload)
    return output, payload


def scaffold_implementation(args: argparse.Namespace) -> tuple[str, bytes]:
    root = discover_repository(args.repo)
    design_id, design_path, raw_design, design = load_design(root, args.design)

    change_id, output = id_and_output(
        args.change_id,
        args.output,
        CHANGE_DIRECTORY,
        "change id",
        "implementation output",
    )
    design_digest = f"sha256:{hashlib.sha256(raw_design).hexdigest()}"
    value = implementation_document(
        change_id,
        design_id,
        design_path,
        design_digest,
        design,
        args.risk_tier,
    )
    payload = render_json(value)
    if args.write:
        write_repository_file_atomic(root, output, payload)
    return output, payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create structurally complete MergeGrounds contract drafts. Dry-run is the default; "
            "pass --write to create a file. Draft placeholders intentionally fail admission."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    design = subparsers.add_parser("design", help="scaffold a reviewed design contract")
    design.add_argument("--design-id", help="canonical lowercase UUID; generated when omitted")
    design.add_argument(
        "--output",
        help="canonical docs/decisions/<uuid>.json path; default follows the resolved id",
    )
    design.add_argument("--repo", default=".", help="path inside the target Git repository")
    design.add_argument("--write", action="store_true", help="atomically create the output")
    design.set_defaults(handler=scaffold_design)

    design_change = subparsers.add_parser(
        "design-change",
        help="scaffold the declaration required for a design-only pull request",
    )
    design_change.add_argument(
        "--design",
        required=True,
        help="completed canonical docs/decisions/<uuid>.json path",
    )
    design_change.add_argument(
        "--change-id",
        help="canonical lowercase UUID; generated when omitted",
    )
    design_change.add_argument(
        "--output",
        help="canonical .mergegrounds/changes/<uuid>.json path; default follows the resolved id",
    )
    design_change.add_argument(
        "--risk-tier",
        choices=("R3", "R4"),
        default="R3",
        help="claimed design-change risk tier (default: R3)",
    )
    design_change.add_argument(
        "--repo",
        default=".",
        help="path inside the target Git repository",
    )
    design_change.add_argument(
        "--write",
        action="store_true",
        help="atomically create the output",
    )
    design_change.set_defaults(handler=scaffold_design_change)

    implementation = subparsers.add_parser(
        "implementation",
        help="scaffold an implementation declaration bound to a reviewed design",
    )
    implementation.add_argument(
        "--design",
        required=True,
        help="canonical docs/decisions/<uuid>.json path",
    )
    implementation.add_argument(
        "--change-id",
        help="canonical lowercase UUID; generated when omitted",
    )
    implementation.add_argument(
        "--output",
        help="canonical .mergegrounds/changes/<uuid>.json path; default follows the resolved id",
    )
    implementation.add_argument(
        "--risk-tier",
        choices=("R3", "R4"),
        default="R3",
        help="claimed implementation risk tier (default: R3)",
    )
    implementation.add_argument("--repo", default=".", help="path inside the target Git repository")
    implementation.add_argument("--write", action="store_true", help="atomically create the output")
    implementation.set_defaults(handler=scaffold_implementation)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        output, payload = args.handler(args)
    except (ScaffoldError, mergegrounds.MergeGroundsError) as exc:
        print(f"scaffold-change: error: {exc}", file=sys.stderr)
        return 2

    if args.write:
        print(f"created {output}")
    else:
        sys.stdout.buffer.write(payload)
        print(f"dry run for {output}; pass --write to create it", file=sys.stderr)
    print(PLACEHOLDER_NOTICE, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
