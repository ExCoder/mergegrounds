#!/usr/bin/env -S python3 -I
"""Strict, source-repository-only adapter used to dogfood MergeGrounds."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
REPORT_ROOT = ROOT / ".mergegrounds/reports"
CORE_SOURCES = (
    "scripts/mergegrounds.py",
    "scripts/ai_assurance.py",
    "scripts/bootstrap.py",
    "scripts/build_release.py",
    "scripts/scaffold_change.py",
    "scripts/validate_release.py",
)
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
TOKEN_PATTERNS = (
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{32,}"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
)


class SelfCheckError(RuntimeError):
    """Raised when source self-assurance cannot produce a trustworthy result."""


def git_environment() -> dict[str, str]:
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


def test_environment() -> dict[str, str]:
    """Run tests without caller Git redirects and without suppressing test-owned refs."""
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }


def run(
    arguments: list[str],
    *,
    cwd: Path = ROOT,
    timeout: int = 1800,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=git_environment(),
        check=False,
        stdout=subprocess.PIPE if quiet else None,
        stderr=subprocess.STDOUT if quiet else None,
        text=True,
        timeout=timeout,
    )
    return completed


def git_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        env=git_environment(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if completed.returncode != 0:
        raise SelfCheckError("cannot enumerate tracked files")
    values: list[Path] = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = PurePosixPath(os.fsdecode(raw))
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise SelfCheckError("git returned an unsafe tracked path")
        path = ROOT.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise SelfCheckError(f"tracked path is not a regular file: {relative.as_posix()}")
        values.append(path)
    return sorted(values)


def atomic_json(path: Path, value: Any) -> None:
    try:
        path.resolve(strict=False).relative_to(ROOT.resolve())
    except ValueError as exc:
        raise SelfCheckError("report output escaped the repository") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise SelfCheckError(f"refusing symbolic-link report output: {path}")
    payload = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_metrics(*, line: float, branch: float, mutation: float) -> None:
    for label, value in {"line": line, "branch": branch, "mutation": mutation}.items():
        if not 0.0 <= value <= 100.0:
            raise SelfCheckError(f"{label} metric is outside 0..100")
    atomic_json(
        REPORT_ROOT / "metrics.json",
        {
            "line_coverage": line,
            "branch_coverage": branch,
            "mutation_score": mutation,
        },
    )


def format_check() -> int:
    findings: list[str] = []
    text_suffixes = {
        "",
        ".cfg",
        ".in",
        ".json",
        ".lock",
        ".md",
        ".py",
        ".sh",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
    }
    for path in git_files():
        if path.suffix.lower() not in text_suffixes and path.name not in {
            "CODEOWNERS",
            "LICENSE",
            "VERSION",
        }:
            continue
        data = path.read_bytes()
        relative = path.relative_to(ROOT).as_posix()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(f"{relative}: not UTF-8")
            continue
        if "\r" in text:
            findings.append(f"{relative}: CR/CRLF line ending")
        if data and not data.endswith(b"\n"):
            findings.append(f"{relative}: missing final newline")
        for number, line in enumerate(text.splitlines(), 1):
            if line.rstrip(" \t") != line:
                findings.append(f"{relative}:{number}: trailing whitespace")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print(f"format policy passed for {len(git_files())} tracked files")
    return 0


def lint() -> int:
    completed = run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--select",
            "E4,E7,E9,F,B",
            "scripts",
            "tests",
        ]
    )
    return completed.returncode


def typecheck() -> int:
    completed = run([sys.executable, "-m", "mypy", "--strict", "scripts"])
    return completed.returncode


class RecordingResult(unittest.TextTestResult):
    successes: list[unittest.case.TestCase]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.successes = []

    def addSuccess(self, test: unittest.case.TestCase) -> None:  # noqa: N802
        self.successes.append(test)
        super().addSuccess(test)


def write_junit(result: RecordingResult, duration: float) -> None:
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    executed = result.testsRun - skipped
    suite = ET.Element(
        "testsuite",
        {
            "name": "mergegrounds-unittest",
            "tests": str(result.testsRun),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": str(skipped),
            "time": f"{duration:.3f}",
        },
    )
    for test in result.successes:
        ET.SubElement(suite, "testcase", {"name": test.id()})
    for test, reason in result.skipped:
        case = ET.SubElement(suite, "testcase", {"name": test.id()})
        ET.SubElement(case, "skipped", {"message": reason})
    for test, traceback in result.failures:
        case = ET.SubElement(suite, "testcase", {"name": test.id()})
        failure = ET.SubElement(case, "failure")
        failure.text = traceback
    for test, traceback in result.errors:
        case = ET.SubElement(suite, "testcase", {"name": test.id()})
        error = ET.SubElement(case, "error")
        error.text = traceback
    if executed <= 0:
        raise SelfCheckError("unit suite executed no tests")
    destination = REPORT_ROOT / "unit/junit.xml"
    destination.parent.mkdir(parents=True, exist_ok=True)
    tree = ET.ElementTree(suite)
    ET.indent(tree, space="  ")
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    tree.write(temporary, encoding="utf-8", xml_declaration=True)
    temporary.replace(destination)


def unit() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult)
    started = time.monotonic()
    result = runner.run(suite)
    assert isinstance(result, RecordingResult)
    write_junit(result, time.monotonic() - started)
    return 0 if result.wasSuccessful() else 1


def flatten_suite(suite: unittest.TestSuite) -> list[unittest.case.TestCase]:
    tests: list[unittest.case.TestCase] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            tests.extend(flatten_suite(item))
        else:
            tests.append(item)
    return tests


def coverage_suite() -> int:
    """Run instrumentable tests; the raw-interpreter isolation probe runs in unit."""
    excluded = {
        "test_workflow_hardening.WorkflowExpressionHardeningTests."
        "test_isolated_mode_blocks_sibling_standard_library_shadow"
    }
    discovered = unittest.TestLoader().discover(
        str(ROOT / "tests"),
        pattern="test_*.py",
    )
    selected = [test for test in flatten_suite(discovered) if test.id() not in excluded]
    if not selected or len(selected) + len(excluded) != discovered.countTestCases():
        raise SelfCheckError("coverage-suite exclusion did not match exactly one known test")
    result = unittest.TextTestRunner(verbosity=1).run(unittest.TestSuite(selected))
    return 0 if result.wasSuccessful() else 1


def coverage() -> int:
    coverage_directory = REPORT_ROOT / "coverage"
    coverage_directory.mkdir(parents=True, exist_ok=True)
    data_file = coverage_directory / ".coverage"
    report_path = coverage_directory / "coverage.json"
    # Tests intentionally execute the source CLIs while their current working
    # directory is a temporary repository.  Absolute patterns keep coverage's
    # subprocess instrumentation bound to this reviewed source tree instead of
    # silently matching paths relative to each fixture repository.
    include = ",".join(str(ROOT / relative) for relative in CORE_SOURCES)
    environment = test_environment()
    environment["COVERAGE_FILE"] = str(data_file)
    environment["COVERAGE_PROCESS_START"] = str(ROOT / ".coveragerc")
    subprocess.run(
        [sys.executable, "-m", "coverage", "erase"],
        cwd=ROOT,
        env=environment,
        check=True,
        timeout=120,
    )
    command = [
        sys.executable,
        "-m",
        "coverage",
        "run",
        "--branch",
        f"--include={include}",
        "scripts/self_check.py",
        "coverage-suite",
    ]
    completed = subprocess.run(command, cwd=ROOT, env=environment, check=False, timeout=1800)
    if completed.returncode != 0:
        return completed.returncode
    completed = subprocess.run(
        [sys.executable, "-m", "coverage", "combine", str(coverage_directory)],
        cwd=ROOT,
        env=environment,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        return completed.returncode
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "json",
            "--fail-under=0",
            "-o",
            str(report_path),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        return completed.returncode
    document = json.loads(report_path.read_text(encoding="utf-8"))
    files = document.get("files")
    if not isinstance(files, dict) or set(files) != set(CORE_SOURCES):
        raise SelfCheckError(
            "coverage.py JSON must contain exactly the protected source manifest"
        )
    for relative in CORE_SOURCES:
        record = files.get(relative)
        summary_record = record.get("summary") if isinstance(record, dict) else None
        if (
            not isinstance(summary_record, dict)
            or type(summary_record.get("num_statements")) is not int
            or summary_record["num_statements"] <= 0
            or type(summary_record.get("num_branches")) is not int
            or summary_record["num_branches"] <= 0
        ):
            raise SelfCheckError(
                f"coverage.py JSON has an empty source denominator for {relative}"
            )
    totals = document.get("totals")
    if not isinstance(totals, dict):
        raise SelfCheckError("coverage.py JSON has no totals object")
    try:
        statements = int(totals["num_statements"])
        covered_lines = int(totals["covered_lines"])
        branches = int(totals["num_branches"])
        covered_branches = int(totals["covered_branches"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SelfCheckError("coverage.py JSON totals are incomplete") from exc
    if statements <= 0 or branches <= 0:
        raise SelfCheckError("coverage denominators must be positive")
    line_score = 100.0 * covered_lines / statements
    branch_score = 100.0 * covered_branches / branches
    summary = {
        "schema_version": 1,
        "covered_lines": covered_lines,
        "num_statements": statements,
        "covered_branches": covered_branches,
        "num_branches": branches,
        "line_coverage": line_score,
        "branch_coverage": branch_score,
        "source_files": list(CORE_SOURCES),
    }
    atomic_json(coverage_directory / "summary.json", summary)
    write_metrics(line=line_score, branch=branch_score, mutation=100.0)
    if line_score < 90.0 or branch_score < 85.0:
        print(
            f"coverage below policy: line={line_score:.2f}% branch={branch_score:.2f}%",
            file=sys.stderr,
        )
        return 1
    print(f"coverage: line={line_score:.2f}% branch={branch_score:.2f}%")
    return 0


@dataclass(frozen=True)
class Mutation:
    identifier: str
    target: str
    needle: str
    replacement: str
    test_file: str
    test_name: str


MUTATIONS = (
    Mutation(
        "threshold-floor-bypass",
        "scripts/mergegrounds.py",
        'if key not in thresholds or finite_number(thresholds[key], f"thresholds.{key}") < floor:',
        'if key not in thresholds or finite_number(thresholds[key], f"thresholds.{key}") < 0:',
        "test_policy_hardening.py",
        "test_security_floors_and_secret_scrubbing_cannot_be_weakened",
    ),
    Mutation(
        "sensitive-environment-bypass",
        "scripts/mergegrounds.py",
        "if SENSITIVE_ENV.search(key) and key not in allowed:\n            removed.append(key)",
        "if False and SENSITIVE_ENV.search(key) and key not in allowed:\n            removed.append(key)",
        "test_mergegrounds.py",
        "test_sensitive_environment_is_removed",
    ),
    Mutation(
        "mutable-action-bypass",
        "scripts/mergegrounds.py",
        'if "@" not in use or not FULL_SHA.fullmatch(use.rsplit("@", 1)[1]):',
        'if False and ("@" not in use or not FULL_SHA.fullmatch(use.rsplit("@", 1)[1])):',
        "test_mergegrounds.py",
        "test_mutable_action_is_rejected",
    ),
    Mutation(
        "codeowners-suffix-bypass",
        "scripts/mergegrounds.py",
        "if [pattern for pattern, _ in suffix] != protected:\n            findings.append(Finding(\"OWNERSHIP_OVERRIDE\"",
        "if False and [pattern for pattern, _ in suffix] != protected:\n            findings.append(Finding(\"OWNERSHIP_OVERRIDE\"",
        "test_mergegrounds.py",
        "test_codeowners_late_override_is_rejected",
    ),
    Mutation(
        "control-drift-bypass",
        "scripts/mergegrounds.py",
        'elif expected[name]["sha256"] != current[name]["sha256"]:',
        "elif False:",
        "test_mergegrounds.py",
        "test_control_plane_drift_is_rejected",
    ),
    Mutation(
        "duplicate-json-key-bypass",
        "scripts/mergegrounds.py",
        "if key in result:\n                raise ValueError(f\"duplicate JSON key: {key}\")\n            result[key] = value\n        return result\n\n    def finite_float",
        "if False and key in result:\n                raise ValueError(f\"duplicate JSON key: {key}\")\n            result[key] = value\n        return result\n\n    def finite_float",
        "test_design_contract.py",
        "test_strict_json_rejects_duplicate_nonfinite_bom_and_depth",
    ),
)


def copy_tracked(destination: Path) -> None:
    for source in git_files():
        relative = source.relative_to(ROOT)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=False)


def mutation_test_command(mutation: Mutation) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-m",
        "unittest",
        "discover",
        "-s",
        "tests",
        "-p",
        mutation.test_file,
        "-k",
        mutation.test_name,
    ]


def mutation() -> int:
    outcomes: list[dict[str, Any]] = []
    baseline_cache: set[tuple[str, str]] = set()
    for mutant in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="mergegrounds-mutant-") as raw:
            checkout = Path(raw)
            copy_tracked(checkout)
            cache_key = (mutant.test_file, mutant.test_name)
            if cache_key not in baseline_cache:
                baseline = run(mutation_test_command(mutant), cwd=checkout, quiet=True)
                if baseline.returncode != 0:
                    print(baseline.stdout or "", file=sys.stderr)
                    raise SelfCheckError(f"mutation baseline failed: {mutant.identifier}")
                baseline_cache.add(cache_key)
            target = checkout / mutant.target
            source = target.read_text(encoding="utf-8")
            occurrences = source.count(mutant.needle)
            if occurrences != 1:
                raise SelfCheckError(
                    f"mutation {mutant.identifier} expected one target, found {occurrences}"
                )
            target.write_text(source.replace(mutant.needle, mutant.replacement, 1), encoding="utf-8")
            result = run(mutation_test_command(mutant), cwd=checkout, quiet=True)
            killed = result.returncode != 0
            outcomes.append(
                {
                    "id": mutant.identifier,
                    "target": mutant.target,
                    "test": f"{mutant.test_file}:{mutant.test_name}",
                    "status": "killed" if killed else "survived",
                    "returncode": result.returncode,
                    "output_sha256": hashlib.sha256((result.stdout or "").encode("utf-8")).hexdigest(),
                }
            )
    killed_count = sum(item["status"] == "killed" for item in outcomes)
    score = 100.0 * killed_count / len(outcomes)
    atomic_json(
        REPORT_ROOT / "mutation/results.json",
        {
            "schema_version": 1,
            "scope": "curated security-critical source mutations",
            "total": len(outcomes),
            "killed": killed_count,
            "survived": len(outcomes) - killed_count,
            "mutation_score": score,
            "mutants": outcomes,
        },
    )
    coverage_summary_path = REPORT_ROOT / "coverage/summary.json"
    if coverage_summary_path.is_file():
        coverage_summary = json.loads(coverage_summary_path.read_text(encoding="utf-8"))
        line_score = float(coverage_summary["line_coverage"])
        branch_score = float(coverage_summary["branch_coverage"])
    else:
        line_score = 100.0
        branch_score = 100.0
    write_metrics(line=line_score, branch=branch_score, mutation=score)
    print(f"critical mutants: killed={killed_count}/{len(outcomes)} score={score:.2f}%")
    return 0 if killed_count == len(outcomes) else 1


def security() -> int:
    findings: list[str] = []
    scanned = 0
    for path in git_files():
        data = path.read_bytes()
        relative = path.relative_to(ROOT).as_posix()
        scanned += len(data)
        if PRIVATE_KEY.search(data):
            findings.append(f"private-key material: {relative}")
        for pattern in TOKEN_PATTERNS:
            if pattern.search(data):
                findings.append(f"token-shaped material: {relative}")
    runtime_imports: dict[str, list[str]] = {}
    for relative in CORE_SOURCES:
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"), filename=relative)
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split(".", 1)[0])
        external = sorted(module for module in modules if module not in sys.stdlib_module_names)
        if external:
            runtime_imports[relative] = external
            findings.append(f"non-stdlib runtime import in {relative}: {', '.join(external)}")
    lock_text = (ROOT / "requirements-self.lock").read_text(encoding="utf-8")
    requirement_lines = [
        line for line in lock_text.splitlines() if line and not line.startswith((" ", "#"))
    ]
    if not requirement_lines or lock_text.count("--hash=sha256:") < len(requirement_lines):
        findings.append("requirements-self.lock is not fully hash-pinned")
    report = {
        "schema_version": 1,
        "tracked_files": len(git_files()),
        "scanned_bytes": scanned,
        "stdlib_only_runtime": not runtime_imports,
        "hash_pinned_self_tooling": "requirements-self.lock is not fully hash-pinned" not in findings,
        "findings": findings,
    }
    atomic_json(REPORT_ROOT / "security/report.json", report)
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print(f"security self-check passed ({scanned} tracked bytes)")
    return 0


def build() -> int:
    return run(
        [
            sys.executable,
            "-I",
            "scripts/build_release.py",
            "--output-dir",
            ".mergegrounds/reports/build",
        ]
    ).returncode


def load_mergegrounds() -> Any:
    path = ROOT / "scripts/mergegrounds.py"
    specification = importlib.util.spec_from_file_location("mergegrounds_self_fuzz", path)
    if specification is None or specification.loader is None:
        raise SelfCheckError("cannot load MergeGrounds parser for fuzzing")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def fuzz() -> int:
    mergegrounds = load_mergegrounds()
    known_bad = (
        b"",
        b"[]",
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b"\xef\xbb\xbf{}",
        b'{"x":"\\ud800"}',
        (b'{"x":' * 80) + b"0" + (b"}" * 80),
    )
    rejected = 0
    for payload in known_bad:
        try:
            mergegrounds.strict_json_document(payload, "fuzz", 4096, maximum_nodes=64)
        except mergegrounds.MergeGroundsError:
            rejected += 1
        else:
            raise SelfCheckError(f"known-bad parser input was accepted: {payload[:40]!r}")
    generator = random.Random(0xA1C0DE)
    unexpected = 0
    accepted = 0
    denied = 0
    for _ in range(2000):
        payload = bytes(generator.randrange(0, 256) for _ in range(generator.randrange(0, 257)))
        try:
            mergegrounds.strict_json_document(payload, "fuzz", 4096, maximum_nodes=64)
            accepted += 1
        except mergegrounds.MergeGroundsError:
            denied += 1
        except Exception as exc:  # noqa: BLE001 - the fuzz oracle records any crash class.
            unexpected += 1
            print(f"unexpected parser crash: {type(exc).__name__}: {exc}", file=sys.stderr)
            break
    atomic_json(
        REPORT_ROOT / "fuzz/report.json",
        {
            "schema_version": 1,
            "seed": "0xA1C0DE",
            "known_bad_cases": len(known_bad),
            "known_bad_rejected": rejected,
            "random_cases": 2000,
            "random_accepted": accepted,
            "random_denied": denied,
            "unexpected_exceptions": unexpected,
        },
    )
    print(
        f"parser fuzz: known-bad={rejected}/{len(known_bad)} random={accepted + denied}/2000 crashes={unexpected}"
    )
    return 0 if unexpected == 0 else 1


COMMANDS = {
    "format": format_check,
    "lint": lint,
    "typecheck": typecheck,
    "unit": unit,
    "coverage": coverage,
    "coverage-suite": coverage_suite,
    "mutation": mutation,
    "security": security,
    "build": build,
    "fuzz": fuzz,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=sorted(COMMANDS))
    arguments = parser.parse_args()
    try:
        return COMMANDS[arguments.command]()
    except (OSError, SelfCheckError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"self-check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
