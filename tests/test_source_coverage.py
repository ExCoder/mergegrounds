from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
import re
import sys
import tempfile
import tomllib
import unittest
import unittest.mock as mock
import uuid
from pathlib import Path
from typing import Any, Callable

import test_exceptions as exception_fixtures
from test_ai_policy import RepositoryFixture, ai
from test_change_contract import (
    CHANGE_ID,
    DESIGN_ID,
    canonical_bytes,
    change_contract,
    design_contract,
)


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "mergegrounds_source_coverage_under_test", ROOT / "scripts" / "mergegrounds.py"
)
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)


Mutation = Callable[[dict[str, Any]], None]


class MetricDecisionCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, relative: str, value: object) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    @staticmethod
    def config(*, risk_tier: str = "R3") -> dict[str, Any]:
        return {
            "risk_tier": risk_tier,
            "thresholds": {
                "line_coverage": 90.0,
                "branch_coverage": 85.0,
                "mutation_score": 90.0,
                "critical_mutation_score": 95.0,
            },
            "mutation_policy": {},
        }

    @staticmethod
    def adapter(report_format: str = "mergegrounds-json") -> dict[str, Any]:
        return {
            "id": "fixture",
            "thresholds": {
                "line_coverage": 95.0,
                "branch_coverage": 80.0,
                "mutation_score": 92.0,
            },
            "metrics": {
                "coverage": {
                    "format": report_format,
                    "paths": ["coverage.json"],
                    "branch_required": True,
                },
                "mutation": {
                    "format": report_format,
                    "paths": ["mutation.json"],
                },
            },
        }

    def test_coverage_uses_stricter_floor_and_records_bound_report(self) -> None:
        report = self.write_json(
            "coverage.json",
            {
                "line_coverage": 92.0,
                "branch_coverage": 88.0,
                "mutation_score": 100.0,
            },
        )
        result = mergegrounds.validate_metric(
            self.root,
            self.config(),
            self.adapter(),
            "coverage",
            {},
        )

        self.assertEqual("fail", result["status"])
        self.assertEqual(
            ["line coverage 92.0000 < 95.0000"], result["violations"]
        )
        self.assertEqual(
            {"line_coverage": 95.0, "branch_coverage": 85.0},
            result["thresholds"],
        )
        self.assertEqual("coverage.json", result["reports"][0]["path"])
        self.assertEqual(report.stat().st_size, result["reports"][0]["bytes"])
        self.assertEqual(mergegrounds.sha256_file(report), result["reports"][0]["sha256"])

    def test_optional_branch_metric_does_not_create_a_hidden_floor(self) -> None:
        self.write_json(
            "coverage.json",
            {
                "line_coverage": 100.0,
                "branch_coverage": 0.0,
                "mutation_score": 100.0,
            },
        )
        adapter = self.adapter()
        adapter["metrics"]["coverage"]["branch_required"] = False

        result = mergegrounds.validate_metric(
            self.root, self.config(), adapter, "coverage", {}
        )

        self.assertEqual("pass", result["status"])
        self.assertEqual([], result["violations"])
        self.assertIsNone(result["thresholds"]["branch_coverage"])

    def test_required_branch_metric_enforces_global_floor(self) -> None:
        self.write_json(
            "coverage.json",
            {
                "line_coverage": 100.0,
                "branch_coverage": 84.0,
                "mutation_score": 100.0,
            },
        )
        result = mergegrounds.validate_metric(
            self.root, self.config(), self.adapter(), "coverage", {}
        )
        self.assertEqual("fail", result["status"])
        self.assertEqual(
            ["branch coverage 84.0000 < 85.0000"], result["violations"]
        )

    def test_generic_mutation_metric_below_perfect_cannot_prove_zero_survivors(self) -> None:
        self.write_json(
            "mutation.json",
            {
                "line_coverage": 100.0,
                "branch_coverage": 100.0,
                "mutation_score": 99.0,
            },
        )
        config = self.config(risk_tier="R4")
        config["thresholds"]["critical_mutation_score"] = 100.0

        result = mergegrounds.validate_metric(
            self.root, config, self.adapter(), "mutation", {}
        )

        self.assertEqual("fail", result["status"])
        self.assertEqual({"mutation_score": 100.0}, result["thresholds"])
        self.assertIn("mutation score 99.0000 < 100.0000", result["violations"])
        self.assertIn(
            "generic mutation metric cannot prove zero survivors below 100%",
            result["violations"],
        )

    def test_perfect_generic_mutation_metric_passes(self) -> None:
        self.write_json(
            "mutation.json",
            {
                "line_coverage": 100.0,
                "branch_coverage": 100.0,
                "mutation_score": 100.0,
            },
        )
        result = mergegrounds.validate_metric(
            self.root, self.config(), self.adapter(), "mutation", {}
        )
        self.assertEqual("pass", result["status"])
        self.assertEqual([], result["violations"])

    def test_native_adverse_mutant_categories_fail_closed_by_default(self) -> None:
        statuses = [
            "Killed",
            "Survived",
            "NoCoverage",
            "Timeout",
            "RuntimeError",
            "CompileError",
            "Ignored",
        ]
        self.write_json(
            "mutation.json",
            {
                "files": {
                    "src/example.py": {
                        "mutants": [
                            {"id": str(index), "status": status}
                            for index, status in enumerate(statuses)
                        ]
                    }
                }
            },
        )
        adapter = self.adapter("stryker-json")
        config = self.config()
        config["thresholds"]["mutation_score"] = 0.0
        adapter["thresholds"]["mutation_score"] = 0.0

        result = mergegrounds.validate_metric(
            self.root, config, adapter, "mutation", {}
        )

        self.assertEqual("fail", result["status"])
        self.assertEqual(
            {
                "killed": 1,
                "survived": 1,
                "not_covered": 1,
                "timeout": 1,
                "invalid": 1,
                "unviable": 1,
                "ignored": 1,
            },
            result["counts"],
        )
        for expected in (
            "survived mutants: 1",
            "not_covered mutants: 1",
            "timeout mutants: 1",
            "invalid mutants: 1",
            "unviable mutants: 1",
            "ignored mutants lack reviewed exclusions: 1",
        ):
            self.assertIn(expected, result["violations"])

    def test_metric_descriptor_errors_are_explicit_denials(self) -> None:
        cases: tuple[tuple[str, dict[str, Any], str, str], ...] = (
            (
                "missing descriptor",
                {"id": "fixture", "metrics": {}},
                "coverage",
                r"has no metrics\.coverage descriptor",
            ),
            (
                "non-table metrics",
                {"id": "fixture", "metrics": []},
                "coverage",
                r"metrics must be a table",
            ),
            (
                "non-table descriptor",
                {"id": "fixture", "metrics": {"coverage": []}},
                "coverage",
                r"metrics\.coverage must be a table",
            ),
            (
                "missing format",
                {
                    "id": "fixture",
                    "metrics": {"coverage": {"paths": ["coverage.json"]}},
                },
                "coverage",
                r"format is missing",
            ),
        )
        for label, adapter, kind, message in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, message):
                    mergegrounds.validate_metric(
                        self.root, self.config(), adapter, kind, {}
                    )


class ConfigurationDecisionCoverageTests(unittest.TestCase):
    @staticmethod
    def valid_config() -> dict[str, Any]:
        return mergegrounds.load_toml(ROOT / ".mergegrounds/mergegrounds.toml")

    def assert_config_denied(self, mutate: Mutation, expected: str) -> None:
        config = copy.deepcopy(self.valid_config())
        mutate(config)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, expected):
            mergegrounds.validate_config(config)

    def test_top_level_and_change_control_policy_is_closed_world(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "boolean schema",
                lambda config: config.__setitem__("schema_version", True),
                "schema_version must be the integer 1",
            ),
            (
                "fail open",
                lambda config: config.__setitem__("fail_closed", False),
                "fail_closed must be the TOML boolean true",
            ),
            (
                "unknown risk",
                lambda config: config.__setitem__("risk_tier", "R9"),
                "risk_tier must be one of",
            ),
            (
                "non-table policy section",
                lambda config: config.__setitem__("execution", []),
                "execution must be a TOML table",
            ),
            (
                "external evidence directory",
                lambda config: config["evidence"].__setitem__(
                    "directory", "artifacts/evidence"
                ),
                "evidence.directory must be exactly",
            ),
            (
                "unknown change control",
                lambda config: config["change_control"].__setitem__(
                    "author_can_override", True
                ),
                "change_control contains unsupported keys",
            ),
            (
                "weakened boolean change control",
                lambda config: config["change_control"].__setitem__(
                    "require_design_in_base", False
                ),
                "change_control.require_design_in_base must be True",
            ),
            (
                "weakened string change control",
                lambda config: config["change_control"].__setitem__(
                    "external_root_of_trust", "self-review"
                ),
                "change_control.external_root_of_trust must be",
            ),
            (
                "risk tier omitted from design requirement",
                lambda config: config["change_control"].__setitem__(
                    "design_required_tiers", ["R1", "R2", "R3", "R4"]
                ),
                "must require design for every risk tier",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                self.assert_config_denied(mutate, expected)

    def test_execution_mutation_and_thresholds_cannot_be_weakened(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "boolean execution flag",
                lambda config: config["execution"].__setitem__(
                    "sanitize_environment", "yes"
                ),
                "execution.sanitize_environment must be a TOML boolean",
            ),
            (
                "boolean timeout",
                lambda config: config["execution"].__setitem__(
                    "timeout_seconds", True
                ),
                "execution.timeout_seconds must be a positive integer",
            ),
            (
                "invalid environment allowlist",
                lambda config: config["execution"].__setitem__(
                    "allowed_environment", ["CI", ""]
                ),
                "allowed_environment must be a string array",
            ),
            (
                "sensitive environment exemption",
                lambda config: config["execution"]["allowed_environment"].append(
                    "API_TOKEN"
                ),
                "must not exempt sensitive names",
            ),
            (
                "required execution control",
                lambda config: config["execution"].__setitem__(
                    "require_clean_tree", False
                ),
                "execution.require_clean_tree must remain true",
            ),
            (
                "non-boolean mutation control",
                lambda config: config["mutation_policy"].__setitem__(
                    "fail_on_timeout", 1
                ),
                "mutation_policy.fail_on_timeout must be a TOML boolean",
            ),
            (
                "weakened mutation control",
                lambda config: config["mutation_policy"].__setitem__(
                    "fail_on_survived", False
                ),
                "mutation_policy.fail_on_survived must remain true",
            ),
            (
                "threshold out of range",
                lambda config: config["thresholds"].__setitem__(
                    "line_coverage", 101.0
                ),
                "thresholds.line_coverage must be between 0 and 100",
            ),
            (
                "critical mutation weaker than baseline",
                lambda config: config["thresholds"].__setitem__(
                    "critical_mutation_score", 84.0
                ),
                "critical_mutation_score must not be weaker",
            ),
            (
                "minimum threshold removed",
                lambda config: config["thresholds"].pop("branch_coverage"),
                "thresholds.branch_coverage must be at least",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                self.assert_config_denied(mutate, expected)

    def test_profiles_guidance_legacy_markers_and_policy_members_are_strict(self) -> None:
        missing_required_file = next(
            iter(mergegrounds.MINIMUM_POLICY_MEMBERS["required_files"])
        )
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "profiles type",
                lambda config: config.__setitem__("profiles", []),
                "profiles must be a TOML table",
            ),
            (
                "guidance becomes authoritative",
                lambda config: config["pull_request_guidance"].__setitem__(
                    "authoritative", True
                ),
                "authoritative must be false",
            ),
            (
                "duplicate guidance prompt",
                lambda config: config["pull_request_guidance"][
                    "informational_prompts"
                ].append("No secrets"),
                "informational_prompts must be a non-empty unique string array",
            ),
            (
                "legacy prompt set misses default",
                lambda config: config.__setitem__(
                    "attestation",
                    {
                        "required_markers": sorted(
                            mergegrounds.DEFAULT_INFORMATIONAL_PROMPTS - {"No secrets"}
                        )
                    },
                ),
                "is missing default informational prompts",
            ),
            (
                "required policy file removed",
                lambda config: config["policy"]["required_files"].remove(
                    missing_required_file
                ),
                "policy.required_files is missing secure minimum members",
            ),
            (
                "control lock redirected",
                lambda config: config["policy"].__setitem__(
                    "control_lock", ".mergegrounds/unsealed.json"
                ),
                "policy.control_lock must be exactly",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                self.assert_config_denied(mutate, expected)

        mergegrounds.validate_config(self.valid_config())

    def test_profile_validator_rejects_type_identity_duplicates_and_omissions(self) -> None:
        valid = self.valid_config()["profiles"]["fast"]
        cases: tuple[tuple[str, Any, str, str], ...] = (
            ("not a table", [], "fast", "must be a TOML table"),
            (
                "wrong id",
                {**valid, "id": "full"},
                "fast",
                "id must be 'fast'",
            ),
            (
                "unknown stage",
                {**valid, "stages": [*valid["stages"], "invented"]},
                "fast",
                "non-empty array of known stages",
            ),
            (
                "duplicate stage",
                {**valid, "stages": [*valid["stages"], "unit"]},
                "fast",
                "must not contain duplicates",
            ),
            (
                "required absent from stages",
                {**valid, "stages": ["format", "lint", "typecheck"]},
                "fast",
                "required_stages are absent from stages",
            ),
            (
                "secure minimum absent",
                {
                    "stages": ["format", "lint", "typecheck", "unit"],
                    "required_stages": ["format", "lint", "typecheck"],
                },
                "fast",
                "missing secure minimum stages",
            ),
        )
        for label, profile, profile_id, expected in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, expected):
                    mergegrounds.validate_profile(profile, profile_id, "fixture")


class RawEvidenceDecisionCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def subject(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "commit": "a" * 40,
            "tree": "b" * 40,
            "policy_sha256": "c" * 64,
            "risk_tier": "R2",
            "thresholds": {"line_coverage": 90.0},
            "config": {"execution": {"timeout_seconds": 30}},
            "profile": {
                "stages": ["policy", "unit", "coverage"],
                "required_stages": ["unit"],
            },
            "adapters": ["fixture"],
            "adapter_values": [],
        }

    def denied_evidence(self) -> dict[str, Any]:
        return {
            "schema_version": mergegrounds.SCHEMA_VERSION,
            "run_id": str(uuid.UUID("12345678-1234-4234-8234-123456789abc")),
            "started_at": "2026-09-05T12:00:00Z",
            "finished_at": "2026-09-05T12:00:01Z",
            "status": "fail",
            "decision": "deny",
            "profile": "pr",
            "risk_tier": "R2",
            "git_commit": "a" * 40,
            "git_tree": "b" * 40,
            "config": {
                "path": ".mergegrounds/mergegrounds.toml",
                "sha256": "c" * 64,
            },
            "adapters": ["fixture"],
            "sanitized_environment_keys": ["CI", "PATH"],
            "tool_versions": {"python": "3.13"},
            "thresholds": {"line_coverage": 90.0},
            "results": [{"adapter": "fixture", "stage": "unit", "status": "fail"}],
            "artifacts": [],
        }

    def test_denied_result_shape_is_fail_closed_and_accepts_only_real_failure(self) -> None:
        subject = self.subject()
        cases: tuple[tuple[str, Any, str | None], ...] = (
            ("empty", [], "EVIDENCE_INCOMPLETE"),
            ("not a record", ["fail"], "EVIDENCE_RESULTS_INVALID"),
            (
                "empty adapter",
                [{"adapter": "", "stage": "unit", "status": "fail"}],
                "EVIDENCE_RESULTS_INVALID",
            ),
            (
                "unsupported status",
                [{"adapter": "fixture", "stage": "unit", "status": "unknown"}],
                "EVIDENCE_RESULTS_INVALID",
            ),
            (
                "forged source adapter",
                [{"adapter": "fixture", "stage": "source", "status": "fail"}],
                "EVIDENCE_RESULTS_INVALID",
            ),
            (
                "unknown toolchain adapter",
                [{"adapter": "invented", "stage": "toolchain", "status": "fail"}],
                "EVIDENCE_RESULTS_INVALID",
            ),
            (
                "unknown profile stage",
                [{"adapter": "fixture", "stage": "lint", "status": "fail"}],
                "EVIDENCE_RESULTS_INVALID",
            ),
            (
                "illegal auxiliary metric",
                [{"adapter": "fixture", "stage": "unit-metrics", "status": "fail"}],
                "EVIDENCE_RESULTS_INVALID",
            ),
            (
                "policy uses candidate adapter",
                [{"adapter": "fixture", "stage": "policy", "status": "fail"}],
                "EVIDENCE_RESULTS_INVALID",
            ),
            (
                "policy has suffix",
                [
                    {
                        "adapter": "mergegrounds",
                        "stage": "policy-artifacts",
                        "status": "fail",
                    }
                ],
                "EVIDENCE_RESULTS_INVALID",
            ),
            (
                "candidate stage has unknown adapter",
                [{"adapter": "invented", "stage": "unit", "status": "fail"}],
                "EVIDENCE_RESULTS_INVALID",
            ),
            (
                "only passing records cannot support denial",
                [{"adapter": "fixture", "stage": "unit", "status": "pass"}],
                "EVIDENCE_VERDICT_MISMATCH",
            ),
            (
                "real stage failure",
                [{"adapter": "fixture", "stage": "unit", "status": "fail"}],
                None,
            ),
            (
                "mergegrounds source failure",
                [{"adapter": "mergegrounds", "stage": "source-final", "status": "fail"}],
                None,
            ),
            (
                "bound coverage metric failure",
                [
                    {
                        "adapter": "fixture",
                        "stage": "coverage-metrics",
                        "status": "fail",
                    }
                ],
                None,
            ),
        )
        for label, results, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(
                    expected,
                    mergegrounds.raw_result_reason(
                        self.root, results, subject, expect_allow=False
                    ),
                )

    def test_allow_result_manifest_is_exact_and_revalidated(self) -> None:
        subject = self.subject()
        manifest = [{"kind": "command", "adapter": {"id": "fixture"}, "stage": "unit"}]
        result = {"adapter": "fixture", "stage": "unit", "status": "pass"}

        with mock.patch.object(
            mergegrounds, "expected_allow_result_manifest", return_value=manifest
        ), mock.patch.object(
            mergegrounds, "successful_result_matches", return_value=True
        ) as matches:
            self.assertIsNone(
                mergegrounds.raw_result_reason(
                    self.root, [result], subject, expect_allow=True
                )
            )
            matches.assert_called_once_with(self.root, subject, result, manifest[0])
            self.assertEqual(
                "EVIDENCE_INCOMPLETE",
                mergegrounds.raw_result_reason(self.root, [], subject, expect_allow=True),
            )
            self.assertEqual(
                "EVIDENCE_RESULTS_INVALID",
                mergegrounds.raw_result_reason(
                    self.root, [result, result], subject, expect_allow=True
                ),
            )

        with mock.patch.object(
            mergegrounds, "expected_allow_result_manifest", return_value=None
        ):
            self.assertEqual(
                "EVIDENCE_INCOMPLETE",
                mergegrounds.raw_result_reason(
                    self.root, [result], subject, expect_allow=True
                ),
            )
        with mock.patch.object(
            mergegrounds,
            "expected_allow_result_manifest",
            side_effect=mergegrounds.MergeGroundsError("invalid immutable policy"),
        ):
            self.assertEqual(
                "EVIDENCE_RESULTS_INVALID",
                mergegrounds.raw_result_reason(
                    self.root, [result], subject, expect_allow=True
                ),
            )
        with mock.patch.object(
            mergegrounds, "expected_allow_result_manifest", return_value=manifest
        ), mock.patch.object(
            mergegrounds, "successful_result_matches", return_value=False
        ):
            self.assertEqual(
                "EVIDENCE_RESULTS_INVALID",
                mergegrounds.raw_result_reason(
                    self.root, [result], subject, expect_allow=True
                ),
            )
        with mock.patch.object(
            mergegrounds, "expected_allow_result_manifest", return_value=manifest
        ), mock.patch.object(
            mergegrounds, "successful_result_matches", side_effect=OSError("report raced")
        ):
            self.assertEqual(
                "EVIDENCE_RESULTS_INVALID",
                mergegrounds.raw_result_reason(
                    self.root, [result], subject, expect_allow=True
                ),
            )

    def test_denied_evidence_schema_and_binding_reason_codes_are_exact(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "missing field",
                lambda value: value.pop("artifacts"),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "wrong profile",
                lambda value: value.__setitem__("profile", "full"),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "unknown risk",
                lambda value: value.__setitem__("risk_tier", "R9"),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "non-v4 run id",
                lambda value: value.__setitem__(
                    "run_id", "12345678-1234-1234-8234-123456789abc"
                ),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "malformed run id",
                lambda value: value.__setitem__("run_id", "not-a-uuid"),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "invalid time",
                lambda value: value.__setitem__(
                    "started_at", "2026-09-05T12:00:00+00:00"
                ),
                "EVIDENCE_TIME_INVALID",
            ),
            (
                "reversed time",
                lambda value: value.__setitem__(
                    "finished_at", "2026-09-05T11:59:59Z"
                ),
                "EVIDENCE_TIME_ORDER",
            ),
            (
                "wrong commit",
                lambda value: value.__setitem__("git_commit", "d" * 40),
                "EVIDENCE_SUBJECT_MISMATCH",
            ),
            (
                "invalid tree identity",
                lambda value: value.__setitem__("git_tree", "not-a-tree"),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "wrong tree",
                lambda value: value.__setitem__("git_tree", "d" * 40),
                "EVIDENCE_TREE_MISMATCH",
            ),
            (
                "noncanonical config path",
                lambda value: value["config"].__setitem__(
                    "path", "config/mergegrounds.toml"
                ),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "extra config field",
                lambda value: value["config"].__setitem__("trusted", True),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "wrong policy digest",
                lambda value: value["config"].__setitem__("sha256", "d" * 64),
                "EVIDENCE_POLICY_MISMATCH",
            ),
            (
                "weaker risk tier",
                lambda value: value.__setitem__("risk_tier", "R1"),
                "EVIDENCE_POLICY_MISMATCH",
            ),
            (
                "threshold drift",
                lambda value: value.__setitem__(
                    "thresholds", {"line_coverage": 89.0}
                ),
                "EVIDENCE_POLICY_MISMATCH",
            ),
            (
                "duplicate adapters",
                lambda value: value.__setitem__(
                    "adapters", ["fixture", "fixture"]
                ),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "adapter drift",
                lambda value: value.__setitem__("adapters", ["invented"]),
                "EVIDENCE_ADAPTER_MISMATCH",
            ),
            (
                "all results pass in deny evidence",
                lambda value: value["results"][0].__setitem__("status", "pass"),
                "EVIDENCE_VERDICT_MISMATCH",
            ),
            (
                "unsorted sanitized environment",
                lambda value: value.__setitem__(
                    "sanitized_environment_keys", ["PATH", "CI"]
                ),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "NUL in sanitized environment",
                lambda value: value.__setitem__(
                    "sanitized_environment_keys", ["CI", "PATH\x00FORGED"]
                ),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "invalid tool version value",
                lambda value: value.__setitem__("tool_versions", {"python": 313}),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "artifacts is not an array",
                lambda value: value.__setitem__("artifacts", {}),
                "EVIDENCE_SCHEMA_INVALID",
            ),
            (
                "forged allow verdict on failed runner",
                lambda value: value.update(status="pass", decision="allow"),
                "EVIDENCE_VERDICT_MISMATCH",
            ),
        )
        for label, mutate, expected_reason in cases:
            with self.subTest(label=label):
                evidence = self.denied_evidence()
                mutate(evidence)
                self.assertEqual(
                    (False, expected_reason),
                    mergegrounds.validate_raw_run_evidence(
                        evidence,
                        "pr",
                        self.subject(),
                        1,
                        "failure",
                    ),
                )

        self.assertEqual(
            (True, "EVIDENCE_VALID"),
            mergegrounds.validate_raw_run_evidence(
                self.denied_evidence(),
                "pr",
                self.subject(),
                1,
                "failure",
            ),
        )
        self.assertEqual(
            (False, "EVIDENCE_VERDICT_MISMATCH"),
            mergegrounds.validate_raw_run_evidence(
                self.denied_evidence(),
                "pr",
                self.subject(),
                1,
                "success",
            ),
        )

    def test_allow_clock_reason_is_preserved_before_other_claims(self) -> None:
        evidence = self.denied_evidence()
        evidence.update(status="pass", decision="allow")
        with mock.patch.object(
            mergegrounds,
            "allow_evidence_time_reason",
            return_value="EVIDENCE_TIME_STALE",
        ), mock.patch.object(mergegrounds, "raw_result_reason") as result_validator:
            self.assertEqual(
                (False, "EVIDENCE_TIME_STALE"),
                mergegrounds.validate_raw_run_evidence(
                    evidence,
                    "pr",
                    self.subject(),
                    0,
                    "success",
                    now=dt.datetime(2026, 9, 5, 12, 0, 2, tzinfo=dt.timezone.utc),
                ),
            )
            result_validator.assert_not_called()

    def test_allow_evidence_revalidates_toolchain_artifacts_and_verdict(self) -> None:
        evidence = self.denied_evidence()
        evidence.update(status="pass", decision="allow")
        environment = {"PATH": "/usr/bin"}
        sanitized = ["CI", "PATH"]
        versions = {"python": "3.13"}
        artifacts = [{"path": "dist/app", "sha256": "d" * 64, "bytes": 1}]
        evidence["sanitized_environment_keys"] = sanitized
        evidence["tool_versions"] = versions
        evidence["artifacts"] = artifacts

        patches = (
            mock.patch.object(mergegrounds, "allow_evidence_time_reason", return_value=None),
            mock.patch.object(mergegrounds, "raw_result_reason", return_value=None),
            mock.patch.object(
                mergegrounds, "environment_for", return_value=(environment, sanitized)
            ),
            mock.patch.object(mergegrounds, "tool_versions", return_value=versions),
            mock.patch.object(mergegrounds, "artifact_records", return_value=artifacts),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            self.assertEqual(
                (True, "EVIDENCE_VALID"),
                mergegrounds.validate_raw_run_evidence(
                    evidence,
                    "pr",
                    self.subject(),
                    0,
                    "success",
                    now=dt.datetime(2026, 9, 5, 12, 0, 2, tzinfo=dt.timezone.utc),
                ),
            )

            forged_tools = copy.deepcopy(evidence)
            forged_tools["tool_versions"] = {"python": "forged"}
            self.assertEqual(
                (False, "EVIDENCE_TOOLCHAIN_MISMATCH"),
                mergegrounds.validate_raw_run_evidence(
                    forged_tools, "pr", self.subject(), 0, "success"
                ),
            )

            forged_artifacts = copy.deepcopy(evidence)
            forged_artifacts["artifacts"] = []
            self.assertEqual(
                (False, "EVIDENCE_ARTIFACT_MISMATCH"),
                mergegrounds.validate_raw_run_evidence(
                    forged_artifacts, "pr", self.subject(), 0, "success"
                ),
            )

            self.assertEqual(
                (False, "EVIDENCE_VERDICT_MISMATCH"),
                mergegrounds.validate_raw_run_evidence(
                    evidence, "pr", self.subject(), 0, "failure"
                ),
            )

        with mock.patch.object(
            mergegrounds, "allow_evidence_time_reason", return_value=None
        ), mock.patch.object(
            mergegrounds, "raw_result_reason", return_value=None
        ), mock.patch.object(
            mergegrounds, "environment_for", side_effect=OSError("tool lookup failed")
        ):
            self.assertEqual(
                (False, "EVIDENCE_RESULTS_INVALID"),
                mergegrounds.validate_raw_run_evidence(
                    evidence, "pr", self.subject(), 0, "success"
                ),
            )


class ContractDecisionCoverageTests(unittest.TestCase):
    @staticmethod
    def config(*, baseline: str = "R0") -> dict[str, Any]:
        return {
            "risk_tier": baseline,
            "policy": {"critical_paths": [".mergegrounds/**", ".github/workflows/**"]},
        }

    def test_design_contract_duplicate_id_collections_all_deny(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "decision ids",
                lambda value: value["decisions"].append(
                    copy.deepcopy(value["decisions"][0])
                ),
                "decision ids must be unique",
            ),
            (
                "invariant ids",
                lambda value: value["invariants"].append(
                    copy.deepcopy(value["invariants"][0])
                ),
                "invariant ids must be unique",
            ),
            (
                "trust boundary ids",
                lambda value: value["trust_boundaries"].append(
                    copy.deepcopy(value["trust_boundaries"][0])
                ),
                "trust-boundary ids must be unique",
            ),
            (
                "failure mode ids",
                lambda value: value["failure_modes"].append(
                    copy.deepcopy(value["failure_modes"][0])
                ),
                "failure-mode ids must be unique",
            ),
            (
                "signal ids",
                lambda value: value["observability"]["signals"].append(
                    copy.deepcopy(value["observability"]["signals"][0])
                ),
                "signal ids must be unique",
            ),
            (
                "acceptance ids",
                lambda value: value["evaluation"]["acceptance_criteria"].append(
                    copy.deepcopy(value["evaluation"]["acceptance_criteria"][0])
                ),
                "acceptance criterion ids must be unique",
            ),
            (
                "outcome metric ids",
                lambda value: value["evaluation"]["outcome_metrics"].append(
                    copy.deepcopy(value["evaluation"]["outcome_metrics"][0])
                ),
                "outcome metric ids must be unique",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                contract = design_contract()
                mutate(contract)
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, expected):
                    mergegrounds.validate_design_contract(contract, DESIGN_ID)

    def test_design_contract_scalar_and_oracle_policy_denials_are_precise(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "boolean schema version",
                lambda value: value.__setitem__("schema_version", True),
                "schema_version must be the integer 1",
            ),
            (
                "filename binding",
                lambda value: value.__setitem__(
                    "design_id", "22222222-2222-4222-8222-222222222222"
                ),
                "must match its lowercase UUID filename",
            ),
            (
                "unsupported case class",
                lambda value: value["evaluation"]["acceptance_criteria"][0].__setitem__(
                    "class", "self_review"
                ),
                "class is unsupported",
            ),
            (
                "unsupported oracle kind",
                lambda value: value["evaluation"]["acceptance_criteria"][0][
                    "oracle"
                ].__setitem__("kind", "model_judge"),
                "oracle.kind is unsupported",
            ),
            (
                "zero duration",
                lambda value: value["evaluation"]["outcome_metrics"][0].__setitem__(
                    "baseline_window", "0d"
                ),
                "positive bounded duration",
            ),
            (
                "unsupported direction",
                lambda value: value["evaluation"]["outcome_metrics"][0].__setitem__(
                    "direction", "observe"
                ),
                "direction is unsupported",
            ),
            (
                "boolean numeric target",
                lambda value: value["evaluation"]["outcome_metrics"][0].__setitem__(
                    "target", True
                ),
                "must be a JSON/TOML number",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                contract = design_contract()
                mutate(contract)
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, expected):
                    mergegrounds.validate_design_contract(contract, DESIGN_ID)

        valid = mergegrounds.validate_design_contract(design_contract(), DESIGN_ID)
        self.assertEqual({"AC-POSITIVE", "AC-RECOVERY"}, {
            identifier
            for identifier in valid["acceptance_ids"]
            if identifier in {"AC-POSITIVE", "AC-RECOVERY"}
        })

    def test_change_contract_control_plane_and_evidence_denials_are_precise(self) -> None:
        design_raw = canonical_bytes(design_contract())
        cases: tuple[tuple[str, Mutation, list[str], str], ...] = (
            (
                "boolean schema",
                lambda value: value.__setitem__("schema_version", True),
                ["src/app.py"],
                "schema_version must be the integer 1",
            ),
            (
                "unknown lane",
                lambda value: value.__setitem__("lane", "emergency"),
                ["src/app.py"],
                "lane must be implementation or design-only",
            ),
            (
                "critical path below R4",
                lambda value: None,
                [".mergegrounds/mergegrounds.toml"],
                "critical control-plane path require risk tier R4",
            ),
            (
                "control impact below R4",
                lambda value: value["risk"]["impact_flags"].append("control_plane"),
                ["src/app.py"],
                "control_plane impact requires risk tier R4",
            ),
            (
                "noncanonical design path",
                lambda value: value["design"].__setitem__(
                    "record_path", f"docs/decisions/../{DESIGN_ID}.json"
                ),
                ["src/app.py"],
                "must be exactly",
            ),
            (
                "duplicate acceptance id",
                lambda value: value["acceptance_criteria"].append(
                    copy.deepcopy(value["acceptance_criteria"][0])
                ),
                ["src/app.py"],
                "acceptance criterion ids must be unique",
            ),
            (
                "duplicate failure id",
                lambda value: value["failure_modes"].append(
                    copy.deepcopy(value["failure_modes"][0])
                ),
                ["src/app.py"],
                "failure-mode ids must be unique",
            ),
            (
                "duplicate challenge id",
                lambda value: value["challenge_plan"].append(
                    copy.deepcopy(value["challenge_plan"][0])
                ),
                ["src/app.py"],
                "challenge ids must be unique",
            ),
            (
                "duplicate outcome id",
                lambda value: value["outcome_metric_ids"].append(
                    value["outcome_metric_ids"][0]
                ),
                ["src/app.py"],
                "must not contain duplicate ids",
            ),
            (
                "author claims",
                lambda value: value["evidence_policy"].__setitem__(
                    "author_claims_are_evidence", True
                ),
                ["src/app.py"],
                "author_claims_are_evidence must be false",
            ),
            (
                "AI usage type",
                lambda value: value["ai_assistance"].__setitem__("used", 1),
                ["src/app.py"],
                "used must be a boolean",
            ),
            (
                "AI inventory mismatch",
                lambda value: value["ai_assistance"].__setitem__("used", True),
                ["src/app.py"],
                "systems must be listed exactly",
            ),
        )
        for label, mutate, paths, expected in cases:
            with self.subTest(label=label):
                contract = change_contract(design_raw)
                mutate(contract)
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, expected):
                    mergegrounds.validate_change_contract(
                        contract, CHANGE_ID, self.config(), paths
                    )

    def test_change_contract_accepts_bound_independent_ai_inventory(self) -> None:
        design_raw = canonical_bytes(design_contract())
        contract = change_contract(design_raw)
        contract["ai_assistance"] = {
            "used": True,
            "systems": [
                {
                    "provider": "OpenAI",
                    "model": "reviewed-model",
                    "purposes": ["implementation", "test generation"],
                }
            ],
            "affected_paths": ["src/*.py", "tests/*.py"],
        }
        result = mergegrounds.validate_change_contract(
            contract, CHANGE_ID, self.config(), ["src/app.py"]
        )
        self.assertEqual("R3", result["tier"])
        self.assertEqual(DESIGN_ID, result["record_id"])

    def test_change_contract_cannot_understate_repository_risk_or_ai_scope(self) -> None:
        design_raw = canonical_bytes(design_contract())
        contract = change_contract(design_raw)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "below repository baseline R4"):
            mergegrounds.validate_change_contract(
                contract,
                CHANGE_ID,
                self.config(baseline="R4"),
                ["src/app.py"],
            )

        contract = change_contract(design_raw)
        contract["ai_assistance"] = {
            "used": True,
            "systems": [
                {
                    "provider": "OpenAI",
                    "model": "reviewed-model",
                    "purposes": ["implementation"],
                }
            ],
            "affected_paths": ["../outside.py"],
        }
        with self.assertRaisesRegex(
            mergegrounds.MergeGroundsError, "AI-assisted paths must be canonical"
        ):
            mergegrounds.validate_change_contract(
                contract, CHANGE_ID, self.config(), ["src/app.py"]
            )


class WorkflowAndExceptionDecisionCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_workflow(self, text: str) -> None:
        path = self.root / ".github/workflows/adversarial.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_exceptions(self, text: str) -> None:
        path = self.root / ".mergegrounds/exceptions.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_candidate_workflow_dangerous_controls_are_all_reported(self) -> None:
        self.write_workflow(
            """name: adversarial
on: [pull_request]
permissions: write-all
concurrency:
  group: shared
  cancel-in-progress: true
jobs:
  test:
    runs-on: ${{ github.event.pull_request.title }}
    container: python:latest
    steps:
      - uses: actions/checkout@main
      - uses: ./.github/actions/candidate
      - run: python3 scripts/mergegrounds.py verify-repo --strict
        continue-on-error: true
        env:
          TOKEN: ${{ secrets.REPOSITORY_TOKEN }}
"""
        )
        codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
        self.assertTrue(
            {
                "PYTHON_ISOLATION",
                "CONCURRENCY_INVALID",
                "DYNAMIC_EXECUTION_CONTROL",
                "MUTABLE_CONTAINER_IMAGE",
                "WRITE_ALL",
                "PR_SECRET",
                "SCRIPT_INJECTION",
                "CONTINUE_ON_ERROR",
                "MUTABLE_ACTION",
                "CHECKOUT_CREDENTIALS",
                "CANDIDATE_LOCAL_ACTION",
            }.issubset(codes),
            codes,
        )

    def test_scheduled_read_only_workflow_does_not_taint_secret_text_in_comments(self) -> None:
        self.write_workflow(
            """name: scheduled
on:
  schedule:
    - cron: '0 4 * * *'
permissions:
  contents: read
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - run: echo safe # secrets.REPOSITORY_TOKEN is documentation only
"""
        )
        codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
        self.assertNotIn("PR_SECRET", codes)
        self.assertNotIn("SCRIPT_INJECTION", codes)

    def test_exception_registry_container_errors_are_exact(self) -> None:
        self.assertEqual(
            ["EXCEPTIONS_MISSING"],
            [finding.code for finding in mergegrounds.exception_findings(self.root)],
        )
        cases = (
            ("unterminated = [", "EXCEPTIONS_INVALID"),
            ('schema_version = 1\nexceptions = "not-an-array"\n', "EXCEPTIONS_INVALID"),
            ("schema_version = 1\nexceptions = [42]\n", "EXCEPTION_INVALID"),
        )
        for text, expected in cases:
            with self.subTest(expected=expected):
                self.write_exceptions(text)
                codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
                self.assertIn(expected, codes)

        self.write_exceptions("schema_version = 1\nexceptions = []\n")
        self.assertEqual([], mergegrounds.exception_findings(self.root))

    def test_exception_fields_fail_closed_with_specific_codes(self) -> None:
        record = exception_fixtures.ExceptionPolicyTests("runTest").record()
        cases: tuple[tuple[str, str, str], ...] = (
            (
                'schema = "mergegrounds/exception/v1"',
                'schema = "unknown/v9"',
                "EXCEPTION_SCHEMA",
            ),
            (
                'exception_id = "EXC-2026-0001"',
                'exception_id = "temporary"',
                "EXCEPTION_ID",
            ),
            ('class = "XQ"', 'class = "unknown"', "EXCEPTION_CLASS"),
            ('risk_tier = "R1"', 'risk_tier = "R9"', "EXCEPTION_RISK"),
            (
                'blast_radius = "component"',
                'blast_radius = "internet"',
                "EXCEPTION_BLAST",
            ),
            (
                'underlying_evidence_digest = "sha256:' + "a" * 64 + '"',
                'underlying_evidence_digest = "sha256:forged"',
                "EXCEPTION_EVIDENCE",
            ),
            ('max_uses = 1', 'max_uses = 0', "EXCEPTION_USES"),
            ('renewals = 0', 'renewals = 1', "EXCEPTION_RENEWAL"),
            ('points = 1', 'points = 9', "EXCEPTION_POINTS"),
            (
                'identity = "user:owner@example.invalid"',
                'identity = "owner with spaces"',
                "EXCEPTION_OWNER",
            ),
        )
        for original, replacement, expected in cases:
            with self.subTest(expected=expected):
                self.assertIn(original, record)
                self.write_exceptions(record.replace(original, replacement, 1))
                codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
                self.assertIn(expected, codes)

        invalid_counter = re.sub(r"^uses = 0$", 'uses = "zero"', record, flags=re.MULTILINE)
        self.write_exceptions(invalid_counter)
        self.assertIn(
            "EXCEPTION_COUNTER",
            {finding.code for finding in mergegrounds.exception_findings(self.root)},
        )

    def test_empty_exception_record_reports_every_missing_security_binding(self) -> None:
        self.write_exceptions("schema_version = 1\nexceptions = [{}]\n")
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertTrue(
            {
                "EXCEPTION_INCOMPLETE",
                "EXCEPTION_SCHEMA",
                "EXCEPTION_ID",
                "EXCEPTION_CLASS",
                "EXCEPTION_RISK",
                "EXCEPTION_BLAST",
                "EXCEPTION_CONTROL_DOMAIN",
                "EXCEPTION_CONTROL_UNMAPPED",
                "EXCEPTION_FIELD",
                "EXCEPTION_EVIDENCE",
                "EXCEPTION_SCOPE",
                "EXCEPTION_OWNER",
                "EXCEPTION_QUORUM",
                "EXCEPTION_TIME",
                "EXCEPTION_COUNTER",
            }.issubset(codes),
            codes,
        )

    def test_exception_nested_bindings_and_authorities_have_specific_denials(self) -> None:
        record = exception_fixtures.ExceptionPolicyTests("runTest").record()
        digest = "sha256:" + "a" * 64
        cases: tuple[tuple[str, str, str, str], ...] = (
            (
                "validation digest",
                f'validation_evidence = ["{digest}"]',
                'validation_evidence = ["sha256:forged"]',
                "EXCEPTION_EVIDENCE",
            ),
            (
                "subject missing binding",
                'repository = "example/service"',
                'repository = ""',
                "EXCEPTION_SCOPE",
            ),
            (
                "subject invalid commit",
                'candidate_commit = "' + "b" * 40 + '"',
                'candidate_commit = "mutable-main"',
                "EXCEPTION_SCOPE",
            ),
            (
                "affected fingerprint",
                'finding_fingerprint = "coverage:src/example.py:42"',
                'finding_fingerprint = "not canonical spaces"',
                "EXCEPTION_SCOPE",
            ),
            (
                "action scope",
                'allowed_actions = ["merge"]',
                'allowed_actions = ["Merge Now"]',
                "EXCEPTION_SCOPE",
            ),
            (
                "environment scope",
                'allowed_environments = ["staging"]',
                'allowed_environments = ["Prod Now"]',
                "EXCEPTION_SCOPE",
            ),
            (
                "owner role",
                'role = "service-owner"',
                'role = "self-approver"',
                "EXCEPTION_OWNER",
            ),
            (
                "approver role",
                'role = "domain-owner"',
                'role = "model-reviewer"',
                "EXCEPTION_APPROVER",
            ),
            (
                "owner/approver independence",
                'identity = "user:reviewer@example.invalid"',
                'identity = "user:owner@example.invalid"',
                "EXCEPTION_INDEPENDENCE",
            ),
        )
        for label, original, replacement, expected in cases:
            with self.subTest(label=label):
                self.assertIn(original, record)
                self.write_exceptions(record.replace(original, replacement, 1))
                codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
                self.assertIn(expected, codes)

        singular = record.replace(
            "[[exceptions.approvers]]", "[exceptions.approver]", 1
        )
        self.write_exceptions(singular)
        self.assertEqual([], mergegrounds.exception_findings(self.root))

    def test_exception_time_role_and_budget_branches_deny_explicitly(self) -> None:
        record = exception_fixtures.ExceptionPolicyTests("runTest").record()

        def replace_line(text: str, key: str, value: str) -> str:
            return re.sub(
                rf"^{re.escape(key)} = .*$",
                f"{key} = {value}",
                text,
                count=1,
                flags=re.MULTILINE,
            )

        time_cases = (
            (
                "invalid timestamp",
                replace_line(record, "issued_at", '"not-a-time"'),
                "EXCEPTION_TIME",
            ),
            (
                "future issue",
                replace_line(record, "issued_at", '"2099-01-01T00:00:00Z"'),
                "EXCEPTION_TIME",
            ),
            (
                "excess admission TTL",
                replace_line(record, "expires_at", '"2099-01-01T00:00:00Z"'),
                "EXCEPTION_TTL",
            ),
            (
                "excess remediation TTL",
                replace_line(record, "must_fix_by", '"2099-01-01T00:00:00Z"'),
                "EXCEPTION_REMEDIATION",
            ),
            (
                "overdue remediation",
                replace_line(record, "must_fix_by", '"2000-01-01T00:00:00Z"'),
                "EXCEPTION_OVERDUE",
            ),
        )
        for label, candidate, expected in time_cases:
            with self.subTest(label=label):
                self.write_exceptions(candidate)
                self.assertIn(
                    expected,
                    {finding.code for finding in mergegrounds.exception_findings(self.root)},
                )

        role_cases = (
            (
                "XM authority seats",
                record.replace('class = "XQ"', 'class = "XM"', 1).replace(
                    "points = 1", "points = 3", 1
                ),
            ),
            (
                "XM license seat",
                record.replace('class = "XQ"', 'class = "XM"', 1)
                .replace('control_id = "MG-QLT-004"', 'control_id = "MG-SEC-003"', 1)
                .replace('control_domain = "coverage"', 'control_domain = "license"', 1)
                .replace("points = 1", "points = 3", 1),
            ),
            (
                "XR authority seats",
                record.replace('class = "XQ"', 'class = "XR"', 1)
                .replace('control_id = "MG-QLT-004"', 'control_id = "MG-OPS-001"', 1)
                .replace('control_domain = "coverage"', 'control_domain = "reliability"', 1)
                .replace("points = 1", "points = 2", 1),
            ),
            (
                "R3 authority seats",
                record.replace('risk_tier = "R1"', 'risk_tier = "R3"', 1).replace(
                    "points = 1", "points = 4", 1
                ),
            ),
            (
                "customer security authority",
                record.replace('class = "XQ"', 'class = "XS"', 1)
                .replace('control_id = "MG-QLT-004"', 'control_id = "MG-SEC-003"', 1)
                .replace('control_domain = "coverage"', 'control_domain = "security"', 1)
                .replace('blast_radius = "component"', 'blast_radius = "multi-service/customer"', 1)
                .replace("points = 1", "points = 12", 1),
            ),
            (
                "R3 security authority",
                record.replace('class = "XQ"', 'class = "XS"', 1)
                .replace('control_id = "MG-QLT-004"', 'control_id = "MG-SEC-003"', 1)
                .replace('control_domain = "coverage"', 'control_domain = "security"', 1)
                .replace('risk_tier = "R1"', 'risk_tier = "R3"', 1)
                .replace("points = 1", "points = 16", 1),
            ),
        )
        for label, candidate in role_cases:
            with self.subTest(label=label):
                self.write_exceptions(candidate)
                codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
                self.assertIn("EXCEPTION_AUTHORITY", codes)

        over_budget = record.replace("points = 1", "points = 13", 1)
        self.write_exceptions(over_budget)
        self.assertIn(
            "EXCEPTION_BUDGET",
            {finding.code for finding in mergegrounds.exception_findings(self.root)},
        )

        xs = (
            record.replace('class = "XQ"', 'class = "XS"', 1)
            .replace('control_id = "MG-QLT-004"', 'control_id = "MG-SEC-003"', 1)
            .replace('control_domain = "coverage"', 'control_domain = "security"', 1)
            .replace("points = 1", "points = 4", 1)
        )
        second = xs.replace("schema_version = 1\n", "", 1).replace(
            'exception_id = "EXC-2026-0001"',
            'exception_id = "EXC-2026-0002"',
            1,
        )
        self.write_exceptions(xs + "\n" + second)
        self.assertIn(
            "EXCEPTION_BUDGET",
            {finding.code for finding in mergegrounds.exception_findings(self.root)},
        )


class AIReportDecisionCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = RepositoryFixture()
        cls.policy = ai.load_policy(cls.fixture.root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.close()

    def assert_report_denied(self, mutate: Mutation, expected_code: str) -> None:
        report = self.fixture.report()
        mutate(report)
        with self.assertRaises(ai.AIAssuranceError) as caught:
            ai._validate_report(
                self.policy,
                report,
                dt.datetime.now(dt.timezone.utc),
            )
        self.assertEqual(expected_code, caught.exception.code)

    def test_report_top_level_producer_and_subject_bindings_deny_exactly(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "boolean schema version",
                lambda report: report.__setitem__("schema_version", True),
                "AI_REPORT_VERSION",
            ),
            (
                "unknown top-level key",
                lambda report: report.__setitem__("self_approved", True),
                "AI_SCHEMA_KEYS",
            ),
            (
                "non-UTC timestamp",
                lambda report: report.__setitem__(
                    "generated_at", "2026-09-05T12:00:00+00:00"
                ),
                "AI_TIMESTAMP",
            ),
            (
                "unknown producer class",
                lambda report: report["producer"].__setitem__(
                    "class", "future_attestation"
                ),
                "AI_PRODUCER_CLASS",
            ),
            (
                "source commit mismatch",
                lambda report: report["subject"].__setitem__(
                    "source_commit", "f" * 40
                ),
                "AI_SOURCE_BINDING",
            ),
            (
                "subject digest mismatch",
                lambda report: report["subject"].__setitem__(
                    "dataset_digest", "sha256:" + "f" * 64
                ),
                "AI_SUBJECT_BINDING",
            ),
            (
                "component inventory mismatch",
                lambda report: report["subject"]["components"]["inference"].__setitem__(
                    "runtime_digest", "sha256:" + "f" * 64
                ),
                "AI_COMPONENT_BINDING",
            ),
            (
                "protected policy mismatch",
                lambda report: report["subject"]["protected_policies"].__setitem__(
                    "sandbox", "sha256:" + "f" * 64
                ),
                "AI_POLICY_BINDING",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                self.assert_report_denied(mutate, expected)

    def test_report_case_slice_metric_and_summary_denials_are_exact(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "unsupported case status",
                lambda report: report["cases"][0].__setitem__(
                    "status", "self_reviewed"
                ),
                "AI_CASE_STATUS",
            ),
            (
                "case input mismatch",
                lambda report: report["cases"][0].__setitem__(
                    "input_digest", "sha256:" + "f" * 64
                ),
                "AI_CASE_INPUT_BINDING",
            ),
            (
                "case expectation mismatch",
                lambda report: report["cases"][0].__setitem__(
                    "expectation_digest", "sha256:" + "f" * 64
                ),
                "AI_CASE_EXPECTATION_BINDING",
            ),
            (
                "slice set duplicate",
                lambda report: report["slice_results"].append(
                    copy.deepcopy(report["slice_results"][0])
                ),
                "AI_SLICE_SET",
            ),
            (
                "slice case binding",
                lambda report: report["slice_results"][0].__setitem__(
                    "case_ids", report["slice_results"][0]["case_ids"][:-1]
                ),
                "AI_SLICE_BINDING",
            ),
            (
                "unexpected metric",
                lambda report: report["metrics"][0].__setitem__(
                    "metric", "invented-score"
                ),
                "AI_METRIC_SET",
            ),
            (
                "metric denominator not sample count",
                lambda report: report["metrics"][0].update(
                    value=1.0,
                    numerator=report["metrics"][0]["sample_count"] + 1,
                    denominator=report["metrics"][0]["sample_count"] + 1,
                ),
                "AI_METRIC_DENOMINATOR_BINDING",
            ),
            (
                "metric set duplicate",
                lambda report: report["metrics"].append(
                    copy.deepcopy(report["metrics"][0])
                ),
                "AI_METRIC_SET",
            ),
            (
                "summary total mismatch",
                lambda report: report["summary"].__setitem__("total", 0),
                "AI_SUMMARY_INVALID",
            ),
            (
                "summary passed mismatch",
                lambda report: report["summary"].__setitem__("passed", 0),
                "AI_SUMMARY_INVALID",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                self.assert_report_denied(mutate, expected)

    def test_report_collection_types_and_zero_cases_deny_before_admission(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "zero cases",
                lambda report: report.__setitem__("cases", []),
                "AI_REPORT_ZERO_CASES",
            ),
            (
                "slice results object",
                lambda report: report.__setitem__("slice_results", {}),
                "AI_SCHEMA_TYPE",
            ),
            (
                "metrics object",
                lambda report: report.__setitem__("metrics", {}),
                "AI_SCHEMA_TYPE",
            ),
            (
                "comparisons object",
                lambda report: report.__setitem__("comparisons", {}),
                "AI_SCHEMA_TYPE",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                self.assert_report_denied(mutate, expected)

    def test_true_policy_internal_cross_field_denials_are_exact(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "protected policy format",
                lambda policy: policy["protected_policies"]["provider"].__setitem__(
                    "path", ".mergegrounds/policies/ai-provider.txt"
                ),
                "AI_POLICY_FORMAT",
            ),
            (
                "protected policy digest",
                lambda policy: policy["protected_policies"]["provider"].__setitem__(
                    "sha256", "sha256:" + "f" * 64
                ),
                "AI_POLICY_DIGEST",
            ),
            (
                "report format",
                lambda policy: policy["evaluation"].__setitem__(
                    "report_path", ".mergegrounds/evidence/ai-assurance.toml"
                ),
                "AI_REPORT_FORMAT",
            ),
            (
                "empty cases",
                lambda policy: policy["evaluation"].__setitem__("cases", []),
                "AI_SCHEMA_EMPTY",
            ),
            (
                "duplicate cases",
                lambda policy: policy["evaluation"]["cases"].append(
                    copy.deepcopy(policy["evaluation"]["cases"][0])
                ),
                "AI_CASE_DUPLICATE",
            ),
            (
                "case manifest mismatch",
                lambda policy: policy["evaluation"]["expected_case_ids"].pop(),
                "AI_CASE_MANIFEST",
            ),
            (
                "critical slice unrepresented",
                lambda policy: policy["evaluation"].__setitem__(
                    "critical_slices", ["unrepresented-security-slice"]
                ),
                "AI_CRITICAL_SLICE_MISSING",
            ),
            (
                "required case not critical",
                lambda policy: policy["evaluation"]["cases"][0].__setitem__(
                    "critical", False
                ),
                "AI_REQUIRED_CASE_NOT_CRITICAL",
            ),
            (
                "empty thresholds",
                lambda policy: policy["evaluation"].__setitem__("thresholds", []),
                "AI_SCHEMA_EMPTY",
            ),
            (
                "duplicate thresholds",
                lambda policy: policy["evaluation"]["thresholds"].append(
                    copy.deepcopy(policy["evaluation"]["thresholds"][0])
                ),
                "AI_THRESHOLD_DUPLICATE",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                raw = tomllib.loads(self.fixture.config_path.read_text(encoding="utf-8"))
                mutate(raw)
                with self.assertRaises(ai.AIAssuranceError) as caught:
                    ai._validate_true_policy(
                        self.fixture.root,
                        raw,
                        self.policy.config_digest,
                        (self.policy.source_commit, self.policy.source_tree),
                    )
                self.assertEqual(expected, caught.exception.code)

    def test_valid_report_is_accepted_by_internal_closed_world_validator(self) -> None:
        report = self.fixture.report()
        ai._validate_report(
            self.policy,
            report,
            dt.datetime.now(dt.timezone.utc),
        )
        generated_at = dt.datetime.fromisoformat(
            report["generated_at"].replace("Z", "+00:00")
        )
        ai._validate_report(
            self.policy,
            report,
            generated_at.replace(tzinfo=None),
        )


class AIFineTuningDecisionCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = RepositoryFixture(("fine_tuning",))
        cls.policy = ai.load_policy(cls.fixture.root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.close()

    def assert_report_denied(self, mutate: Mutation, expected_code: str) -> None:
        report = self.fixture.report()
        mutate(report)
        with self.assertRaises(ai.AIAssuranceError) as caught:
            ai._validate_report(
                self.policy,
                report,
                dt.datetime.now(dt.timezone.utc),
            )
        self.assertEqual(expected_code, caught.exception.code)

    def test_comparison_policy_schema_and_cross_bindings_deny_exactly(self) -> None:
        assert self.policy.evaluation is not None
        values = list(copy.deepcopy(self.policy.evaluation["comparison_policies"]))
        cases = list(self.policy.evaluation["cases"])
        thresholds = list(self.policy.evaluation["thresholds"])
        components = self.policy.components

        with self.assertRaises(ai.AIAssuranceError) as caught:
            ai._validate_comparison_policies(
                {}, self.policy.capabilities, components, cases, thresholds
            )
        self.assertEqual("AI_SCHEMA_TYPE", caught.exception.code)

        with self.assertRaises(ai.AIAssuranceError) as caught:
            ai._validate_comparison_policies(
                values, ("inference",), components, cases, thresholds
            )
        self.assertEqual("AI_COMPARISON_POLICY_UNEXPECTED", caught.exception.code)

        cases_table: tuple[tuple[str, Callable[[list[dict[str, Any]]], None], str], ...] = (
            (
                "missing policies",
                lambda policies: policies.clear(),
                "AI_COMPARISON_POLICY_MISSING",
            ),
            (
                "invalid kind",
                lambda policies: policies[0].__setitem__("kind", "candidate"),
                "AI_COMPARISON_POLICY_SET",
            ),
            (
                "duplicate kind",
                lambda policies: policies[1].__setitem__(
                    "kind", policies[0]["kind"]
                ),
                "AI_COMPARISON_POLICY_SET",
            ),
            (
                "baseline mismatch",
                lambda policies: policies[0].__setitem__(
                    "baseline_digest", "sha256:" + "f" * 64
                ),
                "AI_COMPARISON_POLICY_BASELINE",
            ),
            (
                "case set mismatch",
                lambda policies: policies[0]["case_ids"].pop(),
                "AI_COMPARISON_POLICY_CASES",
            ),
            (
                "manifest mismatch",
                lambda policies: policies[0].__setitem__(
                    "input_manifest_digest", "sha256:" + "f" * 64
                ),
                "AI_COMPARISON_INPUT_MANIFEST",
            ),
            (
                "missing metrics",
                lambda policies: policies[0].__setitem__("metrics", []),
                "AI_COMPARISON_METRIC_MISSING",
            ),
            (
                "duplicate metric",
                lambda policies: policies[0]["metrics"].append(
                    copy.deepcopy(policies[0]["metrics"][0])
                ),
                "AI_COMPARISON_METRIC_DUPLICATE",
            ),
            (
                "missing production kind",
                lambda policies: policies.pop(),
                "AI_COMPARISON_POLICY_SET",
            ),
        )
        for label, mutate, expected in cases_table:
            with self.subTest(label=label):
                candidate = copy.deepcopy(values)
                mutate(candidate)
                with self.assertRaises(ai.AIAssuranceError) as caught:
                    ai._validate_comparison_policies(
                        candidate,
                        self.policy.capabilities,
                        components,
                        cases,
                        thresholds,
                    )
                self.assertEqual(expected, caught.exception.code)

        normalized = ai._validate_comparison_policies(
            values,
            self.policy.capabilities,
            components,
            cases,
            thresholds,
        )
        self.assertEqual({"base_model", "production"}, {item["kind"] for item in normalized})

    def test_fine_tuning_report_comparison_failures_are_exact(self) -> None:
        cases: tuple[tuple[str, Mutation, str], ...] = (
            (
                "invalid comparison kind",
                lambda report: report["comparisons"][0].__setitem__(
                    "kind", "candidate"
                ),
                "AI_COMPARISON_SET",
            ),
            (
                "comparison failed",
                lambda report: report["comparisons"][0].__setitem__(
                    "status", "failed"
                ),
                "AI_COMPARISON_FAILED",
            ),
            (
                "input manifest mismatch",
                lambda report: report["comparisons"][0].__setitem__(
                    "input_manifest_digest", "sha256:" + "f" * 64
                ),
                "AI_COMPARISON_INPUT_MANIFEST",
            ),
            (
                "cross-kind report replay",
                lambda report: report["comparisons"][1].__setitem__(
                    "baseline_report_digest",
                    report["comparisons"][0]["baseline_report_digest"],
                ),
                "AI_COMPARISON_CROSS_KIND_REPLAY",
            ),
            (
                "cross-kind result replay",
                lambda report: report["comparisons"][1].__setitem__(
                    "baseline_result_digest",
                    report["comparisons"][0]["baseline_result_digest"],
                ),
                "AI_COMPARISON_CROSS_KIND_REPLAY",
            ),
            (
                "empty case results",
                lambda report: report["comparisons"][0].__setitem__(
                    "case_results", []
                ),
                "AI_COMPARISON_CASE_RESULTS",
            ),
            (
                "duplicate case result",
                lambda report: report["comparisons"][0]["case_results"].append(
                    copy.deepcopy(report["comparisons"][0]["case_results"][0])
                ),
                "AI_COMPARISON_CASE_RESULTS",
            ),
            (
                "expectation mismatch",
                lambda report: report["comparisons"][0]["case_results"][0].__setitem__(
                    "expectation_digest", "sha256:" + "f" * 64
                ),
                "AI_COMPARISON_EXPECTATION_BINDING",
            ),
            (
                "incomplete case results",
                lambda report: report["comparisons"][0]["case_results"].pop(),
                "AI_COMPARISON_CASE_RESULTS",
            ),
            (
                "empty metric deltas",
                lambda report: report["comparisons"][0].__setitem__(
                    "metric_deltas", []
                ),
                "AI_COMPARISON_METRIC_SET",
            ),
            (
                "duplicate metric delta",
                lambda report: report["comparisons"][0]["metric_deltas"].append(
                    copy.deepcopy(report["comparisons"][0]["metric_deltas"][0])
                ),
                "AI_COMPARISON_METRIC_SET",
            ),
            (
                "metric cases mismatch",
                lambda report: report["comparisons"][0]["metric_deltas"][0][
                    "case_ids"
                ].pop(),
                "AI_COMPARISON_METRIC_CASES",
            ),
            (
                "metric sample mismatch",
                lambda report: report["comparisons"][0]["metric_deltas"][0].__setitem__(
                    "sample_count",
                    report["comparisons"][0]["metric_deltas"][0]["sample_count"]
                    + 1,
                ),
                "AI_COMPARISON_METRIC_SAMPLES",
            ),
            (
                "candidate observation mismatch",
                lambda report: report["comparisons"][0]["metric_deltas"][0].__setitem__(
                    "candidate_observation_set_digest", "sha256:" + "f" * 64
                ),
                "AI_COMPARISON_CANDIDATE_BINDING",
            ),
            (
                "baseline observation mismatch",
                lambda report: report["comparisons"][0]["metric_deltas"][0].__setitem__(
                    "baseline_observation_set_digest", "sha256:" + "f" * 64
                ),
                "AI_COMPARISON_BASELINE_BINDING",
            ),
            (
                "candidate metric mismatch",
                lambda report: report["comparisons"][0]["metric_deltas"][0].__setitem__(
                    "candidate_value", 0.5
                ),
                "AI_COMPARISON_CANDIDATE_BINDING",
            ),
            (
                "regression arithmetic mismatch",
                lambda report: report["comparisons"][0]["metric_deltas"][0].__setitem__(
                    "regression", 0.25
                ),
                "AI_COMPARISON_REGRESSION_ARITHMETIC",
            ),
            (
                "baseline result digest mismatch",
                lambda report: report["comparisons"][0].__setitem__(
                    "baseline_result_digest", "sha256:" + "f" * 64
                ),
                "AI_COMPARISON_RESULT_BINDING",
            ),
            (
                "attestation binding mismatch",
                lambda report: report["comparisons"][0].__setitem__(
                    "comparison_binding_digest", "sha256:" + "f" * 64
                ),
                "AI_COMPARISON_ATTESTATION_BINDING",
            ),
            (
                "missing production comparison",
                lambda report: report["comparisons"].pop(),
                "AI_COMPARISON_SET",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                self.assert_report_denied(mutate, expected)


if __name__ == "__main__":
    unittest.main()
