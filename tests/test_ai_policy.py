from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ai_assurance_under_test", ROOT / "scripts" / "ai_assurance.py"
)
assert SPEC and SPEC.loader
ai = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ai
SPEC.loader.exec_module(ai)


def digest(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def quoted(value: str) -> str:
    return json.dumps(value)


def array(values: list[str]) -> str:
    return "[" + ", ".join(quoted(value) for value in values) + "]"


def component_values(capability: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for field in ai.COMPONENT_FIELDS[capability]:
        if field in ai.COMPONENT_ID_FIELDS:
            result[field] = f"exact:{capability}:{field}:v1"
        else:
            result[field] = digest(f"{capability}:{field}:v1")
    return result


class RepositoryFixture:
    def __init__(self, capabilities: tuple[str, ...] = ("inference",)) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "config", "user.email", "ai-policy@example.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "AI Policy Tests"], cwd=self.root, check=True
        )
        self.capabilities = capabilities
        self.components = {cap: component_values(cap) for cap in capabilities}
        self.authoritative_producers = [
            {"class": "trusted_execution", "id": "ci-evaluator-v1"}
        ]
        self.policy_files = {
            name: (json.dumps({"policy": name, "revision": 1}) + "\n").encode("utf-8")
            for name in ("evaluation", "provider", "sandbox")
        }
        self.cases = self._cases()
        self.critical_slices = ["critical-security"]
        self.thresholds = [
            {
                "metric": "case-pass-rate",
                "scope": "aggregate",
                "operator": "gte",
                "value": 1.0,
                "case_ids": [case["id"] for case in self.cases],
                "sample_count_mode": "exact",
                "sample_count": len(self.cases),
            },
            {
                "metric": "case-pass-rate",
                "scope": "critical-security",
                "operator": "gte",
                "value": 1.0,
                "case_ids": [case["id"] for case in self.cases],
                "sample_count_mode": "exact",
                "sample_count": len(self.cases),
            },
        ]
        self.comparison_direction = "higher_is_better"
        self.comparison_max_regression = 0.0
        self._write_policy_files()
        self.write_config()
        (self.root / ".gitignore").write_text(
            ".mergegrounds/evidence/*\n!.mergegrounds/evidence/.gitkeep\n",
            encoding="utf-8",
        )
        (self.root / "source.txt").write_text("candidate\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "candidate"], cwd=self.root, check=True)
        self.write_report()

    def _cases(self) -> list[dict[str, Any]]:
        requirements: list[tuple[str, str]] = []
        for capability in self.capabilities:
            requirements.extend(
                (capability, requirement)
                for requirement in sorted(ai.REQUIRED_REQUIREMENTS[capability])
            )
        cases = [
            {
                "id": f"case-{index:02d}-{requirement.replace('_', '-')}",
                "class": sorted(ai.REQUIREMENT_ALLOWED_CLASSES[requirement])[0],
                "requirement": requirement,
                "capabilities": [capability],
                "slices": ["critical-security"],
                "critical": True,
                "input_digest": digest(f"input:{capability}:{requirement}:v1"),
                "expectation_digest": digest(f"expectation:{capability}:{requirement}:v1"),
                "sample_count_mode": "exact",
                "sample_count": 1,
            }
            for index, (capability, requirement) in enumerate(requirements)
        ]
        represented = {case["class"] for case in cases}
        for missing in sorted(ai.CASE_CLASSES - represented):
            cases.append(
                {
                    "id": f"case-{len(cases):02d}-product-{missing}",
                    "class": missing,
                    "requirement": "product_specific",
                    "capabilities": [self.capabilities[0]],
                    "slices": ["critical-security"],
                    "critical": True,
                    "input_digest": digest(f"input:product:{missing}:v1"),
                    "expectation_digest": digest(f"expectation:product:{missing}:v1"),
                    "sample_count_mode": "exact",
                    "sample_count": 1,
                }
            )
        return cases

    @property
    def config_path(self) -> Path:
        return self.root / ai.CANONICAL_CONFIG

    @property
    def report_path(self) -> Path:
        return self.root / ".mergegrounds/evidence/ai-assurance.json"

    def _write_policy_files(self) -> None:
        directory = self.root / ".mergegrounds/policies"
        directory.mkdir(parents=True, exist_ok=True)
        for name, data in self.policy_files.items():
            (directory / f"ai-{name}.json").write_bytes(data)

    def render_config(self) -> str:
        lines = [
            f"schema_version = {ai.SCHEMA_VERSION}",
            "product_ai = true",
            "fail_closed = true",
            f"capabilities = {array(list(self.capabilities))}",
            "",
            "[inventory]",
            'product_id = "acme-ai-product-v1"',
            'repository_id = "acme/evaluation-repository"',
        ]
        for capability in self.capabilities:
            lines.extend(["", f"[components.{capability}]"])
            for key, value in self.components[capability].items():
                lines.append(f"{key} = {quoted(value)}")
        for name in ("evaluation", "provider", "sandbox"):
            path = f".mergegrounds/policies/ai-{name}.json"
            lines.extend(
                [
                    "",
                    f"[protected_policies.{name}]",
                    f"path = {quoted(path)}",
                    f"sha256 = {quoted(digest(self.policy_files[name]))}",
                ]
            )
        lines.extend(
            [
                "",
                "[evaluation]",
                'report_path = ".mergegrounds/evidence/ai-assurance.json"',
                f"harness_digest = {quoted(digest('evaluation-harness-v1'))}",
                f"dataset_digest = {quoted(digest('private-dataset-snapshot-v1'))}",
                "max_report_age_seconds = 3600",
                f"expected_case_ids = {array([case['id'] for case in self.cases])}",
                f"critical_slices = {array(self.critical_slices)}",
                *(('comparison_policies = []',) if "fine_tuning" not in self.capabilities else ()),
            ]
        )
        for producer in self.authoritative_producers:
            lines.extend(
                [
                    "",
                    "[[evaluation.authoritative_producers]]",
                    f"class = {quoted(producer['class'])}",
                    f"id = {quoted(producer['id'])}",
                ]
            )
        for case in self.cases:
            lines.extend(
                [
                    "",
                    "[[evaluation.cases]]",
                    f"id = {quoted(case['id'])}",
                    f"class = {quoted(case['class'])}",
                    f"requirement = {quoted(case['requirement'])}",
                    f"capabilities = {array(case['capabilities'])}",
                    f"slices = {array(case['slices'])}",
                    f"critical = {str(case['critical']).lower()}",
                    f"input_digest = {quoted(case['input_digest'])}",
                    f"expectation_digest = {quoted(case['expectation_digest'])}",
                    f"sample_count_mode = {quoted(case['sample_count_mode'])}",
                    f"sample_count = {case['sample_count']}",
                ]
            )
        for threshold in self.thresholds:
            lines.extend(
                [
                    "",
                    "[[evaluation.thresholds]]",
                    f"metric = {quoted(threshold['metric'])}",
                    f"scope = {quoted(threshold['scope'])}",
                    f"operator = {quoted(threshold['operator'])}",
                    f"value = {threshold['value']}",
                    f"case_ids = {array(threshold['case_ids'])}",
                    f"sample_count_mode = {quoted(threshold['sample_count_mode'])}",
                    f"sample_count = {threshold['sample_count']}",
                ]
            )
        if "fine_tuning" in self.capabilities:
            fine_ids = [
                case["id"] for case in self.cases if case["requirement"].startswith("finetune_")
            ]
            manifest = ai._comparison_input_manifest_digest(self.cases, fine_ids)
            for kind, field in (
                ("base_model", "base_model_digest"),
                ("production", "production_baseline_digest"),
            ):
                lines.extend(
                    [
                        "",
                        "[[evaluation.comparison_policies]]",
                        f"kind = {quoted(kind)}",
                        f"baseline_digest = {quoted(self.components['fine_tuning'][field])}",
                        f"case_ids = {array(fine_ids)}",
                        f"input_manifest_digest = {quoted(manifest)}",
                        "",
                        "[[evaluation.comparison_policies.metrics]]",
                        'metric = "case-pass-rate"',
                        'scope = "aggregate"',
                        f"case_ids = {array(fine_ids)}",
                        'sample_count_mode = "exact"',
                        f"sample_count = {len(fine_ids)}",
                        f"direction = {quoted(self.comparison_direction)}",
                        f"max_regression = {self.comparison_max_regression}",
                    ]
                )
        return "\n".join(lines) + "\n"

    def write_config(self, text: str | None = None) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(text if text is not None else self.render_config(), encoding="utf-8")

    def commit_controls(self, message: str = "update assurance controls") -> None:
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", message], cwd=self.root, check=True)

    def report(self) -> dict[str, Any]:
        policy = ai.load_policy(self.root)
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{commit}"], cwd=self.root, text=True
        ).strip()
        tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=self.root, text=True
        ).strip()
        cases = []
        for case in self.cases:
            cases.append(
                {
                    "id": case["id"],
                    "class": case["class"],
                    "requirement": case["requirement"],
                    "capabilities": copy.deepcopy(case["capabilities"]),
                    "slices": copy.deepcopy(case["slices"]),
                    "critical": case["critical"],
                    "status": "passed",
                    "attempts": 1,
                    "oracle": "deterministic",
                    "input_digest": case["input_digest"],
                    "expectation_digest": case["expectation_digest"],
                    "observations_digest": digest(f"observation:{case['id']}"),
                    "sample_count": case["sample_count"],
                }
            )
        report_case_map = {case["id"]: case for case in cases}
        slice_ids = sorted({slice_id for case in cases for slice_id in case["slices"]})
        slice_results: list[dict[str, Any]] = []
        for slice_id in slice_ids:
            ids = [case["id"] for case in cases if slice_id in case["slices"]]
            slice_results.append(
                {
                    "id": slice_id,
                    "status": "passed",
                    "case_ids": ids,
                    "sample_count": sum(report_case_map[case_id]["sample_count"] for case_id in ids),
                    "observation_set_digest": ai._observation_set_digest(ids, report_case_map),
                }
            )
        metrics: list[dict[str, Any]] = []
        for threshold in self.thresholds:
            ids = list(threshold["case_ids"])
            sample_count = sum(report_case_map[case_id]["sample_count"] for case_id in ids)
            metrics.append(
                {
                    "metric": threshold["metric"],
                    "scope": threshold["scope"],
                    "value": 1.0,
                    "numerator": sample_count,
                    "denominator": sample_count,
                    "case_ids": ids,
                    "sample_count": sample_count,
                    "observation_set_digest": ai._observation_set_digest(ids, report_case_map),
                }
            )
        report_metric_map = {(item["metric"], item["scope"]): item for item in metrics}
        comparisons: list[dict[str, Any]] = []
        for comparison_policy in (policy.evaluation or {}).get("comparison_policies", []):
            kind = comparison_policy["kind"]
            ids = list(comparison_policy["case_ids"])
            case_results: list[dict[str, Any]] = []
            normalized_case_results: dict[str, dict[str, Any]] = {}
            for case_id in ids:
                case = report_case_map[case_id]
                baseline_observations = digest(f"baseline:{kind}:{case_id}")
                case_results.append(
                    {
                        "id": case_id,
                        "candidate_input_digest": case["input_digest"],
                        "baseline_input_digest": case["input_digest"],
                        "expectation_digest": case["expectation_digest"],
                        "candidate_observations_digest": case["observations_digest"],
                        "baseline_observations_digest": baseline_observations,
                        "candidate_sample_count": case["sample_count"],
                        "baseline_sample_count": case["sample_count"],
                    }
                )
                normalized_case_results[case_id] = {
                    "id": case_id,
                    "input_digest": case["input_digest"],
                    "expectation_digest": case["expectation_digest"],
                    "candidate_observations_digest": case["observations_digest"],
                    "baseline_observations_digest": baseline_observations,
                    "sample_count": case["sample_count"],
                }
            metric_deltas: list[dict[str, Any]] = []
            normalized_metric_results: dict[tuple[str, str], dict[str, Any]] = {}
            for metric_policy in comparison_policy["metrics"]:
                key = (metric_policy["metric"], metric_policy["scope"])
                ids_for_metric = list(metric_policy["case_ids"])
                candidate_metric = report_metric_map[key]
                baseline_case_view = {
                    case_id: {
                        "input_digest": normalized_case_results[case_id]["input_digest"],
                        "expectation_digest": normalized_case_results[case_id]["expectation_digest"],
                        "observations_digest": normalized_case_results[case_id][
                            "baseline_observations_digest"
                        ],
                        "sample_count": normalized_case_results[case_id]["sample_count"],
                    }
                    for case_id in ids_for_metric
                }
                baseline_observation_set = ai._observation_set_digest(
                    ids_for_metric, baseline_case_view, role="baseline"
                )
                metric_deltas.append(
                    {
                        "metric": key[0],
                        "scope": key[1],
                        "case_ids": ids_for_metric,
                        "sample_count": candidate_metric["sample_count"],
                        "candidate_observation_set_digest": candidate_metric[
                            "observation_set_digest"
                        ],
                        "baseline_observation_set_digest": baseline_observation_set,
                        "candidate_value": 1.0,
                        "baseline_value": 1.0,
                        "delta": 0.0,
                        "regression": 0.0,
                    }
                )
                normalized_metric_results[key] = {
                    "case_ids": ids_for_metric,
                    "sample_count": candidate_metric["sample_count"],
                    "candidate_observation_set_digest": candidate_metric[
                        "observation_set_digest"
                    ],
                    "baseline_observation_set_digest": baseline_observation_set,
                    "candidate_value": 1.0,
                    "baseline_value": 1.0,
                }
            candidate_report_digest = digest(f"candidate-report:{kind}")
            baseline_report_digest = digest(f"baseline-report:{kind}")
            candidate_result_digest = ai._comparison_result_digest(
                "candidate",
                kind,
                comparison_policy["baseline_digest"],
                comparison_policy["input_manifest_digest"],
                ids,
                normalized_case_results,
                normalized_metric_results,
            )
            baseline_result_digest = ai._comparison_result_digest(
                "baseline",
                kind,
                comparison_policy["baseline_digest"],
                comparison_policy["input_manifest_digest"],
                ids,
                normalized_case_results,
                normalized_metric_results,
            )
            comparisons.append(
                {
                    "kind": kind,
                    "baseline_digest": comparison_policy["baseline_digest"],
                    "status": "passed",
                    "case_ids": ids,
                    "input_manifest_digest": comparison_policy["input_manifest_digest"],
                    "candidate_report_digest": candidate_report_digest,
                    "baseline_report_digest": baseline_report_digest,
                    "candidate_result_digest": candidate_result_digest,
                    "baseline_result_digest": baseline_result_digest,
                    "comparison_binding_digest": ai._comparison_binding_digest(
                        kind=kind,
                        baseline_digest=comparison_policy["baseline_digest"],
                        input_manifest_digest=comparison_policy["input_manifest_digest"],
                        candidate_report_digest=candidate_report_digest,
                        baseline_report_digest=baseline_report_digest,
                        candidate_result_digest=candidate_result_digest,
                        baseline_result_digest=baseline_result_digest,
                    ),
                    "case_results": case_results,
                    "metric_deltas": metric_deltas,
                }
            )
        return {
            "schema_version": ai.SCHEMA_VERSION,
            "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
                "+00:00", "Z"
            ),
            "completeness": "complete",
            "producer": {
                "class": "trusted_execution",
                "id": "ci-evaluator-v1",
                "run_id": "run-00000001",
                "attestation_digest": digest("external-attestation-v1"),
            },
            "subject": {
                "source_commit": commit,
                "source_tree": tree,
                "config_digest": policy.config_digest,
                "harness_digest": policy.evaluation["harness_digest"],
                "dataset_digest": policy.evaluation["dataset_digest"],
                "case_set_digest": ai.case_set_digest(policy),
                "components": copy.deepcopy(self.components),
                "protected_policies": {
                    name: reference["sha256"]
                    for name, reference in policy.protected_policies.items()
                },
            },
            "cases": cases,
            "slice_results": slice_results,
            "metrics": metrics,
            "summary": {
                "total": len(self.cases),
                "passed": len(self.cases),
                "failed": 0,
                "skipped": 0,
                "errors": 0,
                "partial": 0,
                "stale": 0,
                "inconclusive": 0,
                "retries": 0,
            },
            "comparisons": comparisons,
        }

    def write_report(self, report: dict[str, Any] | None = None) -> None:
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.write_text(
            json.dumps(report if report is not None else self.report(), sort_keys=True), encoding="utf-8"
        )

    def decision_for(self, report: dict[str, Any]) -> Any:
        self.write_report(report)
        return ai.evaluate_repository(self.root)

    def close(self) -> None:
        self.temp.cleanup()


class NonAIRepositoryFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "config", "user.email", "ai-policy@example.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "AI Policy Tests"], cwd=self.root, check=True
        )
        config = self.root / ai.CANONICAL_CONFIG
        config.parent.mkdir(parents=True)
        config.write_text(
            f"schema_version={ai.SCHEMA_VERSION}\n"
            "product_ai=false\nfail_closed=true\ncapabilities=[]\n",
            encoding="utf-8",
        )
        (self.root / ".gitignore").write_text(
            ".mergegrounds/evidence/*\n!.mergegrounds/evidence/.gitkeep\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "non-ai policy"], cwd=self.root, check=True)

    def close(self) -> None:
        self.temp.cleanup()


class AIAssurancePolicyTests(unittest.TestCase):
    def test_repository_default_is_explicit_and_not_applicable(self) -> None:
        fixture = NonAIRepositoryFixture()
        try:
            decision = ai.evaluate_repository(fixture.root)
            self.assertTrue(decision.allowed, decision.as_dict())
            self.assertFalse(decision.product_ai)
            self.assertEqual("AI_NOT_APPLICABLE", decision.findings[0].code)
            self.assertTrue(any("holdout" in item for item in decision.limitations))
            self.assertIsNotNone(decision.source_commit)
            self.assertIsNotNone(decision.source_tree)
            self.assertIsNotNone(decision.config_digest)
        finally:
            fixture.close()

    def test_false_policy_rejects_capabilities_and_unknown_keys(self) -> None:
        for index, text in enumerate(
            (
                f"schema_version={ai.SCHEMA_VERSION}\nproduct_ai=false\n"
                "fail_closed=true\ncapabilities=['inference']\n",
                f"schema_version={ai.SCHEMA_VERSION}\nproduct_ai=false\n"
                "fail_closed=true\ncapabilities=[]\nunknown=true\n",
                f"schema_version={ai.SCHEMA_VERSION}\nproduct_ai=0\n"
                "fail_closed=true\ncapabilities=[]\n",
                f"schema_version={ai.SCHEMA_VERSION}\nproduct_ai=false\n"
                "fail_closed=false\ncapabilities=[]\n",
            )
        ):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                subprocess.run(["git", "init", "-q", str(root)], check=True)
                subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
                subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
                config = root / ai.CANONICAL_CONFIG
                config.parent.mkdir(parents=True)
                config.write_text(text, encoding="utf-8")
                subprocess.run(["git", "add", "."], cwd=root, check=True)
                subprocess.run(["git", "commit", "-qm", f"invalid policy {index}"], cwd=root, check=True)
                self.assertFalse(ai.validate_repository_policy(root).allowed)

    def test_schema_v1_policy_is_rejected_after_binding_upgrade(self) -> None:
        fixture = NonAIRepositoryFixture()
        try:
            config = fixture.root / ai.CANONICAL_CONFIG
            config.write_text(
                "schema_version=1\nproduct_ai=false\nfail_closed=true\ncapabilities=[]\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", ai.CANONICAL_CONFIG], cwd=fixture.root, check=True)
            subprocess.run(["git", "commit", "-qm", "legacy schema"], cwd=fixture.root, check=True)
            self.assertEqual(
                "AI_SCHEMA_VERSION", ai.validate_repository_policy(fixture.root).findings[0].code
            )
        finally:
            fixture.close()

    def test_valid_inference_policy_and_report_allow_local_conformance(self) -> None:
        fixture = RepositoryFixture()
        try:
            policy_decision = ai.validate_repository_policy(fixture.root)
            self.assertTrue(policy_decision.allowed, policy_decision.as_dict())
            decision = ai.evaluate_repository(fixture.root)
            self.assertTrue(decision.allowed, decision.as_dict())
            self.assertEqual("local-validation-only", decision.as_dict()["authority"])
            self.assertEqual("AI_EXTERNAL_TRUST_REQUIRED", decision.findings[1].code)
            self.assertEqual(digest(fixture.report_path.read_bytes()), decision.report_digest)
            self.assertEqual(ai.case_set_digest(ai.load_policy(fixture.root)), decision.expected_case_set_digest)
            self.assertRegex(decision.source_commit or "", r"^[0-9a-f]{40,64}$")
            self.assertRegex(decision.source_tree or "", r"^[0-9a-f]{40,64}$")
            self.assertRegex(decision.config_digest or "", r"^sha256:[0-9a-f]{64}$")
        finally:
            fixture.close()

    def test_policy_is_closed_and_capability_inventory_is_exact(self) -> None:
        cases: list[tuple[str, Any]] = [
            ("unknown root", lambda text: text + "unknown = true\n"),
            (
                "unknown component",
                lambda text: text.replace(
                    "[components.inference]\n", "[components.inference]\nunknown = \"x\"\n", 1
                ),
            ),
            (
                "wrong digest type",
                lambda text: text.replace("runtime_digest = \"sha256:", "runtime_digest = 7 # sha256:", 1),
            ),
            (
                "duplicate capability",
                lambda text: text.replace(
                    'capabilities = ["inference"]', 'capabilities = ["inference", "inference"]'
                ),
            ),
        ]
        for name, mutate in cases:
            fixture = RepositoryFixture()
            try:
                fixture.write_config(mutate(fixture.render_config()))
                with self.subTest(name=name):
                    self.assertFalse(ai.validate_repository_policy(fixture.root).allowed)
            finally:
                fixture.close()

    def test_all_zero_digest_placeholders_deny_policy_and_report(self) -> None:
        placeholder = "sha256:" + "0" * 64
        fixture = RepositoryFixture()
        try:
            component_digest = fixture.components["inference"]["runtime_digest"]
            fixture.write_config(fixture.render_config().replace(component_digest, placeholder, 1))
            fixture.commit_controls("unresolved digest placeholder")
            policy_decision = ai.validate_repository_policy(fixture.root)
            self.assertFalse(policy_decision.allowed)
            self.assertEqual("AI_DIGEST_PLACEHOLDER", policy_decision.findings[0].code)

            fixture.write_config()
            fixture.commit_controls("restore resolved assurance policy")
            report = fixture.report()
            report["producer"]["attestation_digest"] = placeholder
            report_decision = fixture.decision_for(report)
            self.assertFalse(report_decision.allowed)
            self.assertEqual("AI_DIGEST_PLACEHOLDER", report_decision.findings[0].code)
        finally:
            fixture.close()

    def test_template_identity_case_slice_metric_and_producer_placeholders_deny(self) -> None:
        replacements: list[tuple[str, str]] = [
            ("acme-ai-product-v1", "replace-product-id"),
            ("acme/evaluation-repository", "example-owner/repository"),
            ("exact:inference:provider_id:v1", "replace:inference:provider_id:v1"),
            ("ci-evaluator-v1", "replace-independent-evaluator-v1"),
            ("case-00-inference-expected", "replace-case-id"),
            ("critical-security", "placeholder-critical-slice"),
            ("case-pass-rate", "todo-metric"),
        ]
        for original, placeholder in replacements:
            fixture = RepositoryFixture()
            try:
                config = fixture.render_config()
                self.assertIn(original, config)
                fixture.write_config(config.replace(original, placeholder))
                fixture.commit_controls(f"unresolved identity placeholder {placeholder}")
                with self.subTest(placeholder=placeholder):
                    decision = ai.validate_repository_policy(fixture.root)
                    self.assertFalse(decision.allowed)
                    self.assertEqual("AI_IDENTITY_PLACEHOLDER", decision.findings[0].code)
            finally:
                fixture.close()

    def test_generated_and_static_examples_remain_closed_after_digest_replacement(self) -> None:
        zero = "sha256:" + "0" * 64
        resolved = digest("syntactically-resolved-but-unreviewed")
        examples = {
            "generated": ai.render_policy_example(("inference",)),
            "static": (ROOT / ".mergegrounds/schemas/ai-assurance.example.toml").read_text(
                encoding="utf-8"
            ),
        }
        for name, example in examples.items():
            fixture = RepositoryFixture()
            try:
                fixture.write_config(example.replace(zero, resolved))
                fixture.commit_controls(f"copy unresolved {name} template")
                with self.subTest(example=name):
                    decision = ai.validate_repository_policy(fixture.root)
                    self.assertFalse(decision.allowed)
                    self.assertEqual("AI_IDENTITY_PLACEHOLDER", decision.findings[0].code)
            finally:
                fixture.close()

    def test_policy_refs_reject_traversal_digest_mismatch_and_symlink(self) -> None:
        fixture = RepositoryFixture()
        try:
            original = fixture.render_config()
            fixture.write_config(
                original.replace(
                    ".mergegrounds/policies/ai-provider.json", ".mergegrounds/policies/../ai-provider.json"
                )
            )
            self.assertFalse(ai.validate_repository_policy(fixture.root).allowed)
            fixture.write_config(original.replace(digest(fixture.policy_files["provider"]), digest("tampered")))
            self.assertFalse(ai.validate_repository_policy(fixture.root).allowed)
            provider = fixture.root / ".mergegrounds/policies/ai-provider.json"
            target = fixture.root / "provider-target.json"
            provider.unlink()
            target.write_bytes(fixture.policy_files["provider"])
            provider.symlink_to(target)
            fixture.write_config(original)
            decision = ai.validate_repository_policy(fixture.root)
            self.assertFalse(decision.allowed)
            self.assertIn(decision.findings[0].code, {"AI_PATH_UNSAFE", "AI_PATH_NOT_REGULAR"})
        finally:
            fixture.close()

    def test_report_path_cannot_alias_the_canonical_decision_output(self) -> None:
        fixture = RepositoryFixture()
        try:
            fixture.write_config(
                fixture.render_config().replace(
                    '.mergegrounds/evidence/ai-assurance.json',
                    ai.CANONICAL_DECISION_OUTPUT,
                )
            )
            fixture.commit_controls("collide AI report and decision outputs")
            decision = ai.validate_repository_policy(fixture.root)
            self.assertFalse(decision.allowed)
            self.assertEqual("AI_REPORT_OUTPUT_COLLISION", decision.findings[0].code)
        finally:
            fixture.close()

    def test_empty_config_policy_and_report_inputs_fail_closed(self) -> None:
        fixture = RepositoryFixture()
        try:
            original_provider = fixture.policy_files["provider"]
            fixture.config_path.write_bytes(b"")
            self.assertEqual(
                "AI_FILE_EMPTY", ai.validate_repository_policy(fixture.root).findings[0].code
            )
            fixture.write_config()
            provider = fixture.root / ".mergegrounds/policies/ai-provider.json"
            provider.write_bytes(b"")
            self.assertEqual(
                "AI_FILE_EMPTY", ai.validate_repository_policy(fixture.root).findings[0].code
            )
            provider.write_bytes(original_provider)
            fixture.write_config()
            fixture.report_path.write_bytes(b"")
            self.assertEqual("AI_FILE_EMPTY", ai.evaluate_repository(fixture.root).findings[0].code)
        finally:
            fixture.close()

    def test_config_symlink_bom_and_noncanonical_override_deny(self) -> None:
        fixture = RepositoryFixture()
        try:
            target = fixture.root / "config-target.toml"
            target.write_text(fixture.render_config(), encoding="utf-8")
            fixture.config_path.unlink()
            fixture.config_path.symlink_to(target)
            self.assertFalse(ai.validate_repository_policy(fixture.root).allowed)
            fixture.config_path.unlink()
            fixture.config_path.write_bytes(b"\xef\xbb\xbf" + fixture.render_config().encode())
            self.assertFalse(ai.validate_repository_policy(fixture.root).allowed)
            self.assertFalse(
                ai.validate_repository_policy(fixture.root, ".mergegrounds/other.toml").allowed
            )
        finally:
            fixture.close()

    def test_each_capability_requires_its_complete_critical_case_family(self) -> None:
        for capability in sorted(ai.CAPABILITIES):
            fixture = RepositoryFixture((capability,))
            try:
                self.assertTrue(ai.validate_repository_policy(fixture.root).allowed)
                removed = sorted(ai.REQUIRED_REQUIREMENTS[capability])[0]
                fixture.cases = [case for case in fixture.cases if case["requirement"] != removed]
                fixture.write_config()
                fixture.commit_controls("remove required case")
                with self.subTest(capability=capability, removed=removed):
                    decision = ai.validate_repository_policy(fixture.root)
                    self.assertFalse(decision.allowed)
                    self.assertIn(
                        decision.findings[0].code,
                        {"AI_REQUIRED_CASE_MISSING", "AI_CASE_CLASSES_INCOMPLETE"},
                    )
            finally:
                fixture.close()

    def test_all_five_case_classes_and_critical_slice_thresholds_are_mandatory(self) -> None:
        fixture = RepositoryFixture()
        try:
            for case in fixture.cases:
                case["class"] = "positive"
            fixture.write_config()
            self.assertFalse(ai.validate_repository_policy(fixture.root).allowed)
        finally:
            fixture.close()

    def test_security_requirements_cannot_be_relabeled_as_happy_path_cases(self) -> None:
        fixture = RepositoryFixture(("agent_tools",))
        try:
            for case in fixture.cases:
                if case["requirement"] == "agent_sandbox_escape":
                    case["class"] = "positive"
                    break
            fixture.write_config()
            fixture.commit_controls("relabel security case")
            decision = ai.validate_repository_policy(fixture.root)
            self.assertFalse(decision.allowed)
            self.assertEqual("AI_CASE_SEMANTICS", decision.findings[0].code)
        finally:
            fixture.close()
        fixture = RepositoryFixture()
        try:
            fixture.thresholds = fixture.thresholds[:1]
            fixture.write_config()
            fixture.commit_controls("remove critical threshold")
            decision = ai.validate_repository_policy(fixture.root)
            self.assertFalse(decision.allowed)
            self.assertEqual("AI_THRESHOLD_COVERAGE", decision.findings[0].code)
        finally:
            fixture.close()

    def test_report_rejects_duplicate_keys_nonfinite_bom_depth_and_symlink(self) -> None:
        fixture = RepositoryFixture()
        try:
            fixture.report_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            self.assertEqual("AI_JSON_DUPLICATE_KEY", ai.evaluate_repository(fixture.root).findings[0].code)
            fixture.report_path.write_text('{"schema_version":NaN}', encoding="utf-8")
            self.assertEqual("AI_JSON_NONFINITE", ai.evaluate_repository(fixture.root).findings[0].code)
            fixture.report_path.write_bytes(b"\xef\xbb\xbf{}")
            self.assertEqual("AI_UTF8_BOM", ai.evaluate_repository(fixture.root).findings[0].code)
            fixture.report_path.write_text("[" * 30 + "0" + "]" * 30, encoding="utf-8")
            self.assertIn(
                ai.evaluate_repository(fixture.root).findings[0].code,
                {"AI_JSON_DEPTH", "AI_SCHEMA_TYPE"},
            )
            target = fixture.root / "report-target.json"
            target.write_text(json.dumps(fixture.report()), encoding="utf-8")
            fixture.report_path.unlink()
            fixture.report_path.symlink_to(target)
            self.assertEqual("AI_PATH_UNSAFE", ai.evaluate_repository(fixture.root).findings[0].code)
        finally:
            fixture.close()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO probe requires POSIX")
    def test_report_fifo_is_rejected_without_blocking(self) -> None:
        fixture = RepositoryFixture()
        try:
            fixture.report_path.unlink()
            os.mkfifo(fixture.report_path)
            self.assertEqual(
                "AI_PATH_NOT_REGULAR", ai.evaluate_repository(fixture.root).findings[0].code
            )
        finally:
            fixture.close()

    def test_report_rejects_oversize_and_unknown_fields(self) -> None:
        fixture = RepositoryFixture()
        try:
            with fixture.report_path.open("wb") as handle:
                handle.truncate(ai.MAX_REPORT_BYTES + 1)
            self.assertEqual("AI_FILE_TOO_LARGE", ai.evaluate_repository(fixture.root).findings[0].code)
            report = fixture.report()
            report["persuasive_reasoning"] = "trust me"
            decision = fixture.decision_for(report)
            self.assertFalse(decision.allowed)
            self.assertEqual("AI_SCHEMA_KEYS", decision.findings[0].code)
        finally:
            fixture.close()

    def test_exact_subject_bindings_all_deny_when_tampered(self) -> None:
        mutations = {
            "source_commit": lambda r: r["subject"].__setitem__("source_commit", "0" * 40),
            "source_tree": lambda r: r["subject"].__setitem__("source_tree", "0" * 40),
            "config_digest": lambda r: r["subject"].__setitem__("config_digest", digest("wrong")),
            "harness_digest": lambda r: r["subject"].__setitem__("harness_digest", digest("wrong")),
            "dataset_digest": lambda r: r["subject"].__setitem__("dataset_digest", digest("wrong")),
            "case_set_digest": lambda r: r["subject"].__setitem__("case_set_digest", digest("wrong")),
            "component": lambda r: r["subject"]["components"]["inference"].__setitem__(
                "prompt_digest", digest("wrong")
            ),
            "protected_policy": lambda r: r["subject"]["protected_policies"].__setitem__(
                "provider", digest("wrong")
            ),
        }
        for name, mutate in mutations.items():
            fixture = RepositoryFixture()
            try:
                report = fixture.report()
                mutate(report)
                with self.subTest(name=name):
                    self.assertFalse(fixture.decision_for(report).allowed)
            finally:
                fixture.close()

    def test_model_self_review_and_author_producers_are_never_authoritative(self) -> None:
        for producer_class in sorted(ai.ADVISORY_PRODUCERS):
            fixture = RepositoryFixture()
            try:
                report = fixture.report()
                report["producer"]["class"] = producer_class
                with self.subTest(producer=producer_class):
                    decision = fixture.decision_for(report)
                    self.assertFalse(decision.allowed)
                    self.assertEqual("AI_PRODUCER_ADVISORY", decision.findings[0].code)
            finally:
                fixture.close()

    def test_unlisted_producer_and_model_oracle_deny(self) -> None:
        fixture = RepositoryFixture()
        try:
            report = fixture.report()
            report["producer"]["id"] = "untrusted-evaluator"
            self.assertEqual("AI_PRODUCER_UNAUTHORIZED", fixture.decision_for(report).findings[0].code)
            report = fixture.report()
            report["cases"][0]["oracle"] = "model_judge"
            self.assertEqual("AI_ORACLE_ADVISORY", fixture.decision_for(report).findings[0].code)
        finally:
            fixture.close()

    def test_authorized_producer_class_and_id_are_an_exact_pair(self) -> None:
        fixture = RepositoryFixture()
        try:
            fixture.authoritative_producers.append(
                {"class": "independent_human", "id": "reviewer-alice"}
            )
            fixture.write_config()
            fixture.commit_controls("authorize exact producer pairs")
            report = fixture.report()
            report["producer"].update(
                {"class": "independent_human", "id": "ci-evaluator-v1"}
            )
            self.assertEqual(
                "AI_PRODUCER_UNAUTHORIZED", fixture.decision_for(report).findings[0].code
            )
            report = fixture.report()
            report["producer"].update(
                {"class": "independent_human", "id": "reviewer-alice"}
            )
            self.assertTrue(fixture.decision_for(report).allowed)
        finally:
            fixture.close()

    def test_missing_extra_duplicate_and_zero_case_sets_deny(self) -> None:
        fixture = RepositoryFixture()
        try:
            for mode in ("missing", "extra", "duplicate", "zero"):
                report = fixture.report()
                if mode == "missing":
                    report["cases"].pop()
                elif mode == "extra":
                    added = copy.deepcopy(report["cases"][0])
                    added["id"] = "unexpected-case"
                    report["cases"].append(added)
                elif mode == "duplicate":
                    report["cases"].append(copy.deepcopy(report["cases"][0]))
                else:
                    report["cases"] = []
                with self.subTest(mode=mode):
                    self.assertFalse(fixture.decision_for(report).allowed)
        finally:
            fixture.close()

    def test_every_nonpass_status_and_retry_denies(self) -> None:
        fixture = RepositoryFixture()
        try:
            for status in sorted(ai.DENY_CASE_STATUSES):
                report = fixture.report()
                report["cases"][0]["status"] = status
                with self.subTest(status=status):
                    decision = fixture.decision_for(report)
                    self.assertFalse(decision.allowed)
                    self.assertEqual("AI_CASE_FAILED", decision.findings[0].code)
            report = fixture.report()
            report["cases"][0]["attempts"] = 2
            self.assertFalse(fixture.decision_for(report).allowed)
        finally:
            fixture.close()

    def test_case_metadata_and_slice_membership_are_policy_bound(self) -> None:
        mutations = (
            lambda r: r["cases"][0].__setitem__(
                "class",
                "positive" if r["cases"][0]["class"] != "positive" else "negative",
            ),
            lambda r: r["cases"][0].__setitem__("requirement", "product_specific"),
            lambda r: r["cases"][0].__setitem__("slices", ["other-slice"]),
            lambda r: r["cases"][0].__setitem__("critical", False),
            lambda r: r["slice_results"][0].__setitem__("case_ids", r["slice_results"][0]["case_ids"][:-1]),
        )
        fixture = RepositoryFixture()
        try:
            for mutate in mutations:
                report = fixture.report()
                mutate(report)
                self.assertFalse(fixture.decision_for(report).allowed)
        finally:
            fixture.close()

    def test_metrics_and_slices_bind_exact_cases_observations_and_samples(self) -> None:
        fixture = RepositoryFixture()
        try:
            report = fixture.report()
            report["metrics"][0]["case_ids"].pop()
            self.assertEqual(
                "AI_METRIC_CASE_BINDING", fixture.decision_for(report).findings[0].code
            )
            report = fixture.report()
            report["metrics"][0].update(value=1.0, numerator=1, denominator=1, sample_count=1)
            self.assertEqual(
                "AI_METRIC_SAMPLE_BINDING", fixture.decision_for(report).findings[0].code
            )
            report = fixture.report()
            report["metrics"][0]["observation_set_digest"] = digest("unrelated-observations")
            self.assertEqual(
                "AI_METRIC_OBSERVATION_BINDING", fixture.decision_for(report).findings[0].code
            )
            report = fixture.report()
            report["slice_results"][0]["sample_count"] = 1
            self.assertEqual(
                "AI_SLICE_SAMPLE_BINDING", fixture.decision_for(report).findings[0].code
            )
            report = fixture.report()
            report["slice_results"][0]["observation_set_digest"] = digest("unrelated-slice")
            self.assertEqual(
                "AI_SLICE_OBSERVATION_BINDING", fixture.decision_for(report).findings[0].code
            )
        finally:
            fixture.close()

    def test_case_and_metric_minimum_counts_are_enforced(self) -> None:
        fixture = RepositoryFixture()
        try:
            for case in fixture.cases:
                case["sample_count_mode"] = "minimum"
                case["sample_count"] = 5
            for threshold in fixture.thresholds:
                threshold["sample_count_mode"] = "minimum"
                threshold["sample_count"] = 5 * len(threshold["case_ids"])
            fixture.write_config()
            fixture.commit_controls("require five samples per case")
            report = fixture.report()
            report["cases"][0]["sample_count"] = 1
            self.assertEqual("AI_SAMPLE_COUNT", fixture.decision_for(report).findings[0].code)
        finally:
            fixture.close()

    def test_policy_threshold_cannot_name_unrelated_or_partial_cases(self) -> None:
        fixture = RepositoryFixture()
        try:
            fixture.thresholds[0]["case_ids"] = fixture.thresholds[0]["case_ids"][:-1]
            fixture.write_config()
            fixture.commit_controls("weaken metric case set")
            self.assertEqual(
                "AI_THRESHOLD_CASE_BINDING",
                ai.validate_repository_policy(fixture.root).findings[0].code,
            )
        finally:
            fixture.close()

    def test_controls_are_bound_to_clean_head_and_exact_git_root(self) -> None:
        fixture = RepositoryFixture()
        try:
            fixture.config_path.write_text(fixture.render_config() + "# dirty\n", encoding="utf-8")
            self.assertEqual(
                "AI_CONTROL_DIRTY", ai.validate_repository_policy(fixture.root).findings[0].code
            )
            subprocess.run(["git", "add", ai.CANONICAL_CONFIG], cwd=fixture.root, check=True)
            self.assertEqual(
                "AI_CONTROL_DIRTY", ai.validate_repository_policy(fixture.root).findings[0].code
            )
            subprocess.run(["git", "restore", "--staged", ai.CANONICAL_CONFIG], cwd=fixture.root, check=True)
            subprocess.run(["git", "restore", ai.CANONICAL_CONFIG], cwd=fixture.root, check=True)
            provider = fixture.root / ".mergegrounds/policies/ai-provider.json"
            provider.write_bytes(provider.read_bytes() + b" ")
            self.assertEqual(
                "AI_CONTROL_DIRTY", ai.validate_repository_policy(fixture.root).findings[0].code
            )
            nested = fixture.root / "nested"
            nested.mkdir()
            self.assertEqual(
                "AI_GIT_NESTED_ROOT", ai.validate_repository_policy(nested).findings[0].code
            )
        finally:
            fixture.close()

    def test_control_and_report_data_must_be_non_executable_mode_100644(self) -> None:
        fixture = RepositoryFixture()
        try:
            fixture.config_path.chmod(0o755)
            fixture.commit_controls("make config executable")
            self.assertEqual(
                "AI_CONTROL_GIT_MODE", ai.validate_repository_policy(fixture.root).findings[0].code
            )
        finally:
            fixture.close()
        fixture = RepositoryFixture()
        try:
            provider = fixture.root / ".mergegrounds/policies/ai-provider.json"
            provider.chmod(0o755)
            fixture.commit_controls("make protected policy executable")
            self.assertEqual(
                "AI_CONTROL_GIT_MODE", ai.validate_repository_policy(fixture.root).findings[0].code
            )
        finally:
            fixture.close()
        fixture = RepositoryFixture()
        try:
            fixture.report_path.chmod(0o755)
            self.assertEqual("AI_PATH_EXECUTABLE", ai.evaluate_repository(fixture.root).findings[0].code)
        finally:
            fixture.close()

    def test_report_must_be_ignored_and_untracked(self) -> None:
        fixture = RepositoryFixture()
        try:
            subprocess.run(
                ["git", "add", "-f", ".mergegrounds/evidence/ai-assurance.json"],
                cwd=fixture.root,
                check=True,
            )
            subprocess.run(["git", "commit", "-qm", "track forged report"], cwd=fixture.root, check=True)
            self.assertEqual("AI_REPORT_TRACKED", ai.evaluate_repository(fixture.root).findings[0].code)
        finally:
            fixture.close()
        fixture = RepositoryFixture()
        try:
            subprocess.run(["git", "rm", "-q", ".gitignore"], cwd=fixture.root, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "remove report ignore rule"], cwd=fixture.root, check=True
            )
            self.assertEqual(
                "AI_REPORT_NOT_IGNORED", ai.evaluate_repository(fixture.root).findings[0].code
            )
        finally:
            fixture.close()

    def test_untracked_config_is_not_an_authoritative_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            (root / "seed.txt").write_text("seed\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "seed"], cwd=root, check=True)
            config = root / ai.CANONICAL_CONFIG
            config.parent.mkdir(parents=True)
            config.write_text(
                f"schema_version={ai.SCHEMA_VERSION}\nproduct_ai=false\n"
                "fail_closed=true\ncapabilities=[]\n",
                encoding="utf-8",
            )
            self.assertEqual(
                "AI_CONTROL_UNTRACKED", ai.validate_repository_policy(root).findings[0].code
            )

    def test_git_environment_and_replacement_refs_cannot_substitute_subject(self) -> None:
        fixture = RepositoryFixture()
        try:
            previous = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=fixture.root, text=True
            ).strip()
            (fixture.root / "source.txt").write_text("second candidate\n", encoding="utf-8")
            subprocess.run(["git", "add", "source.txt"], cwd=fixture.root, check=True)
            subprocess.run(["git", "commit", "-qm", "second candidate"], cwd=fixture.root, check=True)
            current = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=fixture.root, text=True
            ).strip()
            fixture.write_report()
            subprocess.run(["git", "replace", current, previous], cwd=fixture.root, check=True)
            poisoned = {
                "GIT_DIR": str(fixture.root / "does-not-exist.git"),
                "GIT_WORK_TREE": str(fixture.root / "wrong-worktree"),
                "GIT_INDEX_FILE": str(fixture.root / "wrong-index"),
                "GIT_OBJECT_DIRECTORY": str(fixture.root / "wrong-objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(fixture.root / "wrong-alternates"),
                "GIT_REPLACE_REF_BASE": "refs/attacker-replacements/",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.worktree",
                "GIT_CONFIG_VALUE_0": str(fixture.root / "wrong-config-worktree"),
            }
            with mock.patch.dict(os.environ, poisoned, clear=False):
                decision = ai.evaluate_repository(fixture.root)
            self.assertTrue(decision.allowed, decision.as_dict())
            self.assertEqual(current, decision.source_commit)
            actual_tree = subprocess.check_output(
                ["git", "--no-replace-objects", "rev-parse", f"{current}^{{tree}}"],
                cwd=fixture.root,
                text=True,
            ).strip()
            self.assertEqual(actual_tree, decision.source_tree)
        finally:
            fixture.close()

    def test_critical_slice_and_aggregate_cannot_hide_failure(self) -> None:
        fixture = RepositoryFixture()
        try:
            report = fixture.report()
            report["slice_results"][0]["status"] = "failed"
            decision = fixture.decision_for(report)
            self.assertEqual("AI_CRITICAL_SLICE_FAILED", decision.findings[0].code)
            report = fixture.report()
            sample_count = report["metrics"][1]["sample_count"]
            report["metrics"][1].update(
                value=(sample_count - 1) / sample_count,
                numerator=sample_count - 1,
                denominator=sample_count,
            )
            decision = fixture.decision_for(report)
            self.assertEqual("AI_CRITICAL_THRESHOLD", decision.findings[0].code)
            report = fixture.report()
            report["metrics"][0].update(value=1.0, numerator=0, denominator=0)
            self.assertEqual("AI_METRIC_DENOMINATOR", fixture.decision_for(report).findings[0].code)
            report = fixture.report()
            report["metrics"][0].update(value=0.5, numerator=1, denominator=1)
            self.assertEqual("AI_METRIC_ARITHMETIC", fixture.decision_for(report).findings[0].code)
            report = fixture.report()
            sample_count = report["metrics"][0]["sample_count"]
            report["metrics"][0].update(
                value=2.0,
                numerator=2 * sample_count,
                denominator=sample_count,
            )
            self.assertEqual("AI_METRIC_RANGE", fixture.decision_for(report).findings[0].code)
            report = fixture.report()
            sample_count = report["metrics"][0]["sample_count"]
            report["metrics"][0].update(value=0.0, numerator=-1, denominator=sample_count)
            self.assertEqual(
                "AI_METRIC_DENOMINATOR", fixture.decision_for(report).findings[0].code
            )
        finally:
            fixture.close()

    def test_summary_cannot_hide_failures_skips_errors_partial_or_retries(self) -> None:
        fixture = RepositoryFixture()
        try:
            for field in ("failed", "skipped", "errors", "partial", "stale", "inconclusive", "retries"):
                report = fixture.report()
                report["summary"][field] = 1
                with self.subTest(field=field):
                    self.assertEqual("AI_SUMMARY_INVALID", fixture.decision_for(report).findings[0].code)
        finally:
            fixture.close()

    def test_stale_future_and_incomplete_reports_deny(self) -> None:
        fixture = RepositoryFixture()
        try:
            report = fixture.report()
            report["generated_at"] = "2000-01-01T00:00:00Z"
            self.assertEqual("AI_REPORT_STALE", fixture.decision_for(report).findings[0].code)
            report = fixture.report()
            report["generated_at"] = "2999-01-01T00:00:00Z"
            self.assertEqual("AI_REPORT_FUTURE", fixture.decision_for(report).findings[0].code)
            report = fixture.report()
            report["completeness"] = "partial"
            self.assertEqual("AI_REPORT_INCOMPLETE", fixture.decision_for(report).findings[0].code)
        finally:
            fixture.close()

    def test_fine_tune_requires_exact_base_and_production_comparisons(self) -> None:
        fixture = RepositoryFixture(("fine_tuning",))
        try:
            self.assertTrue(ai.evaluate_repository(fixture.root).allowed)
            report = fixture.report()
            report["comparisons"].pop()
            self.assertEqual("AI_COMPARISON_SET", fixture.decision_for(report).findings[0].code)
            report = fixture.report()
            report["comparisons"][0]["baseline_digest"] = digest("wrong-base")
            self.assertEqual("AI_COMPARISON_BINDING", fixture.decision_for(report).findings[0].code)
            report = fixture.report()
            report["comparisons"][1]["case_ids"].pop()
            self.assertEqual("AI_COMPARISON_CASES", fixture.decision_for(report).findings[0].code)
        finally:
            fixture.close()

    def test_fine_tune_comparison_rejects_aliases_input_drift_and_false_deltas(self) -> None:
        fixture = RepositoryFixture(("fine_tuning",))
        try:
            report = fixture.report()
            report["comparisons"][0]["baseline_report_digest"] = report["comparisons"][0][
                "candidate_report_digest"
            ]
            self.assertEqual(
                "AI_COMPARISON_DIGEST_ALIAS", fixture.decision_for(report).findings[0].code
            )
            report = fixture.report()
            report["comparisons"][0]["case_results"][0]["baseline_input_digest"] = digest(
                "different-input"
            )
            self.assertEqual(
                "AI_COMPARISON_INPUT_EQUIVALENCE",
                fixture.decision_for(report).findings[0].code,
            )
            report = fixture.report()
            report["comparisons"][0]["case_results"][0][
                "candidate_observations_digest"
            ] = digest("unrelated-candidate")
            self.assertEqual(
                "AI_COMPARISON_CANDIDATE_BINDING",
                fixture.decision_for(report).findings[0].code,
            )
            report = fixture.report()
            report["comparisons"][0]["case_results"][0]["baseline_sample_count"] += 1
            self.assertEqual(
                "AI_COMPARISON_SAMPLE_EQUIVALENCE",
                fixture.decision_for(report).findings[0].code,
            )
            report = fixture.report()
            report["comparisons"][0]["metric_deltas"][0]["delta"] = 0.25
            self.assertEqual(
                "AI_COMPARISON_DELTA_ARITHMETIC",
                fixture.decision_for(report).findings[0].code,
            )
            fixture.comparison_direction = "lower_is_better"
            fixture.write_config()
            fixture.commit_controls("protect lower-is-better comparison")
            report = fixture.report()
            delta = report["comparisons"][0]["metric_deltas"][0]
            delta.update(baseline_value=0.9, delta=0.1, regression=0.1)
            self.assertEqual(
                "AI_COMPARISON_REGRESSION", fixture.decision_for(report).findings[0].code
            )
            report = fixture.report()
            report["comparisons"][0]["candidate_result_digest"] = digest("forged-result")
            self.assertEqual(
                "AI_COMPARISON_RESULT_BINDING",
                fixture.decision_for(report).findings[0].code,
            )
        finally:
            fixture.close()

    def test_base_comparison_cannot_be_replayed_as_production_baseline(self) -> None:
        fixture = RepositoryFixture(("fine_tuning",))
        try:
            report = fixture.report()
            base, production = report["comparisons"]
            self.assertNotEqual(base["baseline_digest"], production["baseline_digest"])
            self.assertNotEqual(base["baseline_result_digest"], production["baseline_result_digest"])
            for base_case, production_case in zip(
                base["case_results"], production["case_results"], strict=True
            ):
                production_case["baseline_observations_digest"] = base_case[
                    "baseline_observations_digest"
                ]
            for base_metric, production_metric in zip(
                base["metric_deltas"], production["metric_deltas"], strict=True
            ):
                for field in (
                    "baseline_observation_set_digest",
                    "baseline_value",
                    "delta",
                    "regression",
                ):
                    production_metric[field] = base_metric[field]

            normalized_cases = {
                item["id"]: {
                    "input_digest": item["candidate_input_digest"],
                    "expectation_digest": item["expectation_digest"],
                    "candidate_observations_digest": item["candidate_observations_digest"],
                    "baseline_observations_digest": item["baseline_observations_digest"],
                    "sample_count": item["candidate_sample_count"],
                }
                for item in production["case_results"]
            }
            normalized_metrics = {
                (item["metric"], item["scope"]): {
                    "case_ids": item["case_ids"],
                    "sample_count": item["sample_count"],
                    "candidate_observation_set_digest": item[
                        "candidate_observation_set_digest"
                    ],
                    "baseline_observation_set_digest": item[
                        "baseline_observation_set_digest"
                    ],
                    "candidate_value": item["candidate_value"],
                    "baseline_value": item["baseline_value"],
                }
                for item in production["metric_deltas"]
            }
            production["baseline_report_digest"] = digest("unique-production-replay-report")
            production["baseline_result_digest"] = ai._comparison_result_digest(
                "baseline",
                production["kind"],
                production["baseline_digest"],
                production["input_manifest_digest"],
                production["case_ids"],
                normalized_cases,
                normalized_metrics,
            )
            production["comparison_binding_digest"] = ai._comparison_binding_digest(
                kind=production["kind"],
                baseline_digest=production["baseline_digest"],
                input_manifest_digest=production["input_manifest_digest"],
                candidate_report_digest=production["candidate_report_digest"],
                baseline_report_digest=production["baseline_report_digest"],
                candidate_result_digest=production["candidate_result_digest"],
                baseline_result_digest=production["baseline_result_digest"],
            )
            self.assertEqual(
                "AI_COMPARISON_CROSS_KIND_REPLAY",
                fixture.decision_for(report).findings[0].code,
            )
        finally:
            fixture.close()

    def test_direct_exec_uses_isolated_python(self) -> None:
        source = (ROOT / "scripts/ai_assurance.py").read_text(encoding="utf-8")
        first_line = source.splitlines()[0]
        self.assertEqual("#!/usr/bin/env -S python3 -I", first_line)
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            script = directory / "ai_assurance.py"
            script.write_text(source, encoding="utf-8")
            script.chmod(0o755)
            marker = directory / "shadow-imported"
            (directory / "dataclasses.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [str(script), "--help"],
                cwd=directory,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertFalse(marker.exists(), "direct execution imported a sibling shadow module")

    def test_non_fine_tune_report_cannot_smuggle_comparisons(self) -> None:
        fixture = RepositoryFixture()
        try:
            report = fixture.report()
            report["comparisons"] = [
                {
                    "kind": "production",
                    "baseline_digest": digest("x"),
                    "status": "passed",
                    "case_ids": [case["id"] for case in fixture.cases],
                }
            ]
            self.assertEqual("AI_COMPARISON_UNEXPECTED", fixture.decision_for(report).findings[0].code)
        finally:
            fixture.close()

    def test_rag_and_agent_suites_include_high_consequence_negative_cases(self) -> None:
        required = {
            "retrieval": {
                "rag_acl_leak",
                "rag_unsupported_claim",
                "rag_abstention",
                "rag_position_beginning",
                "rag_position_middle",
                "rag_position_end",
                "rag_overflow",
            },
            "agent_tools": {
                "agent_sandbox_escape",
                "agent_egress_denied",
                "agent_tool_authorization",
                "agent_human_confirmation",
                "agent_credential_isolation",
                "agent_retrieval_cannot_expand_authority",
            },
        }
        for capability, expected in required.items():
            self.assertTrue(expected.issubset(ai.REQUIRED_REQUIREMENTS[capability]))

    def test_cli_emits_machine_readable_decision_and_exit_status(self) -> None:
        fixture = NonAIRepositoryFixture()
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/ai_assurance.py"),
                    "--root",
                    str(fixture.root),
                    "evaluate",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual("allow", payload["decision"])
            self.assertFalse(payload["product_ai"])
            self.assertRegex(payload["source_commit"], r"^[0-9a-f]{40,64}$")
            self.assertRegex(payload["source_tree"], r"^[0-9a-f]{40,64}$")
            self.assertRegex(payload["config_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertIsNone(payload["report_digest"])
            self.assertIsNone(payload["expected_case_set_digest"])
        finally:
            fixture.close()

    def test_cli_atomically_replaces_decision_symlink_without_following_it(self) -> None:
        fixture = NonAIRepositoryFixture()
        try:
            output = fixture.root / ai.CANONICAL_DECISION_OUTPUT
            output.parent.mkdir(parents=True, exist_ok=True)
            target = fixture.root / ".git/config"
            before = target.read_bytes()
            output.symlink_to(target)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/ai_assurance.py"),
                    "--root",
                    str(fixture.root),
                    "evaluate",
                    "--output",
                    ai.CANONICAL_DECISION_OUTPUT,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("", completed.stdout)
            self.assertEqual(before, target.read_bytes(), "decision output followed a hostile symlink")
            self.assertFalse(output.is_symlink())
            self.assertTrue(output.is_file())
            self.assertEqual(0, output.stat().st_mode & 0o111)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("allow", payload["decision"])
        finally:
            fixture.close()

    def test_cli_refuses_tracked_decision_output(self) -> None:
        fixture = NonAIRepositoryFixture()
        try:
            output = fixture.root / ai.CANONICAL_DECISION_OUTPUT
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("candidate-controlled\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "-f", ai.CANONICAL_DECISION_OUTPUT],
                cwd=fixture.root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "track hostile decision"], cwd=fixture.root, check=True
            )
            before = output.read_bytes()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/ai_assurance.py"),
                    "--root",
                    str(fixture.root),
                    "evaluate",
                    "--output",
                    ai.CANONICAL_DECISION_OUTPUT,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertEqual(before, output.read_bytes())
            self.assertEqual("AI_DECISION_TRACKED", json.loads(completed.stderr)["findings"][0]["code"])
        finally:
            fixture.close()

    def test_print_example_is_complete_for_every_selected_capability(self) -> None:
        selected = tuple(sorted(ai.CAPABILITIES))
        rendered = ai.render_policy_example(selected)
        parsed = tomllib.loads(rendered)
        self.assertTrue(parsed["product_ai"])
        self.assertEqual(list(selected), parsed["capabilities"])
        requirements = {case["requirement"] for case in parsed["evaluation"]["cases"]}
        for capability in selected:
            self.assertTrue(ai.REQUIRED_REQUIREMENTS[capability].issubset(requirements))
            self.assertEqual(
                set(ai.COMPONENT_FIELDS[capability]),
                set(parsed["components"][capability]),
            )
        self.assertEqual(
            set(parsed["evaluation"]["expected_case_ids"]),
            {case["id"] for case in parsed["evaluation"]["cases"]},
        )
        self.assertEqual(ai.SCHEMA_VERSION, parsed["schema_version"])
        for case in parsed["evaluation"]["cases"]:
            self.assertIn(case["sample_count_mode"], ai.SAMPLE_COUNT_MODES)
            self.assertRegex(case["input_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(case["expectation_digest"], r"^sha256:[0-9a-f]{64}$")
        for threshold in parsed["evaluation"]["thresholds"]:
            self.assertTrue(threshold["case_ids"])
            self.assertGreater(threshold["sample_count"], 0)
        self.assertEqual(
            {"base_model", "production"},
            {item["kind"] for item in parsed["evaluation"]["comparison_policies"]},
        )
        self.assertIn("all-zero digest", rendered)


if __name__ == "__main__":
    unittest.main()
