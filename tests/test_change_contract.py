from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mergegrounds_change_contract", ROOT / "scripts" / "mergegrounds.py")
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)

DESIGN_ID = "11111111-1111-4111-8111-111111111111"
CHANGE_ID = "22222222-2222-4222-8222-222222222222"


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def criterion(identifier: str, kind: str) -> dict[str, Any]:
    suffix = kind.upper()
    return {
        "id": identifier,
        "class": kind,
        "observable": f"The {kind} externally visible behavior is measured at the public boundary",
        "oracle": {
            "kind": "test",
            "ref": f"TEST-{suffix}",
            "evidence_class": "trusted_execution",
        },
        "failure_behavior": "A missing, skipped, inconclusive, or adverse observation denies admission",
    }


def acceptance_criteria() -> list[dict[str, Any]]:
    return [
        criterion("AC-POSITIVE", "positive"),
        criterion("AC-NEGATIVE", "negative"),
        criterion("AC-ADVERSARIAL", "adversarial"),
        criterion("AC-RECOVERY", "recovery"),
    ]


def failure_modes() -> list[dict[str, Any]]:
    return [
        {
            "id": "FM-INVALID-INPUT",
            "condition": "An untrusted caller supplies malformed or unauthorized input",
            "expected_behavior": "The request is rejected without changing protected state",
            "detection_ref": "TEST-NEGATIVE",
            "rollback_trigger": "Any accepted malformed request stops rollout and restores the prior release",
        }
    ]


def design_contract() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "design_id": DESIGN_ID,
        "title": "Fail-closed example application change",
        "problem": "The application needs a measurable behavior without weakening existing trust boundaries.",
        "goals": ["Deliver the specified behavior with independently observable results"],
        "non_goals": ["Changing authentication, authorization, or deployment credentials"],
        "decisions": [
            {
                "id": "DEC-BOUNDARY",
                "choice": "Keep validation at the existing public service boundary",
                "alternatives": ["Move validation into each caller"],
                "rationale": "One boundary gives a consistent fail-closed policy and auditable result.",
            }
        ],
        "invariants": [
            {
                "id": "INV-NO-UNAUTHORIZED-WRITE",
                "statement": "Unauthorized input never changes protected application state",
                "verification_ref": "AC-POSITIVE",
            }
        ],
        "trust_boundaries": [
            {
                "id": "TB-CALLER-SERVICE",
                "source": "untrusted caller",
                "target": "application service",
                "data": "request payload",
                "controls": ["schema validation", "authorization", "bounded processing"],
            }
        ],
        "failure_modes": failure_modes(),
        "rollback": {
            "strategy": "Restore the previously admitted artifact and quarantine the failed revision",
            "triggers": ["Any acceptance or recovery oracle fails in canary validation"],
            "verification_ref": "AC-RECOVERY",
        },
        "observability": {
            "signals": [
                {
                    "id": "SIG-CHANGE-FAILURE",
                    "name": "change failure rate",
                    "decision_use": "Block promotion and trigger rollback when the protected limit is exceeded",
                }
            ]
        },
        "evaluation": {
            "acceptance_criteria": acceptance_criteria(),
            "outcome_metrics": [
                {
                    "id": "METRIC-CHANGE-FAILURE",
                    "observable": "Deployments requiring rollback, hotfix, incident response, or quarantine",
                    "source": "trusted deployment and incident telemetry",
                    "evidence_class": "external_verifier",
                    "baseline_window": "28d",
                    "observation_window": "24h",
                    "direction": "not_regress",
                    "target": 0.0,
                    "unit": "percent",
                    "minimum_samples": 20,
                    "maximum_missing_percent": 0.0,
                    "promotion_blocking": True,
                    "failure_action": "rollback",
                }
            ],
        },
    }


def change_contract(design_raw: bytes, lane: str = "implementation") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "change_id": CHANGE_ID,
        "lane": lane,
        "risk": {
            "claimed_tier": "R3",
            "impact_flags": ["application_code", "business_logic"],
            "rationale": "The change affects externally visible application behavior and requires strict review.",
        },
        "summary": {
            "problem": "The existing application does not expose the required fail-closed behavior.",
            "approach": "Implement the already reviewed design and verify each observable boundary condition.",
            "non_goals": ["Changing unrelated authorization or deployment behavior"],
        },
        "design": {
            "record_id": DESIGN_ID,
            "record_path": f"docs/decisions/{DESIGN_ID}.json",
            "record_sha256": "sha256:" + hashlib.sha256(design_raw).hexdigest(),
        },
        "acceptance_criteria": acceptance_criteria(),
        "failure_modes": failure_modes(),
        "challenge_plan": [
            {
                "id": "CH-BOUNDARY-BYPASS",
                "claim_to_falsify": "Malformed input can never bypass validation or mutate protected state",
                "attack_surface": "public request boundary and state transition",
                "evaluation_ref": "TEST-ADVERSARIAL",
                "required_producer": "independent_human",
            }
        ],
        "outcome_metric_ids": ["METRIC-CHANGE-FAILURE"],
        "evidence_policy": {
            "author_claims_are_evidence": False,
            "model_output_is_evidence": False,
            "self_review_is_evidence": False,
        },
        "ai_assistance": {"used": False, "systems": [], "affected_paths": []},
    }


class ChangeRepository:
    def __init__(self, *, design_in_base: bool = True) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "config", "user.email", "contracts@example.invalid"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Contract Tests"], cwd=self.root, check=True)
        (self.root / ".mergegrounds/changes").mkdir(parents=True)
        (self.root / "docs/decisions").mkdir(parents=True)
        (self.root / "src").mkdir()
        (self.root / ".mergegrounds/mergegrounds.toml").write_bytes((ROOT / ".mergegrounds/mergegrounds.toml").read_bytes())
        (self.root / "src/app.py").write_text("VALUE = 1\n", encoding="utf-8")
        self.design = design_contract()
        self.design_raw = canonical_bytes(self.design)
        if design_in_base:
            (self.root / f"docs/decisions/{DESIGN_ID}.json").write_bytes(self.design_raw)
        self.commit("base")
        self.base = self.revision("HEAD")

    def close(self) -> None:
        self.temp.cleanup()

    def revision(self, value: str) -> str:
        return subprocess.run(
            ["git", "rev-parse", value],
            cwd=self.root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def commit(self, message: str) -> None:
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", message], cwd=self.root, check=True)

    def add_change(
        self,
        mutate: Callable[[dict[str, Any]], None] | None = None,
        *,
        lane: str = "implementation",
        add_code: bool = True,
        raw: bytes | None = None,
    ) -> tuple[str, dict[str, Any]]:
        if lane == "design-only":
            (self.root / f"docs/decisions/{DESIGN_ID}.json").write_bytes(self.design_raw)
        if add_code:
            (self.root / "src/app.py").write_text("VALUE = 2\n", encoding="utf-8")
        declaration = change_contract(self.design_raw, lane)
        if mutate:
            mutate(declaration)
        (self.root / f".mergegrounds/changes/{CHANGE_ID}.json").write_bytes(
            raw if raw is not None else canonical_bytes(declaration)
        )
        self.commit("candidate")
        return self.revision("HEAD"), declaration

    def validate(self, head: str) -> dict[str, Any]:
        _, config = mergegrounds.config_for(self.root)
        return mergegrounds.validate_change_between(self.root, config, self.base, head)


class ChangeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ChangeRepository()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_implementation_uses_design_already_in_base(self) -> None:
        head, _ = self.fixture.add_change()
        result = self.fixture.validate(head)
        self.assertEqual("implementation", result["lane"])
        self.assertEqual("declaration-validated-not-admission-evidence", result["authority"])

    def test_same_id_cannot_rebind_acceptance_semantics(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            value["acceptance_criteria"][0]["observable"] = (
                "A different and weaker observable is substituted under the approved identifier"
            )

        head, _ = self.fixture.add_change(mutate)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "changes semantics"):
            self.fixture.validate(head)

    def test_same_id_cannot_rebind_failure_semantics(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            value["failure_modes"][0]["expected_behavior"] = (
                "The malformed request is accepted despite the reviewed fail-closed requirement"
            )

        head, _ = self.fixture.add_change(mutate)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "changes semantics"):
            self.fixture.validate(head)

    def test_change_cannot_omit_reviewed_definitions_or_outcomes(self) -> None:
        extensions = (
            lambda value: value["evaluation"]["acceptance_criteria"].append(
                criterion("AC-POSITIVE-SECOND", "positive")
            ),
            lambda value: value["failure_modes"].append(
                {
                    "id": "FM-SECOND",
                    "condition": "A second independently reviewed adverse condition reaches the boundary",
                    "expected_behavior": "The condition is rejected and protected state remains unchanged",
                    "detection_ref": "TEST-NEGATIVE",
                    "rollback_trigger": "Any acceptance of the condition stops rollout and restores prior state",
                }
            ),
            lambda value: value["evaluation"]["outcome_metrics"].append(
                {
                    **copy.deepcopy(value["evaluation"]["outcome_metrics"][0]),
                    "id": "METRIC-SECOND",
                }
            ),
        )
        for extend in extensions:
            with self.subTest(extend=extend):
                fixture = ChangeRepository()
                try:
                    extend(fixture.design)
                    fixture.design_raw = canonical_bytes(fixture.design)
                    (fixture.root / f"docs/decisions/{DESIGN_ID}.json").write_bytes(
                        fixture.design_raw
                    )
                    fixture.commit("extend reviewed design")
                    fixture.base = fixture.revision("HEAD")
                    head, _ = fixture.add_change()
                    with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "exactly match"):
                        fixture.validate(head)
                finally:
                    fixture.close()

    def test_unresolved_draft_placeholders_cannot_enter_admission(self) -> None:
        replacements = (
            "EDIT ME: replace this long placeholder before review and admission",
            "This TODO remains unresolved even though the surrounding prose is long enough",
            "The implementation detail is still TBD before this declaration is reviewable",
            "__MERGEGROUNDS_TEMPLATE_DRAFT__ replace this generated template sentinel",
        )
        for replacement in replacements:
            with self.subTest(replacement=replacement):
                fixture = ChangeRepository()
                try:
                    head, _ = fixture.add_change(
                        lambda value, replacement=replacement: value["summary"].update(problem=replacement)
                    )
                    with self.assertRaisesRegex(
                        mergegrounds.MergeGroundsError,
                        "unresolved draft placeholder",
                    ):
                        fixture.validate(head)
                finally:
                    fixture.close()

        fixture = ChangeRepository()
        try:
            head, _ = fixture.add_change(
                lambda value: value["summary"].update(
                    non_goals=["A tOdO placeholder hidden inside a string-array item"]
                )
            )
            with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "unresolved draft placeholder"):
                fixture.validate(head)
        finally:
            fixture.close()

    def test_model_or_self_review_cannot_be_evidence(self) -> None:
        cases = (
            lambda value: value["acceptance_criteria"][0]["oracle"].update(evidence_class="model_output"),
            lambda value: value["challenge_plan"][0].update(required_producer="self_review"),
            lambda value: value["evidence_policy"].update(self_review_is_evidence=True),
        )
        for mutate in cases:
            with self.subTest(mutate=mutate):
                fixture = ChangeRepository()
                try:
                    head, _ = fixture.add_change(mutate)
                    with self.assertRaises(mergegrounds.MergeGroundsError):
                        fixture.validate(head)
                finally:
                    fixture.close()

    def test_missing_negative_or_adversarial_oracle_denies(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            value["acceptance_criteria"] = value["acceptance_criteria"][:1]

        head, _ = self.fixture.add_change(mutate)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "requires acceptance classes"):
            self.fixture.validate(head)

    def test_failure_detection_must_use_non_positive_oracle(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            value["failure_modes"][0]["detection_ref"] = "TEST-POSITIVE"

        head, _ = self.fixture.add_change(mutate)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "negative, adversarial, or recovery"):
            self.fixture.validate(head)

    def test_challenge_must_reference_adversarial_oracle(self) -> None:
        def mutate(value: dict[str, Any]) -> None:
            value["challenge_plan"][0]["evaluation_ref"] = "TEST-NEGATIVE"

        head, _ = self.fixture.add_change(mutate)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "adversarial oracle"):
            self.fixture.validate(head)

    def test_unknown_field_and_duplicate_key_deny(self) -> None:
        def unknown(value: dict[str, Any]) -> None:
            value["confidence"] = 1.0

        head, _ = self.fixture.add_change(unknown)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "unsupported fields"):
            self.fixture.validate(head)

        fixture = ChangeRepository()
        try:
            declaration = change_contract(fixture.design_raw)
            raw = canonical_bytes(declaration).replace(
                b'  "change_id":',
                b'  "change_id": "22222222-2222-4222-8222-222222222222",\n  "change_id":',
                1,
            )
            head, _ = fixture.add_change(raw=raw)
            with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "duplicate JSON key"):
                fixture.validate(head)
        finally:
            fixture.close()

    def test_non_finite_and_oversized_contracts_deny(self) -> None:
        def non_finite(value: dict[str, Any]) -> None:
            value["risk"]["score"] = float("nan")

        declaration = change_contract(self.fixture.design_raw)
        raw = json.dumps(declaration, allow_nan=True).replace('"risk": {', '"risk": {"score": NaN,', 1).encode()
        head, _ = self.fixture.add_change(raw=raw)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "non-finite"):
            self.fixture.validate(head)

        fixture = ChangeRepository()
        try:
            huge = b'{"padding":"' + (b"x" * mergegrounds.MAX_CHANGE_CONTRACT_BYTES) + b'"}'
            head, _ = fixture.add_change(raw=huge)
            with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "between 1 and"):
                fixture.validate(head)
        finally:
            fixture.close()

    def test_symlink_contract_is_not_a_regular_git_blob(self) -> None:
        declaration = change_contract(self.fixture.design_raw)
        target = self.fixture.root / "declaration-target.json"
        target.write_bytes(canonical_bytes(declaration))
        path = self.fixture.root / f".mergegrounds/changes/{CHANGE_ID}.json"
        os.symlink(target, path)
        (self.fixture.root / "src/app.py").write_text("VALUE = 2\n", encoding="utf-8")
        self.fixture.commit("symlink candidate")
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "regular Git blob"):
            self.fixture.validate(self.fixture.revision("HEAD"))

    def test_implementation_cannot_add_or_modify_design_record(self) -> None:
        fixture = ChangeRepository(design_in_base=False)
        try:
            fixture.design_raw = canonical_bytes(fixture.design)
            (fixture.root / f"docs/decisions/{DESIGN_ID}.json").write_bytes(fixture.design_raw)
            head, _ = fixture.add_change()
            with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "design contract"):
                fixture.validate(head)
        finally:
            fixture.close()

    def test_design_only_lane_adds_no_implementation(self) -> None:
        fixture = ChangeRepository(design_in_base=False)
        try:
            head, _ = fixture.add_change(lane="design-only", add_code=False)
            self.assertEqual("design-only", fixture.validate(head)["lane"])
        finally:
            fixture.close()

        fixture = ChangeRepository(design_in_base=False)
        try:
            head, _ = fixture.add_change(lane="design-only", add_code=True)
            with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "design-only lane"):
                fixture.validate(head)
        finally:
            fixture.close()

    def test_existing_declaration_is_append_only(self) -> None:
        head, declaration = self.fixture.add_change()
        self.fixture.base = head
        declaration["summary"]["problem"] = "A later pull request attempts to rewrite an already retained change declaration."
        (self.fixture.root / f".mergegrounds/changes/{CHANGE_ID}.json").write_bytes(canonical_bytes(declaration))
        self.fixture.commit("rewrite declaration")
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "append-only"):
            self.fixture.validate(self.fixture.revision("HEAD"))

    def test_base_revision_must_be_ancestor_of_head(self) -> None:
        head, _ = self.fixture.add_change()
        subprocess.run(
            ["git", "checkout", "-q", "-b", "sibling", self.fixture.base],
            cwd=self.fixture.root,
            check=True,
        )
        (self.fixture.root / "sibling.txt").write_text("unrelated branch\n", encoding="utf-8")
        self.fixture.commit("sibling")
        sibling = self.fixture.revision("HEAD")
        _, config = mergegrounds.config_for(self.fixture.root)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "base revision must be an ancestor"):
            mergegrounds.validate_change_between(self.fixture.root, config, sibling, head)


if __name__ == "__main__":
    unittest.main()
