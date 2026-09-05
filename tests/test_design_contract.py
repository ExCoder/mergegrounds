from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

from test_change_contract import DESIGN_ID, design_contract


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mergegrounds_design_contract", ROOT / "scripts" / "mergegrounds.py")
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)


class DesignContractTests(unittest.TestCase):
    def test_valid_contract_exposes_canonical_definitions(self) -> None:
        value = design_contract()
        result = mergegrounds.validate_design_contract(value, DESIGN_ID)
        self.assertIn("AC-ADVERSARIAL", result["acceptance_definitions"])
        self.assertIn("FM-INVALID-INPUT", result["failure_definitions"])

    def test_unknown_top_level_or_nested_field_denies(self) -> None:
        for mutate in (
            lambda value: value.update(approval="self-approved"),
            lambda value: value["evaluation"]["acceptance_criteria"][0].update(confidence=1.0),
            lambda value: value["failure_modes"][0].update(model_reasoning="looks safe"),
        ):
            with self.subTest(mutate=mutate):
                value = design_contract()
                mutate(value)
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "unsupported fields"):
                    mergegrounds.validate_design_contract(value, DESIGN_ID)

    def test_design_must_cover_all_strict_evaluation_classes(self) -> None:
        value = design_contract()
        value["evaluation"]["acceptance_criteria"] = [
            item for item in value["evaluation"]["acceptance_criteria"] if item["class"] != "recovery"
        ]
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "positive, negative, adversarial, and recovery"):
            mergegrounds.validate_design_contract(value, DESIGN_ID)

    def test_unresolved_placeholders_are_rejected_in_text_and_string_arrays(self) -> None:
        cases = (
            lambda value: value.update(title="edit me: generated design title"),
            lambda value: value.update(
                problem="This apparently detailed problem statement still contains a TODO marker"
            ),
            lambda value: value.update(
                goals=["This measurable outcome remains tBd before independent design review"]
            ),
            lambda value: value.update(
                non_goals=["__MERGEGROUNDS_TEMPLATE__ generated draft sentinel remains unresolved"]
            ),
            lambda value: value.update(
                title="MERGEGROUNDS_TEMPLATE_SENTINEL generated design title"
            ),
        )
        for mutate in cases:
            with self.subTest(mutate=mutate):
                value = design_contract()
                mutate(value)
                with self.assertRaisesRegex(
                    mergegrounds.MergeGroundsError,
                    "unresolved draft placeholder",
                ):
                    mergegrounds.validate_design_contract(value, DESIGN_ID)

    def test_failure_mode_cannot_use_positive_oracle(self) -> None:
        value = design_contract()
        value["failure_modes"][0]["detection_ref"] = "TEST-POSITIVE"
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "negative, adversarial, or recovery"):
            mergegrounds.validate_design_contract(value, DESIGN_ID)

    def test_model_output_cannot_be_an_oracle(self) -> None:
        value = design_contract()
        value["evaluation"]["acceptance_criteria"][0]["oracle"]["evidence_class"] = "model_output"
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "independently produced evidence"):
            mergegrounds.validate_design_contract(value, DESIGN_ID)

    def test_outcome_metrics_are_promotion_blocking_and_trusted(self) -> None:
        cases = (
            ("evidence_class", "model_output"),
            ("minimum_samples", 0),
            ("maximum_missing_percent", 100.0),
            ("promotion_blocking", False),
            ("failure_action", "observe"),
        )
        for field, replacement in cases:
            with self.subTest(field=field):
                value = design_contract()
                value["evaluation"]["outcome_metrics"][0][field] = replacement
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.validate_design_contract(value, DESIGN_ID)

    def test_strict_json_rejects_duplicate_nonfinite_bom_and_depth(self) -> None:
        duplicate = b'{"schema_version":1,"schema_version":1}'
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "duplicate JSON key"):
            mergegrounds.strict_json_document(duplicate, "fixture", 1024)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "non-finite"):
            mergegrounds.strict_json_document(b'{"score":NaN}', "fixture", 1024)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "non-finite"):
            mergegrounds.strict_json_document(b'{"score":1e999}', "fixture", 1024)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "byte-order mark"):
            mergegrounds.strict_json_document(b"\xef\xbb\xbf{}", "fixture", 1024)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "invalid Unicode"):
            mergegrounds.strict_json_document(b'{"text":"\\ud800"}', "fixture", 1024)
        nested: object = "leaf"
        for _ in range(mergegrounds.MAX_JSON_DEPTH + 2):
            nested = {"next": nested}
        raw = json.dumps(nested).encode("utf-8")
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "nesting depth"):
            mergegrounds.strict_json_document(raw, "fixture", len(raw) + 1)

    def test_verification_refs_must_exist(self) -> None:
        value = copy.deepcopy(design_contract())
        value["rollback"]["verification_ref"] = "AC-UNKNOWN"
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "verification refs"):
            mergegrounds.validate_design_contract(value, DESIGN_ID)


if __name__ == "__main__":
    unittest.main()
