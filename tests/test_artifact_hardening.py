from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mergegrounds_artifact_hardening", ROOT / "scripts" / "mergegrounds.py")
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)


class ArtifactHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "reports").mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def adapter(stage: str, pattern: str = "reports/*") -> dict[str, object]:
        return {"id": "fixture", "artifacts": {stage: [pattern]}}

    def write(self, name: str, value: str | bytes) -> Path:
        path = self.root / "reports" / name
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")
        return path

    def test_empty_and_oversize_artifacts_are_rejected_before_hashing(self) -> None:
        self.write("empty.bin", b"")
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "is empty"):
            mergegrounds.validate_stage_artifacts(self.root, self.adapter("build"), "build")

        (self.root / "reports" / "empty.bin").unlink()
        self.write("large.bin", b"12345")
        with mock.patch.object(mergegrounds, "MAX_ARTIFACT_BYTES", 4):
            with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "artifact limit"):
                mergegrounds.validate_stage_artifacts(self.root, self.adapter("build"), "build")

    def test_positive_junit_is_semantically_recorded(self) -> None:
        self.write(
            "junit.xml",
            """<?xml version="1.0"?>
<testsuites tests="2" failures="0" errors="0" skipped="1">
  <testsuite name="unit" tests="2" failures="0" errors="0" skipped="1">
    <testcase classname="pkg.Test" name="passes"/>
    <testcase classname="pkg.Test" name="skips"><skipped/></testcase>
  </testsuite>
</testsuites>
""",
        )
        result = mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit", "reports/*.xml"), "unit")
        assert result is not None
        semantics = result["files"][0]["test_results"]
        self.assertEqual("junit", semantics["format"])
        self.assertEqual(2, semantics["tests"])
        self.assertEqual(1, semantics["executed"])
        self.assertEqual(0, semantics["failures"])

    def test_junit_zero_execution_or_hidden_failure_is_rejected(self) -> None:
        path = self.write(
            "junit.xml",
            '<testsuite tests="1" failures="0" errors="0" skipped="1"><testcase name="x"><skipped/></testcase></testsuite>',
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "no executed tests"):
            mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit", "reports/*.xml"), "unit")

        path.write_text(
            '<testsuite tests="1" failures="0" errors="0"><testcase name="x"><failure/></testcase></testsuite>',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "reports a failure"):
            mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit", "reports/*.xml"), "unit")

    def test_positive_trx_is_semantically_recorded(self) -> None:
        self.write(
            "tests.trx",
            f"""<?xml version="1.0"?>
<TestRun xmlns="{mergegrounds.TRX_NAMESPACE}">
  <Results><UnitTestResult executionId="execution-1" testId="test-1" outcome="Passed"/></Results>
  <ResultSummary outcome="Completed">
    <Counters total="1" executed="1" passed="1" failed="0" error="0" notExecuted="0"/>
  </ResultSummary>
</TestRun>
""",
        )
        result = mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit", "reports/*.trx"), "unit")
        assert result is not None
        semantics = result["files"][0]["test_results"]
        self.assertEqual("trx", semantics["format"])
        self.assertEqual(1, semantics["executed"])
        self.assertEqual(1, semantics["passed"])

    def test_trx_adverse_or_inconsistent_results_are_rejected(self) -> None:
        path = self.write(
            "tests.trx",
            f"""<TestRun xmlns="{mergegrounds.TRX_NAMESPACE}">
  <Results><UnitTestResult executionId="execution-1" testId="test-1" outcome="Failed"/></Results>
  <ResultSummary outcome="Completed">
    <Counters total="1" executed="1" passed="0" failed="1" error="0"/>
  </ResultSummary>
</TestRun>""",
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "failed, error, or inconclusive"):
            mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit", "reports/*.trx"), "unit")

        path.write_text(
            f"""<TestRun xmlns="{mergegrounds.TRX_NAMESPACE}">
  <Results><UnitTestResult executionId="execution-1" testId="test-1" outcome="Passed"/></Results>
  <ResultSummary outcome="Completed">
    <Counters total="1" executed="1" passed="0" failed="0" error="0"/>
  </ResultSummary>
</TestRun>""",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "inconsistent total/executed/passed"):
            mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit", "reports/*.trx"), "unit")

    def test_opaque_unit_artifacts_are_supplemental_only(self) -> None:
        self.write("opaque.json", "{}")
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "no supported positive JUnit or TRX"):
            mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit"), "unit")

        self.write(
            "junit.xml",
            '<testsuite tests="1" failures="0" errors="0"><testcase name="passes"/></testsuite>',
        )
        result = mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit"), "unit")
        assert result is not None
        by_path = {record["path"]: record for record in result["files"]}
        self.assertEqual("unavailable", by_path["reports/opaque.json"]["semantic_validation"])
        self.assertEqual("junit", by_path["reports/junit.xml"]["test_results"]["format"])

    def test_test_result_dtd_is_rejected(self) -> None:
        self.write(
            "junit.xml",
            '<!DOCTYPE testsuite [<!ENTITY x "x">]><testsuite tests="1" failures="0" errors="0"><testcase name="&x;"/></testsuite>',
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "DTD or entity"):
            mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit", "reports/*.xml"), "unit")

        # Scan the complete bounded artifact, not just a small prefix that an
        # attacker could pad past before declaring an entity.
        (self.root / "reports" / "junit.xml").write_text(
            " " * 5000
            + '<!DOCTYPE testsuite [<!ENTITY x "x">]><testsuite tests="1" failures="0" errors="0"/>',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "DTD or entity"):
            mergegrounds.validate_stage_artifacts(self.root, self.adapter("unit", "reports/*.xml"), "unit")

    def test_junit_rejects_counter_and_detail_ambiguity(self) -> None:
        invalid = (
            ("<root/>", "no testsuite"),
            ('<testsuite tests="1" errors="0"/>', "lacks the 'failures' counter"),
            ('<testsuite tests="1" failures="1" errors="0"/>', "failures or errors"),
            (
                '<testsuite tests="1" failures="0" errors="0" skipped="2"/>',
                "outcome counters exceed",
            ),
            (
                '<testsuite tests="1" failures="0" errors="0"><testcase/></testsuite>',
                "non-empty name",
            ),
            (
                '<testsuite tests="1" failures="0" errors="0">'
                '<testcase name="x" status="failed"/></testsuite>',
                "adverse status",
            ),
            (
                '<testsuites tests="1"><testsuite tests="1" failures="0" errors="0">'
                '<testcase name="x"/></testsuite></testsuites>',
                "incomplete counter set",
            ),
            (
                '<testsuites tests="1" failures="1" errors="0">'
                '<testsuite tests="1" failures="0" errors="0"><testcase name="x"/>'
                "</testsuite></testsuites>",
                "root reports failures",
            ),
            (
                '<testsuites tests="1" failures="0" errors="0" skipped="2">'
                '<testsuite tests="1" failures="0" errors="0"><testcase name="x"/>'
                "</testsuite></testsuites>",
                "root outcome counters exceed",
            ),
            (
                '<testsuites tests="2" failures="0" errors="0">'
                '<testsuite tests="1" failures="0" errors="0"><testcase name="x"/>'
                "</testsuite></testsuites>",
                "root counters disagree",
            ),
            (
                '<testsuite tests="2" failures="0" errors="0"><testcase name="x"/>'
                "</testsuite>",
                "detail disagrees",
            ),
            (
                '<testsuite tests="2" failures="0" errors="0">'
                '<testcase name="x"/><testcase name="y"><skipped/></testcase></testsuite>',
                "outcomes disagree",
            ),
        )
        for index, (xml, message) in enumerate(invalid):
            with self.subTest(index=index):
                path = self.write(f"invalid-junit-{index}.xml", xml)
                root = mergegrounds.parse_test_result_xml(path)
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, message):
                    mergegrounds.junit_artifact_semantics(root, path)

    def test_trx_rejects_namespace_summary_and_result_ambiguity(self) -> None:
        namespace = mergegrounds.TRX_NAMESPACE

        def trx(results: str, summary: str, namespace_value: str = namespace) -> str:
            return f'<TestRun xmlns="{namespace_value}"><Results>{results}</Results>{summary}</TestRun>'

        completed = (
            '<ResultSummary outcome="Completed"><Counters total="1" executed="1" '
            'passed="1" failed="0" error="0"/></ResultSummary>'
        )
        passed = '<UnitTestResult executionId="one" outcome="Passed"/>'
        invalid = (
            (trx(passed, completed, "urn:wrong"), "unsupported or absent namespace"),
            (trx(passed, ""), "exactly one ResultSummary"),
            (
                trx(passed, completed.replace('outcome="Completed"', 'outcome="Failed"')),
                "outcome must be Completed",
            ),
            (
                trx(passed, completed.replace('failed="0"', 'failed="1"')),
                "failed, error, or inconclusive",
            ),
            (
                trx(passed, completed.replace('passed="1"', 'passed="0"')),
                "inconsistent total/executed/passed",
            ),
            (
                trx(
                    "",
                    completed.replace('total="1" executed="1" passed="1"', 'total="0" executed="0" passed="0"'),
                ),
                "no executed tests",
            ),
            (trx("", completed), "no UnitTestResult"),
            (
                trx('<UnitTestResult executionId="" outcome="Passed"/>', completed),
                "executionId is absent",
            ),
            (
                trx('<UnitTestResult executionId="one" outcome="Failed"/>', completed),
                "adverse or unknown outcome",
            ),
            (
                trx(
                    passed + '<UnitTestResult executionId="two" outcome="NotExecuted"/>',
                    completed,
                ),
                "detail disagrees with the total",
            ),
            (
                trx(
                    '<UnitTestResult executionId="one" outcome="NotExecuted"/>',
                    completed,
                ),
                "passed result detail disagrees",
            ),
        )
        for index, (xml, message) in enumerate(invalid):
            with self.subTest(index=index):
                path = self.write(f"invalid-{index}.trx", xml)
                root = mergegrounds.parse_test_result_xml(path)
                with self.assertRaisesRegex(mergegrounds.MergeGroundsError, message):
                    mergegrounds.trx_artifact_semantics(root, path)

if __name__ == "__main__":
    unittest.main()
