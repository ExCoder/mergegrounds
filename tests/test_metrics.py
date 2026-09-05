from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mergegrounds_metrics_under_test", ROOT / "scripts" / "mergegrounds.py")
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)


class MetricParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_json(self, name: str, value: object) -> Path:
        return self.write(name, json.dumps(value))

    def test_coverage_py_json(self) -> None:
        path = self.write_json(
            "coverage.json",
            {"totals": {"covered_lines": 9, "num_statements": 10, "covered_branches": 4, "num_branches": 5}},
        )
        values, counts = mergegrounds.aggregate_coverage("coverage-json", [path], True)
        self.assertEqual(90.0, values["line_coverage"])
        self.assertEqual(80.0, values["branch_coverage"])
        self.assertEqual(10, counts["line_total"])

    def test_coverage_json_rejects_cross_report_counter_offsets(self) -> None:
        high = self.write_json(
            "high.json",
            {"totals": {"covered_lines": 200, "num_statements": 100, "covered_branches": 20, "num_branches": 10}},
        )
        low = self.write_json(
            "low.json",
            {"totals": {"covered_lines": 0, "num_statements": 100, "covered_branches": 0, "num_branches": 10}},
        )
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.aggregate_coverage("coverage-json", [high, low], True)

    def test_istanbul_summary_json(self) -> None:
        path = self.write_json(
            "coverage-summary.json",
            {"total": {"lines": {"total": 20, "covered": 19}, "branches": {"total": 10, "covered": 9}}},
        )
        values, _ = mergegrounds.aggregate_coverage("coverage-json", [path], True)
        self.assertEqual(95.0, values["line_coverage"])
        self.assertEqual(90.0, values["branch_coverage"])

    def test_cobertura(self) -> None:
        path = self.write("coverage.xml", '<coverage lines-covered="90" lines-valid="100" branches-covered="18" branches-valid="20"/>')
        values, _ = mergegrounds.aggregate_coverage("cobertura", [path], True)
        self.assertEqual(90.0, values["line_coverage"])
        self.assertEqual(90.0, values["branch_coverage"])

    def test_cobertura_rejects_cross_report_counter_offsets(self) -> None:
        high = self.write("high.xml", '<coverage lines-covered="200" lines-valid="100" branches-covered="20" branches-valid="10"/>')
        low = self.write("low.xml", '<coverage lines-covered="0" lines-valid="100" branches-covered="0" branches-valid="10"/>')
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.aggregate_coverage("cobertura", [high, low], True)

    def test_metric_xml_rejects_dtd_and_entities(self) -> None:
        path = self.write(
            "coverage.xml",
            '<!DOCTYPE coverage [<!ENTITY x "1">]><coverage lines-covered="&x;" lines-valid="1"/>',
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "DTD or entity"):
            mergegrounds.aggregate_coverage("cobertura", [path], False)

    def test_jacoco(self) -> None:
        path = self.write(
            "jacoco.xml",
            '<report><counter type="LINE" missed="10" covered="90"/><counter type="BRANCH" missed="2" covered="18"/></report>',
        )
        values, _ = mergegrounds.aggregate_coverage("jacoco", [path], True)
        self.assertEqual(90.0, values["line_coverage"])
        self.assertEqual(90.0, values["branch_coverage"])

    def test_lcov_and_branch_not_required(self) -> None:
        path = self.write("lcov.info", "SF:src/lib.rs\nLF:10\nLH:9\nBRF:0\nBRH:0\nend_of_record\n")
        values, _ = mergegrounds.aggregate_coverage("lcov", [path], False)
        self.assertEqual(90.0, values["line_coverage"])
        self.assertIsNone(values["branch_coverage"])

    def test_lcov_rejects_per_record_counter_offsets_and_duplicates(self) -> None:
        offset = self.write(
            "offset.info",
            "SF:a.rs\nLF:1\nLH:2\nend_of_record\nSF:b.rs\nLF:1\nLH:0\nend_of_record\n",
        )
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.aggregate_coverage("lcov", [offset], False)
        duplicate = self.write(
            "duplicate.info",
            "SF:a.rs\nLF:1\nLF:2\nLH:1\nend_of_record\n",
        )
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.aggregate_coverage("lcov", [duplicate], False)

    def test_go_statement_coverage(self) -> None:
        path = self.write(
            "coverage.out",
            "mode: atomic\nexample/a.go:1.1,2.2 4 1\nexample/a.go:3.1,4.2 1 0\n",
        )
        values, _ = mergegrounds.aggregate_coverage("go-cover", [path], False)
        self.assertEqual(80.0, values["line_coverage"])

    def test_mergegrounds_json_rejects_extra_or_nonfinite_keys(self) -> None:
        extra = self.write_json(
            "extra.json",
            {"line_coverage": 90, "branch_coverage": 90, "mutation_score": 90, "bonus": 100},
        )
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.mergegrounds_metrics(extra)
        invalid = self.write(
            "invalid.json",
            '{"line_coverage": NaN, "branch_coverage": 90, "mutation_score": 90}',
        )
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.mergegrounds_metrics(invalid)

    def test_stryker_statuses(self) -> None:
        path = self.write_json(
            "mutation.json",
            {"files": {"src/a.ts": {"mutants": [{"id": "1", "status": "Killed"}, {"id": "2", "status": "Survived"}, {"id": "3", "status": "CompileError"}]}}},
        )
        score, counts = mergegrounds.aggregate_mutation("stryker-json", [path])
        self.assertEqual(50.0, score)
        self.assertEqual(1, counts["unviable"])

    def test_pit_status_and_detected_must_agree(self) -> None:
        good = self.write(
            "pit.xml",
            '<mutations><mutation detected="true" status="KILLED"/><mutation detected="false" status="SURVIVED"/></mutations>',
        )
        score, _ = mergegrounds.aggregate_mutation("pit-xml", [good])
        self.assertEqual(50.0, score)
        bad = self.write("bad-pit.xml", '<mutations><mutation detected="true" status="SURVIVED"/></mutations>')
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.aggregate_mutation("pit-xml", [bad])

    def test_gremlins_recomputes_native_metrics(self) -> None:
        statuses = ["KILLED"] * 4 + ["LIVED"] * 3 + ["NOT COVERED"] * 3 + ["NOT VIABLE"] * 2
        path = self.write_json(
            "gremlins.json",
            {
                "mutants_total": 9,
                "mutants_killed": 4,
                "mutants_lived": 3,
                "mutants_not_covered": 3,
                "mutants_not_viable": 2,
                "test_efficacy": 57.14285714285714,
                "mutations_coverage": 70,
                "files": [
                    {
                        "file_name": "a.go",
                        "mutations": [
                            {"line": index + 1, "column": 1, "type": f"TYPE_{index}", "status": status}
                            for index, status in enumerate(statuses)
                        ],
                    }
                ],
            },
        )
        score, counts = mergegrounds.aggregate_mutation("gremlins-json", [path])
        self.assertEqual(40.0, score)
        self.assertEqual(2, counts["unviable"])

    def test_gremlins_rejects_duplicate_mutation_identity(self) -> None:
        mutation = {"line": 1, "column": 1, "type": "ARITHMETIC_BASE", "status": "KILLED"}
        path = self.write_json(
            "duplicate-gremlins.json",
            {
                "mutants_total": 2,
                "mutants_killed": 2,
                "mutants_lived": 0,
                "mutants_not_covered": 0,
                "mutants_not_viable": 0,
                "test_efficacy": 100,
                "mutations_coverage": 100,
                "files": [{"file_name": "a.go", "mutations": [mutation, mutation]}],
            },
        )
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.aggregate_mutation("gremlins-json", [path])

    def test_gremlins_rejects_malformed_details_and_native_score_drift(self) -> None:
        mutation = {"line": 1, "column": 1, "type": "ARITHMETIC", "status": "KILLED"}
        base = {
            "mutants_total": 1,
            "mutants_killed": 1,
            "mutants_lived": 0,
            "mutants_not_covered": 0,
            "mutants_not_viable": 0,
            "test_efficacy": 100,
            "mutations_coverage": 100,
            "files": [{"file_name": "a.go", "mutations": [mutation]}],
        }
        malformed = (
            {**base, "files": []},
            {**base, "files": ["bad"]},
            {**base, "files": [{"file_name": "", "mutations": [mutation]}]},
            {**base, "files": [{"file_name": "a.go", "mutations": ["bad"]}]},
            {
                **base,
                "files": [{"file_name": "a.go", "mutations": [{**mutation, "line": 0}]}],
            },
            {
                **base,
                "files": [{"file_name": "a.go", "mutations": [{**mutation, "column": 0}]}],
            },
            {
                **base,
                "files": [{"file_name": "a.go", "mutations": [{**mutation, "type": ""}]}],
            },
            {**base, "mutants_killed": 0},
            {**base, "mutants_total": 2},
            {**base, "test_efficacy": 0},
            {**base, "mutations_coverage": 0},
        )
        for index, document in enumerate(malformed):
            with self.subTest(index=index):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.gremlins_counts(self.write_json(f"bad-gremlins-{index}.json", document))

    def test_mutmut_requires_explained_total(self) -> None:
        path = self.write_json(
            "mutmut.json",
            {"killed": 9, "survived": 1, "total": 10, "no_tests": 0, "skipped": 0, "suspicious": 0, "timeout": 0, "check_was_interrupted_by_user": 0, "segfault": 0},
        )
        score, _ = mergegrounds.aggregate_mutation("mutmut-json", [path])
        self.assertEqual(90.0, score)
        broken = self.write_json(
            "broken-mutmut.json",
            {"killed": 9, "survived": 0, "total": 10, "no_tests": 0, "skipped": 0, "suspicious": 0, "timeout": 0, "check_was_interrupted_by_user": 0, "segfault": 0},
        )
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.aggregate_mutation("mutmut-json", [broken])

    def test_infection_recomputes_native_score(self) -> None:
        path = self.write_json(
            "infection.json",
            {"stats": {"totalMutantsCount": 10, "killedCount": 9, "escapedCount": 1, "notCoveredCount": 0, "timeOutCount": 0, "errorCount": 0, "syntaxErrorCount": 0, "skippedCount": 0, "ignoredCount": 0, "msi": 90, "mutationCodeCoverage": 100, "coveredCodeMsi": 90}},
        )
        score, _ = mergegrounds.aggregate_mutation("infection-json", [path])
        self.assertEqual(90.0, score)

    def test_cargo_mutants(self) -> None:
        path = self.write_json(
            "outcomes.json",
            {
                "total_mutants": 1,
                "caught": 1,
                "missed": 0,
                "timeout": 0,
                "unviable": 0,
                "success": 0,
                "end_time": "2026-09-05T00:00:00Z",
                "outcomes": [
                    {"scenario": "Baseline", "summary": "Success"},
                    {"scenario": {"Mutant": {"name": "fixture"}}, "summary": "CaughtMutant"},
                ],
            },
        )
        score, _ = mergegrounds.aggregate_mutation("cargo-mutants", [path])
        self.assertEqual(100.0, score)

    def test_unchanged_report_is_stale(self) -> None:
        self.write_json(
            "metrics.json",
            {"line_coverage": 100, "branch_coverage": 100, "mutation_score": 100},
        )
        descriptor = {"paths": ["metrics.json"]}
        before = mergegrounds.report_snapshot(self.root, descriptor)
        files = mergegrounds.select_report_files(self.root, descriptor)
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.require_fresh_reports(self.root, files, before)

    def test_touch_alone_does_not_make_report_fresh(self) -> None:
        path = self.write_json(
            "metrics.json",
            {"line_coverage": 100, "branch_coverage": 100, "mutation_score": 100},
        )
        descriptor = {"paths": ["metrics.json"]}
        before = mergegrounds.report_snapshot(self.root, descriptor)
        path.touch()
        files = mergegrounds.select_report_files(self.root, descriptor)
        with self.assertRaises(mergegrounds.MergeGroundsError):
            mergegrounds.require_fresh_reports(self.root, files, before)

    def test_metric_descriptor_and_report_selection_fail_closed(self) -> None:
        adapter = {"id": "fixture", "metrics": "invalid"}
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "metrics must be a table"):
            mergegrounds.descriptor_for(adapter, "coverage")
        adapter["metrics"] = {"coverage": "invalid"}
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "metrics.coverage must be a table"):
            mergegrounds.descriptor_for(adapter, "coverage")
        adapter["metrics"] = {}
        self.assertIsNone(mergegrounds.descriptor_for(adapter, "coverage"))

        for descriptor in ({}, {"paths": []}, {"paths": ["../escape"]}, {"paths": ["missing.*"]}):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.select_report_files(self.root, descriptor)
        empty = self.write("empty.json", "")
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "empty"):
            mergegrounds.select_report_files(self.root, {"paths": [empty.name]})
        outside = self.write("outside.json", "{}")
        link = self.root / "link.json"
        link.symlink_to(outside)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "regular in-repository"):
            mergegrounds.select_report_files(self.root, {"paths": [link.name]})

    def test_coverage_schema_variants_reject_partial_or_impossible_counts(self) -> None:
        invalid_documents = (
            [],
            {},
            {"totals": {"covered_lines": 1, "num_statements": 1, "num_branches": 1}},
            {"total": {"lines": {"covered": 1, "total": 1}}},
            {
                "totals": {
                    "covered_lines": 2,
                    "num_statements": 1,
                    "covered_branches": 0,
                    "num_branches": 0,
                }
            },
        )
        for index, document in enumerate(invalid_documents):
            with self.subTest(index=index):
                path = self.write_json(f"invalid-coverage-{index}.json", document)
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.coverage_json_counts(path)

    def test_xml_coverage_formats_reject_incomplete_roots_and_counters(self) -> None:
        for name, content, parser in (
            ("malformed.xml", "<coverage>", mergegrounds.parse_xml),
            ("missing-cobertura.xml", "<coverage/>", mergegrounds.cobertura_counts),
            (
                "partial-cobertura.xml",
                '<coverage lines-covered="1" lines-valid="1" branches-covered="1"/>',
                mergegrounds.cobertura_counts,
            ),
            ("missing-jacoco.xml", "<report/>", mergegrounds.jacoco_counts),
            (
                "duplicate-jacoco.xml",
                '<report><counter type="LINE" missed="0" covered="1"/>'
                '<counter type="LINE" missed="0" covered="1"/></report>',
                mergegrounds.jacoco_counts,
            ),
        ):
            with self.subTest(name=name):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    parser(self.write(name, content))

    def test_lcov_rejects_truncated_ambiguous_and_empty_records(self) -> None:
        values = (
            "SF:a.py\nLH:1\nLF:1\n",
            "end_of_record\n",
            "SF:a.py\nLH:1\nend_of_record\n",
            "SF:a.py\nLH:1\nLF:1\nBRH:0\nend_of_record\n",
            "SF:a.py\nLH:nope\nLF:1\nend_of_record\n",
            "SF:a.py\nLH:1\nLH:1\nLF:1\nend_of_record\n",
            "",
        )
        for index, value in enumerate(values):
            with self.subTest(index=index):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.lcov_counts(self.write(f"invalid-{index}.lcov", value))

    def test_go_coverage_rejects_invalid_modes_sources_ranges_and_duplicates(self) -> None:
        values = (
            "",
            "mode: invalid\n",
            "mode: set\n",
            "mode: set\nnot a record\n",
            "mode: set\n../a.go:1.1,2.1 1 1\n",
            "mode: set\na.go:0.1,2.1 1 1\n",
            "mode: set\na.go:2.1,1.1 1 1\n",
            "mode: set\na.go:1.1,2.1 1 2\n",
            "mode: count\na.go:1.1,3.1 1 1\na.go:2.1,4.1 1 1\n",
            "mode: count\na.go:1.1,2.1 1 1\na.go:1.1,2.1 1 1\n",
        )
        for index, value in enumerate(values):
            with self.subTest(index=index):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.go_cover_counts(self.write(f"invalid-go-{index}.out", value))

    def test_mutation_parsers_reject_unknown_empty_and_duplicate_records(self) -> None:
        counts = mergegrounds.empty_mutation_counts()
        for status in (None, "", "unknown"):
            with self.subTest(status=status):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.add_status(counts, status, "fixture")
        invalid_stryker = (
            {},
            {"files": {}},
            {"files": {"a": {}}},
            {"files": {"a": {"mutants": ["bad"]}}},
            {
                "files": {
                    "a": {
                        "mutants": [
                            {"id": "same", "status": "Killed"},
                            {"id": "same", "status": "Killed"},
                        ]
                    }
                }
            },
        )
        for index, document in enumerate(invalid_stryker):
            with self.subTest(index=index):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.stryker_counts(self.write_json(f"bad-stryker-{index}.json", document))
        for content in ("<mutations/>", '<mutations><mutation status="KILLED" detected="maybe"/></mutations>'):
            with self.subTest(content=content):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.pit_counts(self.write("bad-pit-extra.xml", content))

    def test_native_mutation_summaries_fail_closed_on_inconsistent_totals(self) -> None:
        mutmut = {
            "killed": 0,
            "survived": 0,
            "total": 0,
            "no_tests": 0,
            "skipped": 0,
            "suspicious": 0,
            "timeout": 0,
            "check_was_interrupted_by_user": 0,
            "segfault": 0,
        }
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "zero mutants"):
            mergegrounds.mutmut_counts(self.write_json("zero-mutmut.json", mutmut))

        invalid_infection = (
            {},
            {"stats": {"totalMutantsCount": 0}},
            {
                "stats": {
                    "totalMutantsCount": 1,
                    "killedCount": 0,
                    "skippedCount": 1,
                    "msi": 0,
                }
            },
        )
        for index, document in enumerate(invalid_infection):
            with self.subTest(index=index):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.infection_counts(self.write_json(f"bad-infection-{index}.json", document))

    def test_cargo_mutants_rejects_incomplete_and_ambiguous_outcomes(self) -> None:
        base = {
            "total_mutants": 1,
            "caught": 1,
            "missed": 0,
            "timeout": 0,
            "unviable": 0,
            "success": 0,
            "end_time": "now",
            "outcomes": [],
        }
        invalid = (
            {**base, "outcomes": None},
            {**base, "end_time": None},
            {**base, "outcomes": ["bad"]},
            {**base, "outcomes": [{"scenario": "Baseline", "summary": "Failed"}]},
            {**base, "outcomes": [{"scenario": "unknown", "summary": "CaughtMutant"}]},
            {
                **base,
                "outcomes": [
                    {"scenario": "Baseline", "summary": "Success"},
                    {"scenario": {"Mutant": {}}, "summary": "Unknown"},
                ],
            },
            {
                **base,
                "outcomes": [
                    {"scenario": "Baseline", "summary": "Success"},
                    {"scenario": {"Mutant": {}}, "summary": "MissedMutant"},
                ],
            },
        )
        for index, document in enumerate(invalid):
            with self.subTest(index=index):
                with self.assertRaises(mergegrounds.MergeGroundsError):
                    mergegrounds.cargo_mutants_counts(self.write_json(f"bad-cargo-{index}.json", document))

    def test_dispatchers_reject_unknown_formats_and_mergegrounds_multi_report_inputs(self) -> None:
        path = self.write_json(
            "mergegrounds.json",
            {"line_coverage": 100, "branch_coverage": 100, "mutation_score": 100},
        )
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "unsupported coverage"):
            mergegrounds.parse_coverage_report("unknown", path)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "unsupported mutation"):
            mergegrounds.parse_mutation_report("unknown", path)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "exactly one"):
            mergegrounds.aggregate_coverage("mergegrounds-json", [path, path], True)
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "exactly one"):
            mergegrounds.aggregate_mutation("mergegrounds-json", [path, path])

    def test_numeric_boundaries_and_mergegrounds_dispatchers_fail_closed(self) -> None:
        invalid_values = (
            ("non-finite", lambda: mergegrounds.finite_number(float("inf"), "metric")),
            ("negative-count", lambda: mergegrounds.count(-1, "metric")),
            ("text-count", lambda: mergegrounds.text_count("not-a-count", "metric")),
            ("percentage", lambda: mergegrounds.percentage(101, "metric")),
            ("zero-denominator", lambda: mergegrounds.ratio(0, 0, "metric")),
            ("numerator-overflow", lambda: mergegrounds.ratio(2, 1, "metric")),
            ("ambiguous-pattern", lambda: mergegrounds.validate_report_pattern(".")),
        )
        for label, operation in invalid_values:
            with self.subTest(label=label), self.assertRaises(mergegrounds.MergeGroundsError):
                operation()

        path = self.write_json(
            "direct-mergegrounds.json",
            {"line_coverage": 99, "branch_coverage": 98, "mutation_score": 97},
        )
        self.assertEqual(
            {"branch_coverage": 98.0, "line_coverage": 99.0, "mutation_score": 97.0},
            mergegrounds.parse_coverage_report("mergegrounds-json", path),
        )
        self.assertEqual((None, 97.0), mergegrounds.parse_mutation_report("mergegrounds-json", path))

    def test_validate_metric_returns_bound_pass_and_fail_evidence(self) -> None:
        config = {
            "risk_tier": "R3",
            "thresholds": {
                "line_coverage": 90,
                "branch_coverage": 85,
                "mutation_score": 85,
                "critical_mutation_score": 100,
            },
            "mutation_policy": {
                "fail_on_survived": True,
                "fail_on_not_covered": True,
                "fail_on_timeout": True,
                "fail_on_invalid": True,
                "fail_on_unviable": True,
                "allow_ignored": False,
            },
        }
        adapter = {
            "id": "fixture",
            "thresholds": {
                "line_coverage": 90,
                "branch_coverage": 85,
                "mutation_score": 85,
            },
            "metrics": {
                "coverage": {
                    "format": "mergegrounds-json",
                    "paths": ["metrics.json"],
                    "branch_required": True,
                },
                "mutation": {
                    "format": "mergegrounds-json",
                    "paths": ["metrics.json"],
                },
            },
        }
        self.write_json(
            "metrics.json",
            {"line_coverage": 95, "branch_coverage": 90, "mutation_score": 100},
        )
        coverage = mergegrounds.validate_metric(self.root, config, adapter, "coverage", {})
        mutation = mergegrounds.validate_metric(self.root, config, adapter, "mutation", {})
        self.assertEqual("pass", coverage["status"])
        self.assertEqual("pass", mutation["status"])
        self.assertEqual("metrics.json", coverage["reports"][0]["path"])

        self.write_json(
            "metrics.json",
            {"line_coverage": 80, "branch_coverage": 70, "mutation_score": 80},
        )
        low_coverage = mergegrounds.validate_metric(self.root, config, adapter, "coverage", {})
        low_mutation = mergegrounds.validate_metric(self.root, config, adapter, "mutation", {})
        self.assertEqual("fail", low_coverage["status"])
        self.assertEqual(2, len(low_coverage["violations"]))
        self.assertEqual("fail", low_mutation["status"])
        self.assertIn("cannot prove zero survivors", low_mutation["violations"][1])

    def test_validate_metric_enforces_descriptor_r4_and_mutant_category_policy(self) -> None:
        config = {
            "risk_tier": "R4",
            "thresholds": {
                "line_coverage": 90,
                "branch_coverage": 85,
                "mutation_score": 85,
                "critical_mutation_score": 100,
            },
            "mutation_policy": {
                "fail_on_survived": True,
                "fail_on_not_covered": True,
                "fail_on_timeout": True,
                "fail_on_invalid": True,
                "fail_on_unviable": True,
                "allow_ignored": False,
            },
        }
        adapter = {
            "id": "fixture",
            "thresholds": {
                "line_coverage": 90,
                "branch_coverage": 85,
                "mutation_score": 85,
            },
            "metrics": {},
        }
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "no metrics.coverage"):
            mergegrounds.validate_metric(self.root, config, adapter, "coverage", {})
        adapter["metrics"] = {"coverage": {"paths": ["coverage.json"]}}
        self.write_json("coverage.json", {"line_coverage": 100, "branch_coverage": 1, "mutation_score": 1})
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, "format is missing"):
            mergegrounds.validate_metric(self.root, config, adapter, "coverage", {})

        adapter["metrics"]["coverage"] = {
            "format": "mergegrounds-json",
            "paths": ["coverage.json"],
            "branch_required": False,
        }
        coverage = mergegrounds.validate_metric(self.root, config, adapter, "coverage", {})
        self.assertEqual("pass", coverage["status"])
        self.assertIsNone(coverage["thresholds"]["branch_coverage"])

        statuses = [
            "Killed",
            "Survived",
            "No_Coverage",
            "Timeout",
            "RuntimeError",
            "CompileError",
            "Ignored",
        ]
        self.write_json(
            "mutation.json",
            {
                "files": {
                    "a.py": {
                        "mutants": [
                            {"id": str(index), "status": status}
                            for index, status in enumerate(statuses)
                        ]
                    }
                }
            },
        )
        adapter["metrics"]["mutation"] = {
            "format": "stryker-json",
            "paths": ["mutation.json"],
        }
        result = mergegrounds.validate_metric(self.root, config, adapter, "mutation", {})
        self.assertEqual("fail", result["status"])
        for category in ("survived", "not_covered", "timeout", "invalid", "unviable", "ignored"):
            self.assertTrue(any(category in violation for violation in result["violations"]))


if __name__ == "__main__":
    unittest.main()
