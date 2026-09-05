from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mergegrounds_go_coverage_hardening", ROOT / "scripts" / "mergegrounds.py")
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)


class GoCoverageHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "coverage.out"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def parse(self, value: str) -> dict[str, int | None]:
        self.path.write_text(value, encoding="utf-8")
        return mergegrounds.go_cover_counts(self.path)

    def assert_rejected(self, value: str, pattern: str) -> None:
        with self.assertRaisesRegex(mergegrounds.MergeGroundsError, pattern):
            self.parse(value)

    def test_valid_profile_uses_statement_weight_and_allows_adjacent_blocks(self) -> None:
        result = self.parse(
            """mode: atomic
example.com/acme/app/a.go:1.1,1.10 1 1
example.com/acme/app/a.go:1.10,2.1 2 0
example.com/acme/app/b.go:1.1,2.1 3 7
"""
        )
        self.assertEqual(
            {"line_covered": 4, "line_total": 6, "branch_covered": None, "branch_total": None},
            result,
        )

    def test_mode_must_be_an_exact_native_mode(self) -> None:
        for mode in ("", "mode: ", "mode: banana", "mode: atomic ", "Mode: atomic"):
            with self.subTest(mode=mode):
                self.assert_rejected(f"{mode}\nexample.com/acme/a.go:1.1,1.2 1 1\n", "mode must be exactly")

    def test_set_mode_rejects_non_boolean_execution_counts(self) -> None:
        self.assert_rejected(
            "mode: set\nexample.com/acme/a.go:1.1,1.2 1 2\n",
            "set-mode execution counter",
        )

    def test_source_must_be_canonical_module_relative_go_path(self) -> None:
        sources = (
            "../a.go",
            "/tmp/a.go",
            "example.com/acme/../a.go",
            "example.com/acme//a.go",
            "example.com\\acme\\a.go",
            "C:/repo/a.go",
            "example.com/acme/a.txt",
            "example.com/acme/a file.go",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_rejected(
                    f"mode: count\n{source}:1.1,1.2 1 1\n",
                    "canonical module-relative path",
                )

    def test_coordinates_must_be_positive_and_strictly_ordered(self) -> None:
        records = (
            "example.com/acme/a.go:0.1,1.2 1 1",
            "example.com/acme/a.go:1.0,1.2 1 1",
            "example.com/acme/a.go:2.1,1.2 1 1",
            "example.com/acme/a.go:1.2,1.2 1 1",
        )
        for record in records:
            with self.subTest(record=record):
                self.assert_rejected(f"mode: count\n{record}\n", "coordinates|positive ordered range")

    def test_duplicate_blocks_cannot_inflate_or_offset_coverage(self) -> None:
        self.assert_rejected(
            """mode: count
example.com/acme/a.go:1.1,2.1 100 1
example.com/acme/a.go:1.1,2.1 1 0
""",
            "duplicate Go coverage block",
        )

    def test_overlapping_blocks_are_rejected_even_when_input_is_unsorted(self) -> None:
        self.assert_rejected(
            """mode: count
example.com/acme/a.go:1.5,1.9 1 1
example.com/acme/a.go:1.1,2.1 1 1
""",
            "overlapping Go coverage blocks",
        )

    def test_empty_header_only_and_malformed_records_are_rejected(self) -> None:
        self.assert_rejected("", "empty")
        self.assert_rejected("mode: atomic\n", "no block records")
        self.assert_rejected("mode: atomic\nnot-a-record\n", "invalid Go coverage record")


if __name__ == "__main__":
    unittest.main()
