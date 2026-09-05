from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AdapterPythonIsolationTests(unittest.TestCase):
    def test_adapter_python_helpers_cannot_import_candidate_shadows(self) -> None:
        invocations: list[tuple[Path, str]] = []
        unsafe = re.compile(r"\bpython3\s+(?!-I(?:\s|$))")
        for path in sorted((ROOT / ".mergegrounds" / "adapters").glob("*.toml")):
            for line in path.read_text(encoding="utf-8").splitlines():
                if "python3 " in line:
                    invocations.append((path, line))
                    self.assertIsNone(
                        unsafe.search(line),
                        f"candidate-adjacent Python must use isolated mode in {path.name}: {line}",
                    )
        self.assertTrue(invocations, "fixture must exercise at least one adapter Python helper")


if __name__ == "__main__":
    unittest.main()
