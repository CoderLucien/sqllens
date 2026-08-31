from __future__ import annotations

import re
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs" / "validation" / "qa-test-matrix.md"
CASE_ROW = re.compile(
    r"^\| `(?P<id>(?P<group>SETUP|DEPLOY|L1|L2|L3|PR|CASE|SEC|PERF|AB|GPU|UI|PLAT)-\d{3})` "
    r"\| .* \| `(?P<status>NOT_RUN|BLOCKED|PASS|FAIL|N/A)` \|$"
)


class QaMatrixContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = MATRIX.read_text(encoding="utf-8")
        cls.rows = [
            match.groupdict()
            for line in cls.text.splitlines()
            if (match := CASE_ROW.fullmatch(line))
        ]

    def test_matrix_contains_the_frozen_baseline_case_groups(self) -> None:
        expected_counts = {
            "SETUP": 11,
            "DEPLOY": 7,
            "L1": 12,
            "L2": 18,
            "L3": 15,
            "PR": 10,
            "CASE": 8,
            "SEC": 10,
            "PERF": 9,
            "AB": 5,
            "GPU": 4,
            "UI": 5,
            "PLAT": 14,
        }

        self.assertEqual(Counter(row["group"] for row in self.rows), expected_counts)
        self.assertEqual(len(self.rows), 128)

    def test_case_ids_are_unique(self) -> None:
        ids = [row["id"] for row in self.rows]
        duplicates = [case_id for case_id, count in Counter(ids).items() if count > 1]

        self.assertEqual(duplicates, [])

    def test_baseline_does_not_claim_unexecuted_work_passed(self) -> None:
        premature = [row["id"] for row in self.rows if row["status"] == "PASS"]

        self.assertEqual(premature, [])

    def test_matrix_traces_every_child_task_and_local_model_gate(self) -> None:
        required_markers = {
            "R-T14-1",
            "R-T14-2",
            "R-T14-3",
            "R-T10-1",
            "R-T10-4",
            "R-T11-1",
            "R-T12-1",
            "R-T13-1",
            "R-P0-PR",
            "R-P0-PLAT",
            "R-P0-LOCAL",
        }

        missing = sorted(marker for marker in required_markers if marker not in self.text)
        self.assertEqual(missing, [])

    def test_known_environment_blockers_are_explicit(self) -> None:
        required_blockers = {
            "Disposable TiDB/Prometheus environment access",
            "Target GPU plus pinned model/runtime artifacts",
            "Performance corpus, warmup/sample counts",
            "Versioned TiDB statement allowlist",
        }

        missing = sorted(blocker for blocker in required_blockers if blocker not in self.text)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
