from __future__ import annotations

import json
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "tests" / "fixtures" / "sql" / "layer1-cases.json"
CANARY_PATH = (
    ROOT / "tests" / "fixtures" / "model_provider" / "egress-canaries.json"
)


class Layer1SqlCorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        cls.cases = cls.corpus["cases"]
        cls.canaries = json.loads(CANARY_PATH.read_text(encoding="utf-8"))["canaries"]

    def test_corpus_has_unique_ids_and_required_categories(self) -> None:
        ids = [case["id"] for case in self.cases]
        categories = Counter(
            category for case in self.cases for category in case["categories"]
        )

        self.assertGreaterEqual(len(self.cases), 20)
        self.assertEqual(len(ids), len(set(ids)))
        for category in {
            "supported_select",
            "tidb_syntax",
            "risky_explain",
            "active_statement",
            "multi_statement",
            "invalid_sql",
            "prompt_injection",
            "egress_canary",
        }:
            with self.subTest(category=category):
                self.assertGreater(categories[category], 0)

    def test_no_case_permits_execution(self) -> None:
        executable = [case["id"] for case in self.cases if case["executionAllowed"]]

        self.assertEqual(executable, [])

    def test_risky_explain_cases_are_explicit(self) -> None:
        risky = [
            case
            for case in self.cases
            if "risky_explain" in case["categories"]
        ]

        self.assertGreaterEqual(len(risky), 2)
        self.assertTrue(all(case["ordinaryExplain"] == "reject" for case in risky))

    def test_egress_literal_uses_the_shared_sql_canary(self) -> None:
        literal = self.canaries["sqlLiteral"]
        matching = [case["id"] for case in self.cases if literal in case["sql"]]

        self.assertEqual(matching, ["sql_literal_egress_canary"])

    def test_fixture_contains_no_credentials_or_real_endpoints(self) -> None:
        serialized = json.dumps(self.corpus).lower()

        for forbidden in {
            "password=",
            "authorization:",
            "127.0.0.1",
            "localhost",
            "@gmail.com",
            "@qq.com",
        }:
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
