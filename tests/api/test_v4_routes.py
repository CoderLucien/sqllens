from __future__ import annotations

import json

from fastapi.testclient import TestClient

from sqllens_api.app import create_app

EVIDENCE_INDEX = {
    "schema_version": "evidence/v3",
    "sql": {
        "sql_digest": "8c27725d5bb319605ec7433f114ddde077401dc4f62174fc58861eee73705f83",
        "database": "sqllens_m0_lab",
        "table_name": "index_orders",
    },
    "runtime": {
        "exec_count": 20,
        "window_minutes": 60,
        "p95_ms": 66,
        "avg_total_keys": 65537,
        "scanned_rows": 65537,
        "result_rows": 1,
    },
    "plan": {
        "operator_rows": [
            {"operator": "TableFullScan", "table": "index_orders", "est_rows": 65537}
        ]
    },
    "stats": {"est_rows": 32768, "actual_rows": 65536, "healthy": 100},
    "schema": {
        "filter_columns": ["customer_id", "state"],
        "indexes": [{"name": "PRIMARY", "columns": ["id"]}],
    },
}


def _client() -> TestClient:
    return TestClient(create_app())


class TestDiagnoseEndpoint:
    def test_report_has_six_sections_and_four_elements(self) -> None:
        response = _client().post("/api/v1/v4/diagnose", json=EVIDENCE_INDEX)
        assert response.status_code == 200, response.text
        report = response.json()
        assert report["schema_version"] == "diagnosis-report/v2"
        assert report["priority"] in ("P1", "P2")
        for key in ("conclusion", "evidence", "analysis", "changes", "validation", "rollback"):
            assert key in report["sections"], key
        assert len(report["sections"]["changes"]) >= 1
        change = report["sections"]["changes"][0]
        for key in ("operation_zh", "risk_zh", "cost_zh", "gain_zh", "gain_formula_zh"):
            assert change[key], key
        assert "IDX_ACCESS_001" in report["sections"]["conclusion"]["rule_ids"]
        assert "REPEATED_SCAN_001" in report["sections"]["conclusion"]["rule_ids"]

    def test_duplicate_json_member_rejected(self) -> None:
        payload = '{"schema_version":"evidence/v3","schema_version":"x"}'
        response = _client().post(
            "/api/v1/v4/diagnose",
            content=payload,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422

    def test_missing_required_field_rejected(self) -> None:
        payload = {"schema_version": "evidence/v3", "sql": {}}
        response = _client().post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 422

    def test_wrong_schema_version_rejected(self) -> None:
        payload = {**EVIDENCE_INDEX, "schema_version": "evidence/v1"}
        response = _client().post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 422

    def test_report_matches_frozen_report_schema(self) -> None:
        response = _client().post("/api/v1/v4/diagnose", json=EVIDENCE_INDEX)
        assert response.status_code == 200
        report = response.json()
        assert report["schema_version"] == "diagnosis-report/v2"
        assert report["priority"] in ("P1", "P2")
        assert report["mode"] in ("rules", "rules_ai", "degraded")
        assert report["ai_status_zh"]
        assert report["sql_digest"] == EVIDENCE_INDEX["sql"]["sql_digest"]
        sections = report["sections"]
        assert set(sections) == {
            "conclusion", "evidence", "analysis", "changes", "validation", "rollback",
        }
        for hit_severity in sections["conclusion"]["severities"]:
            assert hit_severity in ("P1", "P2")
        for row in sections["evidence"]:
            assert row["label_zh"] and row["value_zh"] and isinstance(row["evidence_ids"], list)
        for change in sections["changes"]:
            assert set(change) == {
                "operation_zh", "risk_zh", "cost_zh", "cost_formula_zh",
                "gain_zh", "gain_formula_zh", "rule_id",
            }
        for section_name in ("validation", "rollback"):
            for row in sections[section_name]:
                assert row["text_zh"]

    def test_stats_skew_evidence_yields_stats_rule(self) -> None:
        payload = {
            "schema_version": "evidence/v3",
            "sql": {
                "sql_digest": "a" * 64,
                "database": "billing",
                "table_name": "billing_order",
            },
            "runtime": {"exec_count": 1, "window_minutes": 60, "p95_ms": 10},
            "plan": {"operator_rows": []},
            "stats": {"est_rows": 120, "actual_rows": 180000, "healthy": 0},
            "schema": {"filter_columns": [], "indexes": []},
            "optional": {"batch_before_min": 27, "batch_target_min": 6},
        }
        response = _client().post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 200, response.text
        report = response.json()
        assert "STATS_SKEW_001" in report["sections"]["conclusion"]["rule_ids"]


class TestAiEndpoints:
    def test_ai_test_validation_error(self) -> None:
        response = _client().post("/api/v1/v4/ai/test", json={"base_url": ""})
        assert response.status_code == 422

    def test_ai_test_network_unreachable_classified(self) -> None:
        response = _client().post(
            "/api/v1/v4/ai/test",
            json={
                "base_url": "http://127.0.0.1:1/v1",
                "api_key": "sk-x",
                "model": "m",
                "protocol": "openai",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is False
        assert body["code"] in ("NETWORK_UNREACHABLE", "UNKNOWN")

    def test_ai_models_unreachable_classified(self) -> None:
        response = _client().post(
            "/api/v1/v4/ai/models",
            json={
                "base_url": "http://127.0.0.1:1/v1",
                "api_key": "sk-x",
                "model": "m",
                "protocol": "openai",
            },
        )
        assert response.status_code == 200
        assert response.json()["ok"] is False


class TestDiagnoseWithoutEstRows:
    def test_missing_est_rows_does_not_trigger_stats_skew(self) -> None:
        payload = {
            "schema_version": "evidence/v3",
            "sql": {
                "sql_digest": "a" * 64,
                "database": "tpch",
                "table_name": "lineitem",
            },
            "runtime": {"exec_count": 0, "window_minutes": 1},
            "plan": {"operator_rows": []},
            "stats": {"row_count": 6001215, "healthy": 100},
            "schema": {"filter_columns": [], "indexes": []},
        }
        response = _client().post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 200, response.text
        report = response.json()
        assert "STATS_SKEW_001" not in report["sections"]["conclusion"]["rule_ids"]
        assert "IDX_ACCESS_001" not in report["sections"]["conclusion"]["rule_ids"]
        assert "REPEATED_SCAN_001" not in report["sections"]["conclusion"]["rule_ids"]
        assert report["priority"] == "P2"
