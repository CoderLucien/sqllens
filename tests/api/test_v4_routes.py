from __future__ import annotations

import asyncio
import json

import httpx
from fastapi.testclient import TestClient

from sqllens_api.app import create_app
from sqllens_api.v4_routes import AiConfigInput, _list_models, _probe_ai

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


class TestAiV1Fallback:
    # rd2 实测：网关官方文档推荐裸域 Base URL，裸域 /chat/completions 返回 501（静态页不吃
    # POST），/v1/chat/completions 才是真实端点——缺 /v1 时必须自动补全重试一次。

    @staticmethod
    def _config(base_url: str) -> AiConfigInput:
        return AiConfigInput(base_url=base_url, api_key="sk-x", model="m")

    def test_bare_domain_501_retries_with_v1_and_succeeds(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            if request.url.path == "/chat/completions":
                return httpx.Response(501, text="not implemented")
            return httpx.Response(200, json={"choices": []})

        result = asyncio.run(
            _probe_ai(self._config("https://gw.example"), transport=httpx.MockTransport(handler))
        )
        assert result["ok"] is True
        assert calls == ["/chat/completions", "/v1/chat/completions"]

    def test_v1_base_url_does_not_retry_and_501_message_hints_v1(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(501, text="not implemented")

        result = asyncio.run(
            _probe_ai(self._config("https://gw.example/v1"), transport=httpx.MockTransport(handler))
        )
        assert result["ok"] is False
        assert result["code"] == "PROTOCOL_INCOMPATIBLE"
        assert "/v1" in result["message_zh"]
        assert calls == ["/v1/chat/completions"]

    def test_auth_error_not_retried(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(401, json={"error": "invalid key"})

        result = asyncio.run(
            _probe_ai(self._config("https://gw.example"), transport=httpx.MockTransport(handler))
        )
        assert result["ok"] is False
        assert result["code"] == "AUTH_INVALID"
        assert calls == ["/chat/completions"]

    def test_404_retries_then_classifies_model_not_found(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(404, json={"error": "not found"})

        result = asyncio.run(
            _probe_ai(self._config("https://gw.example"), transport=httpx.MockTransport(handler))
        )
        assert result["ok"] is False
        assert result["code"] == "MODEL_NOT_FOUND"
        assert calls == ["/chat/completions", "/v1/chat/completions"]

    def test_models_bare_domain_501_retries_with_v1(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            if request.url.path == "/models":
                return httpx.Response(501, text="not implemented")
            return httpx.Response(200, json={"data": [{"id": "gpt-x"}, {"id": "deepseek-chat"}]})

        result = asyncio.run(
            _list_models(self._config("https://gw.example"), transport=httpx.MockTransport(handler))
        )
        assert result["ok"] is True
        assert result["models"] == ["deepseek-chat", "gpt-x"]
        assert calls == ["/models", "/v1/models"]

    def test_anthropic_probe_uses_v1_messages_without_retry(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(401, json={"error": "auth"})

        config = AiConfigInput(
            base_url="https://gw.example", api_key="sk-x", model="claude-x", protocol="anthropic"
        )
        result = asyncio.run(_probe_ai(config, transport=httpx.MockTransport(handler)))
        assert result["ok"] is False
        assert result["code"] == "AUTH_INVALID"
        assert calls == ["/v1/messages"]


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


class TestNonSargableScenario:
    def test_function_wrapped_predicate_recommends_rewrite(self) -> None:
        payload = {
            "schema_version": "evidence/v3",
            "sql": {
                "sql_digest": "b" * 64,
                "database": "tpch",
                "table_name": "lineitem",
                "sql_text": "SELECT l_orderkey FROM lineitem WHERE YEAR(l_shipdate) <= 1995;",
            },
            "runtime": {"exec_count": 0, "window_minutes": 1, "scanned_rows": 6001215, "result_rows": 5808334},
            "plan": {
                "operator_rows": [
                    {"operator": "TableFullScan_7", "table": "lineitem", "est_rows": 6001215},
                ]
            },
            "stats": {"row_count": 6001215, "healthy": 100},
            "schema": {"filter_columns": ["l_shipdate"], "indexes": [{"name": "PRIMARY", "columns": ["l_orderkey", "l_linenumber"]}]},
        }
        response = _client().post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 200, response.text
        report = response.json()
        assert report["sections"]["conclusion"]["rule_ids"] == ["IDX_ACCESS_001"]
        changes = report["sections"]["changes"]
        assert "改写" in changes[0]["operation_zh"]
        assert "CREATE INDEX" not in changes[0]["operation_zh"]
        assert "CREATE INDEX" in changes[1]["operation_zh"]
        assert "函数" in report["sections"]["conclusion"]["text_zh"]
        assert report["priority"] == "P2"


class TestUsePrefix:
    # 真实 Plan Replayer 包的 sql0.sql 带前导 `USE <db>;`，库名曾被误计为表，
    # 导致单表被当成多表 JOIN 而整体跳过索引规则。
    def test_use_prefix_single_table_still_hits_index_rule(self) -> None:
        payload = {
            "schema_version": "evidence/v3",
            "sql": {
                "sql_digest": "c" * 64,
                "database": "tpch",
                "table_name": "lineitem",
                "sql_text": (
                    "USE tpch;\n"
                    "SELECT l_orderkey, l_extendedprice FROM lineitem "
                    "WHERE l_shipdate < '1996-01-01';"
                ),
            },
            "runtime": {"exec_count": 0, "window_minutes": 1, "scanned_rows": 6001215, "result_rows": 5808334},
            "plan": {
                "operator_rows": [
                    {"operator": "TableFullScan_7", "table": "lineitem", "est_rows": 6001215},
                ]
            },
            "stats": {"row_count": 6001215, "healthy": 100},
            "schema": {"filter_columns": ["l_shipdate"], "indexes": [{"name": "PRIMARY", "columns": ["l_orderkey", "l_linenumber"]}]},
        }
        response = _client().post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 200, response.text
        report = response.json()
        assert "IDX_ACCESS_001" in report["sections"]["conclusion"]["rule_ids"]
        assert report["sections"]["changes"], "real.zip 形态（带 USE 前缀）应恢复索引规则命中"

    def test_use_prefix_scenario2_rewrite_still_first(self) -> None:
        payload = {
            "schema_version": "evidence/v3",
            "sql": {
                "sql_digest": "b" * 64,
                "database": "tpch",
                "table_name": "lineitem",
                "sql_text": (
                    "USE tpch;\n"
                    "SELECT l_orderkey FROM lineitem WHERE YEAR(l_shipdate) <= 1995;"
                ),
            },
            "runtime": {"exec_count": 0, "window_minutes": 1, "scanned_rows": 6001215, "result_rows": 5808334},
            "plan": {
                "operator_rows": [
                    {"operator": "TableFullScan_7", "table": "lineitem", "est_rows": 6001215},
                ]
            },
            "stats": {"row_count": 6001215, "healthy": 100},
            "schema": {"filter_columns": ["l_shipdate"], "indexes": [{"name": "PRIMARY", "columns": ["l_orderkey", "l_linenumber"]}]},
        }
        response = _client().post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 200, response.text
        report = response.json()
        assert report["sections"]["conclusion"]["rule_ids"] == ["IDX_ACCESS_001"]
        changes = report["sections"]["changes"]
        assert "改写" in changes[0]["operation_zh"]
        assert "CREATE INDEX" not in changes[0]["operation_zh"]


class TestJoinScenario:
    def test_multi_table_join_skips_index_rule(self) -> None:
        payload = {
            "schema_version": "evidence/v3",
            "sql": {
                "sql_digest": "a" * 64,
                "database": "tpch",
                "table_name": "customer",
                "sql_text": (
                    "SELECT c.c_custkey FROM customer c "
                    "JOIN orders o ON c.c_custkey = o.o_custkey "
                    "JOIN lineitem l ON l.l_orderkey = o.o_orderkey "
                    "WHERE l.l_returnflag = 'R';"
                ),
            },
            "runtime": {"exec_count": 0, "window_minutes": 1, "scanned_rows": 6001215, "result_rows": 100},
            "plan": {
                "operator_rows": [
                    {"operator": "TableFullScan_9", "table": "lineitem", "est_rows": 6001215},
                    {"operator": "TableReader_11", "table": "lineitem", "est_rows": 100},
                ]
            },
            "stats": {"row_count": 6001215, "healthy": 100},
            "schema": {"filter_columns": ["l_returnflag"], "indexes": [{"name": "PRIMARY", "columns": ["l_orderkey", "l_linenumber"]}]},
        }
        response = _client().post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 200, response.text
        report = response.json()
        assert "IDX_ACCESS_001" not in report["sections"]["conclusion"]["rule_ids"]
        assert report["sections"]["changes"] == []
        assert "JOIN" in report["sections"]["analysis"]["text_zh"]
