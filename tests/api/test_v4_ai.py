from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from sqllens_api.app import create_app
from sqllens_api.v4_ai import (
    _SESSION_CACHE,
    AiConfigInput,
    augment_report_with_ai,
    select_skills,
    summarize_evidence,
)
from sqllens_api.v4_diagnosis import diagnose_v4

EVIDENCE_INDEX = {
    "schema_version": "evidence/v3",
    "sql": {
        "sql_digest": "8c27725d5bb319605ec7433f114ddde077401dc4f62174fc58861eee73705f83",
        "sql_text": "SELECT * FROM index_orders WHERE customer_id = 7 AND state = 'PAID'",
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

AI_OK = {
    "ai_summary": "该 SQL 在窗口内高频全表扫描，规则结论成立；可从谓词与索引配合继续压缩扫描量。",
    "ai_suggestions": [
        {"text_zh": "建议一", "evidence_ids": ["ev_plan"], "validation_zh": "复看执行计划"},
        {"text_zh": "建议二", "evidence_ids": ["ev_runtime", "ev_made_up"], "validation_zh": "看窗口执行次数"},
        {"text_zh": "无证据出处条目", "evidence_ids": [], "validation_zh": "x"},
        {"text_zh": "无验证方式条目", "evidence_ids": ["ev_stats"]},
    ],
    "ai_review": [
        {"rule_id": "IDX_ACCESS_001", "text_zh": "异议理由"},
        {"rule_id": "UNKNOWN_RULE", "text_zh": "越权异议"},
    ],
}

_RULE_SECTION_KEYS = ("conclusion", "evidence", "analysis", "changes", "validation", "rollback")


def _config(base_url: str = "https://gw.example/v1", protocol: str = "openai") -> AiConfigInput:
    return AiConfigInput(base_url=base_url, api_key="sk-x", model="m", protocol=protocol)


def _openai_handler(content: str, calls: list[str] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request.url.path)
        return httpx.Response(
            200, json={"choices": [{"message": {"role": "assistant", "content": content}}]}
        )

    return handler


@pytest.fixture(autouse=True)
def _clear_cache():
    _SESSION_CACHE.clear()
    yield
    _SESSION_CACHE.clear()


class TestAugmentSuccess:
    def test_rules_sections_unchanged_and_ai_sections_appended(self) -> None:
        calls: list[str] = []
        rules_report = diagnose_v4(EVIDENCE_INDEX, mode="rules")
        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX, mode="rules"),
                EVIDENCE_INDEX,
                _config(),
                transport=httpx.MockTransport(_openai_handler(json.dumps(AI_OK, ensure_ascii=False), calls)),
            )
        )
        assert report["mode"] == "rules_ai"
        assert calls == ["/v1/chat/completions"]
        for key in _RULE_SECTION_KEYS:
            assert json.dumps(report["sections"][key], ensure_ascii=False, sort_keys=True) == json.dumps(
                rules_report["sections"][key], ensure_ascii=False, sort_keys=True
            )
        assert report["sections"]["ai_summary"]["text_zh"] == AI_OK["ai_summary"]
        texts = [item["text_zh"] for item in report["sections"]["ai_suggestions"]]
        assert texts == ["建议一", "建议二"]
        assert report["sections"]["ai_suggestions"][1]["evidence_ids"] == ["ev_runtime"]
        assert [item["rule_id"] for item in report["sections"]["ai_review"]] == ["IDX_ACCESS_001"]

    def test_code_fenced_json_accepted(self) -> None:
        content = "```json\n" + json.dumps(AI_OK, ensure_ascii=False) + "\n```"
        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config(),
                transport=httpx.MockTransport(_openai_handler(content)),
            )
        )
        assert report["mode"] == "rules_ai"

    def test_length_and_count_clamps(self) -> None:
        payload = {
            "ai_summary": "长" * 1000,
            "ai_suggestions": [
                {"text_zh": "建" * 500, "evidence_ids": ["ev_plan"], "validation_zh": "验" * 300}
            ],
            "ai_review": [{"rule_id": "IDX_ACCESS_001", "text_zh": "异" * 800}],
        }
        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config(),
                transport=httpx.MockTransport(_openai_handler(json.dumps(payload, ensure_ascii=False))),
            )
        )
        sections = report["sections"]
        assert len(sections["ai_summary"]["text_zh"]) == 400
        assert len(sections["ai_suggestions"][0]["text_zh"]) == 200
        assert len(sections["ai_suggestions"][0]["validation_zh"]) == 160
        assert len(sections["ai_review"][0]["text_zh"]) == 300

    def test_session_cache_hits_without_new_calls(self) -> None:
        calls: list[str] = []
        transport = httpx.MockTransport(_openai_handler(json.dumps(AI_OK, ensure_ascii=False), calls))
        first = asyncio.run(
            augment_report_with_ai(diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config(), transport=transport)
        )
        second = asyncio.run(
            augment_report_with_ai(diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config(), transport=transport)
        )
        assert calls == ["/v1/chat/completions"]
        assert first["mode"] == second["mode"] == "rules_ai"
        assert first["sections"]["ai_summary"] == second["sections"]["ai_summary"]
        changed = {**EVIDENCE_INDEX, "runtime": {**EVIDENCE_INDEX["runtime"], "exec_count": 5}}
        asyncio.run(
            augment_report_with_ai(diagnose_v4(changed), changed, _config(), transport=transport)
        )
        assert calls == ["/v1/chat/completions", "/v1/chat/completions"]


class TestDegrade:
    def test_http_500_degrades_without_retry(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(500, text="boom")

        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config(),
                transport=httpx.MockTransport(handler),
            )
        )
        assert report["mode"] == "degraded"
        assert calls == ["/v1/chat/completions"]
        assert "降级" in report["ai_status_zh"]
        for key in _RULE_SECTION_KEYS:
            assert key in report["sections"]
        assert "ai_summary" not in report["sections"]

    def test_path_correction_only_once_then_degrade(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(404, text="missing")

        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config("https://gw.example"),
                transport=httpx.MockTransport(handler),
            )
        )
        assert report["mode"] == "degraded"
        assert calls == ["/chat/completions", "/v1/chat/completions"]

    def test_timeout_degrades(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("t")

        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config(),
                transport=httpx.MockTransport(handler),
            )
        )
        assert report["mode"] == "degraded"
        assert "网络不可达" in report["ai_status_zh"]

    def test_invalid_json_output_degrades(self) -> None:
        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config(),
                transport=httpx.MockTransport(_openai_handler("这不是 JSON")),
            )
        )
        assert report["mode"] == "degraded"
        assert "数据契约" in report["ai_status_zh"]

    def test_missing_summary_degrades(self) -> None:
        payload = {"ai_suggestions": [{"text_zh": "x", "evidence_ids": ["ev_plan"], "validation_zh": "y"}]}
        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config(),
                transport=httpx.MockTransport(_openai_handler(json.dumps(payload, ensure_ascii=False))),
            )
        )
        assert report["mode"] == "degraded"


class TestProtocols:
    def test_anthropic_protocol_shape(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            assert request.headers["x-api-key"] == "sk-x"
            body = json.loads(request.content.decode("utf-8"))
            assert body["system"].startswith("你是 TiDB SQL 优化顾问")
            assert body["messages"][0]["role"] == "user"
            return httpx.Response(
                200,
                json={"content": [{"type": "text", "text": json.dumps(AI_OK, ensure_ascii=False)}]},
            )

        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config("https://gw.example", "anthropic"),
                transport=httpx.MockTransport(handler),
            )
        )
        assert report["mode"] == "rules_ai"
        assert calls == ["/v1/messages"]

    def test_openai_bare_domain_path_correction_succeeds(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Request | httpx.Response:
            calls.append(request.url.path)
            if request.url.path == "/chat/completions":
                return httpx.Response(501, text="static")
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": json.dumps(AI_OK, ensure_ascii=False)}}]},
            )

        report = asyncio.run(
            augment_report_with_ai(
                diagnose_v4(EVIDENCE_INDEX), EVIDENCE_INDEX, _config("https://gw.example"),
                transport=httpx.MockTransport(handler),
            )
        )
        assert report["mode"] == "rules_ai"
        assert calls == ["/chat/completions", "/v1/chat/completions"]


class TestSummary:
    def test_summary_within_2kb_and_contains_sql(self) -> None:
        report = diagnose_v4(EVIDENCE_INDEX)
        summary = summarize_evidence(EVIDENCE_INDEX, report)
        assert len(summary.encode("utf-8")) <= 2048
        parsed = json.loads(summary)
        assert parsed["sql_text"] == EVIDENCE_INDEX["sql"]["sql_text"]
        assert parsed["rule_hits"]["rule_ids"]
        assert "plan_operators" in parsed

    def test_long_sql_truncated_near_512_bytes(self) -> None:
        evidence = {
            **EVIDENCE_INDEX,
            "sql": {
                **EVIDENCE_INDEX["sql"],
                "sql_text": "SELECT * FROM big_table WHERE pad = '" + "x" * 4000 + "'",
            },
        }
        summary = summarize_evidence(evidence, diagnose_v4(evidence))
        assert len(summary.encode("utf-8")) <= 2048
        parsed = json.loads(summary)
        assert parsed["sql_text"].startswith("SELECT * FROM big_table")
        assert len(parsed["sql_text"].encode("utf-8")) <= 512
        assert "x" * 600 not in summary

    def test_skills_selected_by_hits_and_join(self) -> None:
        skills = select_skills(EVIDENCE_INDEX, diagnose_v4(EVIDENCE_INDEX))
        assert any("索引与访问路径" in skill for skill in skills)
        assert any("热点重复调用" in skill for skill in skills)
        join_evidence = {
            **EVIDENCE_INDEX,
            "plan": {
                "operator_rows": [
                    {"operator": "TableFullScan", "table": "orders", "est_rows": 100},
                    {"operator": "HashJoin", "table": "customers", "est_rows": 10},
                ]
            },
        }
        assert any("多表 JOIN" in skill for skill in select_skills(join_evidence, diagnose_v4(join_evidence)))


class TestRouteWiring:
    def test_no_ai_config_stays_rules_mode(self) -> None:
        response = TestClient(create_app()).post("/api/v1/v4/diagnose", json=EVIDENCE_INDEX)
        assert response.status_code == 200
        report = response.json()
        assert report["mode"] == "rules"
        assert "ai_summary" not in report["sections"]

    def test_invalid_ai_config_rejected_422(self) -> None:
        payload = {**EVIDENCE_INDEX, "ai_config": {"base_url": "", "api_key": "k", "model": "m"}}
        response = TestClient(create_app()).post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 422

    def test_non_object_ai_config_rejected_422(self) -> None:
        payload = {**EVIDENCE_INDEX, "ai_config": "not-an-object"}
        response = TestClient(create_app()).post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 422

    def test_valid_ai_config_invokes_augment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        async def fake_augment(report, evidence, config, *, transport=None):
            seen["mode"] = report["mode"]
            seen["model"] = config.model
            report["mode"] = "rules_ai"
            return report

        monkeypatch.setattr("sqllens_api.v4_routes.augment_report_with_ai", fake_augment)
        payload = {**EVIDENCE_INDEX, "ai_config": {"base_url": "https://gw.example/v1", "api_key": "k", "model": "m"}}
        response = TestClient(create_app()).post("/api/v1/v4/diagnose", json=payload)
        assert response.status_code == 200
        assert response.json()["mode"] == "rules_ai"
        assert seen == {"mode": "rules", "model": "m"}
