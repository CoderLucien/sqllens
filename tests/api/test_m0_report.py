# ruff: noqa: RUF001
from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from sqllens_api.evidence_connector import (
    CollectedEvidence,
    canonical_sha256,
    strict_json_bytes,
    strict_json_loads,
)
from sqllens_api.m0_report import (
    INDEX_RULE_ID,
    RULE_PACK_REVISION,
    STATISTICS_RULE_ID,
    M0ReportInput,
    build_m0_rules_report,
)

FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "m0" / "report-inputs.json"
NO_BUSINESS_EVIDENCE_ZH = "未提供业务影响证据，仅说明数据库技术影响"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_scenario(name: str) -> M0ReportInput:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["label"] == "fixture/review-only"
    scenario = next(item for item in fixture["scenarios"] if item["scenario"] == name)
    evidence = tuple(
        CollectedEvidence(
            _document_json=strict_json_bytes(item["document"]),
            storage_payload=strict_json_bytes(item["storageDocument"]),
        )
        for item in scenario["evidence"]
    )
    return M0ReportInput(
        case_id=scenario["caseId"],
        database=scenario["database"],
        sql_digest=scenario["sqlDigest"],
        window_start=parse_time(scenario["windowStart"]),
        window_end=parse_time(scenario["windowEnd"]),
        evidence=evidence,
    )


def report(value: M0ReportInput) -> dict[str, Any]:
    loaded = strict_json_loads(build_m0_rules_report(value))
    assert isinstance(loaded, dict)
    return loaded


def evidence_by_kind(value: M0ReportInput, kind: str) -> CollectedEvidence:
    return next(item for item in value.evidence if item.document["kind"] == kind)


def replace_evidence(
    value: M0ReportInput,
    kind: str,
    transform: Callable[[dict[str, Any]], None],
    *,
    recompute_typed_digest: bool = True,
    storage_payload: bytes | None = None,
) -> M0ReportInput:
    replaced: list[CollectedEvidence] = []
    found = False
    for collected in value.evidence:
        document = copy.deepcopy(collected.document)
        if document["kind"] == kind and not found:
            transform(document)
            if recompute_typed_digest:
                document["payload"]["typedDigest"] = canonical_sha256(document["payload"]["typed"])
            replaced.append(
                CollectedEvidence(
                    _document_json=strict_json_bytes(document),
                    storage_payload=(
                        collected.storage_payload if storage_payload is None else storage_payload
                    ),
                )
            )
            found = True
        else:
            replaced.append(collected)
    assert found
    return M0ReportInput(
        case_id=value.case_id,
        database=value.database,
        sql_digest=value.sql_digest,
        window_start=value.window_start,
        window_end=value.window_end,
        evidence=tuple(replaced),
    )


def without_kind(value: M0ReportInput, kind: str) -> M0ReportInput:
    return M0ReportInput(
        case_id=value.case_id,
        database=value.database,
        sql_digest=value.sql_digest,
        window_start=value.window_start,
        window_end=value.window_end,
        evidence=tuple(item for item in value.evidence if item.document["kind"] != kind),
    )


def test_m0_report_input_is_frozen_and_does_not_repr_evidence() -> None:
    value = load_scenario("index-scan")

    assert "evidence=" not in repr(value)
    assert value.evidence[0].document["evidenceId"] not in repr(value)
    with pytest.raises(FrozenInstanceError):
        value.database = "other"  # type: ignore[misc]


def test_index_rule_emits_a_narrow_rules_only_chinese_report() -> None:
    value = load_scenario("index-scan")

    result = report(value)

    assert result["priority"] == "P2"
    assert result["configuredMode"] == result["effectiveMode"] == "rules"
    assert result["trace"]["ruleIds"] == [INDEX_RULE_ID]
    assert result["trace"]["pinnedRevisions"]["rulePack"] == RULE_PACK_REVISION
    assert result["trace"]["evidenceCompleteness"] == 100
    assert "全表扫描" in result["conclusionZh"]
    assert "扫描放大" in result["conclusionZh"]
    assert "一定" not in result["conclusionZh"]
    assert result["impact"]["businessEvidenceIds"] == []
    assert result["impact"]["businessZh"] == NO_BUSINESS_EVIDENCE_ZH
    assert result["reasoning"] == {
        "ruleFindingsZh": [
            "该 SQL 的实测扫描放大达到规则阈值，普通计划为全表扫描，且未找到"
            "匹配过滤列前缀的复合索引。"
        ],
        "aiContributionZh": None,
        "aiStatus": "not_requested",
        "aiCode": None,
        "aiReasonZh": None,
    }
    assert len(result["actions"]) == 1
    action = result["actions"][0]
    assert action["ownerRole"] == "dba"
    assert action["risk"] == "medium"
    assert action["prerequisitesZh"]
    assert action["stepsZh"]
    assert action["validation"]["targetZh"] == (
        "平均扫描行数降至不高于 12000 行，SQL P95 不高于当前 1800 ms 基线；"
        "写入 P95 不高于灰度前冻结基线的 110%"
    )
    assert action["rollbackZh"]
    assert any("参数分布" in item for item in result["uncertainty"])


@pytest.mark.parametrize(
    ("kind", "field", "value"),
    [
        ("ordinary_plan", "accessPath", "index_range_scan"),
        ("index", "indexCoverage", "matching_composite_index"),
        ("slow_query", "averageScanRows", 9_999),
        ("slow_query", "averageReturnRows", 1_201),
        ("slow_query", "callCount", 2),
    ],
)
def test_index_rule_each_one_below_or_false_predicate_abstains(
    kind: str,
    field: str,
    value: object,
) -> None:
    input_value = replace_evidence(
        load_scenario("index-scan"),
        kind,
        lambda document: document["payload"]["typed"].__setitem__(field, value),
    )

    result = report(input_value)

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["reasoning"]["ruleFindingsZh"] == []
    assert result["trace"]["ruleIds"] == []
    assert result["trace"]["evidenceCompleteness"] == 100
    assert any("未同时达到" in item for item in result["uncertainty"])


@pytest.mark.parametrize("missing_kind", ["sql_structure", "ordinary_plan", "index", "slow_query"])
def test_index_rule_requires_all_four_correlated_roles(missing_kind: str) -> None:
    result = report(without_kind(load_scenario("index-scan"), missing_kind))

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["trace"]["ruleIds"] == []
    expected_completeness = 50 if missing_kind == "sql_structure" else 75
    assert result["trace"]["evidenceCompleteness"] == expected_completeness
    assert any(missing_kind in item for item in result["uncertainty"])


def test_index_rule_requires_table_full_scan_even_with_other_positive_roles() -> None:
    value = replace_evidence(
        load_scenario("index-scan"),
        "ordinary_plan",
        lambda document: document["payload"]["typed"].__setitem__("accessPath", "index_full_scan"),
    )

    result = report(value)

    assert result["priority"] == "observe"
    assert INDEX_RULE_ID not in result["trace"]["ruleIds"]


def test_index_rule_requires_index_filter_prefix_to_match_parsed_sql() -> None:
    value = replace_evidence(
        load_scenario("index-scan"),
        "index",
        lambda document: document["payload"]["typed"].__setitem__("filterColumns", ["tenant_id"]),
    )

    result = report(value)

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert INDEX_RULE_ID not in result["trace"]["ruleIds"]


def test_statistics_rule_uses_only_real_health_below_80() -> None:
    result = report(load_scenario("statistics-health"))

    assert result["priority"] == "P2"
    assert result["trace"]["ruleIds"] == [STATISTICS_RULE_ID]
    assert result["trace"]["evidenceCompleteness"] == 100
    assert "统计健康度为 42%" in result["conclusionZh"]
    assert "估算偏差" not in result["conclusionZh"]
    assert "已经导致" not in result["conclusionZh"]
    assert result["reasoning"]["ruleFindingsZh"] == [
        "order_items 表统计健康度低于 M0 的 80% 检查阈值；统计质量可能影响"
        "优化器估算，需由 DBA 复核。"
    ]
    assert len(result["actions"]) == 1
    action = result["actions"][0]
    assert action["ownerRole"] == "dba"
    assert any("SQLLens 不执行" in item for item in action["stepsZh"])
    assert action["validation"]["metricZh"]
    assert action["validation"]["targetZh"] == (
        "SHOW STATS_HEALTHY 恢复至不低于 80%，普通计划不退化，代表性参数 P95 不高于刷新前基线"
    )
    assert action["rollbackZh"]


def test_statistics_rule_does_not_hit_at_80() -> None:
    value = replace_evidence(
        load_scenario("statistics-health"),
        "statistics",
        lambda document: document["payload"]["typed"].__setitem__("healthyPercent", 80),
    )

    result = report(value)

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["trace"]["ruleIds"] == []
    assert result["trace"]["evidenceCompleteness"] == 100


@pytest.mark.parametrize("missing_kind", ["sql_structure", "statistics"])
def test_statistics_rule_requires_structure_and_health(missing_kind: str) -> None:
    result = report(without_kind(load_scenario("statistics-health"), missing_kind))

    assert result["priority"] == "observe"
    assert result["actions"] == []
    expected_completeness = 0 if missing_kind == "sql_structure" else 50
    assert result["trace"]["evidenceCompleteness"] == expected_completeness
    assert any(missing_kind in item for item in result["uncertainty"])


def test_statistics_rule_rejects_plan_stats_or_estimated_actual_shortcuts() -> None:
    def add_forbidden_fields(document: dict[str, Any]) -> None:
        typed = document["payload"]["typed"]
        typed.update({"planStats": "pseudo", "estimatedRows": 1, "actualRows": 1000})

    result = report(
        replace_evidence(
            load_scenario("statistics-health"),
            "statistics",
            add_forbidden_fields,
        )
    )

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["trace"]["ruleIds"] == []
    assert any("statistics" in item for item in result["uncertainty"])


@pytest.mark.parametrize(
    ("label", "kind", "transform", "recompute_typed_digest", "storage_payload"),
    [
        (
            "stale",
            "slow_query",
            lambda document: document.__setitem__("freshness", "stale"),
            True,
            None,
        ),
        (
            "truncated",
            "slow_query",
            lambda document: (
                document["payload"].__setitem__("truncated", True),
                document["collection"].__setitem__("status", "truncated"),
            ),
            True,
            None,
        ),
        (
            "low-coverage",
            "slow_query",
            lambda document: document.__setitem__("coverage", 0.79),
            True,
            None,
        ),
        (
            "wrong-envelope-object",
            "slow_query",
            lambda document: document.__setitem__("profileObjectRef", "sql:" + "f" * 64),
            True,
            None,
        ),
        (
            "wrong-selected-digest",
            "slow_query",
            lambda document: (
                document.__setitem__("profileObjectRef", "sql:" + "f" * 64),
                document["payload"]["typed"].__setitem__("profileObjectRef", "sql:" + "f" * 64),
            ),
            True,
            None,
        ),
        (
            "wrong-case",
            "slow_query",
            lambda document: document.__setitem__("caseId", "case_m0wrongreview0001"),
            True,
            None,
        ),
        (
            "wrong-version",
            "slow_query",
            lambda document: document["collection"].__setitem__(
                "queryRevision", "tidb-8.4/m0-fixture-v1"
            ),
            True,
            None,
        ),
        (
            "bad-typed-digest",
            "slow_query",
            lambda document: document["payload"].__setitem__("typedDigest", "sha256:" + "0" * 64),
            False,
            None,
        ),
        (
            "bad-raw-digest",
            "slow_query",
            lambda document: None,
            True,
            strict_json_bytes({"fixtureLabel": "fixture/review-only", "tampered": True}),
        ),
        (
            "bad-shape",
            "slow_query",
            lambda document: document["payload"]["typed"].__setitem__("unexpected", "untrusted"),
            True,
            None,
        ),
        (
            "wrong-window",
            "slow_query",
            lambda document: document.__setitem__("observedAt", "2026-09-03T05:29:00Z"),
            True,
            None,
        ),
    ],
    ids=lambda item: item if isinstance(item, str) else None,
)
def test_index_rule_fails_closed_on_ineligible_or_invalid_evidence(
    label: str,
    kind: str,
    transform: Callable[[dict[str, Any]], None],
    recompute_typed_digest: bool,
    storage_payload: bytes | None,
) -> None:
    del label
    result = report(
        replace_evidence(
            load_scenario("index-scan"),
            kind,
            transform,
            recompute_typed_digest=recompute_typed_digest,
            storage_payload=storage_payload,
        )
    )

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["trace"]["ruleIds"] == []
    assert result["trace"]["evidenceCompleteness"] < 100


def test_index_rule_rejects_table_level_role_not_declared_by_sql_structure() -> None:
    def move_plan_to_another_table(document: dict[str, Any]) -> None:
        document["profileObjectRef"] = "customers"
        typed = document["payload"]["typed"]
        typed["profileObjectRef"] = "customers"
        typed["tableName"] = "customers"

    result = report(
        replace_evidence(
            load_scenario("index-scan"),
            "ordinary_plan",
            move_plan_to_another_table,
        )
    )

    assert result["priority"] == "observe"
    assert result["actions"] == []


def test_index_rule_rejects_cross_source_role_splicing() -> None:
    def move_to_another_source(document: dict[str, Any]) -> None:
        document["sourceRef"] = {"sourceId": "src_m0othersource0001", "revision": 1}

    result = report(replace_evidence(load_scenario("index-scan"), "index", move_to_another_source))

    assert result["priority"] == "observe"
    assert result["actions"] == []


def test_duplicate_required_role_fails_closed_instead_of_cherry_picking() -> None:
    value = load_scenario("index-scan")
    duplicate = evidence_by_kind(value, "index")
    duplicated = M0ReportInput(
        case_id=value.case_id,
        database=value.database,
        sql_digest=value.sql_digest,
        window_start=value.window_start,
        window_end=value.window_end,
        evidence=(*value.evidence, duplicate),
    )

    result = report(duplicated)

    assert result["priority"] == "observe"
    assert result["actions"] == []


def test_report_bytes_are_canonical_and_independent_of_evidence_order() -> None:
    value = load_scenario("index-scan")
    reversed_value = M0ReportInput(
        case_id=value.case_id,
        database=value.database,
        sql_digest=value.sql_digest,
        window_start=value.window_start,
        window_end=value.window_end,
        evidence=tuple(reversed(value.evidence)),
    )

    rendered = build_m0_rules_report(value)

    assert rendered == strict_json_bytes(strict_json_loads(rendered))
    assert rendered == build_m0_rules_report(reversed_value)
    assert b"confidence" not in rendered.lower()
    assert b"20%" not in rendered


def test_report_never_copies_raw_storage_or_free_form_evidence_summary() -> None:
    marker = "UNTRUSTED_FREE_FORM_MARKER"
    raw_marker = strict_json_bytes({"fixtureLabel": "fixture/review-only", "marker": marker})

    def rebind_storage(document: dict[str, Any]) -> None:
        digest = "sha256:" + hashlib.sha256(raw_marker).hexdigest()
        document["integrityDigest"] = digest
        document["summaryZh"] = marker
        document["payload"]["digest"] = digest

    value = replace_evidence(
        load_scenario("index-scan"),
        "slow_query",
        rebind_storage,
        storage_payload=raw_marker,
    )

    rendered = build_m0_rules_report(value)

    assert marker.encode() not in rendered
