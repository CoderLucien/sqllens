# ruff: noqa: RUF001
from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from datetime import datetime
from html.parser import HTMLParser
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
    REPEATED_SCAN_RULE_ID,
    RULE_PACK_REVISION,
    STATISTICS_RULE_ID,
    M0ReportInput,
    build_m0_rules_report,
)

FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "m0" / "report-inputs.json"
EXAMPLES_PATH = Path(__file__).parents[2] / "docs" / "contracts" / "examples"
PREVIEW_PATH = Path(__file__).parents[2] / "docs" / "product" / "sqllens-m0-report-preview.html"
NO_BUSINESS_EVIDENCE_ZH = "未提供业务影响证据，仅说明数据库技术影响"


class _EmbeddedReportsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._inside_reports_data = False
        self.chunks: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag == "script" and dict(attrs).get("id") == "reports-data":
            self._inside_reports_data = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._inside_reports_data:
            self._inside_reports_data = False

    def handle_data(self, data: str) -> None:
        if self._inside_reports_data:
            self.chunks.append(data)


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


def rebind_review_evidence(
    collected: CollectedEvidence,
    *,
    case_id: str,
    sql_digest: str | None = None,
    table_name: str | None = None,
    evidence_id: str | None = None,
) -> CollectedEvidence:
    document = copy.deepcopy(collected.document)
    storage = strict_json_loads(collected.storage_payload)
    assert isinstance(storage, dict)
    document["caseId"] = case_id
    if evidence_id is not None:
        document["evidenceId"] = evidence_id
    typed = document["payload"]["typed"]
    if sql_digest is not None:
        sql_ref = f"sql:{sql_digest}"
        document["profileObjectRef"] = sql_ref
        typed["profileObjectRef"] = sql_ref
    if table_name is not None:
        document["profileObjectRef"] = table_name
        typed["profileObjectRef"] = table_name
        typed["tableName"] = table_name
        storage["rows"][0]["tableName"] = table_name
        if document["kind"] == "statistics":
            document["summaryZh"] = f"{table_name} 表统计健康度为 {typed['healthyPercent']}%。"
    raw = strict_json_bytes(storage)
    raw_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    document["integrityDigest"] = raw_digest
    document["payload"]["digest"] = raw_digest
    document["payload"]["typedDigest"] = canonical_sha256(typed)
    return CollectedEvidence(
        _document_json=strict_json_bytes(document),
        storage_payload=raw,
    )


def test_m0_report_input_is_frozen_and_does_not_repr_evidence() -> None:
    value = load_scenario("index-scan")

    assert "evidence=" not in repr(value)
    assert value.evidence[0].document["evidenceId"] not in repr(value)
    with pytest.raises(FrozenInstanceError):
        value.database = "other"  # type: ignore[misc]


def test_empty_evidence_is_e0_and_explicitly_incomplete() -> None:
    value = replace(load_scenario("index-scan"), evidence=())

    result = report(value)

    assert result["priority"] == "observe"
    assert result["trace"]["evidenceLevel"] == "E0"
    assert result["trace"]["evidenceCompleteness"] == 0
    assert "证据不足" in result["titleZh"]
    assert "证据不完整" in result["conclusionZh"]


def test_partial_evidence_is_e1() -> None:
    result = report(without_kind(load_scenario("statistics-health"), "statistics"))

    assert result["priority"] == "observe"
    assert result["trace"]["evidenceLevel"] == "E1"
    assert result["trace"]["evidenceCompleteness"] == 50


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
        "平均扫描行数降至不高于 9999 行，SQL P95 不高于当前 1800 ms 基线；"
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
    assert result["trace"]["evidenceLevel"] == "E2"
    assert result["trace"]["evidenceCompleteness"] == 100
    assert "未命中" in result["titleZh"]
    assert "合格证据完整" in result["conclusionZh"]


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


def test_duplicate_evidence_id_invalidates_all_colliding_roles_independent_of_order() -> None:
    index = load_scenario("index-scan")
    statistics = load_scenario("statistics-health")
    duplicate_id = evidence_by_kind(index, "index").document["evidenceId"]
    assert isinstance(duplicate_id, str)
    health = rebind_review_evidence(
        evidence_by_kind(statistics, "statistics"),
        case_id=index.case_id,
        table_name="orders",
        evidence_id=duplicate_id,
    )
    health_last = M0ReportInput(
        case_id=index.case_id,
        database=index.database,
        sql_digest=index.sql_digest,
        window_start=index.window_start,
        window_end=index.window_end,
        evidence=(*index.evidence, health),
    )
    health_first = replace(health_last, evidence=(health, *index.evidence))

    first = report(health_first)
    last = report(health_last)

    assert first == last
    assert first["priority"] == "observe"
    assert first["actions"] == []
    assert first["trace"]["ruleIds"] == []


@pytest.mark.parametrize(
    ("label", "transform"),
    [
        (
            "boolean-revision",
            lambda document: document.__setitem__("revision", True),
        ),
        (
            "zero-record-claim",
            lambda document: (
                document["payload"].__setitem__("recordCount", 0),
                document["collection"]["budget"].__setitem__("rowsRead", 0),
            ),
        ),
    ],
)
def test_index_rule_rejects_schema_invalid_or_empty_evidence(
    label: str,
    transform: Callable[[dict[str, Any]], None],
) -> None:
    del label
    result = report(replace_evidence(load_scenario("index-scan"), "slow_query", transform))

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["trace"]["ruleIds"] == []


def test_index_rule_rejects_noncanonical_raw_storage_even_with_matching_digest() -> None:
    value = load_scenario("index-scan")
    original = evidence_by_kind(value, "slow_query")
    raw_value = strict_json_loads(original.storage_payload)
    noncanonical_raw = json.dumps(raw_value, ensure_ascii=False, indent=2).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(noncanonical_raw).hexdigest()

    def bind_self_declared_digest(document: dict[str, Any]) -> None:
        document["integrityDigest"] = digest
        document["payload"]["digest"] = digest

    result = report(
        replace_evidence(
            value,
            "slow_query",
            bind_self_declared_digest,
            storage_payload=noncanonical_raw,
        )
    )

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["trace"]["ruleIds"] == []


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


@pytest.mark.parametrize(
    ("scenario", "filename"),
    [
        ("index-scan", "diagnosis-report-v1.m0-index-scan.review.json"),
        (
            "statistics-health",
            "diagnosis-report-v1.m0-statistics-health.review.json",
        ),
        ("repeated-scan", "diagnosis-report-v1.m0-repeated-scan.review.json"),
    ],
)
def test_review_json_is_exact_canonical_rule_output(
    scenario: str,
    filename: str,
) -> None:
    expected = build_m0_rules_report(load_scenario(scenario)) + b"\n"

    assert (EXAMPLES_PATH / filename).read_bytes() == expected


def test_standalone_preview_embeds_the_three_exact_review_reports() -> None:
    parser = _EmbeddedReportsParser()
    html = PREVIEW_PATH.read_text(encoding="utf-8")
    parser.feed(html)
    script_data = "".join(parser.chunks)
    embedded = json.loads(script_data)
    expected = [
        json.loads((EXAMPLES_PATH / filename).read_text(encoding="utf-8"))
        for filename in (
            "diagnosis-report-v1.m0-index-scan.review.json",
            "diagnosis-report-v1.m0-statistics-health.review.json",
            "diagnosis-report-v1.m0-repeated-scan.review.json",
        )
    ]

    assert embedded == expected
    assert "\\u8be5" in script_data
    assert not any(character in script_data for character in "<>&\u2028\u2029")
    assert "evidence-item__ids" not in html


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


def test_repeated_scan_rule_emits_measured_hotspot_and_p1_action() -> None:
    result = report(load_scenario("repeated-scan"))

    assert result["priority"] == "P1"
    assert result["trace"]["ruleIds"] == [REPEATED_SCAN_RULE_ID]
    assert result["trace"]["evidenceCompleteness"] == 100
    assert "30 分钟" in result["conclusionZh"]
    assert "24 次" in result["conclusionZh"]
    assert "按聚合字段计算" in result["conclusionZh"]
    assert "CPU" not in result["reasoning"]["ruleFindingsZh"][0]
    assert result["impact"]["businessEvidenceIds"] == []
    assert len(result["actions"]) == 1
    action = result["actions"][0]
    assert action["ownerRole"] == "developer"
    assert action["validation"]["metricZh"] == (
        "同一 30 分钟窗口的执行次数、平均扫描行数与 SQL P95"
    )
    assert action["validation"]["targetZh"] == (
        "执行次数降至不高于 9 次，或平均扫描行数降至不高于 9999 行；SQL P95 不高于当前 6200 ms 基线"
    )
    assert any("恢复" in item for item in action["rollbackZh"])


def test_repeated_scan_rule_accepts_all_four_exact_thresholds() -> None:
    value = replace_evidence(
        load_scenario("repeated-scan"),
        "statement_summary",
        lambda document: document["payload"]["typed"].update(
            {"executionCount": 10, "weightedTotalKeys": 1_000_000}
        ),
    )
    value = replace_evidence(
        value,
        "slow_query",
        lambda document: document["payload"]["typed"].update(
            {"averageScanRows": 10_000, "averageReturnRows": 100}
        ),
    )

    result = report(value)

    assert result["priority"] == "P2"
    assert result["trace"]["ruleIds"] == [REPEATED_SCAN_RULE_ID]


@pytest.mark.parametrize(
    ("kind", "field", "value"),
    [
        ("statement_summary", "executionCount", 9),
        ("statement_summary", "weightedTotalKeys", 999_999),
        ("slow_query", "averageScanRows", 9_999),
        ("slow_query", "averageReturnRows", 1_251),
    ],
)
def test_repeated_scan_rule_each_one_below_threshold_abstains(
    kind: str,
    field: str,
    value: int,
) -> None:
    input_value = replace_evidence(
        load_scenario("repeated-scan"),
        kind,
        lambda document: document["payload"]["typed"].__setitem__(field, value),
    )

    result = report(input_value)

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["trace"]["ruleIds"] == []
    assert result["trace"]["evidenceCompleteness"] == 100


@pytest.mark.parametrize("missing_kind", ["statement_summary", "slow_query"])
def test_repeated_scan_rule_requires_both_correlated_roles(missing_kind: str) -> None:
    result = report(without_kind(load_scenario("repeated-scan"), missing_kind))

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["trace"]["ruleIds"] == []
    assert result["trace"]["evidenceCompleteness"] == 50
    assert any(missing_kind in item for item in result["uncertainty"])


@pytest.mark.parametrize(
    ("kind", "field", "value"),
    [
        ("slow_query", "p95Ms", 4_999),
        ("statement_summary", "executionCount", 19),
    ],
)
def test_repeated_scan_priority_stays_p2_without_both_escalation_metrics(
    kind: str,
    field: str,
    value: int,
) -> None:
    input_value = replace_evidence(
        load_scenario("repeated-scan"),
        kind,
        lambda document: document["payload"]["typed"].__setitem__(field, value),
    )

    result = report(input_value)

    assert result["priority"] == "P2"
    assert result["trace"]["ruleIds"] == [REPEATED_SCAN_RULE_ID]


def test_repeated_scan_rule_rejects_a_mismatched_window() -> None:
    value = replace_evidence(
        load_scenario("repeated-scan"),
        "statement_summary",
        lambda document: document["payload"]["typed"].__setitem__("windowMinutes", 15),
    )

    result = report(value)

    assert result["priority"] == "observe"
    assert result["actions"] == []
    assert result["trace"]["ruleIds"] == []


def test_multiple_hits_use_frozen_order_and_at_most_three_actions() -> None:
    index = load_scenario("index-scan")
    repeated = load_scenario("repeated-scan")
    statistics = load_scenario("statistics-health")
    summary = rebind_review_evidence(
        evidence_by_kind(repeated, "statement_summary"),
        case_id=index.case_id,
        sql_digest=index.sql_digest,
    )
    health = rebind_review_evidence(
        evidence_by_kind(statistics, "statistics"),
        case_id=index.case_id,
        table_name="orders",
    )
    combined = M0ReportInput(
        case_id=index.case_id,
        database=index.database,
        sql_digest=index.sql_digest,
        window_start=index.window_start,
        window_end=index.window_end,
        evidence=(*index.evidence, summary, health),
    )

    result = report(combined)

    assert result["priority"] == "P2"
    assert result["trace"]["ruleIds"] == [
        REPEATED_SCAN_RULE_ID,
        INDEX_RULE_ID,
        STATISTICS_RULE_ID,
    ]
    assert result["reasoning"]["ruleFindingsZh"][0].startswith("该 SQL 在 30 分钟")
    assert [item["labelZh"] for item in result["evidenceSummary"]] == [
        "重复重扫描",
        "扫描与访问路径",
        "统计健康度",
    ]
    assert [item["order"] for item in result["actions"]] == [1, 2, 3]
    assert len(result["actions"]) == 3
