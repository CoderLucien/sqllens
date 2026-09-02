from __future__ import annotations

import hashlib
import json
import math
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqllens_api.evidence_connector import (
    MAX_SAFE_INTEGER,
    EvidenceBuildError,
    EvidenceFreshness,
    ManagedEvidenceContext,
    QueryResult,
    build_managed_evidence,
    canonical_json_bytes,
    canonical_sha256,
    query_pack,
    strict_json_bytes,
    strict_json_loads,
)

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "evidence_connector"
PACK_FIXTURES = {
    "tidb-8.5": "tidb-8.5.4.json",
    "pingkaidb-7.1": "pingkaidb-7.1.8.json",
}


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def slow_query_collection(
    pack_id: str,
) -> tuple[Any, QueryResult, ManagedEvidenceContext, dict[str, Any]]:
    fixture = json.loads((FIXTURE_DIR / PACK_FIXTURES[pack_id]).read_text(encoding="utf-8"))
    recording = fixture["recordings"]["slow_query.current_user"]
    row = recording["rows"][0]
    observed = parse_time(row["observed_at"])
    query = query_pack(pack_id)["slow_query.current_user"]
    result = QueryResult(
        columns=tuple(recording["columns"]),
        rows=(row,),
        truncated=False,
        observed_bytes=2_048,
        elapsed_ms=83,
    )
    context = ManagedEvidenceContext(
        evidence_id="ev_0000000000000001",
        case_id="case_0000000000000002",
        profile_subject_ref="subject_0000000000000002",
        profile_object_ref="orders",
        source_id="src_0000000000000001",
        source_revision=3,
        storage_ref="payload_0000000000000001",
        window_start=observed - timedelta(minutes=5),
        window_end=observed + timedelta(minutes=5),
        collected_at=observed + timedelta(minutes=6),
        freshness=EvidenceFreshness.FRESH,
        coverage_basis_points=9_600,
        schema_name=row["schema_name"],
        sql_digest=row["digest"],
    )
    return query, result, context, fixture


def statement_summary_row(
    *,
    begin: str,
    end: str,
    plan_digest: str = "b" * 64,
    average_total_keys: int = 1_200,
    average_processed_keys: int = 80,
) -> dict[str, str | int | None]:
    return {
        "instance": "tidb-0.internal:4000",
        "summary_begin_time": begin,
        "summary_end_time": end,
        "schema_name": "app_redacted",
        "digest": "a" * 64,
        "plan_digest": plan_digest,
        "exec_count": 12,
        "sum_latency": 14_400_000,
        "avg_latency": 1_200_000,
        "max_latency": 2_000_000,
        "sum_errors": 0,
        "avg_mem": 8_192,
        "max_mem": 16_384,
        "avg_disk": 0,
        "max_disk": 0,
        "avg_total_keys": average_total_keys,
        "avg_processed_keys": average_processed_keys,
        "first_seen": begin,
        "last_seen": end,
    }


def test_canonical_typed_digest_matches_the_frozen_contract_vector() -> None:
    typed = {
        "kind": "slow_query",
        "profileSubjectRef": "subject_0000000000000002",
        "profileObjectRef": "orders",
        "windowMinutes": 10,
        "callCount": 842,
        "p95Ms": 2_800,
        "averageScanRows": 1_260_000,
        "averageReturnRows": 400,
    }

    assert canonical_sha256(typed) == (
        "sha256:9b10ce079c8610618e4ac8959b580ecc67b3d180df4ca475d176533677d417a7"
    )


@pytest.mark.parametrize(
    "source",
    [
        '{"kind":"attacker","kind":"slow_query"}',
        '{"typed":{"kind":"attacker","kind":"slow_query"}}',
        '[{"kind":"attacker","kind":"slow_query"}]',
    ],
)
def test_strict_json_ingress_rejects_duplicate_members_at_every_depth(
    source: str,
) -> None:
    with pytest.raises(ValueError, match="duplicate JSON object member"):
        strict_json_loads(source)


@pytest.mark.parametrize(
    ("value", "error_type"),
    [
        ({"value": math.nan}, ValueError),
        ({"value": math.inf}, ValueError),
        ({"value": 1.25}, TypeError),
        ({"value": MAX_SAFE_INTEGER + 1}, ValueError),
        ({1: "not-a-JSON-object"}, ValueError),
        ((1, 2), ValueError),
    ],
)
def test_canonical_typed_json_rejects_ambiguous_or_unsupported_values(
    value: Any,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        canonical_json_bytes(value)


def test_strict_storage_json_rejects_non_string_object_keys() -> None:
    with pytest.raises(ValueError, match="non-string JSON object key"):
        strict_json_bytes({1: "value"})


@pytest.mark.parametrize("pack_id", ["tidb-8.5", "pingkaidb-7.1"])
def test_recorded_slow_query_becomes_contract_exact_managed_evidence(
    pack_id: str,
) -> None:
    query, result, context, fixture = slow_query_collection(pack_id)

    collected = build_managed_evidence(query=query, result=result, context=context)
    evidence = collected.document
    typed = evidence["payload"]["typed"]

    assert evidence["schemaVersion"] == "evidence/v2"
    assert evidence["origin"] == "managed_source"
    assert evidence["profileSubjectRef"] == typed["profileSubjectRef"]
    assert evidence["profileObjectRef"] == typed["profileObjectRef"]
    assert evidence["sourceRef"] == {
        "sourceId": "src_0000000000000001",
        "revision": 3,
    }
    assert evidence["observedAt"] == context.window_end.isoformat().replace("+00:00", "Z")
    assert evidence["collectedAt"] == context.collected_at.isoformat().replace("+00:00", "Z")
    assert evidence["freshness"] == "fresh"
    assert evidence["sensitivity"] == "confidential"
    assert evidence["payload"]["schemaRevision"] == "slow-query/v2"
    assert evidence["payload"]["extractionRevision"] == "evidence-extractor/v1"
    assert evidence["payload"]["canonicalRevision"] == ("rfc8785-safe-integer/v1")
    assert evidence["payload"]["storageRef"] == context.storage_ref
    assert typed == {
        "kind": "slow_query",
        "profileSubjectRef": "subject_0000000000000002",
        "profileObjectRef": "orders",
        "windowMinutes": 10,
        "callCount": 1,
        "p95Ms": 1_200,
        "averageScanRows": fixture["recordings"]["slow_query.current_user"]["rows"][0][
            "total_keys"
        ],
        "averageReturnRows": fixture["recordings"]["slow_query.current_user"]["rows"][0][
            "result_rows"
        ],
    }
    assert evidence["payload"]["typedDigest"] == canonical_sha256(typed)
    assert evidence["collection"]["queryId"] == query.query_id
    assert evidence["collection"]["queryRevision"] == query.query_revision
    assert evidence["collection"]["collectorId"] == (
        "tidb-readonly" if pack_id == "tidb-8.5" else "pingkaidb-readonly"
    )
    assert evidence["collection"]["collectorRevision"] == "evidence-connector/v1"
    assert evidence["collection"]["redactionRevision"] == "evidence-redaction/v2"
    assert evidence["collection"]["budget"] == {
        "timeoutMs": query.budget.timeout_ms,
        "maxRows": query.budget.max_rows,
        "maxBytes": query.budget.max_bytes,
        "elapsedMs": 83,
        "rowsRead": 1,
        "bytesRead": 2_048,
    }
    assert evidence["collection"]["status"] == "complete"
    assert evidence["payload"]["recordCount"] == 1
    assert evidence["payload"]["truncated"] is False
    assert evidence["coverage"] == 0.96
    assert set(evidence) == {
        "schemaVersion",
        "evidenceId",
        "revision",
        "caseId",
        "profileSubjectRef",
        "profileObjectRef",
        "origin",
        "kind",
        "sourceRef",
        "observedAt",
        "collectedAt",
        "freshness",
        "coverage",
        "sensitivity",
        "integrityDigest",
        "summaryZh",
        "payload",
        "collection",
    }
    assert set(evidence["payload"]) == {
        "schemaRevision",
        "extractionRevision",
        "canonicalRevision",
        "storageRef",
        "recordCount",
        "truncated",
        "digest",
        "typed",
        "typedDigest",
    }
    assert set(evidence["collection"]) == {
        "collectorId",
        "collectorRevision",
        "queryId",
        "queryRevision",
        "status",
        "redactionRevision",
        "budget",
    }
    assert "rows" not in evidence["payload"]
    assert "sql" not in evidence["collection"]
    assert "parameters" not in evidence["collection"]
    storage = json.loads(collected.storage_payload)
    assert storage["rows"] == list(result.rows)
    storage_digest = f"sha256:{hashlib.sha256(collected.storage_payload).hexdigest()}"
    assert evidence["integrityDigest"] == storage_digest
    assert evidence["payload"]["digest"] == storage_digest
    assert collected.document_json == strict_json_bytes(evidence)
    assert context.schema_name not in repr(collected)
    assert context.sql_digest not in repr(collected)

    evidence["kind"] = "attacker"
    assert collected.document["kind"] == "slow_query"


def test_slow_query_summary_is_rendered_from_typed_measurements() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")

    evidence = build_managed_evidence(
        query=query,
        result=result,
        context=context,
    ).document

    assert evidence["summaryZh"] == (
        "该 SQL 在 10 分钟窗口内执行 1 次，P95 1.2 秒，平均扫描 0.12 万行。"  # noqa: RUF001
    )


def test_ineligible_collection_quality_is_recorded_without_becoming_a_claim() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    context = replace(
        context,
        freshness=EvidenceFreshness.STALE,
        coverage_basis_points=0,
    )

    evidence = build_managed_evidence(
        query=query,
        result=result,
        context=context,
    ).document

    assert evidence["freshness"] == "stale"
    assert evidence["coverage"] == 0
    assert evidence["payload"]["typed"]["kind"] == "slow_query"


@pytest.mark.parametrize("pack_id", ["tidb-8.5", "pingkaidb-7.1"])
def test_cross_user_slow_query_uses_the_same_typed_projection(pack_id: str) -> None:
    _, current_result, context, _ = slow_query_collection(pack_id)
    query = query_pack(pack_id)["slow_query.cross_user"]
    row = {"instance": "tidb-0.internal:4000", **current_result.rows[0]}
    result = replace(current_result, columns=query.result_columns, rows=(row,))

    evidence = build_managed_evidence(
        query=query,
        result=result,
        context=context,
    ).document

    assert evidence["kind"] == "slow_query"
    assert evidence["payload"]["typed"]["callCount"] == 1
    assert evidence["collection"]["queryId"] == "slow_query.cross_user"


def test_cross_user_slow_query_requires_a_bounded_instance_identity() -> None:
    _, current_result, context, _ = slow_query_collection("tidb-8.5")
    query = query_pack("tidb-8.5")["slow_query.cross_user"]
    row = {"instance": "", **current_result.rows[0]}
    result = replace(current_result, columns=query.result_columns, rows=(row,))

    with pytest.raises(EvidenceBuildError, match="Slow Query instance"):
        build_managed_evidence(query=query, result=result, context=context)


def test_statement_summary_exact_comparison_builds_stable_typed_evidence() -> None:
    query = query_pack("tidb-8.5")["statement_summary.cross_user"]
    rows = (
        statement_summary_row(begin="2026-09-02T08:00:00Z", end="2026-09-02T08:10:00Z"),
        statement_summary_row(begin="2026-09-02T08:10:00Z", end="2026-09-02T08:20:00Z"),
    )
    result = QueryResult(
        columns=query.result_columns,
        rows=rows,
        truncated=False,
        observed_bytes=4_096,
        elapsed_ms=75,
    )
    context = ManagedEvidenceContext(
        evidence_id="ev_0000000000000003",
        case_id="case_0000000000000004",
        profile_subject_ref="subject_0000000000000004",
        profile_object_ref="payment_tikv_hotspot_window",
        source_id="src_0000000000000003",
        source_revision=2,
        storage_ref="payload_0000000000000003",
        window_start=datetime(2026, 9, 2, 8, 0, tzinfo=UTC),
        window_end=datetime(2026, 9, 2, 8, 20, tzinfo=UTC),
        collected_at=datetime(2026, 9, 2, 8, 21, tzinfo=UTC),
        freshness=EvidenceFreshness.FRESH,
        coverage_basis_points=10_000,
        schema_name="app_redacted",
        sql_digest="a" * 64,
    )

    evidence = build_managed_evidence(
        query=query,
        result=result,
        context=context,
    ).document

    assert evidence["payload"]["schemaRevision"] == "statement-summary/v2"
    assert evidence["payload"]["typed"] == {
        "kind": "statement_summary",
        "profileSubjectRef": "subject_0000000000000004",
        "profileObjectRef": "payment_tikv_hotspot_window",
        "sqlStability": "plan_and_scan_stable",
    }
    assert evidence["summaryZh"] == ("SQL 计划摘要和扫描行数与前一基线窗口接近。")


def test_statement_summary_does_not_compare_rounded_weighted_averages() -> None:
    previous_first = statement_summary_row(
        begin="2026-09-02T08:00:00Z",
        end="2026-09-02T08:10:00Z",
        average_total_keys=1,
        average_processed_keys=1,
    )
    previous_first["exec_count"] = 1
    previous_second = statement_summary_row(
        begin="2026-09-02T08:00:00Z",
        end="2026-09-02T08:10:00Z",
        average_total_keys=2,
        average_processed_keys=2,
    )
    previous_second["exec_count"] = 1
    current = statement_summary_row(
        begin="2026-09-02T08:10:00Z",
        end="2026-09-02T08:20:00Z",
        average_total_keys=2,
        average_processed_keys=2,
    )
    current["exec_count"] = 1
    query, result, context = statement_summary_collection(
        (previous_first, previous_second, current)
    )

    evidence = build_managed_evidence(
        query=query,
        result=result,
        context=context,
    ).document

    assert evidence["payload"]["typed"]["sqlStability"] == "unknown"


def test_statement_summary_accepts_equivalent_unreduced_weighted_ratios() -> None:
    rows = []
    for begin, end, execution_count in (
        ("2026-09-02T08:00:00Z", "2026-09-02T08:10:00Z", 1),
        ("2026-09-02T08:10:00Z", "2026-09-02T08:20:00Z", 2),
    ):
        for average_keys in (1, 2):
            row = statement_summary_row(
                begin=begin,
                end=end,
                average_total_keys=average_keys,
                average_processed_keys=average_keys,
            )
            row["exec_count"] = execution_count
            rows.append(row)
    query, result, context = statement_summary_collection(tuple(rows))

    evidence = build_managed_evidence(
        query=query,
        result=result,
        context=context,
    ).document

    assert evidence["payload"]["typed"]["sqlStability"] == "plan_and_scan_stable"


def statement_summary_collection(
    rows: tuple[dict[str, str | int | None], ...],
) -> tuple[Any, QueryResult, ManagedEvidenceContext]:
    query = query_pack("tidb-8.5")["statement_summary.cross_user"]
    result = QueryResult(
        columns=query.result_columns,
        rows=rows,
        truncated=False,
        observed_bytes=4_096,
        elapsed_ms=75,
    )
    context = ManagedEvidenceContext(
        evidence_id="ev_0000000000000003",
        case_id="case_0000000000000004",
        profile_subject_ref="subject_0000000000000004",
        profile_object_ref="payment_tikv_hotspot_window",
        source_id="src_0000000000000003",
        source_revision=2,
        storage_ref="payload_0000000000000003",
        window_start=datetime(2026, 9, 2, 8, 0, tzinfo=UTC),
        window_end=datetime(2026, 9, 2, 8, 20, tzinfo=UTC),
        collected_at=datetime(2026, 9, 2, 8, 21, tzinfo=UTC),
        freshness=EvidenceFreshness.FRESH,
        coverage_basis_points=10_000,
        schema_name="app_redacted",
        sql_digest="a" * 64,
    )
    return query, result, context


@pytest.mark.parametrize(
    ("context_change", "expected_error"),
    [
        ({"evidence_id": "ev_short"}, "evidence ID"),
        ({"case_id": "case_short"}, "Case ID"),
        ({"profile_subject_ref": "subject_short"}, "profile subject"),
        ({"profile_object_ref": ""}, "profile object"),
        ({"profile_object_ref": 7}, "profile object"),
        ({"source_id": "src_short"}, "Source ID"),
        ({"source_revision": True}, "Source revision"),
        ({"source_revision": "3"}, "Source revision"),
        ({"storage_ref": "payload_short"}, "storage reference"),
        ({"freshness": "fresh"}, "freshness"),
        ({"coverage_basis_points": True}, "coverage"),
        ({"coverage_basis_points": -1}, "coverage"),
        ({"coverage_basis_points": 10_001}, "coverage"),
        ({"schema_name": ""}, "schema name"),
        ({"schema_name": 7}, "schema name"),
        ({"sql_digest": "A" * 64}, "SQL digest"),
        (
            {"window_start": datetime(2026, 9, 2, 1, 23)},
            "timezone",
        ),
        (
            {"window_start": datetime(2026, 9, 2, 1, 27, 30, tzinfo=UTC)},
            "whole minutes",
        ),
        (
            {"window_start": datetime(2026, 9, 1, 1, 27, tzinfo=UTC)},
            "contract range",
        ),
        (
            {"collected_at": datetime(2026, 9, 2, 1, 32, tzinfo=UTC)},
            "time window",
        ),
    ],
)
def test_managed_context_fails_closed_before_evidence_is_emitted(
    context_change: dict[str, Any],
    expected_error: str,
) -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")

    with pytest.raises(EvidenceBuildError, match=expected_error):
        build_managed_evidence(
            query=query,
            result=result,
            context=replace(context, **context_change),
        )


def test_only_registered_diagnostic_queries_can_emit_evidence() -> None:
    query = query_pack("tidb-8.5")["server.identity"]
    result = QueryResult(
        columns=query.result_columns,
        rows=(
            {
                "version": "5.7.25-TiDB-v8.5.4",
                "version_comment": "TiDB Server",
                "tidb_version": "Release Version: v8.5.4",
            },
        ),
        truncated=False,
        observed_bytes=128,
        elapsed_ms=2,
    )
    _, _, context, _ = slow_query_collection("tidb-8.5")

    with pytest.raises(EvidenceBuildError, match="cannot produce diagnostic Evidence"):
        build_managed_evidence(query=query, result=result, context=context)


def test_adapter_rejects_a_valid_but_modified_copy_of_a_server_query() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    modified = replace(
        query,
        budget=replace(query.budget, timeout_ms=query.budget.timeout_ms - 1),
    )

    with pytest.raises(EvidenceBuildError, match="exact server registry entry"):
        build_managed_evidence(query=modified, result=result, context=context)


@pytest.mark.parametrize(
    ("result_change", "expected_error"),
    [
        ({"columns": ("wrong",)}, "columns differ"),
        ({"rows": ()}, "empty collection"),
        ({"truncated": 1}, "truncation flag"),
        ({"elapsed_ms": -1}, "elapsed milliseconds"),
        ({"elapsed_ms": 5_001}, "timeout budget"),
        ({"observed_bytes": -1}, "observed bytes"),
        ({"observed_bytes": 0}, "observed bytes"),
        ({"observed_bytes": 524_289}, "byte budget"),
    ],
)
def test_result_metadata_cannot_understate_or_exceed_a_query_budget(
    result_change: dict[str, Any],
    expected_error: str,
) -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")

    with pytest.raises(EvidenceBuildError, match=expected_error):
        build_managed_evidence(
            query=query,
            result=replace(result, **result_change),
            context=context,
        )


def test_result_rows_must_exactly_match_declared_columns() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    missing_field = dict(result.rows[0])
    missing_field.pop("plan_digest")

    with pytest.raises(EvidenceBuildError, match="row differs"):
        build_managed_evidence(
            query=query,
            result=replace(result, rows=(missing_field,)),
            context=context,
        )


@pytest.mark.parametrize("unsafe_value", [math.nan, math.inf, -math.inf, object()])
def test_result_rows_reject_non_json_or_non_finite_values(unsafe_value: Any) -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    unsafe_row = dict(result.rows[0])
    unsafe_row["cop_time"] = unsafe_value

    with pytest.raises(EvidenceBuildError, match=r"JSON-safe|not finite"):
        build_managed_evidence(
            query=query,
            result=replace(result, rows=(unsafe_row,)),
            context=context,
        )


def test_result_row_count_over_the_registry_budget_is_rejected() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")

    with pytest.raises(EvidenceBuildError, match="row budget"):
        build_managed_evidence(
            query=query,
            result=replace(result, rows=result.rows * (query.budget.max_rows + 1)),
            context=context,
        )


def test_serialized_storage_cannot_bypass_the_byte_budget() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    oversized_row = dict(result.rows[0])
    oversized_row["observed_at"] = "2026-09-02T01:28:00." + "0" * query.budget.max_bytes + "Z"

    with pytest.raises(EvidenceBuildError, match="content exceeded its byte budget"):
        build_managed_evidence(
            query=query,
            result=replace(result, rows=(oversized_row,)),
            context=context,
        )


def test_reported_byte_usage_cannot_understate_the_serialized_payload() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")

    collected = build_managed_evidence(
        query=query,
        result=replace(result, observed_bytes=1),
        context=context,
    )

    assert collected.document["collection"]["budget"]["bytesRead"] == len(collected.storage_payload)


def test_serialized_payload_saturation_uses_the_same_effective_byte_count() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    baseline = build_managed_evidence(query=query, result=result, context=context)
    fractional_digits = query.budget.max_bytes - len(baseline.storage_payload) - 1
    saturated_row = dict(result.rows[0])
    saturated_row["observed_at"] = (
        saturated_row["observed_at"][:-1] + "." + "0" * fractional_digits + "Z"
    )

    collected = build_managed_evidence(
        query=query,
        result=replace(result, rows=(saturated_row,), observed_bytes=1),
        context=context,
    )

    assert len(collected.storage_payload) == query.budget.max_bytes
    assert collected.document["collection"]["budget"]["bytesRead"] == query.budget.max_bytes
    assert collected.document["collection"]["status"] == "truncated"
    assert collected.document["payload"]["truncated"] is True


def test_unencodable_result_content_fails_at_the_evidence_boundary() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    invalid_row = dict(result.rows[0])
    invalid_row["schema_name"] = "\ud800"

    with pytest.raises(EvidenceBuildError, match="not serializable"):
        build_managed_evidence(
            query=query,
            result=replace(result, rows=(invalid_row,)),
            context=replace(context, schema_name="\ud800"),
        )


@pytest.mark.parametrize("saturation", ["client", "rows", "bytes"])
def test_any_budget_saturation_marks_evidence_truncated(saturation: str) -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    if saturation == "client":
        saturated = replace(result, truncated=True)
    elif saturation == "rows":
        saturated = replace(result, rows=result.rows * query.budget.max_rows)
    else:
        saturated = replace(result, observed_bytes=query.budget.max_bytes)

    evidence = build_managed_evidence(
        query=query,
        result=saturated,
        context=context,
    ).document

    assert evidence["payload"]["truncated"] is True
    assert evidence["collection"]["status"] == "truncated"


@pytest.mark.parametrize(
    ("field", "invalid_value", "expected_error"),
    [
        ("query_time", True, "numeric second"),
        ("query_time", "1.2", "numeric second"),
        ("query_time", 0, "typed Evidence range"),
        ("query_time", -1, "typed Evidence range"),
        ("query_time", 3_600.001, "out of range"),
        ("plan_digest", "not-a-digest", "plan digest"),
        ("parse_time", "0.001", "parse time"),
        ("compile_time", -1, "compile time"),
        ("process_keys", 1.5, "process keys"),
        ("mem_max", -1, "peak memory"),
        ("disk_max", False, "peak disk"),
        ("total_keys", True, "total keys"),
        ("total_keys", 0, "total keys"),
        ("total_keys", 1.5, "total keys"),
        ("total_keys", 1_000_000_000_001, "out of range"),
        ("result_rows", False, "result rows"),
        ("result_rows", 0, "result rows"),
        ("result_rows", 1.5, "result rows"),
        ("result_rows", 1_000_000_000_001, "out of range"),
        ("observed_at", "not-a-time", "observation is invalid"),
        ("observed_at", "2026-09-02 01:28:00Z", "RFC3339"),
        ("observed_at", "2026-09-02T01:00:00Z", "outside"),
        ("schema_name", "another_schema", "another schema"),
        ("digest", "f" * 64, "another SQL digest"),
    ],
)
def test_slow_query_measurements_fail_closed_without_coercion(
    field: str,
    invalid_value: Any,
    expected_error: str,
) -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    invalid_row = dict(result.rows[0])
    invalid_row[field] = invalid_value

    with pytest.raises(EvidenceBuildError, match=expected_error):
        build_managed_evidence(
            query=query,
            result=replace(result, rows=(invalid_row,)),
            context=context,
        )


@pytest.mark.parametrize(
    ("field", "extreme_value", "expected_error"),
    [
        ("query_time", 1e100, "query latency is out of range"),
        ("total_keys", 10**100, "typed Slow Query field is out of range"),
    ],
)
def test_extreme_slow_query_numbers_fail_at_the_evidence_boundary(
    field: str,
    extreme_value: int | float,
    expected_error: str,
) -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    row = dict(result.rows[0])
    row[field] = extreme_value

    with pytest.raises(EvidenceBuildError, match=expected_error):
        build_managed_evidence(
            query=query,
            result=replace(result, rows=(row,)),
            context=context,
        )


def test_slow_query_uses_nearest_rank_p95_and_half_up_integer_averages() -> None:
    query, result, context, _ = slow_query_collection("tidb-8.5")
    rows = []
    for ordinal in range(1, 21):
        row = dict(result.rows[0])
        row["query_time"] = ordinal / 1_000
        row["total_keys"] = 1 if ordinal < 20 else 11
        row["result_rows"] = 1 if ordinal < 20 else 11
        rows.append(row)

    evidence = build_managed_evidence(
        query=query,
        result=replace(result, rows=tuple(rows)),
        context=context,
    ).document

    assert evidence["payload"]["typed"] == {
        "kind": "slow_query",
        "profileSubjectRef": context.profile_subject_ref,
        "profileObjectRef": context.profile_object_ref,
        "windowMinutes": 10,
        "callCount": 20,
        "p95Ms": 19,
        "averageScanRows": 2,
        "averageReturnRows": 2,
    }


@pytest.mark.parametrize(
    ("current_change", "expected_stability", "expected_summary"),
    [
        (
            {"plan_digest": "c" * 64},
            "plan_changed",
            "SQL 计划摘要相对前一基线窗口发生变化。",
        ),
        (
            {"average_total_keys": 1_201},
            "unknown",
            "当前 Statement Summary 证据不足以判断计划和扫描稳定性。",
        ),
    ],
)
def test_statement_summary_classification_is_exact_and_conservative(
    current_change: dict[str, Any],
    expected_stability: str,
    expected_summary: str,
) -> None:
    previous = statement_summary_row(
        begin="2026-09-02T08:00:00Z",
        end="2026-09-02T08:10:00Z",
    )
    current = statement_summary_row(
        begin="2026-09-02T08:10:00Z",
        end="2026-09-02T08:20:00Z",
        **current_change,
    )
    query, result, context = statement_summary_collection((previous, current))

    evidence = build_managed_evidence(
        query=query,
        result=result,
        context=context,
    ).document

    assert evidence["payload"]["typed"]["sqlStability"] == expected_stability
    assert evidence["summaryZh"] == expected_summary


def test_one_valid_statement_summary_window_remains_unknown() -> None:
    row = statement_summary_row(
        begin="2026-09-02T08:10:00Z",
        end="2026-09-02T08:20:00Z",
    )
    query, result, context = statement_summary_collection((row,))

    evidence = build_managed_evidence(
        query=query,
        result=result,
        context=context,
    ).document

    assert evidence["payload"]["typed"]["sqlStability"] == "unknown"


@pytest.mark.parametrize(
    ("field", "invalid_value", "expected_error"),
    [
        ("plan_digest", "not-a-digest", "plan digest"),
        ("exec_count", 0, "execution count"),
        ("avg_total_keys", -1, "average total keys"),
        ("avg_processed_keys", 1.5, "average processed keys"),
        ("instance", "", "instance"),
        ("sum_latency", -1, "sum latency"),
        ("first_seen", "not-a-time", "first seen"),
        ("summary_begin_time", "not-a-time", "window start is invalid"),
        ("summary_end_time", "2026-09-02T07:59:00Z", "outside"),
        ("schema_name", "another_schema", "another schema"),
        ("digest", "f" * 64, "another SQL digest"),
    ],
)
def test_statement_summary_rows_are_validated_even_without_a_comparison_window(
    field: str,
    invalid_value: Any,
    expected_error: str,
) -> None:
    row = statement_summary_row(
        begin="2026-09-02T08:10:00Z",
        end="2026-09-02T08:20:00Z",
    )
    row[field] = invalid_value
    query, result, context = statement_summary_collection((row,))

    with pytest.raises(EvidenceBuildError, match=expected_error):
        build_managed_evidence(query=query, result=result, context=context)


def test_missing_statement_plan_digest_yields_unknown_instead_of_a_claim() -> None:
    previous = statement_summary_row(
        begin="2026-09-02T08:00:00Z",
        end="2026-09-02T08:10:00Z",
    )
    current = statement_summary_row(
        begin="2026-09-02T08:10:00Z",
        end="2026-09-02T08:20:00Z",
    )
    current["plan_digest"] = None
    query, result, context = statement_summary_collection((previous, current))

    evidence = build_managed_evidence(
        query=query,
        result=result,
        context=context,
    ).document

    assert evidence["payload"]["typed"]["sqlStability"] == "unknown"
