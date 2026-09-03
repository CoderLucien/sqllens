from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqllens_api.evidence_connector import MAX_SAFE_INTEGER, QueryResult
from sqllens_api.m0_evidence_projection import (
    STATEMENT_SUMMARY_COLUMNS,
    STATISTICS_HEALTH_COLUMNS,
    EvidenceProjectionError,
    project_statement_summary_v3,
    project_statistics_health_v1,
)

SUBJECT_ID = "subject_0123456789abcdef"
SQL_DIGEST = "a" * 64
PLAN_DIGEST = "b" * 64
PROFILE_OBJECT_REF = f"sql:{SQL_DIGEST}"
WINDOW_START = datetime(2026, 9, 3, 4, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 9, 3, 4, 30, tzinfo=UTC)


def query_result(
    *,
    columns: tuple[str, ...],
    rows: tuple[dict[str, Any], ...],
    truncated: bool = False,
) -> QueryResult:
    return QueryResult(
        columns=columns,
        rows=rows,
        truncated=truncated,
        observed_bytes=4096,
        elapsed_ms=25,
    )


def statistics_result(
    *,
    rows: tuple[dict[str, Any], ...] | None = None,
    columns: tuple[str, ...] = (
        "db_name",
        "table_name",
        "partition_name",
        "healthy",
    ),
    truncated: bool = False,
) -> QueryResult:
    return query_result(
        columns=columns,
        rows=rows
        if rows is not None
        else (
            {
                "db_name": "shop",
                "table_name": "orders",
                "partition_name": "",
                "healthy": 42,
            },
        ),
        truncated=truncated,
    )


def project_statistics(result: QueryResult | None = None) -> dict[str, object]:
    return project_statistics_health_v1(
        statistics_result() if result is None else result,
        database="shop",
        table_name="orders",
        profile_subject_ref=SUBJECT_ID,
        profile_object_ref="orders",
    )


def statement_row(
    *,
    instance: str,
    begin: str,
    end: str,
    exec_count: int = 4,
    average_total_keys: int = 120_000,
    average_processed_keys: int = 119_000,
    plan_digest: str | None = PLAN_DIGEST,
) -> dict[str, Any]:
    return {
        "instance": instance,
        "summary_begin_time": begin,
        "summary_end_time": end,
        "schema_name": "shop",
        "digest": SQL_DIGEST,
        "plan_digest": plan_digest,
        "exec_count": exec_count,
        "sum_latency": 40_000,
        "avg_latency": 10_000,
        "max_latency": 20_000,
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


def stable_statement_rows() -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for begin, end in (
        ("2026-09-03T04:00:00Z", "2026-09-03T04:15:00Z"),
        ("2026-09-03T04:15:00Z", "2026-09-03T04:30:00Z"),
    ):
        rows.extend(
            (
                statement_row(instance="tidb-0:4000", begin=begin, end=end, exec_count=4),
                statement_row(instance="tidb-1:4000", begin=begin, end=end, exec_count=5),
            )
        )
    return tuple(rows)


def statement_result(
    *,
    rows: tuple[dict[str, Any], ...] | None = None,
    columns: tuple[str, ...] | None = None,
    truncated: bool = False,
) -> QueryResult:
    return query_result(
        columns=STATEMENT_SUMMARY_COLUMNS if columns is None else columns,
        rows=stable_statement_rows() if rows is None else rows,
        truncated=truncated,
    )


def project_statement(
    result: QueryResult | None = None,
    *,
    window_start: datetime = WINDOW_START,
    window_end: datetime = WINDOW_END,
) -> dict[str, object]:
    return project_statement_summary_v3(
        statement_result() if result is None else result,
        database="shop",
        sql_digest=SQL_DIGEST,
        window_start=window_start,
        window_end=window_end,
        profile_subject_ref=SUBJECT_ID,
        profile_object_ref=PROFILE_OBJECT_REF,
    )


def test_statistics_health_projects_the_only_exact_total_row() -> None:
    assert STATISTICS_HEALTH_COLUMNS == (
        "db_name",
        "table_name",
        "partition_name",
        "healthy",
    )
    assert project_statistics() == {
        "kind": "statistics",
        "profileSubjectRef": SUBJECT_ID,
        "profileObjectRef": "orders",
        "tableName": "orders",
        "healthyPercent": 42,
    }


@pytest.mark.parametrize(
    "result",
    [
        statistics_result(rows=()),
        statistics_result(rows=statistics_result().rows * 2),
        statistics_result(columns=("db_name", "table_name", "partition_name")),
        statistics_result(
            columns=(*STATISTICS_HEALTH_COLUMNS, "extra"),
            rows=(
                {
                    **statistics_result().rows[0],
                    "extra": "untrusted",
                },
            ),
        ),
        statistics_result(truncated=True),
    ],
    ids=("empty", "multiple", "missing-column", "extra-column", "truncated"),
)
def test_statistics_health_rejects_non_exact_result_shapes(result: QueryResult) -> None:
    with pytest.raises(EvidenceProjectionError):
        project_statistics(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("db_name", "other"),
        ("table_name", "customers"),
        ("partition_name", "p0"),
        ("partition_name", None),
        ("healthy", -1),
        ("healthy", 101),
        ("healthy", True),
        ("healthy", 42.0),
        ("healthy", "42"),
    ],
)
def test_statistics_health_rejects_wrong_identity_partition_or_value(
    field: str,
    value: object,
) -> None:
    row = dict(statistics_result().rows[0])
    row[field] = value

    with pytest.raises(EvidenceProjectionError):
        project_statistics(statistics_result(rows=(row,)))


@pytest.mark.parametrize(
    ("subject", "object_ref"),
    [
        ("subject_short", "orders"),
        (SUBJECT_ID, "other"),
        (SUBJECT_ID, ""),
    ],
)
def test_statistics_health_rejects_unbound_output_identity(
    subject: str,
    object_ref: str,
) -> None:
    with pytest.raises(EvidenceProjectionError):
        project_statistics_health_v1(
            statistics_result(),
            database="shop",
            table_name="orders",
            profile_subject_ref=subject,
            profile_object_ref=object_ref,
        )


def test_statement_summary_projects_checked_aggregates_and_latest_window_stability() -> None:
    assert STATEMENT_SUMMARY_COLUMNS == (
        "instance",
        "summary_begin_time",
        "summary_end_time",
        "schema_name",
        "digest",
        "plan_digest",
        "exec_count",
        "sum_latency",
        "avg_latency",
        "max_latency",
        "sum_errors",
        "avg_mem",
        "max_mem",
        "avg_disk",
        "max_disk",
        "avg_total_keys",
        "avg_processed_keys",
        "first_seen",
        "last_seen",
    )
    assert project_statement() == {
        "kind": "statement_summary",
        "profileSubjectRef": SUBJECT_ID,
        "profileObjectRef": PROFILE_OBJECT_REF,
        "windowMinutes": 30,
        "executionCount": 18,
        "averageTotalKeys": 120_000,
        "averageProcessedKeys": 119_000,
        "weightedTotalKeys": 2_160_000,
        "sqlStability": "plan_and_scan_stable",
    }


@pytest.mark.parametrize(
    "result",
    [
        statement_result(rows=()),
        statement_result(columns=STATEMENT_SUMMARY_COLUMNS[:-1]),
        statement_result(columns=(*STATEMENT_SUMMARY_COLUMNS, "extra")),
        statement_result(truncated=True),
    ],
    ids=("empty", "missing-column", "extra-column", "truncated"),
)
def test_statement_summary_rejects_non_exact_result_shapes(result: QueryResult) -> None:
    with pytest.raises(EvidenceProjectionError):
        project_statement(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_name", "other"),
        ("digest", "c" * 64),
        ("instance", ""),
        ("plan_digest", "not-a-digest"),
        ("exec_count", 0),
        ("exec_count", True),
        ("exec_count", 1.5),
        ("avg_total_keys", -1),
        ("avg_total_keys", True),
        ("avg_total_keys", 1.5),
        ("avg_processed_keys", -1),
        ("sum_latency", -1),
        ("avg_mem", MAX_SAFE_INTEGER + 1),
    ],
)
def test_statement_summary_rejects_wrong_identity_or_measurement(
    field: str,
    value: object,
) -> None:
    row = statement_row(
        instance="tidb-0:4000",
        begin="2026-09-03T04:00:00Z",
        end="2026-09-03T04:15:00Z",
    )
    row[field] = value

    with pytest.raises(EvidenceProjectionError):
        project_statement(statement_result(rows=(row,)))


@pytest.mark.parametrize(
    ("begin", "end", "first_seen", "last_seen"),
    [
        (
            "2026-09-03T03:59:59Z",
            "2026-09-03T04:15:00Z",
            "2026-09-03T03:59:59Z",
            "2026-09-03T04:15:00Z",
        ),
        (
            "2026-09-03T04:15:00Z",
            "2026-09-03T04:30:01Z",
            "2026-09-03T04:15:00Z",
            "2026-09-03T04:30:01Z",
        ),
        (
            "2026-09-03T04:00:00Z",
            "2026-09-03T04:15:00Z",
            "2026-09-03T03:59:59Z",
            "2026-09-03T04:15:00Z",
        ),
        (
            "2026-09-03T04:00:00Z",
            "2026-09-03T04:15:00Z",
            "2026-09-03T04:00:00Z",
            "2026-09-03T04:15:01Z",
        ),
    ],
    ids=("starts-before", "ends-after", "first-seen-before", "last-seen-after"),
)
def test_statement_summary_rejects_partial_or_outside_windows(
    begin: str,
    end: str,
    first_seen: str,
    last_seen: str,
) -> None:
    row = statement_row(instance="tidb-0:4000", begin=begin, end=end)
    row["first_seen"] = first_seen
    row["last_seen"] = last_seen

    with pytest.raises(EvidenceProjectionError):
        project_statement(statement_result(rows=(row,)))


def test_statement_summary_rounds_weighted_half_up_away_from_zero() -> None:
    rows = (
        statement_row(
            instance="tidb-0:4000",
            begin="2026-09-03T04:00:00Z",
            end="2026-09-03T04:15:00Z",
            exec_count=1,
            average_total_keys=1,
            average_processed_keys=2,
        ),
        statement_row(
            instance="tidb-1:4000",
            begin="2026-09-03T04:00:00Z",
            end="2026-09-03T04:15:00Z",
            exec_count=1,
            average_total_keys=2,
            average_processed_keys=3,
        ),
    )

    typed = project_statement(statement_result(rows=rows))

    assert typed["executionCount"] == 2
    assert typed["weightedTotalKeys"] == 3
    assert typed["averageTotalKeys"] == 2
    assert typed["averageProcessedKeys"] == 3
    assert typed["sqlStability"] == "unknown"


def test_statement_summary_uses_avg_total_keys_for_weighted_total() -> None:
    row = statement_row(
        instance="tidb-0:4000",
        begin="2026-09-03T04:00:00Z",
        end="2026-09-03T04:15:00Z",
        exec_count=3,
        average_total_keys=10,
        average_processed_keys=999,
    )

    typed = project_statement(statement_result(rows=(row,)))

    assert typed["weightedTotalKeys"] == 30
    assert typed["averageTotalKeys"] == 10
    assert typed["averageProcessedKeys"] == 999


@pytest.mark.parametrize(
    "rows",
    [
        (
            statement_row(
                instance="tidb-0:4000",
                begin="2026-09-03T04:00:00Z",
                end="2026-09-03T04:15:00Z",
                exec_count=2,
                average_total_keys=MAX_SAFE_INTEGER,
            ),
        ),
        (
            statement_row(
                instance="tidb-0:4000",
                begin="2026-09-03T04:00:00Z",
                end="2026-09-03T04:15:00Z",
                exec_count=MAX_SAFE_INTEGER,
                average_total_keys=1,
            ),
            statement_row(
                instance="tidb-1:4000",
                begin="2026-09-03T04:00:00Z",
                end="2026-09-03T04:15:00Z",
                exec_count=1,
                average_total_keys=0,
            ),
        ),
    ],
    ids=("multiplication", "addition"),
)
def test_statement_summary_rejects_safe_integer_overflow(
    rows: tuple[dict[str, Any], ...],
) -> None:
    with pytest.raises(EvidenceProjectionError):
        project_statement(statement_result(rows=rows))


def test_statement_summary_uses_exact_ratios_not_rounded_averages() -> None:
    previous = (
        statement_row(
            instance="tidb-0:4000",
            begin="2026-09-03T04:00:00Z",
            end="2026-09-03T04:15:00Z",
            exec_count=1,
            average_total_keys=1,
            average_processed_keys=1,
        ),
        statement_row(
            instance="tidb-1:4000",
            begin="2026-09-03T04:00:00Z",
            end="2026-09-03T04:15:00Z",
            exec_count=1,
            average_total_keys=2,
            average_processed_keys=2,
        ),
    )
    current = (
        statement_row(
            instance="tidb-0:4000",
            begin="2026-09-03T04:15:00Z",
            end="2026-09-03T04:30:00Z",
            exec_count=1,
            average_total_keys=2,
            average_processed_keys=2,
        ),
    )

    typed = project_statement(statement_result(rows=(*previous, *current)))

    assert typed["averageTotalKeys"] == 2
    assert typed["averageProcessedKeys"] == 2
    assert typed["sqlStability"] == "unknown"


def test_statement_summary_marks_a_different_single_plan_as_changed() -> None:
    rows = stable_statement_rows()
    changed = tuple(dict(row) for row in rows)
    for row in changed[2:]:
        row["plan_digest"] = "c" * 64

    typed = project_statement(statement_result(rows=changed))

    assert typed["sqlStability"] == "plan_changed"


@pytest.mark.parametrize("second_plan", [None, "c" * 64])
def test_statement_summary_mixed_or_null_plan_is_unknown(second_plan: str | None) -> None:
    rows = tuple(dict(row) for row in stable_statement_rows())
    rows[3]["plan_digest"] = second_plan

    typed = project_statement(statement_result(rows=rows))

    assert typed["sqlStability"] == "unknown"


def test_two_instances_in_one_window_do_not_count_as_two_windows() -> None:
    typed = project_statement(statement_result(rows=stable_statement_rows()[:2]))

    assert typed["sqlStability"] == "unknown"


@pytest.mark.parametrize(
    ("window_start", "window_end"),
    [
        (WINDOW_START.replace(tzinfo=None), WINDOW_END),
        (WINDOW_START, WINDOW_START),
        (WINDOW_START, WINDOW_START + timedelta(seconds=90)),
        (WINDOW_START, WINDOW_START + timedelta(days=1, minutes=1)),
    ],
    ids=("naive", "empty", "not-whole-minutes", "too-long"),
)
def test_statement_summary_rejects_invalid_requested_windows(
    window_start: datetime,
    window_end: datetime,
) -> None:
    with pytest.raises(EvidenceProjectionError):
        project_statement(window_start=window_start, window_end=window_end)


@pytest.mark.parametrize(
    ("digest", "subject", "object_ref"),
    [
        ("A" * 64, SUBJECT_ID, f"sql:{'A' * 64}"),
        (SQL_DIGEST, "subject_short", PROFILE_OBJECT_REF),
        (SQL_DIGEST, SUBJECT_ID, "orders"),
        (SQL_DIGEST, SUBJECT_ID, f"sql:{'c' * 64}"),
    ],
)
def test_statement_summary_rejects_unbound_output_identity(
    digest: str,
    subject: str,
    object_ref: str,
) -> None:
    with pytest.raises(EvidenceProjectionError):
        project_statement_summary_v3(
            statement_result(),
            database="shop",
            sql_digest=digest,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            profile_subject_ref=subject,
            profile_object_ref=object_ref,
        )
