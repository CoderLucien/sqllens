"""Plan Replayer zip 解析器单元测试。"""

from __future__ import annotations

import io
import zipfile

import pytest

from sqllens_api.plan_replayer import (
    PlanReplayerError,
    bundle_to_evidence_v3,
    parse_plan_replayer_zip,
    plan_replayer_summary,
)


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def _minimal_zip() -> bytes:
    return _make_zip(
        {
            "meta.txt": "TiDB Version: v8.5.8\ncapture_time: 2026-09-03T22:00:00Z\n",
            "schema.txt": "CREATE TABLE orders (id int primary key, order_date date);\n",
            "stats.txt": '{"orders": {"row_count": 1260000}}',
            "errors.txt": "",
            "sql/1.sql": "SELECT * FROM orders WHERE order_date > '2026-01-01';",
            "explain.txt": "TableFullScan orders estRows 1263814",
        }
    )


def test_parse_minimal_zip() -> None:
    bundle = parse_plan_replayer_zip(_minimal_zip())
    assert bundle.sql_count == 1
    assert bundle.tidb_version == "8.5.8"
    assert bundle.captured_at == "2026-09-03T22:00:00Z"
    assert bundle.digest_sha256.startswith("sha256:")
    assert bundle.schema_text is not None
    assert bundle.stats_text is not None
    assert bundle.explain_text is not None


def test_summary_does_not_leak_sql_text() -> None:
    summary = plan_replayer_summary(parse_plan_replayer_zip(_minimal_zip()))
    assert "SELECT" not in summary["summaryZh"]
    assert "sqlTexts" not in summary
    assert summary["sqlCount"] == 1


def test_reject_path_traversal() -> None:
    with pytest.raises(PlanReplayerError):
        parse_plan_replayer_zip(_make_zip({"../evil.txt": "x"}))


def test_reject_not_a_zip() -> None:
    with pytest.raises(PlanReplayerError):
        parse_plan_replayer_zip(b"not a zip")


def test_reject_empty_payload() -> None:
    with pytest.raises(PlanReplayerError):
        parse_plan_replayer_zip(b"")


def test_reject_missing_recognizable_content() -> None:
    with pytest.raises(PlanReplayerError):
        parse_plan_replayer_zip(_make_zip({"unknown.bin": "x"}))


def test_evidence_v3_mapping() -> None:
    bundle = parse_plan_replayer_zip(
        _make_zip(
            {
                "meta.txt": "TiDB Version: v8.5.8\ndatabase: order_center\n",
                "schema.txt": (
                    "CREATE TABLE orders (id int primary key, order_date date, "
                    "tenant_id int, status varchar(16));\n"
                    "CREATE INDEX idx_tenant_created ON orders(tenant_id, created_at);"
                ),
                "stats.txt": '{"orders": {"row_count": 1260000, "healthy": 92}}',
                "sql/1.sql": "SELECT * FROM orders WHERE tenant_id = ? "
                "AND status = 'open' ORDER BY order_date;",
                "explain.txt": "TableFullScan orders estRows:1263814",
            }
        )
    )
    ev = bundle_to_evidence_v3(bundle)
    assert ev["schema_version"] == "evidence/v3"
    assert ev["sql"]["database"] == "order_center"
    assert ev["sql"]["table_name"] == "orders"
    assert len(ev["sql"]["sql_digest"]) == 64
    assert ev["plan"]["operator_rows"][0]["operator"] == "TableFullScan"
    assert ev["stats"]["row_count"] == 1260000
    assert ev["stats"]["healthy"] == 92
    indexes = {i["name"]: i["columns"] for i in ev["schema"]["indexes"]}
    assert indexes["idx_tenant_created"] == ["tenant_id", "created_at"]
    assert "tenant_id" in ev["schema"]["filter_columns"]
