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


def test_accepts_large_production_stats_entry() -> None:
    """回归（2026-09-07）：真实生产表 stats JSON 单文件可达数 MiB（用户包 6.1 MiB
    曾被 2 MiB 单文件上限误拒、整包 422）。合法大条目必须放行。"""
    big_stats = '{"columns": {"pad": "%s"}}' % ("0" * (3 * 1024 * 1024))
    bundle = parse_plan_replayer_zip(
        _make_zip(
            {
                "meta.txt": "TiDB Version: v8.5.8\n",
                "sql/sql0.sql": "SELECT 1;",
                "stats/testdb.t.json": big_stats,
            }
        )
    )
    assert bundle.stats_text is not None


def test_reject_entry_above_hard_cap() -> None:
    """防线仍在：单文件超过 16 MiB 硬上限仍拒收（zip bomb 防护边界）。"""
    huge = "0" * (16 * 1024 * 1024 + 1)
    with pytest.raises(PlanReplayerError):
        parse_plan_replayer_zip(
            _make_zip(
                {
                    "meta.txt": "TiDB Version: v8.5.8\n",
                    "sql/sql0.sql": "SELECT 1;",
                    "stats/testdb.t.json": huge,
                }
            )
        )


def test_reject_not_a_zip() -> None:
    with pytest.raises(PlanReplayerError):
        parse_plan_replayer_zip(b"not a zip")


def test_reject_empty_payload() -> None:
    with pytest.raises(PlanReplayerError):
        parse_plan_replayer_zip(b"")


def test_reject_missing_recognizable_content() -> None:
    with pytest.raises(PlanReplayerError):
        parse_plan_replayer_zip(_make_zip({"unknown.bin": "x"}))


def test_database_from_schema_filename_fallback() -> None:
    """回归（2026-09-07）：真实生产包 meta.txt 无库名行、stats 无 database_name、
    schema 无 use 语句时，库名应从 schema/<db>.<table>.schema.txt 文件名前缀兜底。"""
    bundle = parse_plan_replayer_zip(
        _make_zip(
            {
                "meta.txt": "TiDB Version: v8.5.8\ncapture_time: 2026-09-07T11:00:00Z\n",
                "schema/lego_leju_oltp.leju_record.schema.txt": (
                    "CREATE TABLE leju_record (id bigint PRIMARY KEY, "
                    "created_at datetime, status varchar(16));"
                ),
                "stats/lego_leju_oltp.leju_record.json": '{"leju_record": {"row_count": 4720000000}}',
                "sql/sql0.sql": "SELECT * FROM leju_record WHERE status = 'open';",
                "explain.txt": "TableFullScan leju_record estRows:4720000000",
            }
        )
    )
    ev = bundle_to_evidence_v3(bundle)
    assert ev["sql"]["database"] == "lego_leju_oltp"
    assert ev["sql"]["table_name"] == "leju_record"


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


def test_sql_txt_filename_recognized() -> None:
    """真实 PLAN REPLAYER DUMP 使用 sql.txt（而非 *.sql），必须被识别。"""
    data = _make_zip(
        {
            "meta.txt": "TiDB Version: v8.5.8\n",
            "schema.txt": "CREATE TABLE lineitem (l_orderkey bigint, PRIMARY KEY (l_orderkey, l_linenumber));\n",
            "stats.txt": '{"lineitem": {"row_count": 6001215, "healthy": 100}}',
            "sql.txt": "SELECT l_orderkey FROM lineitem WHERE l_shipdate >= '1998-01-01';",
            "explain.txt": "TableFullScan lineitem estRows 6001215",
        }
    )
    bundle = parse_plan_replayer_zip(data)
    evidence = bundle_to_evidence_v3(bundle)
    assert evidence["sql"]["sql_text"].startswith("SELECT l_orderkey")
    assert evidence["sql"]["table_name"] == "lineitem"
    assert evidence["schema"]["filter_columns"] == ["l_shipdate"]
    assert "PRIMARY" in [item["name"] for item in evidence["schema"]["indexes"]]
    assert evidence["plan"]["operator_rows"]


def test_real_tidb_dump_structure() -> None:
    """按 mac测试专员 2026-09-04 真实 zip 结构复现：子目录路径 + TAB 分隔 explain + 大写列名。"""
    data = _make_zip(
        {
            "meta.txt": "Release Version: v8.5.8\nEdition: Community\n",
            "schema/tpch.lineitem.schema.txt": (
                "create database if not exists `tpch`; use `tpch`;CREATE TABLE `lineitem` (\n"
                "  `L_ORDERKEY` bigint NOT NULL,\n  `L_SHIPDATE` date NOT NULL,\n"
                "  PRIMARY KEY (`L_ORDERKEY`,`L_LINENUMBER`) /*T![clustered_index] CLUSTERED */\n"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            ),
            "stats/tpch.lineitem.json": (
                '{"database_name": "tpch", "table_name": "lineitem", "count": 6001215, "modify_count": 0}'
            ),
            "sql/sql0.sql": (
                "use tpch; SELECT l_orderkey, l_extendedprice, l_discount "
                "FROM lineitem WHERE L_SHIPDATE < '1996-01-01';"
            ),
            "explain.txt": (
                "TableReader_11\t3482024.00\t3489491\troot\t\ttime:901.7ms, loops:3398\tdata:Projection_5\tN/A\n"
                "    └─TableFullScan_9\t6001215.00\t6001215\tcop[tikv]\ttable:lineitem\t"
                "tikv_task:{proc max:80ms}\tkeep order:false\tN/A\n"
            ),
        }
    )
    bundle = parse_plan_replayer_zip(data)
    evidence = bundle_to_evidence_v3(bundle)
    assert evidence["sql"]["table_name"] == "lineitem"
    assert evidence["sql"]["sql_text"]
    assert evidence["schema"]["filter_columns"] == ["l_shipdate"]
    assert evidence["schema"]["indexes"] == [
        {"name": "PRIMARY", "columns": ["l_orderkey", "l_linenumber"]}
    ]
    assert evidence["stats"]["row_count"] == 6001215
    assert evidence["plan"]["operator_rows"][0]["operator"].startswith("TableReader")
    assert evidence["plan"]["operator_rows"][0]["est_rows"] == 3482024
    assert any(
        row.get("table") == "lineitem" and "FullScan" in row["operator"]
        for row in evidence["plan"]["operator_rows"]
    )
    assert evidence["runtime"]["scanned_rows"] == 6001215
    assert evidence["runtime"]["result_rows"] == 3489491


def test_full_original_export_shape_with_bindings_and_schema_meta() -> None:
    """TiDB 原始 DUMP 全量形态：空 bindings 不抢占 SQL、schema_meta 不覆盖 DDL。"""
    data = _make_zip(
        {
            "sql_meta.toml": "[sql]\n",
            "config.toml": "[config]\n",
            "variables.toml": "[vars]\n",
            "meta.txt": "TiDB Version: v8.5.8\ncapture_time: 2026-09-04T15:12:00+08:00\n",
            "schema/tpch.lineitem.schema.txt": (
                "create database if not exists `tpch`; use `tpch`;"
                "CREATE TABLE `lineitem` (\n"
                "  `L_ORDERKEY` bigint NOT NULL,\n"
                "  `L_LINENUMBER` bigint NOT NULL,\n"
                "  `L_SHIPDATE` date NOT NULL,\n"
                "  PRIMARY KEY (`L_ORDERKEY`,`L_LINENUMBER`)\n"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
            ),
            "schema/schema_meta.txt": "tpch.lineitem;",
            "table_tiflash_replica.txt": "",
            "stats/tpch.lineitem.json": (
                '{"columns": [], "indices": [], "database_name": "tpch", '
                '"table_name": "lineitem", "count": 6001215, "modify_count": 0}'
            ),
            "statsMem/tpch.lineitem.txt": "6001215",
            "sql/sql0.sql": (
                "SELECT l_orderkey, l_extendedprice, l_discount "
                "FROM lineitem WHERE YEAR(l_shipdate) <= 1995"
            ),
            "session_bindings.sql": "",
            "global_bindings.sql": "",
            "explain.txt": (
                "TableReader_11\t4800972.00\t3489491\troot\t\ttime:2.13s, loops:3398\t"
                "data:Projection_5\t13.9 MB\tN/A\n"
                "└─TableFullScan_9\t6001215.00\t6001215\tcop[tikv]\ttable:lineitem\t"
                "tikv_task:{proc max:257ms}\tkeep order:false\tN/A\n"
            ),
        }
    )
    bundle = parse_plan_replayer_zip(data)
    evidence = bundle_to_evidence_v3(bundle)
    assert bundle.sql_texts == [
        "SELECT l_orderkey, l_extendedprice, l_discount "
        "FROM lineitem WHERE YEAR(l_shipdate) <= 1995"
    ]
    assert evidence["sql"]["sql_text"].startswith("SELECT l_orderkey")
    assert evidence["sql"]["table_name"] == "lineitem"
    assert evidence["schema"]["filter_columns"] == ["l_shipdate"]
    assert evidence["schema"]["indexes"] == [
        {"name": "PRIMARY", "columns": ["l_orderkey", "l_linenumber"]}
    ]
    assert evidence["stats"]["row_count"] == 6001215
    assert evidence["runtime"]["scanned_rows"] == 6001215
