from __future__ import annotations

from typing import Any

from sqlglot import exp, parse_one
from sqlglot.errors import ErrorLevel

from sqllens_api.v4_rules import (
    RuleHit,
    build_report_v4,
    index_access_hit,
    repeated_scan_hit,
    stats_skew_hit,
)


def _base_table_count(sql_text: str) -> int:
    """FROM/JOIN 涉及的基础表数量；解析失败返回 1（保守单表）。"""
    try:
        tree = parse_one(sql_text, read="mysql", error_level=ErrorLevel.IGNORE)
    except Exception:
        return 1
    if tree is None:
        return 1
    return max(1, len(list(tree.find_all(exp.Table))))

_DEFAULT_WINDOW_MINUTES = 60


def _full_scan_rows(plan: dict[str, Any]) -> int:
    rows = 0
    for op in plan.get("operator_rows", []):
        name = str(op.get("operator", ""))
        if "FullScan" in name:
            rows = max(rows, int(op.get("est_rows") or 0))
    return rows


def _evidence_rows(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    sql = evidence.get("sql") or {}
    runtime = evidence.get("runtime") or {}
    plan = evidence.get("plan") or {}
    stats = evidence.get("stats") or {}
    schema = evidence.get("schema") or {}

    exec_count = runtime.get("exec_count")
    p95_ms = runtime.get("p95_ms")
    if exec_count is not None or p95_ms is not None:
        parts = []
        if exec_count is not None:
            parts.append(f"{exec_count} 次调用")
        if p95_ms is not None:
            parts.append(f"P95 {float(p95_ms):.0f}ms")
        if runtime.get("avg_total_keys") is not None:
            parts.append(f"平均扫描 {int(runtime['avg_total_keys']):,} keys")
        rows.append({"label_zh": "运行表现", "value_zh": "；".join(parts), "evidence_ids": ["ev_runtime"]})

    if plan.get("operator_rows"):
        ops = "；".join(
            f"{op.get('operator')}({op.get('table')}) est={op.get('est_rows')}"
            for op in plan["operator_rows"][:4]
        )
        rows.append({"label_zh": "执行计划", "value_zh": ops, "evidence_ids": ["ev_plan"]})

    if stats:
        parts = []
        if stats.get("est_rows") is not None:
            parts.append(f"估算 {int(stats['est_rows']):,} 行")
        if stats.get("actual_rows") is not None:
            parts.append(f"实际 {int(stats['actual_rows']):,} 行")
        if stats.get("healthy") is not None:
            parts.append(f"健康度 {int(stats['healthy'])}")
        if parts:
            rows.append({"label_zh": "统计信息", "value_zh": "；".join(parts), "evidence_ids": ["ev_stats"]})

    indexes = schema.get("indexes") or []
    filter_columns = schema.get("filter_columns") or []
    if indexes or filter_columns:
        value = f"索引 {len(indexes)} 个" if indexes else "无索引"
        if filter_columns:
            value += f"；过滤列 {', '.join(map(str, filter_columns))}"
        rows.append({"label_zh": "Schema", "value_zh": value, "evidence_ids": ["ev_schema"]})

    return rows


def diagnose_v4(evidence: dict[str, Any], *, mode: str = "rules") -> dict[str, Any]:
    """证据（evidence/v3）→ 三类规则 → 六段中文报告（diagnosis-report/v2）。"""
    sql = evidence.get("sql") or {}
    runtime = evidence.get("runtime") or {}
    plan = evidence.get("plan") or {}
    stats = evidence.get("stats") or {}
    schema = evidence.get("schema") or {}
    optional = evidence.get("optional") or {}

    sql_text = str(sql.get("sql_text") or "")
    table_name = str(sql.get("table_name") or "")
    exec_count = int(runtime.get("exec_count") or 0)
    p95_ms = float(runtime.get("p95_ms") or 0)
    hits: list[RuleHit] = []

    scanned_rows = int(runtime.get("scanned_rows") or 0) or _full_scan_rows(plan)
    result_rows = int(runtime.get("result_rows") or 0)
    filter_columns = tuple(str(item) for item in (schema.get("filter_columns") or ()))
    index_prefixes = tuple(
        tuple(str(col) for col in (item.get("columns") or []))
        for item in (schema.get("indexes") or [])
    )
    # 索引规则的目标表取执行计划中 FullScan 算子的表名（JOIN 场景下避免用错表生成 DDL）。
    plan_table = ""
    for op in plan.get("operator_rows", []):
        if "FullScan" in str(op.get("operator", "")):
            plan_table = str(op.get("table") or "")
            break
    index_table = plan_table or table_name
    # 多表 JOIN：过滤列无法可靠归属到单表，跳过索引规则（只展示证据，不给可能错误的 DDL）。
    join_detected = sql_text and _base_table_count(sql_text) > 1
    if index_table and scanned_rows and not join_detected:
        hit = index_access_hit(
            table_name=index_table,
            scanned_rows=scanned_rows,
            result_rows=result_rows,
            filter_columns=filter_columns,
            index_prefixes=index_prefixes,
            exec_count=exec_count,
            p95_ms=p95_ms,
            sql_text=sql_text or None,
        )
        if hit is not None:
            hits.append(hit)

    est_rows = stats.get("est_rows")
    actual_rows = int(stats.get("actual_rows") or 0) or int(stats.get("row_count") or 0)
    healthy = int(stats.get("healthy") if stats.get("healthy") is not None else 100)
    if est_rows is not None and actual_rows > 0 and (int(est_rows) > 0 or actual_rows > int(est_rows)):
        est_rows = int(est_rows)
        hit = stats_skew_hit(
            table_name=table_name or "目标表",
            est_rows=est_rows,
            actual_rows=actual_rows,
            healthy=healthy,
            batch_before_min=optional.get("batch_before_min"),
            batch_target_min=optional.get("batch_target_min"),
        )
        if hit is not None:
            hits.append(hit)

    hit = repeated_scan_hit(
        exec_count=exec_count,
        avg_keys=int(runtime.get("avg_total_keys") or 0),
        p95_ms=p95_ms,
        window_minutes=int(runtime.get("window_minutes") or _DEFAULT_WINDOW_MINUTES),
        baseline_weighted_keys=optional.get("baseline_weighted_keys"),
        reduced_weighted_keys=optional.get("reduced_weighted_keys"),
    )
    if hit is not None:
        hits.append(hit)

    sql_digest = str(sql.get("sql_digest") or "0" * 64)
    return build_report_v4(
        hits=hits,
        mode=mode,
        sql_digest=sql_digest,
        database=str(sql.get("database") or ""),
        evidence_rows=_evidence_rows(evidence),
    )
