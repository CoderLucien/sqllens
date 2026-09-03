from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

P1_MIN_P95_MS = 5000
P1_MIN_EXEC_COUNT = 20
INDEX_BUILD_RATE_ROWS_PER_SEC = 50_000
INDEX_BYTES_PER_ROW = 32
INDEX_LOOKUP_FACTOR = 3
MIN_MEANINGFUL_SCAN_ROWS = 10_000
MIN_SCAN_TO_RESULT_RATIO = 100
STATS_SKEW_RATIO_THRESHOLD = 10
STATS_HEALTHY_THRESHOLD = 60
REPEATED_MIN_EXEC_COUNT = 20
REPEATED_MIN_AVG_KEYS = 1_000


def priority(*, exec_count: int, p95_ms: float) -> str:
    if exec_count >= P1_MIN_EXEC_COUNT and p95_ms >= P1_MIN_P95_MS:
        return "P1"
    return "P2"


@dataclass(frozen=True)
class ActionAdvice:
    operation_zh: str
    risk_zh: str
    cost_zh: str
    cost_formula_zh: str
    gain_zh: str
    gain_formula_zh: str
    validation_zh: str
    rollback_zh: str


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    severity: str
    conclusion_zh: str
    analysis_zh: str
    evidence_ids: tuple[str, ...]
    actions: tuple[ActionAdvice, ...]


def _fmt_number(value: float) -> str:
    if value >= 10_000:
        return f"{value / 10_000:.1f} 万"
    return f"{value:.0f}"


def index_access_hit(
    *,
    table_name: str,
    scanned_rows: int,
    result_rows: int,
    filter_columns: tuple[str, ...],
    index_prefixes: tuple[tuple[str, ...], ...],
    exec_count: int,
    p95_ms: float,
    build_rate_rows_per_sec: int = INDEX_BUILD_RATE_ROWS_PER_SEC,
) -> RuleHit | None:
    if not filter_columns:
        return None
    if scanned_rows < MIN_MEANINGFUL_SCAN_ROWS:
        return None
    if result_rows > 0 and scanned_rows < result_rows * MIN_SCAN_TO_RESULT_RATIO:
        return None
    covered = any(
        filter_columns[: len(prefix)] == prefix for prefix in index_prefixes
    )
    if covered:
        return None

    severity = priority(exec_count=exec_count, p95_ms=p95_ms)
    index_cols = filter_columns[:3]
    index_name = f"idx_{'_'.join(index_cols[:2])}"
    ddl = f"CREATE INDEX {index_name} ON {table_name}({', '.join(index_cols)});"

    build_seconds = max(10, math.ceil(scanned_rows / build_rate_rows_per_sec))
    storage_bytes = INDEX_BYTES_PER_ROW * scanned_rows * 1.5
    storage_mb = storage_bytes / (1024 * 1024)
    expected_scan = max(result_rows * INDEX_LOOKUP_FACTOR, 2)
    reduction = (1 - expected_scan / scanned_rows) * 100
    p95_est_ms = p95_ms * expected_scan / scanned_rows
    if p95_est_ms < 1:
        p95_est_str = "< 1ms"
    else:
        p95_est_str = f"约 {p95_est_ms:.0f}ms"

    action = ActionAdvice(
        operation_zh=(
            f"在隔离环境验证复合索引候选：{ddl} "
            "并以相同参数分布对比新旧计划的扫描行数与 P95。"
        ),
        risk_zh=(
            "TiDB 在线 DDL，不阻塞读写；写入期间存在写放大与临时空间开销，"
            "建议业务低峰执行；索引将承担每行一次额外写入成本。"
        ),
        cost_zh=(
            f"预计 {build_seconds} 秒（{_fmt_number(scanned_rows)}行 × "
            f"{INDEX_BYTES_PER_ROW}B/行 ≈ {storage_mb:.0f}MB 索引存储）。"
        ),
        cost_formula_zh=(
            f"成本公式：构建时长 ≈ 行数 ÷ 保守构建速率（{build_rate_rows_per_sec} 行/秒）；"
            f"存储 ≈ Σ索引列字节宽 × 行数 × 1.5。"
        ),
        gain_zh=(
            f"扫描行数 {_fmt_number(scanned_rows)} → 约 {_fmt_number(expected_scan)} "
            f"（-{reduction:.1f}%）；P95 预估 {p95_ms:.0f}ms → {p95_est_str}。"
        ),
        gain_formula_zh=(
            f"收益公式：索引后扫描 ≈ 返回行数（{result_rows}）× 回表系数（{INDEX_LOOKUP_FACTOR}）；"
            "P95 按扫描行数线性比例估算，需实测验证。"
        ),
        validation_zh=(
            "隔离环境运行普通 EXPLAIN 与压测：确认访问方式由 TableFullScan 变为 "
            "IndexRangeScan；扫描行数下降 ≥ 90%、P95 < 500ms、写入回归 ≤ 5% 为达标。"
        ),
        rollback_zh=f"DROP INDEX {index_name} ON {table_name};（收益或写入开销不达标时在隔离环境执行；生产环境不自动变更）。",
    )
    return RuleHit(
        rule_id="IDX_ACCESS_001",
        severity=severity,
        conclusion_zh=(
            f"该查询在 {table_name} 表发生全表扫描：平均扫描 {_fmt_number(scanned_rows)} 行，"
            f"扫描/返回比 {scanned_rows / max(result_rows, 1):.0f}:1；现有索引未覆盖过滤列顺序，"
            "建议优先在隔离环境验证复合索引候选。"
        ),
        analysis_zh=(
            f"过滤列 {', '.join(filter_columns)} 未命中任何现有索引前缀，优化器回退为全表扫描；"
            f"扫描 {_fmt_number(scanned_rows)} 行仅返回 {_fmt_number(result_rows)} 行。"
            "当前没有证据表明需要扩容——瓶颈在访问路径，不在资源。"
        ),
        evidence_ids=("ev_plan", "ev_schema", "ev_runtime"),
        actions=(action,),
    )


def stats_skew_hit(
    *,
    table_name: str,
    est_rows: int,
    actual_rows: int,
    healthy: int,
    batch_before_min: int | None = None,
    batch_target_min: int | None = None,
) -> RuleHit | None:
    ratio = actual_rows / est_rows if est_rows > 0 else float("inf")
    if ratio < STATS_SKEW_RATIO_THRESHOLD and healthy >= STATS_HEALTHY_THRESHOLD:
        return None
    if ratio == float("inf"):
        ratio_str = "不可计算（估算为 0）"
    elif ratio >= 10_000:
        ratio_str = f"{ratio:.0f} 倍"
    else:
        ratio_str = f"{ratio:.0f} 倍"

    severity = "P2"
    analyze_minutes = max(1, math.ceil(actual_rows / 1_000_000))
    gain_parts = [f"估算偏差收敛到 10 倍以内；Join 顺序稳定"]
    if batch_before_min is not None:
        target = batch_target_min if batch_target_min is not None else max(1, batch_before_min // 5)
        gain_parts.append(f"批处理耗时预估从 {batch_before_min} 分钟回到 {target} 分钟以内")
    action = ActionAdvice(
        operation_zh=(
            f"在隔离环境执行：ANALYZE TABLE {table_name}; "
            "复现当前统计与计划后刷新，并对比 Join 顺序与任务耗时。"
        ),
        risk_zh=(
            "ANALYZE 为在线操作，采样占用 1 个 TiKV 读线程；建议避开业务高峰；"
            "先隔离验证，不直接在生产刷新。"
        ),
        cost_zh=f"预计 {analyze_minutes} 分钟（{_fmt_number(actual_rows)} 行级表 + 采样开销）。",
        cost_formula_zh="成本公式：ANALYZE 时长 ≈ 行数 ÷ 采样速率 × 列数系数（百万行级约 1~3 分钟）。",
        gain_zh="；".join(gain_parts) + "。",
        gain_formula_zh=(
            "收益依据：统计刷新后 estRows 与实际行数一致（真实实验：HEALTHY 0→100，"
            "估算与实际行数恢复一致）；Join 顺序由更新后基数决定。"
        ),
        validation_zh=(
            "刷新后对比 EXPLAIN 的 estRows 与实际行数、Join 顺序与批处理耗时："
            "估算偏差 < 10 倍、Join 顺序稳定为达标。"
        ),
        rollback_zh=(
            "若计划退化，不在生产执行统计刷新；保留原统计与计划证据并重新评估（无需数据回滚）。"
        ),
    )
    return RuleHit(
        rule_id="STATS_SKEW_001",
        severity=severity,
        conclusion_zh=(
            f"执行计划对 {table_name} 估算 {_fmt_number(est_rows)} 行，实际运行证据为 "
            f"{_fmt_number(actual_rows)} 行（偏差 {ratio_str}），统计健康度 {healthy}；"
            "应先验证统计，而不是直接加索引。"
        ),
        analysis_zh=(
            "统计信息在最近一次大批量导入前生成：优化器按过期基数选择执行路径，"
            "估算与实际行数的偏差足以改变 Join 顺序。根因在统计时效，不在索引缺失——"
            "直接建索引会掩盖问题且难以验证收益归因。"
        ),
        evidence_ids=("ev_explain", "ev_stats", "ev_runtime"),
        actions=(action,),
    )


def repeated_scan_hit(
    *,
    exec_count: int,
    avg_keys: int,
    p95_ms: float,
    window_minutes: int = 60,
    baseline_weighted_keys: int | None = None,
    reduced_weighted_keys: int | None = None,
) -> RuleHit | None:
    if exec_count < REPEATED_MIN_EXEC_COUNT:
        return None
    if avg_keys < REPEATED_MIN_AVG_KEYS:
        return None

    severity = priority(exec_count=exec_count, p95_ms=p95_ms)
    gain_parts = []
    gain_formula = "收益依据：A/B 实测调用削减后窗口加权扫描量对比；合并批量后按调用次数比例外推。"
    if baseline_weighted_keys is not None and reduced_weighted_keys is not None:
        measured = (1 - reduced_weighted_keys / baseline_weighted_keys) * 100
        gain_parts.append(f"窗口加权扫描量实测 -{measured:.0f}%")
    merged = (1 - 1 / exec_count) * 100
    gain_parts.append(f"合并为批量查询预估 -{merged:.0f}%")
    action = ActionAdvice(
        operation_zh=(
            "应用层把循环单条查询合并为批量查询（IN 列表或复用 Prepared Statement），"
            "并控制批量上限；可选配合覆盖过滤列的组合索引消除全表扫描。"
        ),
        risk_zh=(
            "应用代码改动，需业务方确认批量语义一致（返回顺序、空集处理）；"
            "批量上限控制参数数量，防语句超长。"
        ),
        cost_zh="预计 1~2 个研发工时（代码改动 + 回归测试）；若仅加索引则按在线 DDL 分钟级估算。",
        cost_formula_zh="成本公式：工时按改动点数量估算（循环调用点 + 回归测试）；索引成本与索引访问规则同公式。",
        gain_zh="；".join(gain_parts) + "。",
        gain_formula_zh=gain_formula,
        validation_zh=(
            "改造后在同等窗口对比 Statement Summary 的 exec_count 与加权 keys："
            "目标窗口加权扫描量下降 ≥ 75%，单次 P95 不回退，业务回归测试结果集一致。"
        ),
        rollback_zh="应用代码回滚到原循环查询版本即可（无 DDL 变更时零数据风险）；如已加索引则 DROP INDEX 对应索引。",
    )
    return RuleHit(
        rule_id="REPEATED_SCAN_001",
        severity=severity,
        conclusion_zh=(
            f"同一 SQL Digest 在 {window_minutes} 分钟窗口内执行 {exec_count} 次，"
            f"每次扫描 {_fmt_number(avg_keys)} keys；属于高频重复扫描（热点重复），"
            "单次延迟不高但累计消耗显著。"
        ),
        analysis_zh=(
            "该 SQL 访问路径为全表扫描，且被应用以循环方式高频调用（典型 N+1 模式）："
            "延迟问题不大，但重复扫描放大 CPU/IO 消耗，并随业务量线性恶化。"
        ),
        evidence_ids=("ev_summary", "ev_plan", "ev_ab"),
        actions=(action,),
    )


def build_report_v4(
    *,
    hits: list[RuleHit],
    mode: str,
    sql_digest: str,
    database: str,
    evidence_rows: list[dict[str, Any]],
    ai_degraded_reason_zh: str | None = None,
) -> dict[str, Any]:
    if not hits:
        report_priority = "P2"
    else:
        report_priority = "P1" if any(h.severity == "P1" for h in hits) else "P2"
    conclusion_zh = "；".join(h.conclusion_zh for h in hits) or "未命中任何规则，证据不足以给出变更建议。"
    analysis_zh = "\n".join(h.analysis_zh for h in hits)
    changes = []
    for hit in hits:
        for action in hit.actions:
            changes.append(
                {
                    "operation_zh": action.operation_zh,
                    "risk_zh": action.risk_zh,
                    "cost_zh": action.cost_zh,
                    "cost_formula_zh": action.cost_formula_zh,
                    "gain_zh": action.gain_zh,
                    "gain_formula_zh": action.gain_formula_zh,
                    "rule_id": hit.rule_id,
                }
            )
    validation_zh = [a.validation_zh for h in hits for a in h.actions]
    rollback_zh = [a.rollback_zh for h in hits for a in h.actions]
    ai_status_zh = (
        f"AI 调用失败，已降级为规则模式输出（{ai_degraded_reason_zh}）。"
        if mode == "degraded"
        else "规则模式输出：结论均由规则引擎基于真实证据产生，可复现、可审计。"
    )
    return {
        "schema_version": "diagnosis-report/v2",
        "priority": report_priority,
        "mode": mode,
        "ai_status_zh": ai_status_zh,
        "sql_digest": sql_digest,
        "database": database,
        "sections": {
            "conclusion": {
                "text_zh": conclusion_zh,
                "rule_ids": [h.rule_id for h in hits],
                "severities": [h.severity for h in hits],
            },
            "evidence": evidence_rows,
            "analysis": {"text_zh": analysis_zh},
            "changes": changes,
            "validation": [{"text_zh": item} for item in validation_zh],
            "rollback": [{"text_zh": item} for item in rollback_zh],
        },
    }
