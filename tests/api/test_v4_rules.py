from __future__ import annotations

import pytest

from sqllens_api.v4_rules import (
    INDEX_BYTES_PER_ROW,
    build_report_v4,
    index_access_hit,
    priority,
    repeated_scan_hit,
    stats_skew_hit,
)


class TestPriority:
    def test_default_p2(self) -> None:
        assert priority(exec_count=1, p95_ms=100) == "P2"

    def test_p1_requires_both_thresholds(self) -> None:
        assert priority(exec_count=20, p95_ms=5000) == "P1"
        assert priority(exec_count=19, p95_ms=5000) == "P2"
        assert priority(exec_count=20, p95_ms=4999) == "P2"

    def test_never_p0(self) -> None:
        assert priority(exec_count=10**6, p95_ms=10**9) != "P0"


class TestIndexAccess:
    def test_hit_full_scan_without_covering_index(self) -> None:
        hit = index_access_hit(
            table_name="orders",
            scanned_rows=1_263_814,
            result_rows=400,
            filter_columns=("tenant_id", "status", "created_at"),
            index_prefixes=(("tenant_id", "created_at"),),
            exec_count=842,
            p95_ms=2800,
        )
        assert hit is not None
        assert hit.rule_id == "IDX_ACCESS_001"
        assert hit.severity == "P2"
        assert "CREATE INDEX" in hit.actions[0].operation_zh
        assert "租" in "".join(hit.actions[0].operation_zh) or "idx" in hit.actions[0].operation_zh.lower()

    def test_miss_when_index_covers_filters(self) -> None:
        hit = index_access_hit(
            table_name="orders",
            scanned_rows=1_263_814,
            result_rows=400,
            filter_columns=("tenant_id", "created_at"),
            index_prefixes=(("tenant_id", "created_at"),),
            exec_count=842,
            p95_ms=2800,
        )
        assert hit is None

    def test_miss_when_scan_is_small(self) -> None:
        hit = index_access_hit(
            table_name="orders",
            scanned_rows=90,
            result_rows=30,
            filter_columns=("a", "b"),
            index_prefixes=(),
            exec_count=842,
            p95_ms=2800,
        )
        assert hit is None

    def test_cost_and_gain_formulas(self) -> None:
        hit = index_access_hit(
            table_name="orders",
            scanned_rows=1_263_814,
            result_rows=400,
            filter_columns=("tenant_id", "status", "created_at"),
            index_prefixes=(),
            exec_count=842,
            p95_ms=2800,
        )
        assert hit is not None
        action = hit.actions[0]
        assert "公式" in action.cost_formula_zh
        assert "公式" in action.gain_formula_zh
        expected_scan = 400 * 3
        reduction = (1 - expected_scan / 1_263_814) * 100
        assert f"{reduction:.1f}" in action.gain_zh or "-99" in action.gain_zh
        storage_mb = INDEX_BYTES_PER_ROW * 1_263_814 * 1.5 / (1024 * 1024)
        assert f"{storage_mb:.0f}" in action.cost_zh

    def test_p1_upgrade(self) -> None:
        hit = index_access_hit(
            table_name="orders",
            scanned_rows=1_263_814,
            result_rows=400,
            filter_columns=("tenant_id", "status", "created_at"),
            index_prefixes=(),
            exec_count=100,
            p95_ms=5900,
        )
        assert hit is not None and hit.severity == "P1"


class TestStatsSkew:
    def test_hit_on_large_ratio(self) -> None:
        hit = stats_skew_hit(
            table_name="billing_order",
            est_rows=120,
            actual_rows=180_000,
            healthy=100,
            batch_before_min=4,
        )
        assert hit is not None
        assert hit.rule_id == "STATS_SKEW_001"
        assert hit.severity == "P2"
        assert "ANALYZE" in hit.actions[0].operation_zh

    def test_hit_on_unhealthy_stats(self) -> None:
        hit = stats_skew_hit(table_name="t", est_rows=1000, actual_rows=1100, healthy=0)
        assert hit is not None

    def test_miss_when_fresh_and_accurate(self) -> None:
        hit = stats_skew_hit(table_name="t", est_rows=1000, actual_rows=1050, healthy=100)
        assert hit is None

    def test_gain_mentions_batch_recovery(self) -> None:
        hit = stats_skew_hit(
            table_name="billing_order",
            est_rows=120,
            actual_rows=180_000,
            healthy=100,
            batch_before_min=27,
            batch_target_min=6,
        )
        assert hit is not None
        assert "27" in hit.actions[0].gain_zh and "6" in hit.actions[0].gain_zh


class TestRepeatedScan:
    def test_hit_on_high_frequency_full_scan(self) -> None:
        hit = repeated_scan_hit(exec_count=20, avg_keys=65_537, p95_ms=66)
        assert hit is not None
        assert hit.rule_id == "REPEATED_SCAN_001"
        assert hit.severity == "P2"

    def test_miss_below_frequency(self) -> None:
        assert repeated_scan_hit(exec_count=19, avg_keys=65_537, p95_ms=66) is None

    def test_miss_below_scan_volume(self) -> None:
        assert repeated_scan_hit(exec_count=100, avg_keys=500, p95_ms=66) is None

    def test_gain_uses_measured_reduction(self) -> None:
        hit = repeated_scan_hit(
            exec_count=20,
            avg_keys=65_537,
            p95_ms=66,
            baseline_weighted_keys=1_310_740,
            reduced_weighted_keys=327_685,
        )
        assert hit is not None
        assert "75" in hit.actions[0].gain_zh


class TestBuildReport:
    def _index_hit(self):
        return index_access_hit(
            table_name="orders",
            scanned_rows=1_263_814,
            result_rows=400,
            filter_columns=("tenant_id", "status", "created_at"),
            index_prefixes=(),
            exec_count=842,
            p95_ms=2800,
        )

    def test_six_sections_present(self) -> None:
        report = build_report_v4(
            hits=[self._index_hit()],
            mode="rules",
            sql_digest="8c27725d5bb319605ec7433f114ddde077401dc4f62174fc58861eee73705f83",
            database="sqllens_m0_lab",
            evidence_rows=[
                {"label_zh": "运行表现", "value_zh": "842 次调用 · P95 2.8s · 平均扫描 126 万行", "evidence_ids": ["ev_1"]}
            ],
        )
        for key in ("conclusion", "evidence", "analysis", "changes", "validation", "rollback"):
            assert key in report["sections"], key
        change = report["sections"]["changes"][0]
        for key in ("operation_zh", "risk_zh", "cost_zh", "cost_formula_zh", "gain_zh", "gain_formula_zh"):
            assert change[key], key

    def test_priority_is_max_of_hits_and_never_p0(self) -> None:
        hit = self._index_hit()
        report = build_report_v4(hits=[hit], mode="rules", sql_digest="a" * 64, database="d", evidence_rows=[])
        assert report["priority"] in ("P1", "P2")
        assert report["priority"] == "P2"

    def test_degraded_ai_status_kept(self) -> None:
        report = build_report_v4(
            hits=[self._index_hit()],
            mode="degraded",
            ai_degraded_reason_zh="外部模型超时（MODEL_TIMEOUT）",
            sql_digest="a" * 64,
            database="d",
            evidence_rows=[],
        )
        assert report["mode"] == "degraded"
        assert "超时" in report["ai_status_zh"]

    def test_rule_ids_and_evidence_bound(self) -> None:
        report = build_report_v4(
            hits=[self._index_hit()],
            mode="rules",
            sql_digest="a" * 64,
            database="d",
            evidence_rows=[],
        )
        assert report["sections"]["conclusion"]["rule_ids"] == ["IDX_ACCESS_001"]
