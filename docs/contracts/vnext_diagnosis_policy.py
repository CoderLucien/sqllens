"""Deterministic diagnosis policy for Evidence -> Fact -> Rule -> Decision.

This module is intentionally free of schema and report concerns.  It owns the
versioned dependency graph, evidence eligibility, rule predicates, evidence
level/completeness calculation, and server-rendered uncertainty text.
"""

from __future__ import annotations

from typing import Any

EVIDENCE_LEVELS = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4}

FACT_DEPENDENCY_REGISTRY = {
    ("fact.index_scan_profile", "v1"): {
        "runtimeEvidenceId": {
            "kind": "slow_query",
            "fields": {
                "windowMinutes": "windowMinutes",
                "callCount": "callCount",
                "p95Ms": "p95Ms",
                "averageScanRows": "averageScanRows",
                "averageReturnRows": "averageReturnRows",
            },
        },
        "planEvidenceId": {
            "kind": "ordinary_plan",
            "fields": {"tableName": "tableName", "accessPath": "accessPath"},
        },
        "indexEvidenceId": {
            "kind": "index",
            "fields": {
                "tableName": "tableName",
                "filterColumns": "filterColumns",
                "indexCoverage": "indexCoverage",
            },
        },
    },
    ("fact.statistics_estimation_profile", "v1"): {
        "statisticsEvidenceId": {
            "kind": "statistics",
            "fields": {
                "estimatedRows": "estimatedRows",
                "actualRows": "actualRows",
                "statisticsFreshness": "statisticsFreshness",
            },
        }
    },
    ("fact.runtime_hotspot_profile", "v1"): {
        "statementEvidenceId": {
            "kind": "statement_summary",
            "fields": {"sqlStability": "sqlStability"},
        },
        "runtimeEvidenceId": {
            "kind": "runtime_metric",
            "fields": {"resourceCorrelation": "resourceCorrelation"},
        },
        "alertEvidenceId": {
            "kind": "alert",
            "fields": {"alertScope": "alertScope"},
        },
    },
}

# Candidate identity is separate from measured Fact fields.  Each supported
# profile explicitly declares canonical typed Evidence fields that identify a
# role candidate; measurements must never be inferred as identity.
FACT_CANDIDATE_IDENTITY_REGISTRY = {
    ("fact.index_scan_profile", "v1"): {
        "runtimeEvidenceId": ("profileSubjectRef", "profileObjectRef"),
        "planEvidenceId": ("profileSubjectRef", "profileObjectRef"),
        "indexEvidenceId": ("profileSubjectRef", "profileObjectRef"),
    },
    ("fact.statistics_estimation_profile", "v1"): {
        "statisticsEvidenceId": ("profileSubjectRef", "profileObjectRef"),
    },
    ("fact.runtime_hotspot_profile", "v1"): {
        "statementEvidenceId": ("profileSubjectRef", "profileObjectRef"),
        "runtimeEvidenceId": ("profileSubjectRef", "profileObjectRef"),
        "alertEvidenceId": ("profileSubjectRef", "profileObjectRef"),
    },
}

DIAGNOSIS_DEPENDENCY_REGISTRY = {
    ("decision.index_scan_priority", "v1"): {
        "factTemplate": "fact.index_scan_profile",
        "rules": {
            "IDX_ACCESS_001": (
                "runtimeEvidenceId",
                "planEvidenceId",
                "indexEvidenceId",
            )
        },
        "supportRules": ("IDX_ACCESS_001",),
        "claims": {
            ("ai.index_candidate_priority", "v1"): {
                "rules": ("IDX_ACCESS_001",),
                "evidenceRoles": (
                    "runtimeEvidenceId",
                    "planEvidenceId",
                    "indexEvidenceId",
                ),
            }
        },
        "actions": {
            ("action.index_candidate_isolated", "v1"): {
                "rules": ("IDX_ACCESS_001",),
                "evidenceRoles": (
                    "runtimeEvidenceId",
                    "planEvidenceId",
                    "indexEvidenceId",
                ),
            }
        },
    },
    ("decision.statistics_estimation", "v1"): {
        "factTemplate": "fact.statistics_estimation_profile",
        "rules": {"STATS_ESTIMATION_001": ("statisticsEvidenceId",)},
        "supportRules": ("STATS_ESTIMATION_001",),
        "claims": {},
        "actions": {
            ("action.statistics_refresh_isolated", "v1"): {
                "rules": ("STATS_ESTIMATION_001",),
                "evidenceRoles": ("statisticsEvidenceId",),
            }
        },
    },
    ("decision.runtime_hotspot", "v1"): {
        "factTemplate": "fact.runtime_hotspot_profile",
        "rules": {
            "RUNTIME_HOTSPOT_001": (
                "statementEvidenceId",
                "runtimeEvidenceId",
                "alertEvidenceId",
            ),
            "SQL_REGRESSION_001": ("statementEvidenceId",),
        },
        # The conflicted SQL regression hypothesis is retained for explanation,
        # but only the hit hotspot rule may support a Decision/Claim/Action.
        "supportRules": ("RUNTIME_HOTSPOT_001",),
        "claims": {
            ("ai.resource_hotspot_priority", "v1"): {
                "rules": ("RUNTIME_HOTSPOT_001",),
                "evidenceRoles": (
                    "statementEvidenceId",
                    "runtimeEvidenceId",
                    "alertEvidenceId",
                ),
            }
        },
        "actions": {
            ("action.resource_hotspot_runbook", "v1"): {
                "rules": ("RUNTIME_HOTSPOT_001",),
                "evidenceRoles": (
                    "statementEvidenceId",
                    "runtimeEvidenceId",
                    "alertEvidenceId",
                ),
            }
        },
    },
    ("decision.evidence_insufficient", "v1"): {
        "factTemplate": "fact.evidence_gap_profile",
        "rules": {},
        "supportRules": (),
        "claims": {},
        "actions": {},
    },
}

EVIDENCE_KIND_ZH = {
    "slow_query": "慢查询运行",
    "ordinary_plan": "普通执行计划",
    "index": "索引元数据",
    "statistics": "统计信息",
    "statement_summary": "Statement Summary",
    "runtime_metric": "运行指标",
    "alert": "告警",
}

EVIDENCE_ELIGIBILITY = {
    "business_observation": {"coverage": 0.5, "records": 1, "rows": 1},
    "sql_structure": {"coverage": 0.8, "records": 1, "rows": 1},
    "statement_summary": {"coverage": 0.8, "records": 1, "rows": 1},
    "slow_query": {"coverage": 0.8, "records": 1, "rows": 1},
    "schema": {"coverage": 0.8, "records": 1, "rows": 1},
    "index": {"coverage": 0.8, "records": 1, "rows": 1},
    "statistics": {"coverage": 0.8, "records": 1, "rows": 1},
    "ordinary_plan": {"coverage": 1.0, "records": 1, "rows": 1},
    "runtime_metric": {"coverage": 0.8, "records": 1, "rows": 1},
    "alert": {"coverage": 1.0, "records": 1, "rows": 1},
    "validation_result": {"coverage": 1.0, "records": 1, "rows": 1},
    "effect_metric_comparison": {"coverage": 1.0, "records": 1, "rows": 1},
    "rollback_confirmation": {"coverage": 1.0, "records": 1, "rows": 1},
}

_RULE_POLICIES_V2 = {
    "IDX_ACCESS_001": {
        "minimumEvidenceLevel": "E2",
        "documentRefs": [
            "pingkaidb-sql-tuning-overview@2026-09-02",
            "pingkaidb-explain-walkthrough@2026-09-02",
        ],
        "hit": {
            "severity": "high",
            "conclusionZh": "高频慢 SQL 使用全表扫描，且过滤列缺少匹配访问路径。",
        },
        "miss": {
            "status": "not_applicable",
            "severity": "info",
            "conclusionZh": "当前频率、延迟、扫描放大或访问路径未达到该规则的命中条件。",
        },
    },
    "STATS_ESTIMATION_001": {
        "minimumEvidenceLevel": "E3",
        "documentRefs": ["tidb-sql-tuning-statistics@2026-09-02"],
        "hit": {
            "severity": "high",
            "conclusionZh": "估算/实际行数偏差超过版本规则阈值，且统计早于数据变更。",
        },
        "miss": {
            "status": "not_applicable",
            "severity": "info",
            "conclusionZh": "估算偏差或统计新鲜度未达到统计信息规则阈值。",
        },
    },
    "RUNTIME_HOTSPOT_001": {
        "minimumEvidenceLevel": "E4",
        "documentRefs": ["tidb-troubleshoot-hot-regions@2026-09-02"],
        "hit": {
            "severity": "critical",
            "conclusionZh": "SQL 基线稳定，TiKV 热点和延迟在同一窗口共同异常。",
        },
        "miss": {
            "status": "not_applicable",
            "severity": "info",
            "conclusionZh": "SQL、资源指标与告警未形成同窗口热点证据链。",
        },
    },
    "SQL_REGRESSION_001": {
        "minimumEvidenceLevel": "E3",
        "documentRefs": ["tidb-sql-tuning-overview@2026-09-02"],
        "hit": {
            "severity": "high",
            "conclusionZh": "计划或扫描量相对基线发生退化，需要单独验证 SQL 回归假设。",
        },
        "stable": {
            "status": "conflicted",
            "severity": "medium",
            "conclusionZh": "没有检测到计划或扫描量退化，SQL 结构退化假设被冲突证据抑制。",
        },
        "miss": {
            "status": "not_applicable",
            "severity": "info",
            "conclusionZh": "Statement Summary 证据不足以判断 SQL 是否发生回归。",
        },
    },
}


def _policy_with_documents(rule_id: str, document_refs: list[str]) -> dict[str, Any]:
    return {**_RULE_POLICIES_V2[rule_id], "documentRefs": document_refs}


RULE_POLICY_REGISTRY = {
    "pingkaidb-7.1-rules/v2": {
        "IDX_ACCESS_001": _RULE_POLICIES_V2["IDX_ACCESS_001"],
        "STATS_ESTIMATION_001": _policy_with_documents(
            "STATS_ESTIMATION_001",
            ["pingkaidb-sql-tuning-statistics@2026-09-02"],
        ),
        "RUNTIME_HOTSPOT_001": _policy_with_documents(
            "RUNTIME_HOTSPOT_001",
            ["pingkaidb-troubleshoot-hot-regions@2026-09-02"],
        ),
        "SQL_REGRESSION_001": _policy_with_documents(
            "SQL_REGRESSION_001",
            ["pingkaidb-sql-tuning-overview@2026-09-02"],
        ),
    },
    "tidb-8.5-rules/v2": {
        "IDX_ACCESS_001": _policy_with_documents(
            "IDX_ACCESS_001",
            [
                "tidb-sql-tuning-overview@2026-09-02",
                "tidb-explain-walkthrough@2026-09-02",
            ],
        ),
        "STATS_ESTIMATION_001": _RULE_POLICIES_V2["STATS_ESTIMATION_001"],
        "RUNTIME_HOTSPOT_001": _RULE_POLICIES_V2["RUNTIME_HOTSPOT_001"],
        "SQL_REGRESSION_001": _RULE_POLICIES_V2["SQL_REGRESSION_001"],
    },
}

RULE_PACK_BY_VERSION_FAMILY = {
    "pingkaidb-7.1": "pingkaidb-7.1-rules/v2",
    "tidb-8.5": "tidb-8.5-rules/v2",
}

UNCERTAINTY_POLICY = {
    ("decision.index_scan_priority", "v1"): [
        {
            "code": "PARAMETER_DISTRIBUTION_UNKNOWN",
            "descriptionZh": "当前证据未覆盖所有参数分布，索引收益必须在代表性数据上验证。",
            "requiredEvidenceKinds": ["statistics", "validation_result"],
        }
    ],
    ("decision.statistics_estimation", "v1"): [
        {
            "code": "PRODUCTION_CAPACITY_UNKNOWN",
            "descriptionZh": "尚未取得生产峰值窗口的资源余量，不能直接安排生产 ANALYZE。",
            "requiredEvidenceKinds": ["runtime_metric"],
        }
    ],
    ("decision.runtime_hotspot", "v1"): [
        {
            "code": "CAUSALITY_UNCONFIRMED",
            "descriptionZh": "时间窗相关性不等于根因已被物理证明，仍需 Region/Store 级确认。",
            "requiredEvidenceKinds": ["runtime_metric"],
        },
        {
            "code": "TEM_SCOPE_READONLY",
            "descriptionZh": "TEM Key 的只读能力由连接预检确认，本报告未执行任何告警修改。",
            "requiredEvidenceKinds": ["alert"],
        },
    ],
}

AI_DEGRADED_UNCERTAINTY = {
    "code": "AI_DEGRADED",
    "descriptionZh": "模型未参与本轮解释，effective mode 为 rules。",
    "requiredEvidenceKinds": [],
}


def evidence_eligibility_reasons(evidence: dict[str, Any]) -> list[str]:
    policy = EVIDENCE_ELIGIBILITY[evidence["kind"]]
    reasons: list[str] = []
    if evidence["freshness"] != "fresh":
        reasons.append("NOT_FRESH")
    if evidence["coverage"] < policy["coverage"]:
        reasons.append("COVERAGE_BELOW_POLICY")
    if evidence["payload"]["recordCount"] < policy["records"]:
        reasons.append("NO_RECORDS")
    if evidence["payload"]["truncated"]:
        reasons.append("TRUNCATED")
    if evidence["collection"]["status"] != "complete":
        reasons.append("COLLECTION_INCOMPLETE")
    if evidence["collection"]["budget"]["rowsRead"] < policy["rows"]:
        reasons.append("NO_ROWS_READ")
    return reasons


def require_eligible(evidence: dict[str, Any], context: str) -> None:
    reasons = evidence_eligibility_reasons(evidence)
    if reasons:
        raise ValueError(
            f"ineligible evidence for {context}: {evidence['evidenceId']} ({','.join(reasons)})"
        )


def evidence_profile_values(
    dependency: dict[str, Any], evidence: dict[str, Any]
) -> dict[str, Any]:
    """Project one Evidence role onto the profile fields shared by the registry."""

    if evidence["kind"] != dependency["kind"]:
        raise ValueError("Evidence kind is incompatible with the profile role")
    typed = evidence["payload"]["typed"]
    return {
        profile_field: typed[evidence_field]
        for profile_field, evidence_field in dependency["fields"].items()
    }


def _merge_profile_values(
    role_evidence: dict[str, dict[str, Any]],
    role_spec: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for role, evidence in role_evidence.items():
        for field, value in evidence_profile_values(role_spec[role], evidence).items():
            if field in merged and merged[field] != value:
                raise ValueError(
                    "evidence-gap Fact selected Evidence is not profile-compatible"
                )
            merged[field] = value
    return merged


def evidence_candidate_identity(
    fact_key: tuple[str, str], role: str, evidence: dict[str, Any]
) -> dict[str, Any]:
    """Project the canonical typed candidate identity declared for one role."""

    if fact_key not in FACT_CANDIDATE_IDENTITY_REGISTRY:
        raise ValueError("Fact profile has no candidate identity registry")
    identity_spec = FACT_CANDIDATE_IDENTITY_REGISTRY[fact_key]
    if set(identity_spec) != set(FACT_DEPENDENCY_REGISTRY[fact_key]):
        raise ValueError("Fact candidate identity roles differ from dependencies")
    if role not in identity_spec:
        raise ValueError("Fact role has no candidate identity declaration")
    validate_evidence_object_identity(evidence)
    typed = evidence["payload"]["typed"]
    return {field: typed[field] for field in identity_spec[role]}


def validate_evidence_object_identity(evidence: dict[str, Any]) -> None:
    """Bind the Evidence envelope to canonical typed identity and object data."""

    typed = evidence["payload"]["typed"]
    if evidence["kind"] in {
        "slow_query",
        "ordinary_plan",
        "index",
        "statistics",
        "statement_summary",
        "runtime_metric",
        "alert",
    } and {
        "profileSubjectRef": evidence["profileSubjectRef"],
        "profileObjectRef": evidence["profileObjectRef"],
    } != {
        "profileSubjectRef": typed["profileSubjectRef"],
        "profileObjectRef": typed["profileObjectRef"],
    }:
        raise ValueError("Evidence envelope differs from typed profile identity")
    if (
        evidence["kind"]
        in {
            "ordinary_plan",
            "index",
            "statistics",
        }
        and typed["tableName"] != typed["profileObjectRef"]
    ):
        raise ValueError("Evidence object identity differs from typed tableName")


def derive_evidence_level(
    evidence: list[dict[str, Any]], supporting_evidence_ids: set[str]
) -> str:
    eligible_kinds = {
        item["kind"]
        for item in evidence
        if item["evidenceId"] in supporting_evidence_ids
        and not evidence_eligibility_reasons(item)
    }
    if {"statement_summary", "runtime_metric", "alert"} <= eligible_kinds:
        return "E4"
    if (
        "statistics" in eligible_kinds
        or {
            "slow_query",
            "ordinary_plan",
            "index",
        }
        <= eligible_kinds
    ):
        return "E3"
    if eligible_kinds & {
        "sql_structure",
        "statement_summary",
        "slow_query",
        "ordinary_plan",
        "index",
        "schema",
    }:
        return "E2"
    if eligible_kinds:
        return "E1"
    return "E0"


def derive_completeness(
    decision: dict[str, Any],
    facts_by_id: dict[str, dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
) -> int:
    fact = facts_by_id[decision["params"]["profileFactId"]]
    if fact["templateId"] == "fact.evidence_gap_profile":
        assessments = validate_gap_fact(fact, evidence_by_id)
        eligible = sum(item["eligible"] for item in assessments)
        return round(eligible * 100 / len(assessments))
    roles = FACT_DEPENDENCY_REGISTRY[(fact["templateId"], fact["templateRevision"])]
    eligible = 0
    for role in roles:
        evidence_id = fact["params"][role]
        if evidence_id in evidence_by_id and not evidence_eligibility_reasons(
            evidence_by_id[evidence_id]
        ):
            eligible += 1
    return round(eligible * 100 / len(roles))


def validate_gap_fact(
    fact: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Rebuild an incomplete profile from explicit role assessments."""

    params = fact["params"]
    if set(params) != {
        "attemptedDecisionTemplateId",
        "attemptedDecisionTemplateRevision",
        "profileIdentity",
        "roleAssessments",
    }:
        raise ValueError("evidence-gap Fact parameters are not closed")
    attempted_key = (
        params["attemptedDecisionTemplateId"],
        params["attemptedDecisionTemplateRevision"],
    )
    if attempted_key not in DIAGNOSIS_DEPENDENCY_REGISTRY or attempted_key == (
        "decision.evidence_insufficient",
        "v1",
    ):
        raise ValueError("evidence-gap Fact references an unknown diagnosis profile")
    attempted_spec = DIAGNOSIS_DEPENDENCY_REGISTRY[attempted_key]
    fact_key = (attempted_spec["factTemplate"], "v1")
    role_spec = FACT_DEPENDENCY_REGISTRY[fact_key]
    identity_spec = FACT_CANDIDATE_IDENTITY_REGISTRY[fact_key]
    if set(identity_spec) != set(role_spec):
        raise ValueError("evidence-gap profile identity roles differ from dependencies")
    profile_identity = params["profileIdentity"]
    if set(profile_identity) != {"profileSubjectRef", "profileObjectRef"}:
        raise ValueError("evidence-gap profile identity is not closed")
    provided = params["roleAssessments"]
    if len(provided) != len(role_spec):
        raise ValueError("evidence-gap Fact does not assess every required role")
    provided_by_role = {item["role"]: item for item in provided}
    if len(provided_by_role) != len(provided) or set(provided_by_role) != set(
        role_spec
    ):
        raise ValueError("evidence-gap Fact role assessments differ from the profile")

    selected_evidence_by_role: dict[str, dict[str, Any]] = {}
    seen_evidence_ids: set[str] = set()
    for role, dependency in role_spec.items():
        evidence_id = provided_by_role[role]["evidenceId"]
        if evidence_id is None:
            continue
        if evidence_id in seen_evidence_ids:
            raise ValueError("evidence-gap Fact reuses one Evidence for two roles")
        seen_evidence_ids.add(evidence_id)
        if evidence_id not in evidence_by_id:
            raise ValueError("evidence-gap Fact references missing Evidence")
        evidence = evidence_by_id[evidence_id]
        if evidence["kind"] != dependency["kind"]:
            raise ValueError("evidence-gap Fact role has the wrong Evidence kind")
        selected_identity = evidence_candidate_identity(fact_key, role, evidence)
        expected_identity = {
            field: profile_identity[field] for field in identity_spec[role]
        }
        if selected_identity != expected_identity:
            raise ValueError(
                "evidence-gap Fact selected Evidence is not profile-compatible"
            )
        selected_evidence_by_role[role] = evidence
    _merge_profile_values(selected_evidence_by_role, role_spec)

    expected: list[dict[str, Any]] = []
    for role, dependency in role_spec.items():
        supplied = provided_by_role[role]
        evidence_id = supplied["evidenceId"]
        expected_identity = {
            field: profile_identity[field] for field in identity_spec[role]
        }
        matching_candidates = [
            evidence
            for evidence in evidence_by_id.values()
            if evidence["kind"] == dependency["kind"]
            and evidence_candidate_identity(fact_key, role, evidence)
            == expected_identity
        ]
        eligible_candidate_ids = {
            evidence["evidenceId"]
            for evidence in matching_candidates
            if not evidence_eligibility_reasons(evidence)
        }
        if evidence_id is None:
            if matching_candidates:
                raise ValueError(
                    "evidence-gap Fact ignores a matching Evidence candidate"
                )
            reasons = ["MISSING_EVIDENCE"]
        else:
            evidence = evidence_by_id[evidence_id]
            if eligible_candidate_ids and evidence_id not in eligible_candidate_ids:
                raise ValueError(
                    "evidence-gap Fact ignores an eligible matching Evidence candidate"
                )
            reasons = evidence_eligibility_reasons(evidence)
        expected.append(
            {
                "role": role,
                "expectedKind": dependency["kind"],
                "evidenceId": evidence_id,
                "eligible": not reasons,
                "reasonCodes": reasons,
            }
        )
    if provided != expected:
        raise ValueError("evidence-gap Fact is not the derived role assessment")
    expected_evidence_ids = [
        item["evidenceId"] for item in expected if item["evidenceId"] is not None
    ]
    if fact["evidenceIds"] != expected_evidence_ids:
        raise ValueError("evidence-gap Fact evidenceIds are not its role projection")
    if all(item["eligible"] for item in expected):
        raise ValueError("fully eligible evidence cannot produce an evidence-gap Fact")
    return expected


def _rule_state(rule_id: str, params: dict[str, Any]) -> str:
    if rule_id == "IDX_ACCESS_001":
        return (
            "hit"
            if params["callCount"] >= 10
            and params["p95Ms"] >= 500
            and params["averageScanRows"] >= 10_000
            and params["averageScanRows"] >= params["averageReturnRows"] * 100
            and params["accessPath"] == "table_full_scan"
            and params["indexCoverage"] == "no_matching_composite_index"
            else "miss"
        )
    if rule_id == "STATS_ESTIMATION_001":
        high = max(params["estimatedRows"], params["actualRows"])
        low = min(params["estimatedRows"], params["actualRows"])
        return (
            "hit"
            if low > 0
            and high >= low * 10
            and params["statisticsFreshness"] in {"predates_bulk_import", "stale"}
            else "miss"
        )
    if rule_id == "RUNTIME_HOTSPOT_001":
        return (
            "hit"
            if params["sqlStability"] == "plan_and_scan_stable"
            and params["resourceCorrelation"] == "same_window_elevated"
            and params["alertScope"] == "cluster_component_window_match"
            else "miss"
        )
    if rule_id == "SQL_REGRESSION_001":
        if params["sqlStability"] == "plan_and_scan_stable":
            return "stable"
        if params["sqlStability"] in {"plan_changed", "scan_changed"}:
            return "hit"
        return "miss"
    raise ValueError(f"unknown rule policy: {rule_id}")


def validate_policy_pins(case: dict[str, Any]) -> None:
    database_sources = [
        item for item in case["sourceSnapshots"] if item["type"] == "tidb"
    ]
    if len(database_sources) != 1:
        raise ValueError("diagnosis policy requires one database version family")
    database_source = database_sources[0]
    database_family_by_product = {
        "tidb": "tidb-8.5",
        "pingkaidb": "pingkaidb-7.1",
    }
    if database_source["product"] not in database_family_by_product:
        raise ValueError("database Source snapshot product is not supported")
    family = database_source["versionFamily"]
    if family != database_family_by_product[database_source["product"]]:
        raise ValueError("database Source snapshot product and version disagree")
    for source in case["sourceSnapshots"]:
        if source["type"] != "tidb" and source["product"] != source["type"]:
            raise ValueError("non-database Source snapshot product and type disagree")
    if family not in RULE_PACK_BY_VERSION_FAMILY:
        raise ValueError("database version family has no deterministic rule pack")
    if case["pinnedRevisions"]["rulePack"] != RULE_PACK_BY_VERSION_FAMILY[family]:
        raise ValueError("Case rulePack pin does not match its database version")
    if case["pinnedRevisions"]["policy"] != "diagnosis-policy/v4":
        raise ValueError("Case does not pin the evidence-quality diagnosis policy")


def expected_rule_findings(
    rule_pack: str,
    decision: dict[str, Any],
    facts_by_id: dict[str, dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if rule_pack not in RULE_POLICY_REGISTRY:
        raise ValueError(f"unknown rule pack: {rule_pack}")
    rule_pack_policy = RULE_POLICY_REGISTRY[rule_pack]
    decision_key = (decision["templateId"], decision["templateRevision"])
    spec = DIAGNOSIS_DEPENDENCY_REGISTRY[decision_key]
    if decision_key == ("decision.evidence_insufficient", "v1"):
        fact = facts_by_id[decision["params"]["profileFactId"]]
        validate_gap_fact(fact, evidence_by_id)
        return []
    fact = facts_by_id[decision["params"]["profileFactId"]]
    role_ids = {
        role: fact["params"][role]
        for role in FACT_DEPENDENCY_REGISTRY[
            (fact["templateId"], fact["templateRevision"])
        ]
    }
    expected: list[dict[str, Any]] = []
    for rule_id, roles in spec["rules"].items():
        if rule_id not in rule_pack_policy:
            raise ValueError(f"rule {rule_id} is absent from pinned pack {rule_pack}")
        evidence_ids = [role_ids[role] for role in roles]
        for evidence_id in evidence_ids:
            require_eligible(evidence_by_id[evidence_id], f"rule {rule_id}")
        policy = rule_pack_policy[rule_id]
        state = _rule_state(rule_id, fact["params"])
        result = policy[state]
        expected.append(
            {
                "ruleId": rule_id,
                "status": result.get("status", "hit"),
                "severity": result["severity"],
                "minimumEvidenceLevel": policy["minimumEvidenceLevel"],
                "conclusionZh": result["conclusionZh"],
                "evidenceIds": evidence_ids,
                "documentRefs": policy["documentRefs"],
            }
        )
    return expected


def expected_uncertainty(case: dict[str, Any]) -> list[dict[str, Any]]:
    key = (case["decision"]["templateId"], case["decision"]["templateRevision"])
    if key == ("decision.evidence_insufficient", "v1"):
        fact = case["facts"][0]
        missing_kinds = sorted(
            {
                item["expectedKind"]
                for item in fact["params"]["roleAssessments"]
                if not item["eligible"]
            }
        )
        missing_zh = "、".join(EVIDENCE_KIND_ZH[item] for item in missing_kinds)
        expected = [
            {
                "code": "EVIDENCE_INSUFFICIENT",
                "descriptionZh": (
                    f"缺少符合资格的{missing_zh}证据，当前证据完整度为 "
                    f"{case['evidenceCompleteness']}%，不能发布根因或动作。"
                ),
                "requiredEvidenceKinds": missing_kinds,
            }
        ]
    else:
        expected = [dict(item) for item in UNCERTAINTY_POLICY[key]]
    if case["aiSynthesis"]["status"] in {"degraded", "abstained"}:
        expected.append(dict(AI_DEGRADED_UNCERTAINTY))
    return expected
