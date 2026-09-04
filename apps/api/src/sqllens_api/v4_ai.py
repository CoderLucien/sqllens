"""B 档 AI 增强（v1）：单次结构化调用，三条输出，规则结论不可动。

设计约束（QA 验收清单 v1.1 / mgr 定案）：
- 输入为结构化证据摘要，总上限 2KB，含被诊断 SQL 原文（截断 ~512B），不含计划/统计 dump；
- 一次诊断恰一次模型调用（/v1 路径补全属路径修正，与失败重试分开）；
- 输出 JSON 契约校验 + 条数/字数钳制；失败/超时/不合法 → 降级，不重试；
- 会话缓存仅内存；不配 AI 零调用（由路由层保证）。
"""

from __future__ import annotations

import json
from collections import OrderedDict
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

AI_DIAGNOSE_TIMEOUT_SECONDS = 30.0
AI_MAX_OUTPUT_TOKENS = 900

SUMMARY_MAX_BYTES = 2048
SQL_MAX_BYTES = 512

SUGGESTIONS_MAX = 3
SUGGESTION_TEXT_MAX = 200
SUGGESTION_VALIDATION_MAX = 160
REVIEW_MAX = 2
REVIEW_TEXT_MAX = 300
AI_SUMMARY_MAX = 400

_ALLOWED_EVIDENCE_IDS = frozenset({"ev_runtime", "ev_plan", "ev_stats", "ev_schema"})

# 路径未实现类状态：Base URL 缺 /v1 时补全重试一次（路径修正，非失败重试）。
_RETRYABLE_PATH_STATUSES = frozenset({404, 501})

_CACHE_LIMIT = 32
_SESSION_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()


class AiConfigInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(min_length=1, max_length=2048)
    api_key: str = Field(min_length=1, max_length=4096)
    model: str = Field(min_length=1, max_length=256)
    protocol: str = Field(default="openai", pattern="^(openai|anthropic)$")


def _headers(config: AiConfigInput) -> dict[str, str]:
    if config.protocol == "anthropic":
        return {
            "x-api-key": config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
    return {"Authorization": f"Bearer {config.api_key}", "Content-Type": "application/json"}


def _candidate_urls(base: str, suffix: str) -> list[str]:
    """OpenAI 兼容路由可能在裸域或 /v1 下；裸域 404/501 时补 /v1 重试一次。"""
    urls = [f"{base}{suffix}"]
    if not urlsplit(base).path.rstrip("/").endswith("/v1"):
        urls.append(f"{base}/v1{suffix}")
    return urls


def _classify(exc: httpx.HTTPError) -> dict[str, Any]:
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout)):
        return {
            "ok": False,
            "code": "NETWORK_UNREACHABLE",
            "message_zh": "网络不可达 / 超时：请检查 Base URL 与本机网络（防火墙 / 代理）。",
        }
    response = getattr(exc, "response", None)
    if response is None:
        return {"ok": False, "code": "UNKNOWN", "message_zh": f"未知错误：{exc.__class__.__name__}"}
    status = response.status_code
    if status == 401:
        return {"ok": False, "code": "AUTH_INVALID", "message_zh": "401：API Key 无效。请检查 Key 后重试。"}
    if status == 403:
        return {"ok": False, "code": "AUTH_FORBIDDEN", "message_zh": "403：Key 权限不足，请确认该 Key 具有模型调用权限。"}
    if status == 404:
        return {"ok": False, "code": "MODEL_NOT_FOUND", "message_zh": "模型不存在：未找到该模型名，请用「识别模型」从可用列表选择。"}
    if status == 501:
        return {
            "ok": False,
            "code": "PROTOCOL_INCOMPATIBLE",
            "message_zh": (
                "协议不兼容：端点返回 HTTP 501（该路径未实现）。"
                "请确认 Base URL 为服务的 OpenAI/Anthropic 兼容根地址——"
                "若网关路由在 /v1 下，请在末尾补 /v1 后重试（如 https://api.deepseek.com/v1）。"
            ),
        }
    if status >= 400:
        return {
            "ok": False,
            "code": "PROTOCOL_INCOMPATIBLE",
            "message_zh": f"协议不兼容：端点返回 HTTP {status}，请确认网关适配层兼容 OpenAI/Anthropic 约束接口。",
        }
    return {"ok": False, "code": "UNKNOWN", "message_zh": f"未预期状态：HTTP {status}"}


def _truncate_utf8(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")[:max_bytes]
    return encoded.decode("utf-8", errors="ignore")


def _summary_payload(
    evidence: dict[str, Any],
    report: dict[str, Any],
    *,
    sql_bytes: int,
    conc_chars: int,
    ops_max: int,
    include_optional: bool,
) -> dict[str, Any]:
    sql = evidence.get("sql") or {}
    runtime = evidence.get("runtime") or {}
    plan = evidence.get("plan") or {}
    stats = evidence.get("stats") or {}
    schema = evidence.get("schema") or {}
    optional = evidence.get("optional") or {}
    conclusion = report["sections"]["conclusion"]

    data: dict[str, Any] = {
        "sql_digest": str(sql.get("sql_digest") or "")[:16],
        "sql_text": _truncate_utf8(str(sql.get("sql_text") or ""), sql_bytes),
        "database": str(sql.get("database") or "")[:64],
        "table": str(sql.get("table_name") or "")[:64],
        "runtime": {
            key: runtime.get(key)
            for key in ("exec_count", "window_minutes", "p95_ms", "avg_total_keys", "scanned_rows", "result_rows")
            if runtime.get(key) is not None
        },
        "plan_operators": [
            {
                "op": str(op.get("operator") or "")[:32],
                "table": str(op.get("table") or "")[:64],
                "est_rows": op.get("est_rows"),
            }
            for op in (plan.get("operator_rows") or [])[:ops_max]
        ],
        "stats": {
            key: stats.get(key)
            for key in ("est_rows", "actual_rows", "healthy")
            if stats.get(key) is not None
        },
        "schema": {
            "filter_columns": [str(col)[:64] for col in (schema.get("filter_columns") or [])][:8],
            "indexes": [
                {"name": str(item.get("name") or "")[:64], "columns": [str(col)[:32] for col in (item.get("columns") or [])[:4]]}
                for item in (schema.get("indexes") or [])[:4]
            ],
        },
        "rule_hits": {
            "rule_ids": list(conclusion.get("rule_ids") or []),
            "severities": list(conclusion.get("severities") or []),
            "conclusion_zh": _truncate_utf8(str(conclusion.get("text_zh") or ""), conc_chars * 3),
            "analysis_zh": _truncate_utf8(str(report["sections"]["analysis"].get("text_zh") or ""), conc_chars * 3),
        },
    }
    if include_optional:
        data["optional_ab"] = {
            key: optional.get(key)
            for key in ("baseline_weighted_keys", "reduced_weighted_keys", "batch_before_min", "batch_target_min")
            if optional.get(key) is not None
        }
    return data


def summarize_evidence(evidence: dict[str, Any], report: dict[str, Any]) -> str:
    """证据 + 规则结论 → 结构化摘要（≤2KB，含截断 SQL 原文，不含计划/统计原文）。"""
    stages = (
        {"sql_bytes": SQL_MAX_BYTES, "conc_chars": 160, "ops_max": 6, "include_optional": True},
        {"sql_bytes": 256, "conc_chars": 100, "ops_max": 4, "include_optional": False},
        {"sql_bytes": 128, "conc_chars": 60, "ops_max": 3, "include_optional": False},
        {"sql_bytes": 64, "conc_chars": 40, "ops_max": 2, "include_optional": False},
    )
    for stage in stages:
        text = json.dumps(
            _summary_payload(evidence, report, **stage),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if len(text.encode("utf-8")) <= SUMMARY_MAX_BYTES:
            return text
    return text


_SKILL_INDEX = (
    "【索引与访问路径】关注全表扫描与过滤列：谓词是否可 sargable（函数包裹列需先改写再谈索引）、"
    "复合索引列序与最左前缀、现有索引为何未被使用。给建议时引用具体过滤列名。"
)
_SKILL_STATS = (
    "【统计信息】关注估算行数与实际行数偏差、统计健康度：统计陈旧如何误导计划选择、"
    "ANALYZE TABLE 的时机与代价、刷新后需要复看的执行计划。"
)
_SKILL_REPEATED = (
    "【热点重复调用】关注窗口内执行次数与加权扫描量：批量化合并、应用侧缓存/结果复用、"
    "削峰与调用削减的验证方式（同窗口对比加权 keys）。"
)
_SKILL_JOIN = (
    "【多表 JOIN】仅当 SQL 涉及多表时使用：驱动表选择、JOIN 顺序、小表驱动大表、"
    "连接键索引与谓词下推；建议必须落到具体表与列。"
)
_SKILL_GENERAL = "【通用体检】基于证据给增量优化方向，不编造证据中不存在的瓶颈。"


def select_skills(evidence: dict[str, Any], report: dict[str, Any]) -> list[str]:
    rule_ids = set(report["sections"]["conclusion"].get("rule_ids") or [])
    tables = {
        str(op.get("table") or "")
        for op in (evidence.get("plan") or {}).get("operator_rows") or []
    }
    sql_text = str((evidence.get("sql") or {}).get("sql_text") or "").lower()
    skills: list[str] = []
    if "IDX_ACCESS_001" in rule_ids:
        skills.append(_SKILL_INDEX)
    if "STATS_SKEW_001" in rule_ids:
        skills.append(_SKILL_STATS)
    if "REPEATED_SCAN_001" in rule_ids:
        skills.append(_SKILL_REPEATED)
    if len([t for t in tables if t]) > 1 or " join " in f" {sql_text} ":
        skills.append(_SKILL_JOIN)
    if not skills:
        skills.append(_SKILL_GENERAL)
    return skills


def _build_system_prompt(skills: list[str]) -> str:
    return (
        "你是 TiDB SQL 优化顾问，为一份已由本地规则引擎产出的中文诊断报告做 AI 增强。硬性约束：\n"
        "1. 只基于输入证据与规则结论，不编造任何数字或指标；\n"
        "2. 全部输出使用中文；\n"
        "3. 只输出一个 JSON 对象，不输出任何其他文字或代码块标记；\n"
        "4. 规则结论不可推翻、不可改写：若认为某条命中规则的结论证据不足或有更优解释，"
        "仅在 ai_review 中给出异议条目并说明理由；\n"
        "5. ai_suggestions 每条必须注明证据出处与验证方式；"
        "evidence_ids 只能取 ev_runtime/ev_plan/ev_stats/ev_schema；证据撑不住该建议就不要输出它；\n"
        "6. 长度限制：ai_summary ≤400 字；ai_suggestions ≤3 条、每条 ≤200 字、验证方式 ≤160 字；"
        "ai_review ≤2 条、每条 ≤300 字。\n"
        "输出 JSON 结构：\n"
        '{"ai_summary":"…","ai_suggestions":[{"text_zh":"…","evidence_ids":["ev_plan"],"validation_zh":"…"}],'
        '"ai_review":[{"rule_id":"IDX_ACCESS_001","text_zh":"…"}]}\n'
        "本次按证据特征加载的分析技能：\n" + "\n".join(skills)
    )


def _build_user_content(summary: str, report: dict[str, Any]) -> str:
    conclusion = report["sections"]["conclusion"]
    analysis = report["sections"]["analysis"]
    return (
        f"证据摘要（JSON）：\n{summary}\n\n"
        f"规则引擎结论：{conclusion.get('text_zh')}\n"
        f"规则 ID：{', '.join(conclusion.get('rule_ids') or [])}\n"
        f"问题分析：{analysis.get('text_zh')}\n\n"
        "请按系统约束输出 JSON。"
    )


async def _call_model(
    config: AiConfigInput,
    system_prompt: str,
    user_content: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[str | None, str | None]:
    """单次模型调用；返回 (content, None) 或 (None, 失败原因中文)。

    404/501 时的 /v1 补全是路径修正（最多两个 URL），失败后不再重试。
    """
    base = config.base_url.rstrip("/")
    if config.protocol == "anthropic":
        urls = [f"{base}/v1/messages"]
        payload: dict[str, Any] = {
            "model": config.model,
            "max_tokens": AI_MAX_OUTPUT_TOKENS,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_content}],
        }
    else:
        urls = _candidate_urls(base, "/chat/completions")
        payload = {
            "model": config.model,
            "max_tokens": AI_MAX_OUTPUT_TOKENS,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
        }

    async with httpx.AsyncClient(timeout=AI_DIAGNOSE_TIMEOUT_SECONDS, transport=transport) as client:
        for index, url in enumerate(urls):
            try:
                response = await client.post(url, headers=_headers(config), json=payload)
            except httpx.HTTPError as exc:
                return None, _classify(exc)["message_zh"]
            if 200 <= response.status_code < 300:
                try:
                    data = response.json()
                except ValueError:
                    return None, "网关返回了非 JSON 响应"
                if config.protocol == "anthropic":
                    content = "".join(
                        str(block.get("text") or "")
                        for block in data.get("content") or []
                        if isinstance(block, dict) and block.get("type") == "text"
                    )
                else:
                    choices = data.get("choices") or []
                    message = choices[0].get("message") if choices and isinstance(choices[0], dict) else None
                    content = str(message.get("content") or "") if isinstance(message, dict) else ""
                if not content.strip():
                    return None, "模型返回了空内容"
                return content, None
            if not (
                index < len(urls) - 1 and response.status_code in _RETRYABLE_PATH_STATUSES
            ):
                classified = _classify(
                    httpx.HTTPStatusError(
                        "ai call failed", request=response.request, response=response
                    )
                )
                return None, classified["message_zh"]
    return None, "AI 调用未产生结果"


def _extract_json(content: str) -> Any:
    text = content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except (json.JSONDecodeError, ValueError):
            return None
    return None


def _clamp_ai_payload(data: Any, report: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    summary = data.get("ai_summary")
    if not isinstance(summary, str) or not summary.strip():
        return None
    allowed_rule_ids = set(report["sections"]["conclusion"].get("rule_ids") or [])

    suggestions: list[dict[str, Any]] = []
    for item in (data.get("ai_suggestions") or [])[:SUGGESTIONS_MAX]:
        if not isinstance(item, dict):
            continue
        text = item.get("text_zh")
        validation = item.get("validation_zh")
        ids = item.get("evidence_ids")
        if not isinstance(text, str) or not text.strip():
            continue
        if not isinstance(validation, str) or not validation.strip():
            continue
        if not isinstance(ids, list):
            continue
        ids = [str(item_id) for item_id in ids if item_id in _ALLOWED_EVIDENCE_IDS][:4]
        if not ids:
            continue
        suggestions.append(
            {
                "text_zh": text.strip()[:SUGGESTION_TEXT_MAX],
                "evidence_ids": ids,
                "validation_zh": validation.strip()[:SUGGESTION_VALIDATION_MAX],
            }
        )

    reviews: list[dict[str, Any]] = []
    for item in (data.get("ai_review") or [])[:REVIEW_MAX]:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("rule_id")
        text = item.get("text_zh")
        if rule_id not in allowed_rule_ids:
            continue
        if not isinstance(text, str) or not text.strip():
            continue
        reviews.append({"rule_id": str(rule_id), "text_zh": text.strip()[:REVIEW_TEXT_MAX]})

    return {
        "ai_summary": {"text_zh": summary.strip()[:AI_SUMMARY_MAX]},
        "ai_suggestions": suggestions,
        "ai_review": reviews,
    }


def _cache_key(evidence: dict[str, Any], config: AiConfigInput) -> str:
    material = json.dumps(
        {"evidence": evidence, "config": config.model_dump()},
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return sha256(material.encode("utf-8")).hexdigest()


def _cache_get(key: str) -> dict[str, Any] | None:
    payload = _SESSION_CACHE.get(key)
    if payload is not None:
        _SESSION_CACHE.move_to_end(key)
    return payload


def _cache_put(key: str, payload: dict[str, Any]) -> None:
    _SESSION_CACHE[key] = payload
    _SESSION_CACHE.move_to_end(key)
    while len(_SESSION_CACHE) > _CACHE_LIMIT:
        _SESSION_CACHE.popitem(last=False)


def _apply(report: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    report["mode"] = "rules_ai"
    report["ai_status_zh"] = "AI 增强：AI 已归纳转述规则结论，并补充策略建议与 review 异议（不改变规则结论）。"
    report["sections"].update(payload)
    return report


def _degrade(report: dict[str, Any], reason: str) -> dict[str, Any]:
    report["mode"] = "degraded"
    report["ai_status_zh"] = f"AI 调用失败，已降级为规则模式输出（{reason}）。"
    return report


async def augment_report_with_ai(
    report: dict[str, Any],
    evidence: dict[str, Any],
    config: AiConfigInput,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """在规则报告之上追加 AI 三输出；失败降级；会话内同证据同配置命中缓存零新调用。"""
    key = _cache_key(evidence, config)
    cached = _cache_get(key)
    if cached is not None:
        return _apply(report, cached)

    summary = summarize_evidence(evidence, report)
    skills = select_skills(evidence, report)
    content, fail_reason = await _call_model(
        config, _build_system_prompt(skills), _build_user_content(summary, report), transport=transport
    )
    if content is None:
        return _degrade(report, str(fail_reason))
    payload = _clamp_ai_payload(_extract_json(content), report)
    if payload is None:
        return _degrade(report, "AI 输出不满足数据契约（非 JSON 或结构不合法）")
    _cache_put(key, payload)
    return _apply(report, payload)
