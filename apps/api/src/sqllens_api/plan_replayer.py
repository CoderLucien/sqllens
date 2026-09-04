"""Plan Replayer (离线诊断包) zip 解析。

将 TiDB ``PLAN REPLAYER DUMP`` 产出的 zip 诊断包解析为结构化的只读证据视图，
供诊断内核以 ``origin="plan_replayer"`` 的 Evidence 形态消费（契约见
``docs/contracts/evidence-v2.schema.json``）。

安全边界：
- 仅接受 zip，拒绝目录遍历与超限文件（zip bomb 防护）。
- 只解析白名单内的文本文件，未知文件忽略。
- 不执行包内任何 SQL；SQL/plan 仅作为文本证据保留，不回放。
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlglot import exp, parse_one
from sqlglot.errors import ErrorLevel

# 单个文件读取上限与 zip 内条目上限，防止 zip bomb / 超大诊断包。
_MAX_ENTRY_BYTES = 2 * 1024 * 1024  # 2 MiB / 文件
_MAX_TOTAL_BYTES = 32 * 1024 * 1024  # 32 MiB / 包
_MAX_ENTRIES = 512

# 允许解析的文本文件白名单（按名称后缀匹配）。
_WHITELIST_SUFFIXES = (
    ".txt",
    ".sql",
    ".toml",
    ".json",
)

_META_VERSION_RE = re.compile(r"v(\d+\.\d+\.\d+)")


class PlanReplayerError(ValueError):
    """Plan Replayer 包解析失败（属于输入校验错误，映射为 422）。"""


@dataclass
class PlanReplayerBundle:
    """解析产物：一个只读的 Plan Replayer 证据包视图。"""

    files: dict[str, str] = field(default_factory=dict)
    sql_texts: list[str] = field(default_factory=list)
    schema_text: str | None = None
    stats_text: str | None = None
    explain_text: str | None = None
    errors_text: str | None = None
    meta_text: str | None = None
    tidb_version: str | None = None
    captured_at: str | None = None
    digest_sha256: str = ""

    @property
    def sql_count(self) -> int:
        return len(self.sql_texts)


def _bounded_read(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    """读取单个条目并施加字节上限，返回解码后的 UTF-8 文本。"""
    if info.is_dir():
        return ""
    if info.file_size > _MAX_ENTRY_BYTES:
        raise PlanReplayerError(f"条目 {info.filename!r} 超过单文件上限 {_MAX_ENTRY_BYTES} 字节")
    raw = archive.read(info)
    if len(raw) > _MAX_ENTRY_BYTES:
        raise PlanReplayerError(f"条目 {info.filename!r} 解压后超过上限")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def _safe_name(filename: str) -> str:
    """拒绝绝对路径与目录遍历，返回规范化后的安全相对路径。"""
    normalized = filename.replace("\\", "/")
    if normalized.startswith("/") or ".." in normalized.split("/"):
        raise PlanReplayerError(f"非法路径条目: {filename!r}")
    return normalized


def parse_plan_replayer_zip(data: bytes) -> PlanReplayerBundle:
    """解析 Plan Replayer zip 字节流，返回结构化证据视图。

    抛出 :class:`PlanReplayerError` 当包损坏、超限或结构非法。
    """
    if not data:
        raise PlanReplayerError("诊断包为空")
    if len(data) > _MAX_TOTAL_BYTES:
        raise PlanReplayerError(f"诊断包超过总上限 {_MAX_TOTAL_BYTES} 字节")

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise PlanReplayerError("不是有效的 zip 诊断包") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) > _MAX_ENTRIES:
            raise PlanReplayerError(f"诊断包条目过多（>{_MAX_ENTRIES}）")

        bundle = PlanReplayerBundle()
        bundle.digest_sha256 = "sha256:" + hashlib.sha256(data).hexdigest()

        sql_by_name: dict[str, str] = {}
        for info in infos:
            name = _safe_name(info.filename)
            lowered = name.lower()
            if not lowered.endswith(_WHITELIST_SUFFIXES):
                continue
            text = _bounded_read(archive, info)
            bundle.files[name] = text

            base = lowered.split("/")[-1]
            if base == "meta.txt":
                bundle.meta_text = text
            elif "schema" in lowered and (
                base.endswith(".schema.txt") or base == "schema.txt" or base.endswith(".sql")
            ):
                # TiDB 原始导出含 schema/schema_meta.txt（清单，非 DDL），按 zip
                # 条目顺序后写会覆盖真实 *.schema.txt——只接受含 CREATE TABLE 的文本。
                if "create table" in text.lower():
                    bundle.schema_text = text
            elif base == "stats.txt" or "stats" in lowered.split("/") or (
                "stats" in lowered and base.endswith(".json")
            ):
                bundle.stats_text = text
            elif base == "errors.txt":
                bundle.errors_text = text
            elif base.startswith("explain") or "explain" in base:
                bundle.explain_text = text
            elif lowered.endswith(".sql") or (base.startswith("sql") and base.endswith(".txt")):
                # 根目录 session/global_bindings.sql 是 TiDB 基线绑定导出（常为空），
                # 不是被抓取的查询，不能进入 sql_texts。
                if "bindings" not in base:
                    sql_by_name[name] = text

        # SQL 文本按文件名稳定排序，避免结果非确定。
        bundle.sql_texts = [sql_by_name[k] for k in sorted(sql_by_name)]

        if not bundle.sql_texts and not bundle.schema_text and not bundle.meta_text:
            raise PlanReplayerError("诊断包缺少可识别内容（sql/schema/meta 均缺失）")

        _parse_meta(bundle)
        return bundle


def _parse_meta(bundle: PlanReplayerBundle) -> None:
    """从 meta.txt 提取 TiDB 版本与采集时间（尽力而为，失败不阻断）。"""
    if not bundle.meta_text:
        return
    match = _META_VERSION_RE.search(bundle.meta_text)
    if match:
        bundle.tidb_version = match.group(1)
    for line in bundle.meta_text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key in ("capture_time", "captured_at", "time", "timestamp") and value:
                bundle.captured_at = value
                break


def bundle_to_evidence_v3(bundle: PlanReplayerBundle) -> dict:
    """将解析产物投影为冻结契约 ``evidence/v3``（#t27↔#t25 汇合点）。

    契约见 ``docs/contracts/v4-diagnosis-input.schema.json``。只做类型化投影，
    不生成诊断结论；无法可靠解析的字段不填充（保持可选缺省），由诊断内核
    按证据不足降级处理。数字一律为安全整数，禁止 NaN/Infinity。
    """
    sql_text = _first_sql(bundle)
    return {
        "schema_version": "evidence/v3",
        "sql": {
            "sql_digest": _sql_digest(sql_text),
            "sql_text": sql_text,
            "database": _database_from_bundle(bundle),
            "table_name": _table_from_sql(sql_text),
        },
        "runtime": _parse_runtime(bundle),
        "plan": _parse_plan(bundle.explain_text),
        "stats": _parse_stats(bundle.stats_text),
        "schema": _parse_schema(bundle.schema_text, sql_text),
        "optional": {},
    }


def _first_sql(bundle: PlanReplayerBundle) -> str:
    for text in bundle.sql_texts:
        if text and text.strip():
            return text
    return ""


def _sql_digest(sql_text: str) -> str:
    """TiDB SQL digest 语义的 64 位十六进制（sha256 原文）。"""
    if not sql_text:
        return ""
    return hashlib.sha256(sql_text.encode("utf-8")).hexdigest()


def _database_from_meta(meta_text: str | None) -> str:
    if not meta_text:
        return ""
    for line in meta_text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            if key.strip().lower() in ("database", "db", "schema"):
                value = value.strip()
                if value:
                    return value
    return ""


def _database_from_bundle(bundle: PlanReplayerBundle) -> str:
    """多来源提取 database 名（契约要求非空，meta.txt 常无此字段）。"""
    db = _database_from_meta(bundle.meta_text)
    if db:
        return db
    if bundle.stats_text:
        try:
            data = json.loads(bundle.stats_text)
            if isinstance(data, dict) and data.get("database_name"):
                return str(data["database_name"])
        except json.JSONDecodeError:
            pass
    if bundle.schema_text:
        m = re.search(r"\buse\s+`?([\w]+)`?", bundle.schema_text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


_TABLE_RE = re.compile(r"\bFROM\s+([`\w.]+)", re.IGNORECASE)


def _table_from_sql(sql_text: str) -> str:
    match = _TABLE_RE.search(sql_text or "")
    return match.group(1) if match else ""


_ACT_ROWS_RE = re.compile(r"actRows[:=]\s*(\d+)", re.IGNORECASE)


def _split_explain_line(line: str) -> tuple[str, float | None, int | None, str] | None:
    """解析一行 EXPLAIN 输出为 (operator, est_rows, act_rows, info)。

    兼容真实 TiDB 三种输出形态：
    1. TAB 分隔（Plan Replayer explain.txt）：`    └─TableFullScan_9\t6001215.00\t6001215\tcop[tikv]\ttable:lineitem\t...`
    2. 表格线框（mysql 客户端）：`│ TableFullScan_16 │ 6001215.00 │ 5998605 │ cop[tikv] │ table:lineitem ...│`
    3. 简化文本：`TableFullScan lineitem estRows 6001215`
    """
    if "\t" in line:
        parts = line.split("\t")
        head = re.sub(r"^[\s│├└─]+", "", parts[0] or "")
        head_match = re.match(r"(?P<op>[A-Za-z][A-Za-z0-9_]*(?:_\d+)?)\s*$", head)
        if not head_match or len(parts) < 3:
            return None
        op = head_match.group("op")
        est = parts[1] if len(parts) > 1 else ""
        act = parts[2] if len(parts) > 2 else ""
        info = "\t".join(parts[3:])
    elif "│" in line:
        cells = [c.strip() for c in line.split("│")]
        if len(cells) < 3 or not cells[1]:
            return None
        op = cells[1]
        if not re.match(r"^[A-Za-z]", op):
            return None
        est = cells[2] if len(cells) > 2 else ""
        act = cells[3] if len(cells) > 3 else ""
        info = " ".join(cells[4:]) if len(cells) > 4 else ""
    else:
        match = _TIDB_PLAN_RE.search(line)
        if not match:
            # 简化文本兜底："TableFullScan lineitem estRows 6001215"
            fallback = _PLAN_OP_RE.search(line)
            if not fallback:
                return None
            op = fallback.group("op")
            est = fallback.group("est") or ""
            act = ""
            table = fallback.group("table") or ""
            info = f"table:{table}" if table else ""
        else:
            op = match.group("op")
            est = match.group("est")
            info = match.group("info") or ""
            act_match = _ACT_ROWS_RE.search(info)
            act = act_match.group(1) if act_match else ""
    try:
        est_val = float(est) if est else None
    except ValueError:
        est_val = None
    try:
        act_val = int(act) if act else None
    except ValueError:
        act_val = None
    return op, est_val, act_val, info


def _parse_runtime(bundle: PlanReplayerBundle) -> dict:
    """离线包运行时指标：从 EXPLAIN ANALYZE 文本提取 actRows 实测行数。

    exec_count 保持 0（DUMP 包无语句级执行次数，不伪造）；scanned_rows 取
    FullScan 算子的最大 actRows，result_rows 取首个 actRows（根算子）。
    """
    runtime: dict = {"exec_count": 0, "window_minutes": 1}
    scanned = 0
    first_act: int | None = None
    for line in (bundle.explain_text or "").splitlines():
        parsed = _split_explain_line(line)
        if not parsed:
            continue
        op, _est, act_val, _info = parsed
        if act_val is None:
            continue
        if first_act is None:
            first_act = act_val
        if "FullScan" in op:
            scanned = max(scanned, act_val)
    if scanned:
        runtime["scanned_rows"] = scanned
    if first_act is not None:
        runtime["result_rows"] = first_act
    return runtime


_PLAN_OP_RE = re.compile(
    r"(?P<op>[A-Za-z][A-Za-z0-9_]+)\s*(?:\(\s*)?(?P<table>[`\w.]+)?"
    r"(?:[^\n]*?estRows[: ]?\s*(?P<est>\d+))?",
    re.IGNORECASE,
)
# 真实 TiDB explain.txt 行形如：
#   "└─TableFullScan_15 6001215.00 cop[tikv] table:lineitem, range:[...] keep order:false"
#   以及无算子编号的 "TableReader 100.00 root data:..."
_TIDB_PLAN_RE = re.compile(
    r"^\s*[│├└─\s]*\s*(?P<op>[A-Za-z][A-Za-z0-9_]*?)(?:_\d+)?\s+"
    r"(?P<est>[\d.]+)\s+\S+\s+(?P<info>.*)$"
)
_TABLE_IN_INFO_RE = re.compile(r"\btable:([`\w.]+)", re.IGNORECASE)
_EXPLAIN_FILTER_OPS = {"explain", "id", "estrows", "task", "access", "object"}


def _parse_plan(explain_text: str | None) -> dict:
    """从 explain 文本尽力提取算子行（operator/table/est_rows）。

    兼容真实 TiDB 三种输出形态（TAB 分隔 / 表格线框 / 简化文本），
    保持确定性：仅取前若干行，失败时返回空 operator_rows。
    """
    if not explain_text:
        return {"operator_rows": []}
    rows: list[dict] = []
    for line in explain_text.splitlines():
        parsed = _split_explain_line(line)
        if not parsed:
            continue
        operator, est_val, _act_val, info = parsed
        if operator.lower() in _EXPLAIN_FILTER_OPS:
            continue
        row: dict = {"operator": operator}
        if est_val is not None:
            row["est_rows"] = _safe_int(est_val)
        table_match = _TABLE_IN_INFO_RE.search(info)
        if table_match:
            row["table"] = table_match.group(1)
        rows.append(row)
        if len(rows) >= 128:
            break
    return {"operator_rows": rows}


def _parse_stats(stats_text: str | None) -> dict:
    if not stats_text:
        return {}
    stats: dict = {}
    try:
        data = json.loads(stats_text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        _collect_stat_fields(data, stats)
        if not stats:
            # 表级嵌套：{"orders": {...}} → 取第一个表对象数值字段。
            for value in data.values():
                if isinstance(value, dict):
                    _collect_stat_fields(value, stats)
                    if stats:
                        break
        return stats
    # 非 JSON：正则兜底提取 key=value / key: value。
    for key in ("est_rows", "actual_rows", "row_count", "healthy"):
        m = re.search(rf"\b{key}\b\s*[:=]\s*(\d+)", stats_text, re.IGNORECASE)
        if m:
            stats[key] = _safe_int(m.group(1))
    return stats


def _collect_stat_fields(data: dict, stats: dict) -> None:
    for key in ("est_rows", "actual_rows", "row_count", "healthy"):
        if isinstance(data.get(key), (int, float)):
            stats[key] = _safe_int(data[key])
    if "row_count" not in stats and isinstance(data.get("count"), (int, float)):
        stats["row_count"] = _safe_int(data["count"])


_INDEX_INLINE_RE = re.compile(r"\b(?:KEY|INDEX)\s+([`\w]+)\s*\(([^)]+)\)", re.IGNORECASE)
_INDEX_CREATE_RE = re.compile(
    r"\b(?:CREATE\s+)?INDEX\s+([`\w]+)\s+ON\s+[`\w.]+\s*\(([^)]+)\)", re.IGNORECASE
)
_PRIMARY_KEY_RE = re.compile(r"\bPRIMARY\s+KEY\s*\(([^)]+)\)", re.IGNORECASE)


def _parse_schema(schema_text: str | None, sql_text: str) -> dict:
    result: dict = {}
    if schema_text:
        indexes: list[dict] = []
        seen: set[str] = set()
        for pattern in (_INDEX_CREATE_RE, _INDEX_INLINE_RE):
            for m in pattern.finditer(schema_text):
                name = m.group(1).strip("` ")
                if name in seen:
                    continue
                seen.add(name)
                columns = [c.strip("` ").lower() for c in m.group(2).split(",") if c.strip()]
                indexes.append({"name": name, "columns": columns})
        for m in _PRIMARY_KEY_RE.finditer(schema_text):
            if "PRIMARY" in seen:
                continue
            seen.add("PRIMARY")
            columns = [c.strip("` ").lower() for c in m.group(1).split(",") if c.strip()]
            indexes.append({"name": "PRIMARY", "columns": columns})
        if indexes:
            result["indexes"] = indexes
    filter_columns = _filter_columns_from_sql(sql_text)
    if filter_columns:
        result["filter_columns"] = filter_columns
    return result


_FILTER_COL_RE = re.compile(r"\b([a-zA-Z_][\w]*)\s*(?:=|>|<|>=|<=|!=|IN|LIKE)", re.IGNORECASE)


def _filter_columns_from_sql(sql_text: str) -> list[str]:
    """用 sqlglot 语义解析 WHERE 中的列引用（正则兜底仅在解析失败时使用）。"""
    columns: list[str] = []
    try:
        tree = parse_one(sql_text, read="mysql", error_level=ErrorLevel.IGNORE)
    except Exception:
        tree = None
    if tree is not None:
        where = tree.find(exp.Where)
        if where is not None:
            for column in where.find_all(exp.Column):
                name = column.name
                if name and name.lower() not in columns:
                    columns.append(name.lower())
        if columns:
            return columns[:32]
    for m in _FILTER_COL_RE.finditer(sql_text or ""):
        col = m.group(1).lower()
        if col in ("select", "where", "and", "or", "from", "order", "group", "by", "limit"):
            continue
        if col not in columns:
            columns.append(col)
    return columns[:32]


def _safe_int(value: object) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def plan_replayer_summary(bundle: PlanReplayerBundle) -> dict:
    """供上传接口返回的轻量摘要（不含 SQL 原文，避免日志/响应泄露）。"""
    return {
        "accepted": True,
        "digestSha256": bundle.digest_sha256,
        "tidbVersion": bundle.tidb_version,
        "capturedAt": bundle.captured_at,
        "sqlCount": bundle.sql_count,
        "availableFiles": sorted(bundle.files),
        "summaryZh": (
            f"已解析 Plan Replayer 诊断包：{bundle.sql_count} 条 SQL"
            + (f"（TiDB {bundle.tidb_version}）" if bundle.tidb_version else "")
            + "，证据仅会话内存、不落盘。"
        ),
    }


def parse_meta_json(meta_text: str | None) -> dict:
    """尝试将 meta.txt 解析为 JSON（新版 Plan Replayer 可能输出 JSON 元数据）。"""
    if not meta_text:
        return {}
    try:
        value = json.loads(meta_text)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        return {}
