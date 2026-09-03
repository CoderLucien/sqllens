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
            elif base == "schema.txt":
                bundle.schema_text = text
            elif base == "stats.txt":
                bundle.stats_text = text
            elif base == "errors.txt":
                bundle.errors_text = text
            elif base.startswith("explain") or "explain" in base:
                bundle.explain_text = text
            elif lowered.endswith(".sql") and "sql" in lowered:
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


def bundle_to_evidence_payload(bundle: PlanReplayerBundle) -> dict:
    """将解析产物映射为契约 Evidence 的载荷视图（origin=plan_replayer）。

    仅做结构投影，不生成诊断结论；诊断内核据此构造完整 Evidence。
    """
    now = datetime.now(timezone.utc).isoformat()
    return {
        "origin": "plan_replayer",
        "integrityDigest": bundle.digest_sha256,
        "observedAt": bundle.captured_at or now,
        "collectedAt": now,
        "tidbVersion": bundle.tidb_version,
        "sqlCount": bundle.sql_count,
        "sqlTexts": bundle.sql_texts,
        "hasSchema": bundle.schema_text is not None,
        "hasStats": bundle.stats_text is not None,
        "hasExplain": bundle.explain_text is not None,
        "errors": bundle.errors_text or "",
        "meta": bundle.meta_text or "",
    }


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
