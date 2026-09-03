from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs" / "validation" / "m0-private-preview-acceptance-matrix.md"
EVIDENCE_TEMPLATE = (
    ROOT / "docs" / "validation" / "m0-private-preview-evidence-template.md"
)

EXPECTED_GROUP_COUNTS = {
    "BOOT": 1,
    "FLOW": 1,
    "DX": 3,
    "RPT": 1,
    "EVD": 1,
    "SAFE": 5,
    "FAIL": 3,
}
EXPECTED_CASE_IDS = {
    "BOOT-001",
    "FLOW-001",
    "DX-001",
    "DX-002",
    "DX-003",
    "RPT-001",
    "EVD-001",
    "SAFE-001",
    "SAFE-002",
    "SAFE-003",
    "SAFE-004",
    "SAFE-005",
    "FAIL-001",
    "FAIL-002",
    "FAIL-003",
}
CORE_SHA = "a39ba5584e5ed17cef2fe91e2dc8f4b788ca80db"
RUNTIME_ADDENDUM_SHA = "fe1440b94405e113d64934865fae953e906e3669"
ALLOWED_RESULTS = {"PASS", "FAIL", "BLOCKED", "UNVERIFIED"}
CASE_ID = re.compile(r"^`(?P<id>(?P<group>BOOT|FLOW|DX|RPT|EVD|SAFE|FAIL)-\d{3})`$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_rows(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        match = CASE_ID.fullmatch(cells[0]) if cells else None
        if match is None:
            continue
        require(
            len(cells) == 7,
            f"line {line_number}: expected 7 matrix columns, found {len(cells)}",
        )
        rows.append(
            {
                "id": match.group("id"),
                "group": match.group("group"),
                "refs": cells[1],
                "environment": cells[2],
                "steps": cells[3],
                "expected": cells[4],
                "evidence": cells[5],
                "result": cells[6].strip("`"),
            }
        )
    return rows


def validate_rows(rows: list[dict[str, str]]) -> None:
    require(rows, "no M0 acceptance cases found")
    counts = Counter(row["group"] for row in rows)
    require(
        counts == EXPECTED_GROUP_COUNTS,
        f"case groups/counts drifted: expected {EXPECTED_GROUP_COUNTS}, found {counts}",
    )
    ids = [row["id"] for row in rows]
    duplicates = sorted(case_id for case_id, count in Counter(ids).items() if count > 1)
    require(not duplicates, f"duplicate case IDs: {duplicates}")
    require(
        set(ids) == EXPECTED_CASE_IDS,
        f"case IDs drifted: expected {sorted(EXPECTED_CASE_IDS)}, found {sorted(ids)}",
    )
    for row in rows:
        require(
            all(value for key, value in row.items() if key not in {"id", "group"}),
            f"{row['id']}: empty required cell",
        )
        require(
            row["result"] in ALLOWED_RESULTS,
            f"{row['id']}: unsupported result {row['result']}",
        )
        require(
            row["result"] == "UNVERIFIED",
            f"{row['id']}: frozen definition must not contain execution results",
        )


def validate_scope(matrix: str, evidence_template: str) -> None:
    require(
        "状态：`FROZEN`（定义已冻结；正式执行仍为 `0` 且门禁状态为 `BLOCKED`）"
        in matrix,
        "matrix must be definition-frozen while formal execution remains blocked at 0",
    )
    for name, sha in {
        "report/evidence core": CORE_SHA,
        "runtime addendum": RUNTIME_ADDENDUM_SHA,
    }.items():
        require(f"`{sha}`" in matrix, f"matrix missing frozen {name} SHA")
        require(f"`{sha}`" in evidence_template, f"template missing frozen {name} SHA")

    required_markers = {
        "M0-G1",
        "M0-G2",
        "M0-J1",
        "M0-D1",
        "M0-R1",
        "M0-S1",
        "M0-S2",
        "M0-S3",
        "M0-S4",
        "M0-F1",
        "T22-A1",
        "T22-A2",
        "T22-A3",
    }
    missing_markers = sorted(
        marker for marker in required_markers if marker not in matrix
    )
    require(not missing_markers, f"missing requirement markers: {missing_markers}")

    required_phrases = {
        f"`{CORE_SHA}`",
        f"`{RUNTIME_ADDENDUM_SHA}`",
        "正式执行必须保持为 `0`",
        "选择“方案 2”本身不等于报告验收",
        "一个仅在宿主发布 `127.0.0.1:18080` 的只读根文件系统应用容器",
        "规范地址 `http://localhost:18080`",
        "`/api/v1/m0/connection`、`/api/v1/m0/sql-candidates` 和 `/api/v1/m0/diagnoses`",
        "`GET /api/v1/setup/status`、`POST /api/v1/setup/owner`",
        "`GET /api/v1/auth/session`、`POST /api/v1/auth/login`",
        "`POST /api/v1/auth/logout`",
        "legacy bootstrap、model/settings 和旧 `/cases/sql`/job 路线",
        "冻结清单中的每个历史及新版路径都必须返回 `404`",
        "`migrate`、`bootstrap-ingest`",
        "退出 `64`",
        "`/data`",
        "`/secrets`",
        "`asyncmy==0.2.14`",
        "`_client_flag & MULTI_STATEMENTS == 0`",
        "`Connection.connect()`",
        '`_password=b""`',
        "`_password_creator=None`",
        "`ssl.create_default_context()`",
        "`CERT_REQUIRED`",
        "不传 `ssl=True`",
        "非 `@@autocommit=1` 不安装",
        "精确 8 个安全字段投影",
        "`schema_version/connection_id/state/product/version/database/tls_mode/connected_at`",
        "`Cache-Control: no-store`",
        "5 秒总 I/O deadline",
        "无自动重试或重连",
        "`force_close`",
        "`statistics-health/v1`",
        "不得出现 `planStats`、`estimatedRows`、`actualRows`",
        "`statement-summary/v3`",
        "`weightedTotalKeys`/加权平均独立复算",
        "`ROUND_HALF_UP`",
        "`sql_structure + ordinary_plan + index + slow_query`",
        "`accessPath=table_full_scan`",
        "`businessEvidenceIds=[]`",
        "未提供业务影响证据，仅说明数据库技术影响",
        "`fixture/review-only`",
        "managed-Evidence wrapper",
        "ServerQuery registry/binder equality",
        "`additionalProperties:false`",
        "连接/查询 deadline 与禁止自动重试/重连策略",
        "`390px` 无全页横向溢出",
        "固定 `20%` 完整度展示",
        "每条稳定规则 ID 的反例与六类 fault ID",
        "actionless `observe`",
        "`aiStatus=not_requested`",
        "`409 M0_BUSY`",
        "不依赖已禁用 OpenAPI 推断路由",
        "三场景不得只用 JSON fixture、mock、截图或作者自报替代真实 TiDB 观测",
        "总体 PASS 要求 15 项全部 PASS",
        "只允许一轮针对首轮失败项的复测",
        "QA 不重复私有字段代码审查",
    }
    missing_phrases = sorted(
        phrase for phrase in required_phrases if phrase not in matrix
    )
    require(not missing_phrases, f"missing scope/gate statements: {missing_phrases}")

    template_phrases = {
        "应用 OCI image digest",
        f"M0 runtime addendum 完整 Git SHA（必须为 `{RUNTIME_ADDENDUM_SHA}`）",
        "Human 索引报告 acceptance ref / artifact SHA-256",
        "延期路由清单 SHA-256",
        "CLI allowlist/退出码清单 SHA-256",
        "只读查询清单 SHA-256",
        "`asyncmy==0.2.14` distribution 文件名 / SHA-256",
        "runtime adapter 行为探针证据 SHA-256",
        "`#t23` 同 commit/image digest 定向审查 ref / result",
        "只有 15 项全部 PASS",
    }
    missing_template = sorted(
        phrase for phrase in template_phrases if phrase not in evidence_template
    )
    require(
        not missing_template, f"evidence template is incomplete: {missing_template}"
    )


def validate_no_ambiguous_placeholders(*texts: str) -> None:
    forbidden = {"TBD", "TODO", "FIXME", "待定"}
    found = sorted(token for token in forbidden if any(token in text for text in texts))
    require(not found, f"ambiguous placeholders remain: {found}")


def validate_no_stale_contract_terms(matrix: str, evidence_template: str) -> None:
    forbidden = {
        "状态：`DRAFT`",
        "5 秒连接/read/write",
        "有限重试",
        "`CLIENT_MULTI_STATEMENTS`",
        "`write_timeout` 参数",
        "`/var/lib/sqllens`",
        "`SQLLENS_SECRETS_DIR`",
        "`totalKeysRead`",
        "`QueryResult -> CollectedEvidence`",
    }
    found = sorted(
        term for term in forbidden if term in matrix or term in evidence_template
    )
    require(not found, f"stale or contradictory contract terms remain: {found}")


def main() -> None:
    matrix = read(MATRIX)
    evidence_template = read(EVIDENCE_TEMPLATE)
    rows = parse_rows(matrix)
    validate_rows(rows)
    validate_scope(matrix, evidence_template)
    validate_no_ambiguous_placeholders(matrix, evidence_template)
    validate_no_stale_contract_terms(matrix, evidence_template)
    print(
        "M0 acceptance matrix valid: "
        f"{len(rows)} cases, results={dict(Counter(row['result'] for row in rows))}"
    )


if __name__ == "__main__":
    main()
