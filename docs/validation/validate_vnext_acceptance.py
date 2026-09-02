from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs" / "validation" / "vnext-customer-journey-matrix.md"

BASELINE_COMMIT = "746f55231cc4b059ab3f72126d20f6a4df104e48"
EXPECTED_GROUP_COUNTS = {
    "INST": 2,
    "OWN": 3,
    "SRC": 5,
    "DX": 3,
    "MODE": 4,
    "RPT": 4,
    "DEG": 3,
}
ALLOWED_RESULTS = {"PASS", "FAIL", "BLOCKED", "UNVERIFIED"}
REQUIRED_FREEZE_FIELDS = {
    "Baseline commit",
    "Contract freeze ref",
    "Freeze state",
    "Human gate ref",
    "SUT commit",
    "Image digest",
    "Fixture manifest SHA-256",
    "Environment manifest SHA-256",
    "Source revisions",
    "Provider and model",
    "Pinned policy revisions",
    "Execution count",
}
REQUIRED_TRACE_MARKERS = {
    "T22-AC1",
    "T22-AC2",
    "T22-AC3",
    "T22-AC4",
    "T22-R1",
    "T22-R2",
    "T22-R3",
    "VNX-A1",
    "VNX-A2",
    "VNX-A3",
    "VNX-A4",
    "VNX-B1",
    "VNX-B2",
    "VNX-B3",
}
CASE_ID = re.compile(r"^`(?P<id>(?P<group>INST|OWN|SRC|DX|MODE|RPT|DEG)-\d{3})`$")
METADATA = re.compile(r"^- (?P<key>[^:]+): `(?P<value>[^`]+)`$")
GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^sha256:[a-f0-9]{64}$")


def read_matrix() -> str:
    return MATRIX.read_text(encoding="utf-8")


def parse_metadata(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if match := METADATA.fullmatch(line):
            values[match.group("key")] = match.group("value")
    return values


def parse_rows(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not (match := CASE_ID.fullmatch(cells[0])):
            continue
        if len(cells) != 9:
            raise ValueError(
                f"line {line_number}: expected 9 matrix columns, found {len(cells)}"
            )
        rows.append(
            {
                "id": match.group("id"),
                "group": match.group("group"),
                "refs": cells[1],
                "object": cells[2],
                "environment": cells[3],
                "steps": cells[4],
                "expected": cells[5],
                "actual": cells[6],
                "evidence": cells[7],
                "result": cells[8].strip("`"),
            }
        )
    return rows


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_metadata(metadata: dict[str, str]) -> None:
    missing = sorted(REQUIRED_FREEZE_FIELDS - metadata.keys())
    require(not missing, f"missing freeze fields: {', '.join(missing)}")
    require(
        metadata["Baseline commit"] == BASELINE_COMMIT,
        "matrix is not bound to the approved vNext baseline",
    )
    freeze_state = metadata["Freeze state"]
    require(freeze_state in {"PENDING", "READY"}, "invalid freeze state")
    if freeze_state == "READY":
        unresolved = sorted(
            key
            for key in REQUIRED_FREEZE_FIELDS
            - {"Freeze state", "Baseline commit", "Execution count"}
            if metadata[key] in {"UNASSIGNED", "PENDING"}
        )
        require(not unresolved, f"READY freeze has unresolved fields: {unresolved}")
        require(
            GIT_SHA.fullmatch(metadata["Contract freeze ref"]) is not None,
            "contract freeze ref must be a full Git SHA",
        )
        require(
            GIT_SHA.fullmatch(metadata["SUT commit"]) is not None,
            "SUT commit must be a full Git SHA",
        )
        for key in (
            "Image digest",
            "Fixture manifest SHA-256",
            "Environment manifest SHA-256",
        ):
            require(
                SHA256.fullmatch(metadata[key]) is not None,
                f"{key} must be an immutable sha256 digest",
            )
    require(
        metadata["Execution count"] in {"0", "1", "2"},
        "invalid execution count",
    )
    if freeze_state == "PENDING":
        require(metadata["Execution count"] == "0", "pending matrix was executed")


def validate_rows(rows: list[dict[str, str]], metadata: dict[str, str]) -> None:
    require(rows, "no acceptance cases found")
    require(
        Counter(row["group"] for row in rows) == EXPECTED_GROUP_COUNTS,
        "case groups/counts drifted from the bounded vNext matrix",
    )
    ids = [row["id"] for row in rows]
    duplicates = sorted(case_id for case_id, count in Counter(ids).items() if count > 1)
    require(not duplicates, f"duplicate case IDs: {duplicates}")

    for row in rows:
        require(
            all(row[field] for field in row if field not in {"id", "group"}),
            f"{row['id']}: empty required cell",
        )
        require(
            row["result"] in ALLOWED_RESULTS,
            f"{row['id']}: unsupported result {row['result']}",
        )
        if row["result"] != "UNVERIFIED":
            require("未执行" not in row["actual"], f"{row['id']}: no actual result")
            require("待采集" not in row["evidence"], f"{row['id']}: no raw evidence")

    if metadata["Freeze state"] == "PENDING":
        premature = [row["id"] for row in rows if row["result"] != "UNVERIFIED"]
        require(not premature, f"results recorded before freeze: {premature}")
        require(
            all("未执行" in row["actual"] for row in rows),
            "pending matrix must state that every case is unexecuted",
        )


def validate_traceability(text: str) -> None:
    missing = sorted(marker for marker in REQUIRED_TRACE_MARKERS if marker not in text)
    require(not missing, f"missing requirement markers: {missing}")
    required_phrases = {
        "job completed、存在 hypothesis、容器可启动均不能单独构成 PASS",
        "严重产品价值缺陷",
        "Plan Replayer 与手工资料入口",
        "2C4G、跨平台 clean install、SBOM、签名、provenance 与正式 RC",
        "只允许一轮有界补证或复测",
    }
    missing_phrases = sorted(
        phrase for phrase in required_phrases if phrase not in text
    )
    require(not missing_phrases, f"missing scope or gate statements: {missing_phrases}")


def main() -> None:
    text = read_matrix()
    metadata = parse_metadata(text)
    rows = parse_rows(text)
    validate_metadata(metadata)
    validate_rows(rows, metadata)
    validate_traceability(text)
    print(
        "vNext acceptance matrix valid: "
        f"{len(rows)} cases, freeze={metadata['Freeze state']}, "
        f"results={dict(Counter(row['result'] for row in rows))}"
    )


if __name__ == "__main__":
    main()
