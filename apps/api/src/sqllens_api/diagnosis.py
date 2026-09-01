from __future__ import annotations

import hashlib
import json
import logging
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

import sqlglot
from sqlalchemy import Column, MetaData, String, Table, Text, delete, insert, select, update
from sqlalchemy.engine import Engine, RowMapping
from sqlalchemy.exc import IntegrityError
from sqlglot import exp
from sqlglot.errors import ErrorLevel, SqlglotError

from sqllens_api.credentials import EncryptedCredential
from sqllens_api.provider import (
    ModelEvidence,
    ModelEvidenceCompleteness,
    ModelHypothesis,
    ModelRankingPayload,
)
from sqllens_api.setup import diagnosis_admission, setup_state

MAX_SQL_BYTES = 65_536
MAX_IDEMPOTENCY_KEY_LENGTH = 128
PARSER_REVISION = "sqlglot/mysql@30.17.0"
RULE_SET_REVISION = "sql-rules/v1"
POLICY_REVISION = "policy/v1"
REDACTION_REVISION = "sql-structure/v1"

# SQLGlot may include the original unsupported statement in fallback warnings.
logging.getLogger("sqlglot").disabled = True

diagnosis_metadata = MetaData()
diagnosis_cases = Table(
    "diagnosis_cases",
    diagnosis_metadata,
    Column("case_id", String(80), primary_key=True),
    Column("payload", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
)
diagnosis_jobs = Table(
    "diagnosis_jobs",
    diagnosis_metadata,
    Column("job_id", String(80), primary_key=True),
    Column("case_id", String(80), nullable=False, unique=True),
    Column("idempotency_key", String(128), nullable=False, unique=True),
    Column("request_fingerprint", String(71), nullable=False),
    Column("provider_snapshot", Text),
    Column("payload", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
)

_MUTATING_EXPRESSIONS = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.Merge,
    exp.TruncateTable,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Grant,
    exp.Revoke,
    exp.Copy,
    exp.LoadData,
    exp.Into,
    exp.Lock,
    exp.Analyze,
    exp.Execute,
)


class SqlDiagnosisError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class IdempotencyConflictError(RuntimeError):
    pass


class DiagnosisCapacityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ProviderConfiguration:
    mode: Literal["rules", "external"]
    revision: str | None
    external_model_egress: bool
    allowed_provider_hosts: tuple[str, ...]
    base_url: str | None
    model: str | None
    credential: EncryptedCredential | None


@dataclass(frozen=True, slots=True)
class JobReservation:
    job: dict[str, Any]
    owner: bool
    expected_payload: str | None = None
    provider_configuration: ProviderConfiguration | None = None


@dataclass(frozen=True, slots=True)
class SqlStructure:
    statement_kind: Literal["query", "explain"]
    table_references: int
    joins: int
    ctes: int
    subqueries: int
    set_operations: int
    has_predicate: bool
    has_aggregation: bool
    has_grouping: bool
    has_ordering: bool
    has_limit: bool
    has_distinct: bool

    def summary(self) -> str:
        enabled = [
            label
            for label, present in (
                ("predicate", self.has_predicate),
                ("aggregation", self.has_aggregation),
                ("grouping", self.has_grouping),
                ("ordering", self.has_ordering),
                ("limit", self.has_limit),
                ("distinct", self.has_distinct),
            )
            if present
        ]
        flags = ", ".join(enabled) if enabled else "no classified modifiers"
        return (
            f"Parsed one read-only MySQL {self.statement_kind} structure with "
            f"{self.table_references} table reference(s), {self.joins} join(s), "
            f"{self.ctes} CTE(s), {self.subqueries} subquery node(s), and {flags}. "
            "No TiDB version, schema, statistics, ordinary plan, or runtime metrics "
            "were supplied."
        )


def request_fingerprint(sql: str) -> str:
    return f"sha256:{hashlib.sha256(sql.encode('utf-8')).hexdigest()}"


def validate_idempotency_key(value: str | None) -> str:
    if value is None or not value.strip():
        raise SqlDiagnosisError(
            428,
            "IDEMPOTENCY_KEY_REQUIRED",
            "An Idempotency-Key header is required.",
        )
    if (
        len(value) > MAX_IDEMPOTENCY_KEY_LENGTH
        or not value.isascii()
        or any(character.isspace() or ord(character) < 0x21 for character in value)
    ):
        raise SqlDiagnosisError(
            422,
            "IDEMPOTENCY_KEY_INVALID",
            "The Idempotency-Key header is invalid.",
        )
    return value


def parse_sql_structure(sql: str) -> SqlStructure:
    if len(sql) > MAX_SQL_BYTES or len(sql.encode("utf-8")) > MAX_SQL_BYTES:
        raise SqlDiagnosisError(
            413,
            "SQL_INPUT_TOO_LARGE",
            "SQL input exceeds the 64 KiB limit.",
        )
    if not sql.strip():
        raise SqlDiagnosisError(422, "SQL_INPUT_INVALID", "SQL input is invalid.")
    try:
        statements = [
            statement
            for statement in sqlglot.parse(
                sql,
                read="mysql",
                error_level=ErrorLevel.RAISE,
            )
            if statement is not None
        ]
    except (SqlglotError, ValueError, RecursionError):
        raise _classify_strict_parse_failure(sql) from None
    if len(statements) != 1:
        code = "SQL_INPUT_MULTIPLE_STATEMENTS" if len(statements) > 1 else "SQL_INPUT_INVALID"
        raise SqlDiagnosisError(422, code, "Exactly one SQL statement is required.")

    statement = statements[0]
    if any(isinstance(node, _MUTATING_EXPRESSIONS) for node in statement.walk()):
        raise SqlDiagnosisError(
            422,
            "SQL_INPUT_NOT_READ_ONLY",
            "Only a non-locking read-only query or ordinary EXPLAIN is accepted.",
        )

    statement_kind: Literal["query", "explain"]
    query: exp.Query
    if isinstance(statement, exp.Describe):
        style = statement.args.get("style")
        if style is not None and str(style).upper() == "ANALYZE":
            raise SqlDiagnosisError(
                422,
                "SQL_INPUT_NOT_READ_ONLY",
                "EXPLAIN ANALYZE is not accepted.",
            )
        query = statement.this
        if not isinstance(query, exp.Query):
            raise SqlDiagnosisError(
                422,
                "SQL_INPUT_UNSUPPORTED",
                "The SQL statement is not supported by Layer 1.",
            )
        statement_kind = "explain"
    elif isinstance(statement, exp.Query):
        query = statement
        statement_kind = "query"
    else:
        raise SqlDiagnosisError(
            422,
            "SQL_INPUT_UNSUPPORTED",
            "The SQL statement is not supported by Layer 1.",
        )

    _validate_query_tree(query)
    nodes = list(query.walk())
    selects = [node for node in nodes if isinstance(node, exp.Select)]
    return SqlStructure(
        statement_kind=statement_kind,
        table_references=sum(isinstance(node, exp.Table) for node in nodes),
        joins=sum(isinstance(node, exp.Join) for node in nodes),
        ctes=sum(isinstance(node, exp.CTE) for node in nodes),
        subqueries=sum(isinstance(node, exp.Subquery) for node in nodes),
        set_operations=sum(
            isinstance(node, (exp.Union, exp.Intersect, exp.Except)) for node in nodes
        ),
        has_predicate=any(isinstance(node, (exp.Where, exp.Having)) for node in nodes),
        has_aggregation=any(isinstance(node, exp.AggFunc) for node in nodes),
        has_grouping=any(isinstance(node, exp.Group) for node in nodes),
        has_ordering=any(isinstance(node, exp.Order) for node in nodes),
        has_limit=any(isinstance(node, exp.Limit) for node in nodes),
        has_distinct=any(select.args.get("distinct") is not None for select in selects),
    )


def _classify_strict_parse_failure(sql: str) -> SqlDiagnosisError:
    """Classify a rejected statement without ever accepting a recovery parse."""
    try:
        recovered = [
            statement
            for statement in sqlglot.parse(
                sql,
                read="mysql",
                error_level=ErrorLevel.IGNORE,
            )
            if statement is not None
        ]
    except (SqlglotError, ValueError, RecursionError):
        recovered = []
    if len(recovered) == 1:
        statement = recovered[0]
        if any(isinstance(node, _MUTATING_EXPRESSIONS) for node in statement.walk()):
            return SqlDiagnosisError(
                422,
                "SQL_INPUT_NOT_READ_ONLY",
                "Only a non-locking read-only query or ordinary EXPLAIN is accepted.",
            )
        if not isinstance(statement, (exp.Query, exp.Describe)):
            return SqlDiagnosisError(
                422,
                "SQL_INPUT_UNSUPPORTED",
                "The SQL statement is not supported by Layer 1.",
            )
    return SqlDiagnosisError(422, "SQL_INPUT_INVALID", "SQL input is invalid.")


def _validate_query_tree(query: exp.Query) -> None:
    selects = list(query.find_all(exp.Select))
    if not selects:
        raise SqlDiagnosisError(422, "SQL_INPUT_INVALID", "SQL input is invalid.")
    for select_expression in selects:
        if not select_expression.expressions:
            raise SqlDiagnosisError(422, "SQL_INPUT_INVALID", "SQL input is invalid.")
        from_expression = select_expression.args.get("from_")
        if isinstance(from_expression, exp.From) and from_expression.this is None:
            raise SqlDiagnosisError(422, "SQL_INPUT_INVALID", "SQL input is invalid.")
    if any(not table.name for table in query.find_all(exp.Table)):
        raise SqlDiagnosisError(422, "SQL_INPUT_INVALID", "SQL input is invalid.")


def build_case(
    *,
    sql: str,
    structure: SqlStructure,
    now: datetime,
    provider: str | None,
    model: str | None,
    prompt: str | None = None,
    case_id: str | None = None,
) -> dict[str, Any]:
    timestamp = _rfc3339(now)
    case_id = case_id or _identifier("case")
    evidence_id = _identifier("ev")
    structure_payload = json.dumps(
        asdict(structure),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    evidence_digest = f"sha256:{hashlib.sha256(structure_payload).hexdigest()}"
    hypotheses = _build_hypotheses(structure, evidence_id)
    return {
        "schemaVersion": "diagnosis-case/v1",
        "caseId": case_id,
        "revision": 1,
        "sourceLayer": "sql",
        "workflowState": "ready",
        "outcome": "pending",
        "inputFingerprint": request_fingerprint(sql),
        "createdAt": timestamp,
        "updatedAt": timestamp,
        "evidenceCompleteness": {
            "score": 0.2,
            "classification": "insufficient",
            "missing": [
                "tidb_version",
                "schema",
                "statistics",
                "ordinary_plan",
                "runtime_metrics",
            ],
        },
        "evidence": [
            {
                "evidenceId": evidence_id,
                "kind": "sql_structure",
                "source": PARSER_REVISION,
                "observedAt": timestamp,
                "collectedAt": timestamp,
                "freshness": "fresh",
                "coverage": 0.2,
                "sensitivity": "metadata",
                "integrityDigest": evidence_digest,
                "summary": structure.summary(),
            }
        ],
        "hypotheses": hypotheses,
        "recommendations": [
            {
                "recommendationId": _identifier("rec"),
                "title": "Collect read-only TiDB context",
                "rationale": (
                    "SQL structure alone cannot justify a production change or a performance claim."
                ),
                "risk": "low",
                "prerequisites": ["Obtain an approved read-only TiDB metadata connection"],
                "validation": [
                    "Collect TiDB version, schema metadata, statistics, and an ordinary plan"
                ],
                "rollback": [
                    "Disconnect the read-only source and discard the newly collected metadata"
                ],
                "evidenceIds": [evidence_id],
                "owner": {
                    "kind": "role",
                    "id": "dba",
                    "displayName": "Database administrator",
                },
                "requiresHumanApproval": True,
            }
        ],
        "reviews": [],
        "feedback": [],
        "pinnedRevisions": {
            "ruleSet": RULE_SET_REVISION,
            "parser": PARSER_REVISION,
            "policy": POLICY_REVISION,
            "redaction": REDACTION_REVISION,
            "provider": provider,
            "model": model,
            "modelArtifact": None,
            "prompt": prompt,
        },
    }


def build_model_ranking_payload(case_payload: dict[str, Any]) -> ModelRankingPayload:
    completeness = cast(dict[str, Any], case_payload["evidenceCompleteness"])
    evidence = cast(list[dict[str, Any]], case_payload["evidence"])
    hypotheses = cast(list[dict[str, Any]], case_payload["hypotheses"])
    return ModelRankingPayload(
        evidence_completeness=ModelEvidenceCompleteness(
            score=cast(float, completeness["score"]),
            classification=cast(
                Literal["insufficient", "partial", "sufficient"],
                completeness["classification"],
            ),
            missing=cast(list[str], completeness["missing"]),
        ),
        evidence=[
            ModelEvidence(
                evidence_id=cast(str, item["evidenceId"]),
                kind=cast(str, item["kind"]),
                sensitivity="metadata",
                summary=cast(str, item["summary"]),
            )
            for item in evidence
        ],
        hypotheses=[
            ModelHypothesis(
                hypothesis_id=cast(str, item["hypothesisId"]),
                statement=cast(str, item["statement"]),
                confidence=cast(float, item["confidence"]),
                evidence_ids=cast(list[str], item["supportingEvidenceIds"]),
            )
            for item in hypotheses
        ],
    )


def apply_model_ranking(case_payload: dict[str, Any], ranked_ids: list[str]) -> bool:
    hypotheses = cast(list[dict[str, Any]], case_payload["hypotheses"])
    by_id = {cast(str, item["hypothesisId"]): item for item in hypotheses}
    if len(ranked_ids) != len(hypotheses) or set(ranked_ids) != set(by_id):
        return False
    case_payload["hypotheses"] = [by_id[hypothesis_id] for hypothesis_id in ranked_ids]
    return True


def _build_hypotheses(structure: SqlStructure, evidence_id: str) -> list[dict[str, Any]]:
    statements = [
        "The SQL structure alone cannot establish a TiDB execution bottleneck."
    ]
    if structure.joins:
        statements.append(
            "Join strategy remains unknown without schema, statistics, and plan evidence."
        )
    if structure.has_aggregation or structure.has_grouping:
        statements.append(
            "Aggregation cost remains unknown without cardinality and runtime evidence."
        )
    if structure.has_predicate:
        statements.append(
            "Predicate selectivity remains unknown without statistics and plan evidence."
        )
    return [
        {
            "hypothesisId": _identifier("hyp"),
            "statement": statement,
            "confidence": min(0.2 + index * 0.03, 0.32),
            "supportingEvidenceIds": [evidence_id],
            "contradictingEvidenceIds": [],
            "status": "candidate",
        }
        for index, statement in enumerate(statements)
    ]


class DiagnosisStore:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        diagnosis_metadata.create_all(engine)
        diagnosis_admission.create(engine, checkfirst=True)
        with self.engine.begin() as connection:
            existing_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(diagnosis_jobs)")
            }
            if "provider_snapshot" not in existing_columns:
                connection.exec_driver_sql(
                    "ALTER TABLE diagnosis_jobs ADD COLUMN provider_snapshot TEXT"
                )

    def reserve_job(
        self,
        *,
        idempotency_key: str,
        fingerprint: str,
        case_id: str | None = None,
        now: datetime,
    ) -> JobReservation:
        job_id = _identifier("job")
        case_id = case_id or _identifier("case")
        job_payload: dict[str, Any] = {
            "jobId": job_id,
            "caseId": case_id,
            "status": "in_progress",
            "explanation": {
                "status": "pending",
                "code": None,
                "policy": "pending/v1",
                "payloadSchema": None,
                "payloadDigest": None,
            },
        }
        serialized_job = _serialize(job_payload)
        created_at = _rfc3339(now)
        try:
            with self.engine.connect() as connection:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                try:
                    existing = (
                        connection.execute(
                            select(
                                diagnosis_jobs.c.request_fingerprint,
                                diagnosis_jobs.c.payload,
                            ).where(diagnosis_jobs.c.idempotency_key == idempotency_key)
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if existing is not None:
                        reservation = JobReservation(
                            job=self._resolve_replay(dict(existing), fingerprint),
                            owner=False,
                        )
                    else:
                        setup_row = (
                            connection.execute(select(setup_state).where(setup_state.c.id == 1))
                            .mappings()
                            .one()
                        )
                        provider_configuration = _provider_configuration_from_setup(setup_row)
                        connection.execute(
                            insert(diagnosis_jobs).values(
                                job_id=job_id,
                                case_id=case_id,
                                idempotency_key=idempotency_key,
                                request_fingerprint=fingerprint,
                                provider_snapshot=_serialize_provider_configuration(
                                    provider_configuration
                                ),
                                payload=serialized_job,
                                created_at=created_at,
                            )
                        )
                        lease = connection.execute(
                            insert(diagnosis_admission)
                            .prefix_with("OR IGNORE")
                            .values(slot=1, job_id=job_id, created_at=created_at)
                        )
                        if lease.rowcount != 1:
                            raise DiagnosisCapacityError
                        reservation = JobReservation(
                            job=job_payload,
                            owner=True,
                            expected_payload=serialized_job,
                            provider_configuration=provider_configuration,
                        )
                except BaseException:
                    connection.rollback()
                    raise
                else:
                    connection.commit()
        except IntegrityError:
            concurrent = self._job_by_idempotency_key(idempotency_key)
            if concurrent is not None:
                return JobReservation(
                    job=self._resolve_replay(concurrent, fingerprint),
                    owner=False,
                )
            if self.has_active_lease():
                raise DiagnosisCapacityError from None
            raise
        return reservation

    def complete_job(
        self,
        reservation: JobReservation,
        *,
        case_payload: dict[str, Any],
        explanation: dict[str, str | None],
        now: datetime,
    ) -> dict[str, Any]:
        if not reservation.owner or reservation.expected_payload is None:
            return reservation.job
        case_id = cast(str, case_payload["caseId"])
        if case_id != reservation.job["caseId"]:
            raise RuntimeError("reserved case identifier changed")
        completed = {
            "jobId": reservation.job["jobId"],
            "caseId": case_id,
            "status": "completed",
            "explanation": explanation,
        }
        with self.engine.begin() as connection:
            connection.execute(
                insert(diagnosis_cases).values(
                    case_id=case_id,
                    payload=_serialize(case_payload),
                    created_at=_rfc3339(now),
                )
            )
            result = connection.execute(
                update(diagnosis_jobs)
                .where(
                    diagnosis_jobs.c.job_id == reservation.job["jobId"],
                    diagnosis_jobs.c.payload == reservation.expected_payload,
                )
                .values(payload=_serialize(completed))
            )
            if result.rowcount != 1:
                raise RuntimeError("diagnosis job ownership changed")
            connection.execute(
                delete(diagnosis_admission).where(
                    diagnosis_admission.c.job_id == reservation.job["jobId"]
                )
            )
        return completed

    def fail_job(
        self,
        reservation: JobReservation,
        *,
        code: str,
        retryable: bool = True,
    ) -> dict[str, Any]:
        if not reservation.owner or reservation.expected_payload is None:
            return reservation.job
        failed = _failed_job(reservation.job, code, retryable=retryable)
        with self.engine.begin() as connection:
            result = connection.execute(
                update(diagnosis_jobs)
                .where(
                    diagnosis_jobs.c.job_id == reservation.job["jobId"],
                    diagnosis_jobs.c.payload == reservation.expected_payload,
                )
                .values(payload=_serialize(failed))
            )
            if result.rowcount == 1:
                connection.execute(
                    delete(diagnosis_admission).where(
                        diagnosis_admission.c.job_id == reservation.job["jobId"]
                    )
                )
        if result.rowcount == 1:
            return failed
        current = self.get_job(cast(str, reservation.job["jobId"]))
        return current or failed

    def cancel_job(self, reservation: JobReservation) -> dict[str, Any]:
        return self.fail_job(reservation, code="REQUEST_CANCELLED")

    def recover_interrupted_jobs(self) -> int:
        recovered = 0
        with self.engine.begin() as connection:
            rows = (
                connection.execute(
                    select(diagnosis_jobs.c.job_id, diagnosis_jobs.c.payload)
                )
                .mappings()
                .all()
            )
            for row in rows:
                payload = _deserialize(row["payload"])
                if payload.get("status") != "in_progress":
                    continue
                result = connection.execute(
                    update(diagnosis_jobs)
                    .where(
                        diagnosis_jobs.c.job_id == row["job_id"],
                        diagnosis_jobs.c.payload == row["payload"],
                    )
                    .values(payload=_serialize(_failed_job(payload, "PROCESS_INTERRUPTED")))
                )
                recovered += result.rowcount
            connection.execute(delete(diagnosis_admission))
        return recovered

    def has_active_lease(self) -> bool:
        with self.engine.connect() as connection:
            return (
                connection.execute(select(diagnosis_admission.c.slot).limit(1)).first()
                is not None
            )

    def resolve_idempotency(
        self,
        idempotency_key: str,
        fingerprint: str,
    ) -> dict[str, Any] | None:
        existing = self._job_by_idempotency_key(idempotency_key)
        if existing is None:
            return None
        return self._resolve_replay(existing, fingerprint)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    select(diagnosis_jobs.c.payload).where(diagnosis_jobs.c.job_id == job_id)
                )
                .mappings()
                .one_or_none()
            )
        return _deserialize(row["payload"]) if row is not None else None

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    select(diagnosis_cases.c.payload).where(diagnosis_cases.c.case_id == case_id)
                )
                .mappings()
                .one_or_none()
            )
        return _deserialize(row["payload"]) if row is not None else None

    def _job_by_idempotency_key(self, idempotency_key: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    select(
                        diagnosis_jobs.c.request_fingerprint,
                        diagnosis_jobs.c.payload,
                    ).where(diagnosis_jobs.c.idempotency_key == idempotency_key)
                )
                .mappings()
                .one_or_none()
            )
        return dict(row) if row is not None else None

    @staticmethod
    def _resolve_replay(existing: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if existing["request_fingerprint"] != fingerprint:
            raise IdempotencyConflictError
        return _deserialize(cast(str, existing["payload"]))


def _provider_configuration_from_setup(
    row: RowMapping,
) -> ProviderConfiguration:
    mode: Literal["rules", "external"] = (
        "external" if row["model_mode"] == "external" else "rules"
    )
    credential = None
    if row["provider_credential_ciphertext"] and row["provider_credential_key_version"]:
        credential = EncryptedCredential(
            ciphertext=cast(str, row["provider_credential_ciphertext"]),
            key_version=cast(str, row["provider_credential_key_version"]),
        )
    allowed_hosts = tuple(
        sorted(cast(list[str], json.loads(row["allowed_provider_hosts"] or "[]")))
    )
    revision = None
    if mode == "external":
        revision_payload = {
            "allowedProviderHosts": allowed_hosts,
            "baseUrl": row["provider_base_url"],
            "credentialCiphertextDigest": (
                hashlib.sha256(credential.ciphertext.encode("ascii")).hexdigest()
                if credential is not None
                else None
            ),
            "credentialKeyVersion": credential.key_version if credential is not None else None,
            "externalModelEgress": row["external_model_egress"] is True,
            "model": row["provider_model"],
            "setupEpoch": row["setup_epoch"],
        }
        digest = hashlib.sha256(_serialize(revision_payload).encode("ascii")).hexdigest()
        revision = f"openai-compatible@sha256:{digest}"
    return ProviderConfiguration(
        mode=mode,
        revision=revision,
        external_model_egress=row["external_model_egress"] is True,
        allowed_provider_hosts=allowed_hosts,
        base_url=cast(str | None, row["provider_base_url"]),
        model=cast(str | None, row["provider_model"]),
        credential=credential,
    )


def _serialize_provider_configuration(configuration: ProviderConfiguration) -> str:
    return _serialize(
        {
            "mode": configuration.mode,
            "revision": configuration.revision,
            "externalModelEgress": configuration.external_model_egress,
            "allowedProviderHosts": list(configuration.allowed_provider_hosts),
            "baseUrl": configuration.base_url,
            "model": configuration.model,
            "credential": (
                {
                    "ciphertext": configuration.credential.ciphertext,
                    "keyVersion": configuration.credential.key_version,
                }
                if configuration.credential is not None
                else None
            ),
        }
    )


def _serialize(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _deserialize(payload: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(payload))


def _failed_job(
    job: dict[str, Any],
    code: str,
    *,
    retryable: bool = True,
) -> dict[str, Any]:
    return {
        **job,
        "status": "failed",
        "error": {"code": code, "retryable": retryable},
    }


def _identifier(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
