"""Trusted audit boundary for Source/v1 projections.

The Source JSON document is a projection, not an authorization authority.  A
runtime validator must resolve every embedded event ID against an independent,
server-owned audit ledger. Every state record additionally binds its complete
immutable Source state projection so historical work cannot be authorized by a
later rewritten revision.
"""

from __future__ import annotations

import copy
import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from vnext_canonical_json import canonical_sha256

SOURCE_AUDIT_ATTESTATION_REVISION = "server-source-audit/v1"
SOURCE_VERIFICATION_BINDING_REVISION = "source-verification-input/v1"
IDEMPOTENCY_RECEIPT_ID = re.compile(r"^idem_[a-z0-9]{16,64}$")
AUTHORIZATION_RECEIPT_ID = re.compile(r"^authz_[a-z0-9]{16,64}$")
SHA256_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")

SourceAuditResolver = Callable[[str], dict[str, Any] | None]

SOURCE_STATE_SNAPSHOT_FIELDS = frozenset(
    {
        "schemaVersion",
        "sourceId",
        "revision",
        "type",
        "name",
        "state",
        "product",
        "version",
        "endpoint",
        "auth",
        "credentialLifecycle",
        "activeLeases",
        "associatedSourceIds",
        "allowedSchemas",
        "capabilities",
        "budgets",
        "owner",
        "verification",
        "createdAt",
        "updatedAt",
    }
)

# Test-only state snapshots keyed by their never-reused state event ID. Runtime
# resolvers read the same data from the transactional Source revision store. The
# registry exists only so generated contract fixtures can model that store
# without adding private audit rows to the public Source/v1 JSON projection.
_FIXTURE_STATE_SNAPSHOTS: dict[tuple[str, str], dict[str, Any]] = {}
_FIXTURE_PINNED_STATE_KEYS: set[tuple[str, str]] = set()

SOURCE_EVENT_PERMISSIONS = {
    "registered": "register_source",
    "verified": "publish_source_verification",
    "enabled": "enable_source",
    "edited": "edit_source",
    "leases_updated": "manage_source_reservation",
    "rotation_started": "rotate_source_credential",
    "rotation_completed": "manage_source_lifecycle",
    "disable_started": "disable_source",
    "disabled": "manage_source_lifecycle",
    "delete_started": "delete_source",
    "leases_drained": "manage_source_reservation",
    "tombstoned": "manage_source_lifecycle",
    "verification_failure_started": "publish_source_verification",
    "verification_failed": "publish_source_verification",
}

LEASE_EVENT_PERMISSIONS = {
    "lease_acquired": "manage_source_reservation",
    "lease_released": "manage_source_reservation",
    "lease_force_cancelled": "manage_source_reservation",
}

SYSTEM_OPERATION_PRINCIPALS = {
    "verified": {"source-verifier"},
    "verification_failure_started": {"source-verifier"},
    "verification_failed": {"source-verifier"},
    "rotation_completed": {"source-lifecycle"},
    "disabled": {"source-lifecycle"},
    "tombstoned": {"source-lifecycle"},
    "leases_updated": {"diagnosis-job", "source-verifier", "source-lifecycle"},
    "leases_drained": {"source-lifecycle"},
    "lease_acquired": {"diagnosis-job", "source-verifier"},
    "lease_released": {"diagnosis-job", "source-verifier"},
    "lease_force_cancelled": {"source-lifecycle"},
}


def canonical_string_set(values: list[str]) -> list[str]:
    """Return unique strings in RFC 8785/ECMAScript UTF-16 order."""

    if not all(isinstance(value, str) for value in values):
        raise ValueError("Source string set contains a non-string value")
    if len(values) != len(set(values)):
        raise ValueError("Source string set contains a duplicate value")
    return sorted(
        values,
        key=lambda value: value.encode("utf-16be", errors="surrogatepass"),
    )


def _source_event_permission(event: dict[str, Any]) -> str:
    if event["operation"] == "verification_failed" and event["fromState"] == "draining":
        return "manage_source_lifecycle"
    return SOURCE_EVENT_PERMISSIONS[event["operation"]]


def _allowed_system_principals(event: dict[str, Any]) -> set[str] | None:
    if event["operation"] == "verification_failed" and event["fromState"] == "draining":
        return {"source-lifecycle"}
    return SYSTEM_OPERATION_PRINCIPALS.get(event["operation"])


def source_verification_binding(source: dict[str, Any]) -> dict[str, Any]:
    """Return the exact non-secret input identity covered by verification."""

    return {
        "bindingRevision": SOURCE_VERIFICATION_BINDING_REVISION,
        "sourceId": source["sourceId"],
        "type": source["type"],
        "product": source["product"],
        "endpoint": copy.deepcopy(source["endpoint"]),
        "allowedSchemas": canonical_string_set(source["allowedSchemas"]),
        "auth": {
            key: source["auth"][key]
            for key in (
                "kind",
                "credentialRef",
                "credentialRevision",
                "username",
            )
        },
    }


def source_verification_binding_digest(source: dict[str, Any]) -> str:
    return canonical_sha256(source_verification_binding(source))


def source_state_snapshot(source: Mapping[str, Any]) -> dict[str, Any]:
    """Return the complete state projection bound by one state audit record.

    Append-only state/lease events are attested independently. Keeping those
    ledgers outside this value avoids recursively embedding the audit history in
    every private revision row while still binding every mutable Source field.
    """

    if not isinstance(source, Mapping) or not SOURCE_STATE_SNAPSHOT_FIELDS.issubset(
        source
    ):
        raise ValueError("Source revision lacks its complete state snapshot")
    return {
        field: copy.deepcopy(source[field]) for field in SOURCE_STATE_SNAPSHOT_FIELDS
    }


def register_fixture_source_snapshot(source: Mapping[str, Any]) -> None:
    """Register one explicit test-only Source revision state snapshot."""

    snapshot = source_state_snapshot(source)
    events = source.get("transitionEvents")
    if not isinstance(events, list) or not events:
        raise ValueError("fixture Source revision lacks a state event")
    event = events[-1]
    if (
        not isinstance(event, dict)
        or event.get("sourceRevision") != snapshot["revision"]
    ):
        raise ValueError("fixture Source revision does not end at its state event")
    event_id = event.get("eventId")
    if not isinstance(event_id, str):
        raise TypeError("fixture Source revision has no state event ID")
    key = (event_id, canonical_sha256(event))
    if key not in _FIXTURE_PINNED_STATE_KEYS:
        _FIXTURE_STATE_SNAPSHOTS[key] = snapshot


def register_fixture_source_state_history(
    entries: Iterable[Mapping[str, Any]],
) -> None:
    """Register explicit private state rows for checked-in JSON fixtures."""

    seen: set[tuple[str, str]] = set()
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {
            "eventId",
            "eventDigest",
            "snapshot",
        }:
            raise ValueError("invalid fixture Source state history entry")
        event_id = entry["eventId"]
        snapshot = entry["snapshot"]
        if not isinstance(event_id, str) or not isinstance(snapshot, Mapping):
            raise TypeError("invalid fixture Source state history entry")
        if set(snapshot) != SOURCE_STATE_SNAPSHOT_FIELDS:
            raise ValueError("fixture Source state snapshot is not complete")
        event_digest = entry.get("eventDigest")
        if not isinstance(event_digest, str):
            raise TypeError("fixture Source state history lacks its event digest")
        if not SHA256_DIGEST.fullmatch(event_digest):
            raise ValueError("fixture Source state history has an invalid event digest")
        key = (event_id, event_digest)
        if key in seen:
            raise ValueError("fixture Source state history repeats an audit identity")
        seen.add(key)
        _FIXTURE_STATE_SNAPSHOTS[key] = copy.deepcopy(dict(snapshot))
        _FIXTURE_PINNED_STATE_KEYS.add(key)


def _required_resolver(
    resolver: SourceAuditResolver | None,
) -> SourceAuditResolver:
    if resolver is None:
        raise ValueError("Source projection has no trusted Source audit resolver")
    return resolver


def _expected_record(
    source: dict[str, Any], event: dict[str, Any], event_kind: str
) -> dict[str, Any]:
    expected = {
        "auditRecordId": event["eventId"],
        "attestationRevision": SOURCE_AUDIT_ATTESTATION_REVISION,
        "sourceId": source["sourceId"],
        "sourceRevision": event["sourceRevision"],
        "eventKind": event_kind,
        "eventDigest": canonical_sha256(event),
        "principalId": event["actor"]["id"],
        "role": event["actor"]["role"],
        "permission": (
            _source_event_permission(event)
            if event_kind == "state"
            else LEASE_EVENT_PERMISSIONS[event["operation"]]
        ),
        "capturedAt": event["createdAt"],
    }
    if event_kind == "lease" and event["operation"] == "lease_force_cancelled":
        approval = event["ownerApproval"]
        expected.update(
            ownerApprovalDigest=canonical_sha256(approval),
            ownerApprovalPrincipalId=approval["approvedBy"]["id"],
            ownerApprovalRole="owner",
            ownerApprovalPermission="force_cancel_source_reservation",
            ownerApprovedAt=approval["approvedAt"],
        )
    return expected


def build_fixture_source_audit_resolver(
    *snapshots: dict[str, Any],
) -> SourceAuditResolver:
    """Build an explicit test-only stand-in for the server audit store.

    Runtime code must resolve these records from the transactional server
    ledger.  This helper exists only so checked-in examples can exercise the
    trust boundary without shipping a database alongside JSON fixtures.
    """

    if not snapshots:
        raise ValueError("fixture Source audit resolver requires a Source revision")
    final = max(snapshots, key=lambda item: item["revision"])
    source_id = final["sourceId"]
    local_state_snapshots: dict[tuple[str, str], dict[str, Any]] = {}
    for snapshot in snapshots:
        if snapshot["sourceId"] != source_id:
            raise ValueError("fixture Source audit resolver mixes Source identities")
        final_revision = snapshot["revision"]
        if final["transitionEvents"][:final_revision] != snapshot["transitionEvents"]:
            raise ValueError("fixture Source state histories are not one prefix chain")
        expected_lease_prefix = [
            event
            for event in final["leaseEvents"]
            if event["sourceRevision"] <= final_revision
        ]
        if expected_lease_prefix != snapshot["leaseEvents"]:
            raise ValueError("fixture Source lease histories are not one prefix chain")
        latest_event = snapshot["transitionEvents"][-1]
        event_id = latest_event["eventId"]
        local_state_snapshots[(event_id, canonical_sha256(latest_event))] = (
            source_state_snapshot(snapshot)
        )
        register_fixture_source_snapshot(snapshot)

    verification_receipt_by_revision = {
        event["sourceRevision"]: f"idem_{event['jobId'].split('_', 1)[1]}"
        for event in final["leaseEvents"]
        if event["purpose"] == "verification"
    }
    records: dict[str, dict[str, Any]] = {}
    for event_kind, events in (
        ("state", final["transitionEvents"]),
        ("lease", final["leaseEvents"]),
    ):
        for event in events:
            record = _expected_record(final, event, event_kind)
            if event_kind == "state":
                event_key = (event["eventId"], canonical_sha256(event))
                state_snapshot = local_state_snapshots.get(
                    event_key, _FIXTURE_STATE_SNAPSHOTS.get(event_key)
                )
                if state_snapshot is None:
                    raise ValueError(
                        "fixture Source audit resolver lacks every revision snapshot"
                    )
                state_snapshot = copy.deepcopy(state_snapshot)
                record.update(
                    sourceSnapshot=state_snapshot,
                    sourceSnapshotDigest=canonical_sha256(state_snapshot),
                )
            if event["actor"]["kind"] == "user":
                record["idempotencyReceiptId"] = (
                    f"idem_{event['eventId'].split('_', 1)[1]}"
                )
            verification_receipt = verification_receipt_by_revision.get(
                event["sourceRevision"]
            )
            if verification_receipt is not None and (
                (event_kind == "lease" and event["purpose"] == "verification")
                or event["operation"]
                in {
                    "leases_updated",
                    "verified",
                    "verification_failure_started",
                    "verification_failed",
                }
            ):
                record["idempotencyReceiptId"] = verification_receipt
            if event_kind == "lease":
                if event["operation"] == "lease_acquired":
                    record["committedBeforeCredentialUse"] = True
                else:
                    record["executionTerminated"] = True
                if event["operation"] == "lease_force_cancelled":
                    record["commandReceiptId"] = (
                        f"idem_{event['eventId'].split('_', 1)[1]}"
                    )
                    record["ownerApprovalReceiptId"] = (
                        f"authz_{event['eventId'].split('_', 1)[1]}"
                    )
            records[event["eventId"]] = record

    def resolve(record_id: str) -> dict[str, Any] | None:
        record = records.get(record_id)
        return copy.deepcopy(record) if record is not None else None

    return resolve


def _validate_event_authority(event: dict[str, Any]) -> None:
    actor = event["actor"]
    if actor["kind"] == "user":
        if actor["role"] != "owner":
            raise ValueError("Source user audit is not an authenticated Owner action")
        return
    allowed = _allowed_system_principals(event)
    if allowed is None or actor["id"] not in allowed:
        raise ValueError("Source system actor is not authoritative for its operation")


def validate_trusted_source_audit(
    source: dict[str, Any],
    resolve_source_audit: SourceAuditResolver | None,
) -> dict[int, dict[str, Any]]:
    """Resolve embedded audit identities through a server-owned ledger.

    The resolver must never be supplied by an API caller.  Runtime code obtains
    it from the same transactional store that commits Source revisions.
    """

    resolver = _required_resolver(resolve_source_audit)
    latest_state_record: dict[str, Any] | None = None
    state_records: list[tuple[dict[str, Any], dict[str, Any]]] = []
    verification_jobs_by_revision: dict[int, set[str]] = defaultdict(set)
    verification_receipts_by_job: dict[str, set[str]] = defaultdict(set)
    receipt_subject_by_id: dict[str, tuple[str, str]] = {}
    state_snapshots: dict[int, dict[str, Any]] = {}

    def bind_receipt(receipt_id: str, subject: tuple[str, str]) -> None:
        existing = receipt_subject_by_id.setdefault(receipt_id, subject)
        if existing != subject:
            raise ValueError(
                "Source idempotency receipt authorizes distinct Source intents"
            )

    for lease_event in source["leaseEvents"]:
        if lease_event["purpose"] == "verification":
            verification_jobs_by_revision[lease_event["sourceRevision"]].add(
                lease_event["jobId"]
            )
    for event_kind, events in (
        ("state", source["transitionEvents"]),
        ("lease", source["leaseEvents"]),
    ):
        for event in events:
            _validate_event_authority(event)
            record = resolver(event["eventId"])
            expected = _expected_record(source, event, event_kind)
            if record is None or any(
                record.get(field) != value for field, value in expected.items()
            ):
                raise ValueError(
                    "Source event differs from its trusted Source audit record"
                )
            receipt_id = record.get("idempotencyReceiptId")
            if event["actor"]["kind"] == "user":
                if not isinstance(
                    receipt_id, str
                ) or not IDEMPOTENCY_RECEIPT_ID.fullmatch(receipt_id):
                    raise ValueError(
                        "Source Owner action lacks a committed idempotency receipt"
                    )
                bind_receipt(receipt_id, ("owner", event["eventId"]))
            verification_jobs: set[str] = set()
            if event_kind == "lease" and event["purpose"] == "verification":
                verification_jobs.add(event["jobId"])
            elif event_kind == "state" and event["operation"] in {
                "leases_updated",
                "verified",
                "verification_failure_started",
                "verification_failed",
            }:
                verification_jobs = verification_jobs_by_revision.get(
                    event["sourceRevision"], set()
                )
            if verification_jobs:
                if not isinstance(
                    receipt_id, str
                ) or not IDEMPOTENCY_RECEIPT_ID.fullmatch(receipt_id):
                    raise ValueError(
                        "Source verifier action lacks a committed idempotency receipt"
                    )
                for job_id in verification_jobs:
                    bind_receipt(receipt_id, ("verification", job_id))
                    verification_receipts_by_job[job_id].add(receipt_id)
            if event_kind == "lease":
                if (
                    event["operation"] == "lease_acquired"
                    and record.get("committedBeforeCredentialUse") is not True
                ):
                    raise ValueError(
                        "Source reservation was not committed before credential use"
                    )
                if (
                    event["operation"] != "lease_acquired"
                    and record.get("executionTerminated") is not True
                ):
                    raise ValueError(
                        "Source reservation was released before execution termination"
                    )
                if event["operation"] == "lease_force_cancelled":
                    command_receipt = record.get("commandReceiptId")
                    if not isinstance(
                        command_receipt, str
                    ) or not IDEMPOTENCY_RECEIPT_ID.fullmatch(command_receipt):
                        raise ValueError(
                            "forced Source reservation cancellation lacks a force-cancel command receipt"
                        )
                    bind_receipt(
                        command_receipt,
                        ("owner-force-cancel", event["eventId"]),
                    )
                    approval_receipt = record.get("ownerApprovalReceiptId")
                    if not isinstance(
                        approval_receipt, str
                    ) or not AUTHORIZATION_RECEIPT_ID.fullmatch(approval_receipt):
                        raise ValueError(
                            "forced Source reservation cancellation lacks trusted Owner approval"
                        )
            else:
                state_records.append((event, record))
                snapshot = record.get("sourceSnapshot")
                snapshot_digest = record.get("sourceSnapshotDigest")
                if (
                    not isinstance(snapshot, dict)
                    or set(snapshot) != SOURCE_STATE_SNAPSHOT_FIELDS
                ):
                    raise ValueError(
                        "Source state audit lacks a complete revision snapshot"
                    )
                if snapshot_digest != canonical_sha256(snapshot):
                    raise ValueError(
                        "Source revision snapshot digest differs from audit"
                    )
                if not (
                    snapshot["sourceId"] == source["sourceId"]
                    and snapshot["revision"] == event["sourceRevision"]
                    and snapshot["state"] == event["toState"]
                    and snapshot["updatedAt"] == event["createdAt"]
                    and snapshot["auth"]["credentialRevision"]
                    == event["credentialRevision"]
                ):
                    raise ValueError(
                        "Source revision snapshot differs from its state event"
                    )
                if event["sourceRevision"] in state_snapshots:
                    raise ValueError("Source audit repeats a revision snapshot")
                state_snapshots[event["sourceRevision"]] = copy.deepcopy(snapshot)
            if event_kind == "state" and event is source["transitionEvents"][-1]:
                latest_state_record = copy.deepcopy(record)

    if any(len(receipts) != 1 for receipts in verification_receipts_by_job.values()):
        raise ValueError("Source verifier audit chain lacks one idempotency receipt")

    if latest_state_record is None:
        raise ValueError("Source projection lacks a trusted latest state record")
    if sorted(state_snapshots) != list(range(1, source["revision"] + 1)):
        raise ValueError("Source audit lacks every revision snapshot")
    latest_snapshot = state_snapshots[source["revision"]]
    if latest_state_record.get("sourceSnapshotDigest") != canonical_sha256(
        source_state_snapshot(source)
    ) or latest_snapshot != source_state_snapshot(source):
        raise ValueError("Source snapshot digest differs from trusted audit")

    status = source["verification"]["status"]
    if status in {"passed", "failed"}:
        result_operations = {
            "verified",
            "verification_failed",
            "verification_failure_started",
        }
        result_events = [
            event
            for event, _ in state_records
            if event["operation"] in result_operations
            and not (
                event["operation"] == "verification_failed"
                and event["fromState"] == "draining"
            )
        ]
        if not result_events:
            raise ValueError(
                "Source verification projection lacks a trusted verifier result"
            )
        latest_result = result_events[-1]
        expected_operations = (
            {"verified"}
            if status == "passed"
            else {"verification_failed", "verification_failure_started"}
        )
        if latest_result["operation"] not in expected_operations:
            raise ValueError("Source verification projection replays a stale result")
        if source["verification"]["testedAt"] != latest_result["createdAt"]:
            raise ValueError("Source verification time differs from trusted result")
        releases = [
            event
            for event in source["leaseEvents"]
            if event["sourceRevision"] == latest_result["sourceRevision"]
            and event["operation"] == "lease_released"
            and event["purpose"] == "verification"
        ]
        if len(releases) != 1:
            raise ValueError(
                "Source verification result lacks its trusted reservation release"
            )
        release = releases[0]
        if release["credentialRevision"] != source["auth"][
            "credentialRevision"
        ] or release["bindingDigest"] != source_verification_binding_digest(source):
            raise ValueError(
                "Source verification projection is stale for its current bound input"
            )
    return state_snapshots
