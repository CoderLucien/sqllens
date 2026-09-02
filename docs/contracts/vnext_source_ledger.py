"""Full-history replay for the Source state and lease ledgers."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from typing import Any

LEASE_STATE_OPERATIONS = {"leases_updated", "leases_drained"}
DRAIN_START_OPERATIONS = {
    "rotation_started",
    "disable_started",
    "delete_started",
    "verification_failure_started",
}


def replay_source_history(
    source: dict[str, Any], parse_time: Callable[[str], datetime]
) -> None:
    """Replay both ledgers by revision and reject any poisoned snapshot."""

    state_events = source["transitionEvents"]
    lease_events = source["leaseEvents"]
    if len({item["eventId"] for item in state_events}) != len(state_events):
        raise ValueError("duplicate Source state event")
    if len({item["eventId"] for item in lease_events}) != len(lease_events):
        raise ValueError("duplicate Source lease event")

    state_by_revision: dict[int, dict[str, Any]] = {}
    for event in state_events:
        revision = event["sourceRevision"]
        if revision in state_by_revision:
            raise ValueError("Source revision has multiple state snapshot events")
        state_by_revision[revision] = event
    expected_revision_count = len(state_events)
    if source["revision"] != expected_revision_count or sorted(
        state_by_revision
    ) != list(range(1, expected_revision_count + 1)):
        raise ValueError(
            "Source state ledger does not cover every revision exactly once"
        )

    leases_by_revision: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for event in lease_events:
        if event["sourceRevision"] not in state_by_revision:
            raise ValueError("lease event has no state snapshot in its revision")
        leases_by_revision[event["sourceRevision"]].append(event)

    current_state: str | None = None
    active: dict[str, dict[str, Any]] = {}
    seen_leases: set[str] = set()
    seen_jobs: set[str] = set()
    prior_state_at: datetime | None = None

    for revision in range(1, expected_revision_count + 1):
        state_event = state_by_revision[revision]
        state_at = parse_time(state_event["createdAt"])
        if prior_state_at is not None and state_at <= prior_state_at:
            raise ValueError("Source state revisions must have increasing timestamps")
        if state_event["fromState"] != current_state:
            raise ValueError("Source state ledger is discontinuous during full replay")

        revision_leases = sorted(
            leases_by_revision.get(revision, []),
            key=lambda item: parse_time(item["createdAt"]),
        )
        operation = state_event["operation"]
        if revision_leases and operation not in LEASE_STATE_OPERATIONS:
            raise ValueError("lease events are attached to a non-lease state revision")
        if operation in LEASE_STATE_OPERATIONS and not revision_leases:
            raise ValueError("lease state revision lacks lease ledger events")
        if operation in DRAIN_START_OPERATIONS and revision_leases:
            raise ValueError("drain admission revision cannot mutate active leases")

        for lease_event in revision_leases:
            lease_at = parse_time(lease_event["createdAt"])
            if prior_state_at is not None and lease_at <= prior_state_at:
                raise ValueError("lease event predates its Source revision")
            if lease_at > state_at:
                raise ValueError("Source state snapshot precedes its lease events")
            if lease_event["fromLeaseCount"] != len(active):
                raise ValueError("Source lease ledger count is discontinuous")
            lease_operation = lease_event["operation"]
            lease_id = lease_event["leaseId"]
            job_id = lease_event["jobId"]

            if lease_operation == "lease_acquired":
                if not (
                    operation == "leases_updated"
                    and current_state == "enabled"
                    and state_event["toState"] == "enabled"
                ):
                    raise ValueError("lease acquisition is outside enabled admission")
                if lease_id in seen_leases or job_id in seen_jobs:
                    raise ValueError("lease acquisition reuses an audit identity")
                if lease_event["toLeaseCount"] != len(active) + 1:
                    raise ValueError("lease acquisition count does not add one")
                active[lease_id] = {
                    "leaseId": lease_id,
                    "jobId": job_id,
                    "acquiredRevision": revision,
                    "acquiredAt": lease_event["createdAt"],
                }
                seen_leases.add(lease_id)
                seen_jobs.add(job_id)
                continue

            if lease_id not in active or active[lease_id]["jobId"] != job_id:
                raise ValueError(
                    "lease release/cancel is absent from the active ledger"
                )
            if lease_event["toLeaseCount"] != len(active) - 1:
                raise ValueError("lease release/cancel count does not remove one")
            if lease_operation == "lease_force_cancelled":
                if not (
                    operation == "leases_drained"
                    and current_state == "draining"
                    and state_event["toState"] == "draining"
                ):
                    raise ValueError("force cancellation requires an admitted drain")
            elif lease_operation == "lease_released":
                allowed = (
                    operation == "leases_updated"
                    and current_state == "enabled"
                    and state_event["toState"] == "enabled"
                ) or (
                    operation == "leases_drained"
                    and current_state == "draining"
                    and state_event["toState"] == "draining"
                )
                if not allowed:
                    raise ValueError(
                        "ordinary lease release violates Source state policy"
                    )
            else:
                raise ValueError(f"unknown lease operation: {lease_operation}")
            del active[lease_id]

        if operation == "leases_updated" and not (
            current_state == "enabled" and state_event["toState"] == "enabled"
        ):
            raise ValueError("leases_updated must snapshot an enabled Source")
        if operation == "leases_drained" and not (
            current_state == "draining" and state_event["toState"] == "draining"
        ):
            raise ValueError("leases_drained must snapshot an admitted drain")
        current_state = state_event["toState"]
        prior_state_at = state_at

    if current_state != source["state"]:
        raise ValueError("replayed Source state differs from snapshot")
    expected_active = {item["leaseId"]: item for item in source["activeLeases"]}
    if active != expected_active:
        raise ValueError("replayed active lease set differs from Source snapshot")
    if source["credentialLifecycle"]["activeLeaseCount"] != len(active):
        raise ValueError("Source activeLeaseCount differs from unified replay")
