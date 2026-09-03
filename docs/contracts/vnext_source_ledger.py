"""Full-history replay for the Source state and lease ledgers."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from vnext_source_audit import source_verification_binding_digest

LEASE_STATE_OPERATIONS = {
    "leases_updated",
    "leases_drained",
    "verified",
    "verification_failed",
    "verification_failure_started",
}
DRAIN_START_OPERATIONS = {
    "rotation_started",
    "disable_started",
    "delete_started",
    "verification_failure_started",
}


def replay_source_history(
    source: dict[str, Any],
    parse_time: Callable[[str], datetime],
    trusted_snapshots: Mapping[int, dict[str, Any]] | None = None,
) -> None:
    """Reject the legacy raw replay entry point; it cannot establish trust."""

    raise ValueError(
        "Direct Source history replay is non-authorizing; "
        "use the canonical Source validator"
    )


def _replay_prevalidated_source_history(
    source: dict[str, Any],
    parse_time: Callable[[str], datetime],
    trusted_snapshots: Mapping[int, dict[str, Any]],
) -> None:
    """Replay snapshots already validated by the canonical Source validator."""

    if not isinstance(trusted_snapshots, Mapping):
        raise TypeError("Source replay requires prevalidated revision snapshots")
    _replay_source_history(source, parse_time, trusted_snapshots)


def replay_source_ledger_structure(
    source: dict[str, Any], parse_time: Callable[[str], datetime]
) -> None:
    """Check ledger structure only; never use this result for authorization."""

    _replay_source_history(source, parse_time, None)


def _replay_source_history(
    source: dict[str, Any],
    parse_time: Callable[[str], datetime],
    trusted_snapshots: Mapping[int, dict[str, Any]] | None,
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
    drain_started_at: datetime | None = None
    verified_binding: tuple[int | None, str] | None = None
    prior_snapshot: dict[str, Any] | None = None

    for revision in range(1, expected_revision_count + 1):
        state_event = state_by_revision[revision]
        snapshot = (
            trusted_snapshots.get(revision) if trusted_snapshots is not None else None
        )
        if trusted_snapshots is not None:
            if not isinstance(snapshot, dict):
                raise ValueError("Source replay lacks a trusted revision snapshot")
            if not (
                snapshot["sourceId"] == source["sourceId"]
                and snapshot["revision"] == revision
                and snapshot["state"] == state_event["toState"]
                and snapshot["updatedAt"] == state_event["createdAt"]
                and snapshot["auth"]["credentialRevision"]
                == state_event["credentialRevision"]
            ):
                raise ValueError(
                    "Source trusted revision snapshot differs from its state event"
                )
        state_at = parse_time(state_event["createdAt"])
        if prior_state_at is not None and state_at <= prior_state_at:
            raise ValueError("Source state revisions must have increasing timestamps")
        if state_event["fromState"] != current_state:
            raise ValueError("Source state ledger is discontinuous during full replay")

        revision_leases = sorted(
            leases_by_revision.get(revision, []),
            key=lambda item: parse_time(item["createdAt"]),
        )
        lease_operations = {item["operation"] for item in revision_leases}
        if "lease_acquired" in lease_operations and lease_operations != {
            "lease_acquired"
        }:
            raise ValueError("Source lease revision cannot mix acquisition and release")
        operation = state_event["operation"]
        if revision_leases and operation not in LEASE_STATE_OPERATIONS:
            raise ValueError("lease events are attached to a non-lease state revision")
        if operation in {"leases_updated", "leases_drained"} and not revision_leases:
            raise ValueError("lease state revision lacks lease ledger events")
        if (
            operation in DRAIN_START_OPERATIONS
            and operation != "verification_failure_started"
            and revision_leases
        ):
            raise ValueError("drain admission revision cannot mutate active leases")

        prior_lease_at = prior_state_at
        for lease_event in revision_leases:
            lease_at = parse_time(lease_event["createdAt"])
            if prior_lease_at is not None and lease_at <= prior_lease_at:
                raise ValueError("Source lease events must be strictly ordered")
            if lease_at >= state_at:
                raise ValueError("Source lease event must precede its state snapshot")
            prior_lease_at = lease_at
            if lease_event["fromLeaseCount"] != len(active):
                raise ValueError("Source lease ledger count is discontinuous")
            lease_operation = lease_event["operation"]
            lease_id = lease_event["leaseId"]
            job_id = lease_event["jobId"]

            if lease_operation == "lease_acquired":
                if not (
                    operation == "leases_updated"
                    and state_event["toState"] == current_state
                ):
                    raise ValueError(
                        "lease acquisition is outside reservation admission"
                    )
                if lease_event["purpose"] == "diagnosis":
                    if current_state != "enabled":
                        raise ValueError(
                            "diagnosis lease acquisition is outside enabled admission"
                        )
                    if snapshot is not None:
                        binding = source_verification_binding_digest(snapshot)
                        expected = (
                            snapshot["auth"]["credentialRevision"],
                            binding,
                        )
                        if (
                            snapshot["verification"]["status"] != "passed"
                            or verified_binding != expected
                        ):
                            raise ValueError(
                                "diagnosis reservation requires a previously verified binding"
                            )
                        if (
                            lease_event["credentialRevision"],
                            lease_event["bindingDigest"],
                        ) != expected:
                            raise ValueError(
                                "diagnosis reservation differs from its trusted Source revision"
                            )
                elif current_state in {"draining", "tombstoned"}:
                    raise ValueError(
                        "verification reservation is outside a testable Source state"
                    )
                if (
                    snapshot is not None
                    and lease_event["purpose"] == "verification"
                    and (
                        lease_event["credentialRevision"]
                        != snapshot["auth"]["credentialRevision"]
                        or lease_event["bindingDigest"]
                        != source_verification_binding_digest(snapshot)
                    )
                ):
                    raise ValueError(
                        "verification reservation differs from its trusted Source revision"
                    )
                if lease_id in seen_leases or job_id in seen_jobs:
                    raise ValueError("lease acquisition reuses an audit identity")
                if lease_event["toLeaseCount"] != len(active) + 1:
                    raise ValueError("lease acquisition count does not add one")
                active[lease_id] = {
                    "leaseId": lease_id,
                    "jobId": job_id,
                    "purpose": lease_event["purpose"],
                    "credentialRevision": lease_event["credentialRevision"],
                    "bindingDigest": lease_event["bindingDigest"],
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
            if any(
                active[lease_id][field] != lease_event[field]
                for field in ("purpose", "credentialRevision", "bindingDigest")
            ):
                raise ValueError(
                    "Source lease release differs from acquisition binding"
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
                approval = lease_event["ownerApproval"]
                if (
                    drain_started_at is None
                    or parse_time(approval["approvedAt"]) <= drain_started_at
                ):
                    raise ValueError(
                        "force-cancel Owner approval must be captured after drain admission"
                    )
            elif lease_operation == "lease_released":
                allowed = (
                    (
                        operation == "leases_updated"
                        and current_state
                        in {"draft", "enabled", "disabled", "verification_failed"}
                        and state_event["toState"] == current_state
                    )
                    or (
                        operation == "leases_drained"
                        and current_state == "draining"
                        and state_event["toState"] == "draining"
                    )
                    or (
                        lease_event["purpose"] == "verification"
                        and operation
                        in {
                            "verified",
                            "verification_failed",
                            "verification_failure_started",
                        }
                    )
                )
                if not allowed:
                    raise ValueError(
                        "ordinary lease release violates Source state policy"
                    )
            else:
                raise ValueError(f"unknown lease operation: {lease_operation}")
            del active[lease_id]

        if operation == "leases_updated" and not (
            current_state in {"draft", "enabled", "disabled", "verification_failed"}
            and state_event["toState"] == current_state
        ):
            raise ValueError("leases_updated must preserve a reservable Source state")
        if operation == "leases_drained" and not (
            current_state == "draining" and state_event["toState"] == "draining"
        ):
            raise ValueError("leases_drained must snapshot an admitted drain")
        direct_verification_result = operation in {
            "verified",
            "verification_failure_started",
        } or (
            operation == "verification_failed"
            and state_event["fromState"] != "draining"
        )
        if direct_verification_result:
            released_verifications = [
                event
                for event in revision_leases
                if event["operation"] == "lease_released"
                and event["purpose"] == "verification"
            ]
            if len(revision_leases) != 1 or len(released_verifications) != 1:
                raise ValueError(
                    "verification result revision must release one reservation"
                )
            release = released_verifications[0]
            # The active entry has already been removed above, so recover the
            # immutable acquisition revision from the release's matching ledger
            # event rather than trusting the current projection.
            acquisitions = [
                event
                for event in lease_events
                if event["leaseId"] == release["leaseId"]
                and event["operation"] == "lease_acquired"
            ]
            if len(acquisitions) != 1:
                raise ValueError(
                    "verification result lacks one reservation acquisition"
                )
            acquisition_revision = acquisitions[0]["sourceRevision"]
            if acquisition_revision != revision - 1:
                raise ValueError(
                    "verification result crossed its reserved Source revision"
                )
            if snapshot is not None:
                expected = (
                    snapshot["auth"]["credentialRevision"],
                    source_verification_binding_digest(snapshot),
                )
                if (
                    release["credentialRevision"],
                    release["bindingDigest"],
                ) != expected:
                    raise ValueError(
                        "verification result differs from its trusted Source revision"
                    )
                expected_status = "passed" if operation == "verified" else "failed"
                if not (
                    snapshot["verification"]["status"] == expected_status
                    and snapshot["verification"]["testedAt"] == state_event["createdAt"]
                ):
                    raise ValueError(
                        "verification result differs from its trusted snapshot"
                    )
                verified_binding = expected if expected_status == "passed" else None

        if snapshot is not None:
            snapshot_active = {
                item["leaseId"]: item for item in snapshot["activeLeases"]
            }
            if len(snapshot_active) != len(snapshot["activeLeases"]):
                raise ValueError(
                    "Source revision snapshot repeats an active reservation"
                )
            if snapshot_active != active:
                raise ValueError(
                    "Source revision snapshot differs from replayed active reservations"
                )
            if snapshot["credentialLifecycle"]["activeLeaseCount"] != len(active):
                raise ValueError(
                    "Source revision activeLeaseCount differs from full replay"
                )
            max_concurrency = snapshot["budgets"]["maxConcurrency"]
            if (
                not isinstance(max_concurrency, int)
                or isinstance(max_concurrency, bool)
                or max_concurrency < len(active)
            ):
                raise ValueError(
                    "Source revision reservations exceed its trusted concurrency budget"
                )

            if prior_snapshot is None:
                if not (
                    operation == "registered"
                    and snapshot["verification"]["status"] == "not_run"
                ):
                    raise ValueError(
                        "registered Source revision must begin without verification"
                    )
                verified_binding = None
            elif operation == "edited":
                prior_binding = source_verification_binding_digest(prior_snapshot)
                current_binding = source_verification_binding_digest(snapshot)
                if prior_binding == current_binding:
                    if snapshot["verification"] != prior_snapshot["verification"]:
                        raise ValueError(
                            "metadata-only historical edit rewrites verification"
                        )
                elif snapshot["verification"]["status"] != "not_run":
                    raise ValueError(
                        "verification-bound historical edit retains stale verification"
                    )
                else:
                    verified_binding = None
            elif operation in {"rotation_completed", "tombstoned"}:
                if snapshot["verification"]["status"] != "not_run":
                    raise ValueError(
                        "credential/delete completion retains stale verification"
                    )
                verified_binding = None
            elif not direct_verification_result:
                if snapshot["verification"] != prior_snapshot["verification"]:
                    raise ValueError(
                        "historical Source operation rewrites verification without a verifier result"
                    )

            if operation == "enabled":
                expected = (
                    snapshot["auth"]["credentialRevision"],
                    source_verification_binding_digest(snapshot),
                )
                if (
                    snapshot["verification"]["status"] != "passed"
                    or verified_binding != expected
                ):
                    raise ValueError(
                        "enabled Source revision lacks a previously verified binding"
                    )

        if (
            current_state == "draining"
            and state_event["toState"] != "draining"
            and active
        ):
            raise ValueError("drain completion requires zero active reservations")
        current_state = state_event["toState"]
        if operation in DRAIN_START_OPERATIONS:
            drain_started_at = state_at
        elif current_state != "draining":
            drain_started_at = None
        prior_state_at = state_at
        if snapshot is not None:
            prior_snapshot = snapshot

    if current_state != source["state"]:
        raise ValueError("replayed Source state differs from snapshot")
    expected_active = {item["leaseId"]: item for item in source["activeLeases"]}
    if active != expected_active:
        raise ValueError("replayed active lease set differs from Source snapshot")
    if source["credentialLifecycle"]["activeLeaseCount"] != len(active):
        raise ValueError("Source activeLeaseCount differs from unified replay")
