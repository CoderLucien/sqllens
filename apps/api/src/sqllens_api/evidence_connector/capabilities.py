from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Literal


class UnsupportedVersionPackError(ValueError):
    pass


class CapabilityClass(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    OPTIONAL_SENSITIVE = "optional_sensitive"


class ProbeState(StrEnum):
    AVAILABLE = "available"
    DENIED = "denied"
    UNSUPPORTED = "unsupported"
    UNVERIFIED = "unverified"


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    capability_id: str
    capability_class: CapabilityClass
    required_privilege: str
    denied_behavior: str


@dataclass(frozen=True, slots=True)
class CapabilityOutcome:
    definition: CapabilityDefinition
    state: ProbeState


@dataclass(frozen=True, slots=True)
class CapabilityEvaluation:
    pack_id: str
    source_usable: bool
    discovery_scope: Literal["current_user", "cross_user"]
    outcomes: tuple[CapabilityOutcome, ...]
    denied_required: tuple[str, ...]
    unverified_required: tuple[str, ...]
    denied_optional: tuple[str, ...]
    requested_privilege_expansion: bool = False


_COMMON_CAPABILITIES = (
    CapabilityDefinition(
        capability_id="schema_metadata",
        capability_class=CapabilityClass.REQUIRED,
        required_privilege="SELECT_ON_ALLOWED_SCHEMAS",
        denied_behavior="source_unusable",
    ),
    CapabilityDefinition(
        capability_id="statistics_metadata",
        capability_class=CapabilityClass.OPTIONAL,
        required_privilege="SELECT_ON_ALLOWED_SCHEMAS",
        denied_behavior="omit_statistics",
    ),
    CapabilityDefinition(
        capability_id="ordinary_explain",
        capability_class=CapabilityClass.OPTIONAL,
        required_privilege="SELECT_ON_ALLOWED_SCHEMAS",
        denied_behavior="use_recorded_plan_only",
    ),
    CapabilityDefinition(
        capability_id="process",
        capability_class=CapabilityClass.OPTIONAL_SENSITIVE,
        required_privilege="PROCESS",
        denied_behavior="current_user_only",
    ),
)

_CAPABILITY_MATRICES = {
    "tidb-8.5": _COMMON_CAPABILITIES,
    "pingkaidb-7.1": _COMMON_CAPABILITIES,
}


def capability_matrix(pack_id: str) -> Mapping[str, CapabilityDefinition]:
    definitions = _CAPABILITY_MATRICES.get(pack_id)
    if definitions is None:
        raise UnsupportedVersionPackError(f"unsupported version pack: {pack_id}")
    return MappingProxyType(
        {definition.capability_id: definition for definition in definitions}
    )


def evaluate_capabilities(
    pack_id: str,
    probe_outcomes: Mapping[str, ProbeState],
) -> CapabilityEvaluation:
    matrix = capability_matrix(pack_id)
    unknown_capabilities = set(probe_outcomes) - set(matrix)
    if unknown_capabilities:
        unknown = ", ".join(sorted(unknown_capabilities))
        raise ValueError(f"unknown capability probe: {unknown}")

    outcomes = tuple(
        CapabilityOutcome(
            definition=definition,
            state=probe_outcomes.get(capability_id, ProbeState.UNVERIFIED),
        )
        for capability_id, definition in matrix.items()
    )
    denied_required = _capability_ids(
        outcomes,
        capability_class=CapabilityClass.REQUIRED,
        states=(ProbeState.DENIED,),
    )
    unverified_required = _capability_ids(
        outcomes,
        capability_class=CapabilityClass.REQUIRED,
        states=(ProbeState.UNSUPPORTED, ProbeState.UNVERIFIED),
    )
    denied_optional = tuple(
        outcome.definition.capability_id
        for outcome in outcomes
        if outcome.definition.capability_class is not CapabilityClass.REQUIRED
        and outcome.state is ProbeState.DENIED
    )
    process_state = next(
        outcome.state
        for outcome in outcomes
        if outcome.definition.capability_id == "process"
    )
    return CapabilityEvaluation(
        pack_id=pack_id,
        source_usable=not denied_required and not unverified_required,
        discovery_scope=(
            "cross_user" if process_state is ProbeState.AVAILABLE else "current_user"
        ),
        outcomes=outcomes,
        denied_required=denied_required,
        unverified_required=unverified_required,
        denied_optional=denied_optional,
    )


def _capability_ids(
    outcomes: tuple[CapabilityOutcome, ...],
    *,
    capability_class: CapabilityClass,
    states: tuple[ProbeState, ...],
) -> tuple[str, ...]:
    return tuple(
        outcome.definition.capability_id
        for outcome in outcomes
        if outcome.definition.capability_class is capability_class and outcome.state in states
    )
