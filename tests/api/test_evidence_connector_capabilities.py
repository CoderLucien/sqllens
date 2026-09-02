from __future__ import annotations

import pytest
from sqllens_api.evidence_connector import (
    CapabilityClass,
    ProbeState,
    UnsupportedVersionPackError,
    capability_matrix,
    evaluate_capabilities,
)


@pytest.mark.parametrize("pack_id", ["tidb-8.5", "pingkaidb-7.1"])
def test_process_is_optional_sensitive_in_each_supported_pack(pack_id: str) -> None:
    matrix = capability_matrix(pack_id)

    assert matrix["schema_metadata"].capability_class is CapabilityClass.REQUIRED
    assert matrix["process"].capability_class is CapabilityClass.OPTIONAL_SENSITIVE
    assert matrix["process"].required_privilege == "PROCESS"
    assert matrix["process"].denied_behavior == "current_user_only"


def test_process_denial_is_visible_degradation_not_permission_expansion() -> None:
    result = evaluate_capabilities(
        "tidb-8.5",
        {
            "schema_metadata": ProbeState.AVAILABLE,
            "statistics_metadata": ProbeState.AVAILABLE,
            "ordinary_explain": ProbeState.AVAILABLE,
            "process": ProbeState.DENIED,
        },
    )

    assert result.source_usable is True
    assert result.discovery_scope == "current_user"
    assert result.denied_required == ()
    assert result.denied_optional == ("process",)
    assert result.requested_privilege_expansion is False


def test_process_availability_enables_cross_user_discovery() -> None:
    result = evaluate_capabilities(
        "pingkaidb-7.1",
        {
            "schema_metadata": ProbeState.AVAILABLE,
            "statistics_metadata": ProbeState.AVAILABLE,
            "ordinary_explain": ProbeState.AVAILABLE,
            "process": ProbeState.AVAILABLE,
        },
    )

    assert result.source_usable is True
    assert result.discovery_scope == "cross_user"
    assert result.denied_optional == ()


def test_required_capability_denial_fails_closed() -> None:
    result = evaluate_capabilities(
        "pingkaidb-7.1",
        {
            "schema_metadata": ProbeState.DENIED,
            "process": ProbeState.AVAILABLE,
        },
    )

    assert result.source_usable is False
    assert result.denied_required == ("schema_metadata",)
    assert result.discovery_scope == "cross_user"


def test_missing_required_probe_is_unverified_and_fails_closed() -> None:
    result = evaluate_capabilities(
        "tidb-8.5",
        {"process": ProbeState.DENIED},
    )

    assert result.source_usable is False
    assert result.unverified_required == ("schema_metadata",)
    assert result.discovery_scope == "current_user"


def test_unknown_pack_has_no_capability_matrix() -> None:
    with pytest.raises(UnsupportedVersionPackError, match="unsupported version pack"):
        capability_matrix("tidb-8.4")
