"""Canonical alert contract tests.

Proves the single shape the LLM and downstream see is enforceable. A schema
that accepts any input dict is not a schema; the test pins the validation.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from triage.schemas.alert import Asset, CanonicalAlertEvent, Observable


def _valid_event_kwargs() -> dict:
    return dict(
        tenant_id="tenant_a",
        alert_id="alert_001",
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id="okta.impossible_travel.v3",
        rule_family="impossible_travel",
        received_at=datetime(2026, 6, 15, 14, 32, 11),
        detected_at=datetime(2026, 6, 15, 14, 32, 10),
        severity_hint="P1",
        primary_assets=[
            Asset(
                asset_id="u_acct_lead",
                asset_type="user",
                tenant_id="tenant_a",
            )
        ],
        observables=[
            Observable(
                observable_type="ip",
                value="198.51.100.42",
                source_field_path="client.ipAddress",
            )
        ],
        summary="impossible travel",
    )


def test_canonical_event_round_trip():
    event = CanonicalAlertEvent(**_valid_event_kwargs())
    serialized = event.model_dump()
    rehydrated = CanonicalAlertEvent.model_validate(serialized)
    assert rehydrated == event
    assert rehydrated.schema_version == "1.0"


def test_canonical_event_rejects_unknown_severity():
    kwargs = _valid_event_kwargs()
    kwargs["severity_hint"] = "URGENT"
    with pytest.raises(ValidationError):
        CanonicalAlertEvent(**kwargs)


def test_canonical_event_rejects_unknown_rule_family():
    kwargs = _valid_event_kwargs()
    kwargs["rule_family"] = "speculative_anomaly"
    with pytest.raises(ValidationError):
        CanonicalAlertEvent(**kwargs)


def test_canonical_event_requires_tenant_id():
    kwargs = _valid_event_kwargs()
    kwargs.pop("tenant_id")
    with pytest.raises(ValidationError):
        CanonicalAlertEvent(**kwargs)


def test_canonical_event_requires_source_adapter_version():
    kwargs = _valid_event_kwargs()
    kwargs.pop("source_adapter_version")
    with pytest.raises(ValidationError):
        CanonicalAlertEvent(**kwargs)


def test_grouping_entity_prefers_primary_asset():
    event = CanonicalAlertEvent(**_valid_event_kwargs())
    assert event.grouping_entity() == "u_acct_lead"


def test_grouping_entity_falls_back_to_observable():
    kwargs = _valid_event_kwargs()
    kwargs["primary_assets"] = []
    event = CanonicalAlertEvent(**kwargs)
    assert event.grouping_entity() == "198.51.100.42"


def test_primary_ioc_picks_highest_priority_observable():
    kwargs = _valid_event_kwargs()
    kwargs["observables"] = [
        Observable(
            observable_type="user_id",
            value="u_acct_lead",
            source_field_path="actor.id",
        ),
        Observable(
            observable_type="ip",
            value="198.51.100.42",
            source_field_path="client.ipAddress",
        ),
        Observable(
            observable_type="domain",
            value="evil.example.invalid",
            source_field_path="dns.query",
        ),
    ]
    event = CanonicalAlertEvent(**kwargs)
    assert event.primary_ioc() == "evil.example.invalid"
