"""Acceptance gate: Okta source adapter per IMPL #2 + RECONCILED §4.2.

Proves the adapter produces a canonical event from a clean Okta payload AND
correctly identifies/labels itself with a version string. Drift behavior is
exercised in test_schema_drift.py.
"""

from __future__ import annotations

from triage.schemas.alert import CanonicalAlertEvent


def test_okta_clean_payload_yields_canonical(okta_adapter, okta_payload_clean, tenant_a_id):
    event = okta_adapter.to_canonical(okta_payload_clean, tenant_id=tenant_a_id)
    assert isinstance(event, CanonicalAlertEvent)
    assert event.tenant_id == tenant_a_id
    assert event.source_system == "okta"
    assert event.source_adapter_version == "okta_v1"
    assert event.rule_id == "okta.impossible_travel.v3"
    assert event.rule_family == "impossible_travel"
    assert event.severity_hint == "P1"
    assert event.summary.startswith("Sign-on policy evaluated")
    assert event.schema_drift_detected is False
    assert event.additive_drift_fields == []


def test_okta_clean_payload_extracts_user_asset(okta_adapter, okta_payload_clean, tenant_a_id):
    event = okta_adapter.to_canonical(okta_payload_clean, tenant_id=tenant_a_id)
    assert len(event.primary_assets) == 1
    asset = event.primary_assets[0]
    assert asset.asset_id == "u_acct_lead"
    assert asset.asset_type == "user"
    assert asset.tenant_id == tenant_a_id


def test_okta_clean_payload_extracts_ip_observable(okta_adapter, okta_payload_clean, tenant_a_id):
    event = okta_adapter.to_canonical(okta_payload_clean, tenant_id=tenant_a_id)
    ip_obs = [o for o in event.observables if o.observable_type == "ip"]
    assert len(ip_obs) == 1
    assert ip_obs[0].value == "198.51.100.42"
    assert ip_obs[0].source_field_path == "client.ipAddress"


def test_okta_tenant_id_is_carried_onto_assets(okta_adapter, okta_payload_clean, tenant_b_id):
    event = okta_adapter.to_canonical(okta_payload_clean, tenant_id=tenant_b_id)
    assert event.tenant_id == tenant_b_id
    for asset in event.primary_assets:
        assert asset.tenant_id == tenant_b_id
