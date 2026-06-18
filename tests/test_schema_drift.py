"""Schema drift handling tests.

Four variants:
  1. Clean v1 payload  → canonical event, no drift flags.
  2. Destructive drift → DestructiveDriftError raised; caller quarantines.
  3. Additive drift    → event flows; unknown fields captured; confidence
                         is NOT downgraded (no flag implies downgrade).
  4. Unknown source    → UnknownSourceError raised by the registry.

This is the load-bearing test that distinguishes vendor benign field
additions (don't drown the SOC) from a schema break (do quarantine).
"""

from __future__ import annotations

import pytest

from triage.adapters.registry import get_adapter
from triage.errors import DestructiveDriftError, UnknownSourceError


def test_clean_v1_payload_no_drift_flags(okta_adapter, okta_payload_clean, tenant_a_id):
    event = okta_adapter.to_canonical(okta_payload_clean, tenant_id=tenant_a_id)
    assert event.schema_drift_detected is False
    assert event.additive_drift_fields == []
    assert event.raw_unknown_extras == {}


def test_destructive_drift_raises_with_attempted_paths(
    okta_adapter, okta_payload_destructive, tenant_a_id
):
    with pytest.raises(DestructiveDriftError) as excinfo:
        okta_adapter.to_canonical(okta_payload_destructive, tenant_id=tenant_a_id)
    err = excinfo.value
    assert err.source_system == "okta"
    assert "geographicalContext.country" in err.missing_field


def test_additive_drift_flows_with_unknown_fields_captured(
    okta_adapter, okta_payload_additive, tenant_a_id
):
    event = okta_adapter.to_canonical(okta_payload_additive, tenant_id=tenant_a_id)
    assert event.rule_family == "impossible_travel"
    assert event.severity_hint == "P1"
    assert "_v2_experimental_signal_block" in event.additive_drift_fields
    assert "client._experimental_tracing_id" in event.additive_drift_fields
    assert "client.geographicalContext._continent_v2_tag" in event.additive_drift_fields
    assert "actor._experimental_actor_lineage_id" in event.additive_drift_fields
    # Confidence-downgrade signal is the absence of schema_drift_detected for
    # additive drift. The boolean stays False; only destructive flips it.
    assert event.schema_drift_detected is False


def test_unknown_source_raises_via_registry(unknown_source_payload):
    source_system = unknown_source_payload["source_system"]
    with pytest.raises(UnknownSourceError) as excinfo:
        get_adapter(source_system)
    assert excinfo.value.source_system == source_system
