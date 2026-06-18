"""T1 deterministic plan resolver tests.

T1 is no longer an LLM call. It is a deterministic YAML lookup keyed on
`(rule_family, severity_hint)`. These tests pin:
  1. Every supported family resolves to a valid InvestigationPlan
  2. The alert's severity_hint flows into the resolved plan
  3. The deterministic surface returns confidence=1.0, tier_recommendation=standard_t2,
     and zero cost/tokens (no LLM spend)
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from triage.classifier.pre_classify import T1Classification, pre_classify
from triage.schemas.alert import Asset, CanonicalAlertEvent, Observable


def _make_alert(rule_family="impossible_travel", severity="P1") -> CanonicalAlertEvent:
    return CanonicalAlertEvent(
        tenant_id="tenant_a",
        alert_id="alert_t1_test_001",
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id=f"okta.{rule_family}.v1",
        rule_family=rule_family,
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        detected_at=datetime(2026, 6, 15, 14, 32, 10, tzinfo=UTC),
        severity_hint=severity,
        primary_assets=[
            Asset(asset_id="u_acct_lead", asset_type="user", tenant_id="tenant_a")
        ],
        observables=[
            Observable(
                observable_type="ip",
                value="198.51.100.42",
                source_field_path="client.ipAddress",
            )
        ],
        summary=f"{rule_family} test",
    )


@pytest.mark.parametrize(
    "family,expected_required_source",
    [
        ("impossible_travel", "identity_store"),
        ("ransomware", "asset_cmdb"),
        ("c2_callback", "threat_intel"),
        ("dns_exfil", "threat_intel"),
        ("privilege_escalation", "identity_store"),
    ],
)
def test_pre_classify_returns_yaml_plan_for_each_family(family, expected_required_source):
    """Every supported family resolves to a plan with the expected required source."""
    alert = _make_alert(rule_family=family, severity="P2")
    result = pre_classify(alert)

    assert isinstance(result, T1Classification)
    assert result.alert_family == family
    assert expected_required_source in result.investigation_plan.required_sources


def test_pre_classify_uses_alert_severity_hint():
    """The alert's severity_hint flows through to the resolved plan."""
    p0_result = pre_classify(_make_alert(severity="P0"))
    p3_result = pre_classify(_make_alert(severity="P3"))

    assert p0_result.severity_hint == "P0"
    assert p3_result.severity_hint == "P3"
    # Both resolve a plan (templates accept all severities for the family)
    assert p0_result.investigation_plan is not None
    assert p3_result.investigation_plan is not None


def test_pre_classify_returns_confidence_one_and_tier_standard_t2():
    """Deterministic shim returns confidence=1.0 and standard_t2 with zero LLM spend."""
    result = pre_classify(_make_alert())

    assert result.confidence == 1.0
    assert result.tier_recommendation == "standard_t2"
    assert result.cost_usd == 0.0
    assert result.tokens_in == 0
    assert result.tokens_out == 0
    assert "deterministic" in result.rationale.lower()
