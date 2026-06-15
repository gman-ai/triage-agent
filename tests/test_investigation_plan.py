"""Acceptance gate: T1 emits a valid InvestigationPlan per family
per IMPL #5 + RECONCILED §5.1.

Specifically pins the two architectural exclusions from IMPL #5:
  * impossible_travel plan excludes runbook KB
  * c2_callback plan excludes identity_store

Plus the tier_preference exclusions from v1.3 / D34:
  * No family default includes "cold"
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from triage.classifier.pre_classify import build_t1_request, pre_classify
from triage.llm.client import FixtureReplayClient
from triage.schemas.alert import Asset, CanonicalAlertEvent


def _make_alert(rule_family: str) -> CanonicalAlertEvent:
    return CanonicalAlertEvent(
        tenant_id="tenant_a",
        alert_id=f"alert_plan_{rule_family}",
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id=f"okta.{rule_family}.v1",
        rule_family=rule_family,
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        detected_at=datetime(2026, 6, 15, 14, 32, 10, tzinfo=UTC),
        severity_hint="P2",
        primary_assets=[
            Asset(asset_id="u_acct_lead", asset_type="user", tenant_id="tenant_a")
        ],
        summary=f"{rule_family} test",
    )


def _seed_fixture(tmp_path, alert, family):
    request = build_t1_request(alert)
    digest = request.digest()
    payload = {
        "content": json.dumps(
            {
                "severity_hint": "P2",
                "alert_family": family,
                "tier_recommendation": "standard_t2",
                "confidence": 0.78,
                "rationale": "fixture",
                "override_plan": None,
            }
        ),
        "stop_reason": "end_turn",
        "tokens_in": 400,
        "tokens_out": 100,
        "cost_usd": 0.0003,
        "model": "claude-haiku-4-5-20251001",
    }
    (tmp_path / f"{digest}.json").write_text(json.dumps(payload))


def test_impossible_travel_plan_excludes_runbook(tmp_path):
    alert = _make_alert("impossible_travel")
    _seed_fixture(tmp_path, alert, "impossible_travel")
    result = pre_classify(alert, FixtureReplayClient(fixture_dir=tmp_path))
    assert "runbook" not in result.investigation_plan.all_planned_sources()


def test_c2_callback_plan_excludes_identity_store(tmp_path):
    alert = _make_alert("c2_callback")
    _seed_fixture(tmp_path, alert, "c2_callback")
    result = pre_classify(alert, FixtureReplayClient(fixture_dir=tmp_path))
    assert "identity_store" not in result.investigation_plan.all_planned_sources()


@pytest.mark.parametrize(
    "family",
    ["impossible_travel", "ransomware", "c2_callback", "dns_exfil", "privilege_escalation"],
)
def test_no_family_default_plan_has_cold_tier(tmp_path, family):
    alert = _make_alert(family)
    _seed_fixture(tmp_path, alert, family)
    result = pre_classify(alert, FixtureReplayClient(fixture_dir=tmp_path))
    assert "cold" not in result.investigation_plan.tier_preference


@pytest.mark.parametrize(
    "family,expected_required",
    [
        ("impossible_travel", "identity_store"),
        ("ransomware", "asset_cmdb"),
        ("c2_callback", "threat_intel"),
        ("dns_exfil", "threat_intel"),
        ("privilege_escalation", "identity_store"),
    ],
)
def test_each_family_required_source_is_seeded(tmp_path, family, expected_required):
    alert = _make_alert(family)
    _seed_fixture(tmp_path, alert, family)
    result = pre_classify(alert, FixtureReplayClient(fixture_dir=tmp_path))
    assert expected_required in result.investigation_plan.required_sources
