"""Severity-aware budget override tests.

Budget exhaustion does NOT silently skip P0 alerts. A ransomware-family P0
during exhausted budget routes to T2 with needs_human_urgent AND emits
`budget_exceeded_p0_override` as a routing metric. The audit ledger
persists the metric on the triage row.
"""

from __future__ import annotations

from datetime import UTC, datetime

from triage.classifier.pre_classify import T1Classification
from triage.llm.budget import TenantBudget
from triage.routing.route import route
from triage.schemas.alert import Asset, CanonicalAlertEvent
from triage.schemas.plan import InvestigationPlan


def _alert(rule_family: str, severity: str) -> CanonicalAlertEvent:
    return CanonicalAlertEvent(
        tenant_id="tenant_a",
        alert_id=f"alert_{rule_family}_{severity}",
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id="okta.test.v1",
        rule_family=rule_family,
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        detected_at=datetime(2026, 6, 15, 14, 32, 10, tzinfo=UTC),
        severity_hint=severity,
        primary_assets=[
            Asset(asset_id="srv_x", asset_type="service", tenant_id="tenant_a")
        ],
        summary="test",
    )


def _plan(family: str) -> InvestigationPlan:
    return InvestigationPlan(
        plan_id="plan_x",
        alert_family=family,
        severity_hint="P0",
        required_sources=["asset_cmdb"],
        optional_sources=[],
        tier_preference=["hot"],
        rationale="test",
        plan_template_version="1.0",
    )


def _t1(family: str, severity: str, confidence: float = 0.85) -> T1Classification:
    return T1Classification(
        severity_hint=severity,
        alert_family=family,
        tier_recommendation="standard_t2",
        confidence=confidence,
        rationale="test",
        investigation_plan=_plan(family),
    )


def test_p0_ransomware_during_exhausted_budget_overrides_with_metric():
    """Budget hard-cap reached; P0 ransomware still reaches T2 with
    needs_human_urgent AND budget_exceeded_p0_override metric.
    """
    decision = route(
        _alert("ransomware", "P0"),
        _t1("ransomware", "P0"),
        TenantBudget(tenant_id="tenant_a", daily_budget_usd=10.0, spent_usd=15.0),
    )
    assert decision.outcome == "t2_urgent"
    assert decision.needs_human_urgent is True
    assert "budget_exceeded_p0_override" in decision.metrics


def test_p1_privesc_during_exhausted_budget_overrides_with_metric():
    decision = route(
        _alert("privilege_escalation", "P1"),
        _t1("privilege_escalation", "P1"),
        TenantBudget(tenant_id="tenant_a", daily_budget_usd=10.0, spent_usd=12.0),
    )
    assert decision.outcome == "t2_urgent"
    assert "budget_exceeded_p0_override" in decision.metrics


def test_p3_during_exhausted_budget_skips_silently_in_telemetry():
    """A P3 during budget exhaustion is skipped. No P0 override metric
    fires — that telemetry is reserved for the override path.
    """
    decision = route(
        _alert("impossible_travel", "P3"),
        _t1("impossible_travel", "P3"),
        TenantBudget(tenant_id="tenant_a", daily_budget_usd=10.0, spent_usd=15.0),
    )
    assert decision.outcome == "skip_low_severity"
    assert "budget_exceeded_p0_override" not in decision.metrics


def test_no_classification_path_also_emits_override_metric():
    """If T1 didn't run (e.g., rule prefilter ahead) and budget is exhausted
    on a P0 deep family, the no-T1 routing branch must ALSO emit the metric.
    """
    decision = route(
        _alert("ransomware", "P0"),
        classification=None,
        budget=TenantBudget(tenant_id="tenant_a", daily_budget_usd=10.0, spent_usd=15.0),
    )
    assert decision.outcome == "t2_urgent"
    assert "budget_exceeded_p0_override" in decision.metrics


def test_unexhausted_budget_does_not_emit_override():
    decision = route(
        _alert("ransomware", "P0"),
        _t1("ransomware", "P0"),
        TenantBudget(tenant_id="tenant_a", daily_budget_usd=100.0, spent_usd=10.0),
    )
    assert decision.outcome == "t2_escalate_if_low_conf"
    assert decision.metrics == []
