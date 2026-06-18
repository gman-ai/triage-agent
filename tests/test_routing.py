"""Deterministic router tests.

10+ cases proving the router is deterministic (no LLM in the router), that
P0/P1 of deep families cannot be silently skipped on budget exhaustion, and
that rule prefilter overrides T1.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from triage.classifier.pre_classify import T1Classification
from triage.llm.budget import TenantBudget
from triage.routing.route import route
from triage.schemas.alert import Asset, CanonicalAlertEvent
from triage.schemas.plan import InvestigationPlan


def _alert(rule_family="impossible_travel", rule_id="rule_x", severity="P2") -> CanonicalAlertEvent:
    return CanonicalAlertEvent(
        tenant_id="tenant_a",
        alert_id=f"alert_{rule_family}_{severity}",
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id=rule_id,
        rule_family=rule_family,
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        detected_at=datetime(2026, 6, 15, 14, 32, 10, tzinfo=UTC),
        severity_hint=severity,
        primary_assets=[
            Asset(asset_id="u_acct_lead", asset_type="user", tenant_id="tenant_a")
        ],
        summary=f"{rule_family} {severity}",
    )


def _plan(family="impossible_travel") -> InvestigationPlan:
    return InvestigationPlan(
        plan_id="plan_test",
        alert_family=family,
        severity_hint="P2",
        required_sources=["identity_store"],
        optional_sources=[],
        tier_preference=["hot"],
        rationale="test",
        plan_template_version="1.0",
    )


def _classify(
    family="impossible_travel",
    severity="P2",
    confidence=1.0,
    tier_recommendation="standard_t2",
) -> T1Classification:
    """Deterministic T1 shim always returns confidence=1.0; tests can override
    to exercise the low-confidence branch of the router."""
    return T1Classification(
        severity_hint=severity,
        alert_family=family,
        tier_recommendation=tier_recommendation,
        confidence=confidence,
        rationale="test",
        investigation_plan=_plan(family),
    )


def _budget(spent=0.0, total=50.0) -> TenantBudget:
    return TenantBudget(tenant_id="tenant_a", daily_budget_usd=total, spent_usd=spent)


def test_rule_prefilter_known_benign_returns_rule_fast():
    decision = route(
        _alert(rule_id="benign_rule"),
        _classify(),
        _budget(),
        known_benign_rules=frozenset({"benign_rule"}),
    )
    assert decision.outcome == "rule_fast"
    assert not decision.hits_llm


def test_rule_prefilter_known_malicious_returns_rule_to_t2():
    decision = route(
        _alert(rule_id="bad_rule"),
        _classify(family="impossible_travel", severity="P3", confidence=0.95),
        _budget(),
        known_malicious_rules=frozenset({"bad_rule"}),
    )
    assert decision.outcome == "rule_to_t2"
    assert decision.hits_llm


def test_t1_low_confidence_routes_to_t2_standard():
    decision = route(
        _alert(),
        _classify(family="impossible_travel", severity="P3", confidence=0.55),
        _budget(),
    )
    assert decision.outcome == "t2_standard"


def test_p0_in_deep_family_routes_escalate():
    decision = route(
        _alert(rule_family="ransomware", severity="P0"),
        _classify(family="ransomware", severity="P0", confidence=0.85),
        _budget(),
    )
    assert decision.outcome == "t2_escalate_if_low_conf"
    assert decision.hits_llm


def test_p1_in_deep_family_routes_escalate():
    decision = route(
        _alert(rule_family="privilege_escalation", severity="P1"),
        _classify(family="privilege_escalation", severity="P1", confidence=0.85),
        _budget(),
    )
    assert decision.outcome == "t2_escalate_if_low_conf"


def test_hard_budget_p0_overrides_to_t2_urgent():
    """Budget exhaustion does NOT silently skip P0.
    The alert routes to T2 with needs_human_urgent flagged.
    """
    decision = route(
        _alert(rule_family="ransomware", severity="P0"),
        _classify(family="ransomware", severity="P0", confidence=0.85),
        _budget(spent=60.0, total=50.0),  # 120% spent
    )
    assert decision.outcome == "t2_urgent"
    assert decision.needs_human_urgent is True


def test_hard_budget_p3_skips_low_severity():
    decision = route(
        _alert(severity="P3"),
        _classify(family="impossible_travel", severity="P3", confidence=0.75),
        _budget(spent=60.0, total=50.0),
    )
    assert decision.outcome == "skip_low_severity"
    assert not decision.hits_llm


def test_no_classification_falls_back_to_source_severity():
    decision = route(
        _alert(rule_family="impossible_travel", severity="P2"),
        classification=None,
        budget=_budget(),
    )
    assert decision.outcome == "t2_standard"


def test_no_classification_with_p0_source_severity_escalates():
    decision = route(
        _alert(rule_family="ransomware", severity="P0"),
        classification=None,
        budget=_budget(),
    )
    assert decision.outcome == "t2_escalate_if_low_conf"


def test_no_classification_hard_budget_p0_still_overrides():
    decision = route(
        _alert(rule_family="ransomware", severity="P0"),
        classification=None,
        budget=_budget(spent=60.0, total=50.0),
    )
    assert decision.outcome == "t2_urgent"
    assert decision.needs_human_urgent is True


def test_p1_non_deep_family_routes_standard():
    """P1 + impossible_travel (not in DEEP_FAMILIES) does not auto-escalate."""
    decision = route(
        _alert(rule_family="impossible_travel", severity="P1"),
        _classify(family="impossible_travel", severity="P1", confidence=0.85),
        _budget(),
    )
    assert decision.outcome == "t2_standard"
