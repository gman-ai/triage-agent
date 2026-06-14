"""Acceptance gate: plan templates per IMPL #5a + RECONCILED §5.1.

Each of the five required families loads a valid plan with required and
optional sources. The IMPL gate specifies two specific source-exclusion
claims that drive the architecture defense:

  * impossible_travel plan EXCLUDES runbook KB (identity-driven, runbook noise)
  * c2_callback plan EXCLUDES identity_store (network-driven, identity noise)

Those exclusions are why plan-gating exists at all — they prove the plan
templates change what gets fetched per family.
"""

from __future__ import annotations

import pytest

from triage.schemas.plan import InvestigationPlan

REQUIRED_FAMILIES = [
    "impossible_travel",
    "ransomware",
    "c2_callback",
    "dns_exfil",
    "privilege_escalation",
]


def test_registry_loads_all_five_required_families(plan_registry):
    families = set(plan_registry.families())
    for f in REQUIRED_FAMILIES:
        assert f in families, f"missing template for family={f}"


@pytest.mark.parametrize("family", REQUIRED_FAMILIES)
def test_each_family_builds_a_valid_investigation_plan(plan_registry, family):
    plan = plan_registry.build_plan(rule_family=family, severity_hint="P2")
    assert isinstance(plan, InvestigationPlan)
    assert plan.alert_family == family
    assert plan.severity_hint == "P2"
    assert len(plan.required_sources) >= 2
    assert plan.rationale != ""
    assert plan.plan_template_version == "1.0"


def test_impossible_travel_plan_excludes_runbook(plan_registry):
    plan = plan_registry.build_plan("impossible_travel", "P1")
    assert "runbook" not in plan.all_planned_sources()


def test_c2_callback_plan_excludes_identity_store(plan_registry):
    plan = plan_registry.build_plan("c2_callback", "P1")
    assert "identity_store" not in plan.all_planned_sources()


def test_unknown_family_raises(plan_registry):
    with pytest.raises(KeyError):
        plan_registry.build_plan("nonexistent_family", "P0")  # type: ignore[arg-type]
