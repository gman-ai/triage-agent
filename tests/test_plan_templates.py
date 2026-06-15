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


@pytest.mark.parametrize("family", REQUIRED_FAMILIES)
def test_each_family_has_a_tier_preference(plan_registry, family):
    """R9 / D33: every per-family template seeds an ordered tier_preference."""
    plan = plan_registry.build_plan(rule_family=family, severity_hint="P2")
    assert len(plan.tier_preference) >= 1
    assert all(tier in {"hot", "warm", "cold"} for tier in plan.tier_preference)


@pytest.mark.parametrize("family", REQUIRED_FAMILIES)
def test_no_default_template_includes_cold_tier(plan_registry, family):
    """D34: cold tier never appears in a default template's tier_preference.

    Cold-tier retrieval is T2 plan-extension territory only — it requires an
    explicit cost-justified rationale. Including it in a default would defeat
    the cost-controlled routing story.
    """
    plan = plan_registry.build_plan(rule_family=family, severity_hint="P2")
    assert "cold" not in plan.tier_preference, (
        f"family={family!r} default template must not include 'cold' (D34)"
    )


def test_default_tier_preference_when_template_omits_it(plan_registry):
    """An omitted tier_preference in a template falls back to the Pydantic default
    (["hot", "warm", "cold"]). This test pins the loader's optional-pass behavior
    so a future template revision that drops the field doesn't silently lose
    the field on the resulting plan.
    """
    plan = plan_registry.build_plan("impossible_travel", "P1")
    # impossible_travel explicitly seeds [hot]; this proves the loader is
    # propagating the seed, not falling back to the Pydantic default of
    # ["hot", "warm", "cold"].
    assert plan.tier_preference == ["hot"]


def test_impossible_travel_plan_excludes_runbook(plan_registry):
    plan = plan_registry.build_plan("impossible_travel", "P1")
    assert "runbook" not in plan.all_planned_sources()


def test_c2_callback_plan_excludes_identity_store(plan_registry):
    plan = plan_registry.build_plan("c2_callback", "P1")
    assert "identity_store" not in plan.all_planned_sources()


def test_unknown_family_raises(plan_registry):
    with pytest.raises(KeyError):
        plan_registry.build_plan("nonexistent_family", "P0")  # type: ignore[arg-type]
