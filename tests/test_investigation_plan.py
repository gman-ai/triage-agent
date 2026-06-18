"""InvestigationPlan resolution tests.

T1 plan resolution is deterministic — the PlanTemplateRegistry loads YAML
templates at startup and resolves plans per (rule_family, severity_hint).
These tests pin the architectural exclusions and tier policies directly
against the registry (the LLM no longer participates in plan emission).

Pinned invariants:
  * impossible_travel plan excludes runbook KB
  * c2_callback plan excludes identity_store
  * No family default tier_preference includes "cold"
  * Each family seeds its expected required source
"""

from __future__ import annotations

import pytest

from triage.schemas.plan_loader import PlanTemplateRegistry


@pytest.fixture
def registry() -> PlanTemplateRegistry:
    return PlanTemplateRegistry()


def test_impossible_travel_plan_excludes_runbook(registry):
    plan = registry.build_plan("impossible_travel", "P2")
    assert "runbook" not in plan.all_planned_sources()


def test_c2_callback_plan_excludes_identity_store(registry):
    plan = registry.build_plan("c2_callback", "P2")
    assert "identity_store" not in plan.all_planned_sources()


@pytest.mark.parametrize(
    "family",
    ["impossible_travel", "ransomware", "c2_callback", "dns_exfil", "privilege_escalation"],
)
def test_no_family_default_plan_has_cold_tier(registry, family):
    plan = registry.build_plan(family, "P2")
    assert "cold" not in plan.tier_preference


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
def test_each_family_required_source_is_seeded(registry, family, expected_required):
    plan = registry.build_plan(family, "P2")
    assert expected_required in plan.required_sources
