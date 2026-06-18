"""InvestigationPlan schema.

T1 resolves this from (rule_family, severity_hint) against the YAML plan
template registry. The enrichment fan-out reads required + optional
sources and fetches only those. Plan-gating beats always-fan-out on cost
and latency without giving up coverage, because required_sources are
conservative starting points and T2 may extend via tool call when
reasoning identifies a gap.

The InvestigationPlan is a typed Pydantic object resolved deterministically;
plan emission is NOT a separate Planner Agent. Multi-agent planning would
add orchestration latency and cost without measurable accuracy at this
scale.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from triage.schemas.alert import RuleFamily, Severity

SourceType = Literal[
    "asset_cmdb",
    "identity_store",
    "historical",
    "threat_intel",
    "runbook",
    "log_search",
    "siem_alert_field",
]

PlanFallback = Literal["proceed_with_partial", "request_more", "needs_human"]

StorageTier = Literal["hot", "warm", "cold"]
# Where the retrieval lives in the tiered telemetry pipeline.
#   hot  = SIEM-resident / indexed / fast (recent identity, current alerts, threat intel)
#   warm = pipeline-resident operational logs (queryable, not SIEM-indexed)
#   cold = compliance archive (badge logs, retention-required, on-demand pull)


class InvestigationPlan(BaseModel):
    plan_id: str
    alert_family: RuleFamily
    severity_hint: Severity
    required_sources: list[SourceType]
    optional_sources: list[SourceType] = Field(default_factory=list)
    tier_preference: list[StorageTier] = Field(default_factory=lambda: ["hot", "warm", "cold"])
    # Ordered tier preference. Plan-gated fan-out attempts cheaper tiers
    # first. Per-family default templates never include "cold"; cold-tier
    # retrieval is T2 plan-extension territory only.
    expected_fact_categories: list[str] = Field(default_factory=list)
    rationale: str
    fallback_strategy: PlanFallback = "proceed_with_partial"
    plan_template_version: str

    def all_planned_sources(self) -> set[SourceType]:
        """Union of required and optional sources.

        Enrichment fan-out uses this to enforce plan-gating: any source not in
        this set must not be fetched for this alert.
        """
        return set(self.required_sources) | set(self.optional_sources)
