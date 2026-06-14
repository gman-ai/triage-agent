"""InvestigationPlan schema per RECONCILED §5.1 (R8, industry-pass v1.2).

T1 emits this alongside its severity/family/tier classification. The enrichment
fan-out reads required + optional sources and fetches only those. Plan-gating
beats always-fan-out on cost and latency without giving up coverage, because
required_sources are conservative starting points and T2 may extend via tool
call when reasoning identifies a gap.

D32 is binding: InvestigationPlan is a Pydantic field on T1's output, NOT a
separate Planner Agent. If anyone writes a PlannerAgent class, that is the
wrong architecture for this prototype.
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


class InvestigationPlan(BaseModel):
    plan_id: str
    alert_family: RuleFamily
    severity_hint: Severity
    required_sources: list[SourceType]
    optional_sources: list[SourceType] = Field(default_factory=list)
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
