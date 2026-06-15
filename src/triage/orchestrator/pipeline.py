"""End-to-end triage pipeline orchestrator.

Wires the components built across Days 1-4 into a single triage() function
the FastAPI surface and the notebook walkthrough both consume.

Flow:
  Okta-shaped JSON
      → SourceAdapter (canonical AlertEvent)
      → StormGrouper (incident_group or individual)
      → router.route() (RouteDecision)
      → T1 pre_classify (InvestigationPlan)
      → enrichment fan-out (EvidenceBundle with spans)
      → T2 reason() (LLM response + plan_extensions)
      → validator (TriageVerdict OR hardcoded needs_human per R6)
      → AuditLedger.record()

The orchestrator is provider-agnostic: it accepts any LLMClient. The
FastAPI surface picks FixtureReplayClient by default (no API key needed
for the panel) and switches to AnthropicClient when ANTHROPIC_API_KEY
is in env and TRIAGE_LIVE_LLM=1.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from triage.adapters.registry import get_adapter
from triage.audit.ledger import AuditLedger
from triage.classifier.pre_classify import pre_classify
from triage.enrichment.base import EnrichmentSource, SourceQuery
from triage.enrichment.fanout import build_default_registry, run_fanout
from triage.errors import DestructiveDriftError, UnknownSourceError
from triage.grouping.storm import get_storm_grouper
from triage.llm.budget import TenantBudget
from triage.llm.client import LLMClient
from triage.reasoning.agent import reason
from triage.routing.route import RouteDecision, route
from triage.schemas.alert import CanonicalAlertEvent
from triage.schemas.plan import SourceType
from triage.schemas.plan_loader import PlanTemplateRegistry
from triage.schemas.retrieval import EvidenceBundle
from triage.schemas.verdict import (
    AIMetadata,
    TriageVerdict,
    needs_human_terminal,
)
from triage.validation.validator import (
    ValidationOutcome,
    run_with_terminal_failsafe,
    validate_response,
)


@dataclass
class TriageResult:
    verdict: TriageVerdict
    route_decision: RouteDecision | None
    bundle: EvidenceBundle
    validation: ValidationOutcome | None
    degraded_reason: str | None = None
    metrics: list[str] = field(default_factory=list)


def triage(
    raw_payload: dict[str, Any],
    tenant_id: str,
    *,
    source_system: str,
    client: LLMClient,
    plan_registry: PlanTemplateRegistry | None = None,
    sources: dict[SourceType, EnrichmentSource] | None = None,
    audit: AuditLedger | None = None,
    budget: TenantBudget | None = None,
) -> TriageResult:
    plan_registry = plan_registry or PlanTemplateRegistry()
    sources = sources or build_default_registry()
    audit = audit or AuditLedger()
    budget = budget or TenantBudget(tenant_id=tenant_id, daily_budget_usd=50.0)

    received_at = datetime.now(UTC)

    # 1. Canonical alert via source adapter. Destructive drift quarantines
    #    with a hardcoded needs_human verdict; pipeline never raises uncaught.
    try:
        adapter = get_adapter(source_system)
        alert = adapter.to_canonical(raw_payload, tenant_id=tenant_id)
    except (DestructiveDriftError, UnknownSourceError) as exc:
        verdict = needs_human_terminal(
            triage_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            alert_id=raw_payload.get("uuid") or raw_payload.get("alert_id") or "unknown",
            investigation_plan={"plan_id": "quarantine"},
            received_at=received_at,
            completed_at=datetime.now(UTC),
            degraded="schema_drift",
            summary=f"Schema drift / unknown source: {exc}. Manual review required.",
        )
        bundle = EvidenceBundle()
        return TriageResult(
            verdict=verdict,
            route_decision=None,
            bundle=bundle,
            validation=None,
            degraded_reason="schema_drift",
        )

    # 2. Storm grouping. Group attaches return early with the group's verdict
    #    (the sample alert's verdict applied to all members) per §4.3.
    storm = get_storm_grouper()
    decision = storm.classify(alert)
    if decision.is_group_attach and decision.group is not None:
        # Member alert; emit storm_mode degraded verdict pointing at group.
        verdict = TriageVerdict(
            triage_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            alert_id=alert.alert_id,
            incident_group_id=decision.group.group_id,
            received_at=received_at,
            completed_at=datetime.now(UTC),
            investigation_plan={"plan_id": "storm"},
            verdict="undetermined",
            confidence=0.5,
            severity=alert.severity_hint or "P3",
            severity_rationale="Storm-grouped; verdict inherited from incident group.",
            summary=f"Member of incident group {decision.group.group_id}.",
            degraded="storm_mode",
            ai_metadata=AIMetadata(route_tier="storm_group", model_chain=[]),
        )
        return TriageResult(
            verdict=verdict,
            route_decision=None,
            bundle=EvidenceBundle(),
            validation=None,
            degraded_reason="storm_mode",
        )

    # 3. T1 pre-classifier + deterministic routing.
    classification = pre_classify(alert, client, plan_registry)
    route_decision = route(alert, classification, budget)
    plan = classification.investigation_plan

    # Skip-low-severity path: emit a degraded verdict, no LLM/retrieval spend.
    if route_decision.outcome == "skip_low_severity":
        verdict = needs_human_terminal(
            triage_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            alert_id=alert.alert_id,
            investigation_plan=plan.model_dump(),
            received_at=received_at,
            completed_at=datetime.now(UTC),
            degraded="cost_cap_reached",
            summary="Tenant budget hard-cap reached; low-severity skipped.",
        )
        return TriageResult(
            verdict=verdict,
            route_decision=route_decision,
            bundle=EvidenceBundle(),
            validation=None,
            degraded_reason="cost_cap_reached",
            metrics=list(route_decision.metrics),
        )

    # 4. Plan-gated tier-ordered fan-out.
    query = SourceQuery(
        tenant_id=alert.tenant_id,
        alert_id=alert.alert_id,
        entity_id=alert.grouping_entity(),
        ioc=alert.primary_ioc(),
        extra={"rule_family": alert.rule_family},
    )
    bundle = run_fanout(plan, query, sources)

    # 5. T2 reasoning agent (single pass; plan-extension loop bounded by
    #    MAX_PLAN_EXTENSIONS inside reason()).
    response, augmented_bundle, plan_extensions = reason(
        alert, plan, bundle, client, sources=sources
    )

    # 6. Output validator with terminal failsafe (no exception on double-fail).
    ai_metadata = AIMetadata(
        route_tier="standard_t2",
        model_chain=[classification.tier_recommendation, "sonnet"],
        cost_usd=classification.cost_usd + response.cost_usd,
        tokens={
            "prompt": classification.tokens_in + response.tokens_in,
            "completion": classification.tokens_out + response.tokens_out,
        },
        enrichments_failed=list(augmented_bundle.enrichments_failed),
    )
    outcome = validate_response(
        response.content,
        augmented_bundle,
        triage_id=f"triage_{alert.alert_id}",
        tenant_id=alert.tenant_id,
        alert_id=alert.alert_id,
        investigation_plan_dump=plan.model_dump(),
        received_at=received_at,
        ai_metadata=ai_metadata,
    )

    # 7. Audit ledger.
    audit.record(
        verdict=outcome.verdict,
        bundle=augmented_bundle,
        prompt_text="<prompt text not persisted by default>",
        response_text=response.content,
        validation_result="ok" if outcome.ok else "schema_fail",
    )

    # Plug needs_human_urgent if the router said so but the LLM didn't surface it.
    if route_decision.needs_human_urgent and not outcome.verdict.needs_human_urgent:
        outcome.verdict.needs_human_urgent = True
        outcome.verdict.degraded = outcome.verdict.degraded or "needs_human_urgent"

    return TriageResult(
        verdict=outcome.verdict,
        route_decision=route_decision,
        bundle=augmented_bundle,
        validation=outcome,
        degraded_reason=outcome.verdict.degraded,
        metrics=list(route_decision.metrics),
    )
