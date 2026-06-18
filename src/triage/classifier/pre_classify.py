"""T1 deterministic plan resolver.

T1 is a deterministic policy lookup, not an LLM call. The investigation plan
is resolved from `(rule_family, severity_hint)` against the YAML plan-template
registry. LLM judgment enters only at T2 (Sonnet reasoning) and T3 (Opus
escalation).

This module exists as a thin shim so downstream callers (orchestrator, router,
audit, eval) continue to consume the same `T1Classification` struct shape. The
shim populates the struct from adapter outputs and the registry; there is no
provider call, no token spend, no failsafe path because there is no fallible
LLM step.

Rationale: routing and plan selection are detection-engineering decisions that
belong in YAML, where SecOps teams own them. The LLM picking plans would buy
adaptability at the cost of auditability; the engine accommodates upgrading T1
to an LLM strategist later because the routing struct shape is the same
regardless of where the plan came from.
"""

from __future__ import annotations

from pydantic import BaseModel

from triage.schemas.alert import CanonicalAlertEvent, RuleFamily, Severity
from triage.schemas.plan import InvestigationPlan
from triage.schemas.plan_loader import PlanTemplateRegistry


class T1Classification(BaseModel):
    """Routing struct produced by deterministic T1.

    Fields kept for compatibility with the router, audit ledger, and eval
    harness. `confidence` is always 1.0 (the lookup is deterministic, not
    probabilistic) and `tier_recommendation` is always `standard_t2`
    (downstream routing handles severity-aware escalation and budget overrides).
    """

    severity_hint: Severity
    alert_family: RuleFamily
    tier_recommendation: str = "standard_t2"
    confidence: float = 1.0
    rationale: str = "deterministic plan lookup"
    investigation_plan: InvestigationPlan
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0


def pre_classify(
    alert: CanonicalAlertEvent,
    plan_registry: PlanTemplateRegistry | None = None,
) -> T1Classification:
    """Resolve the investigation plan for an alert via deterministic lookup.

    The alert's `rule_family` (set by the source adapter) and `severity_hint`
    drive the YAML template selection. No LLM call.

    `severity_hint` defaults to `P3` when the adapter did not emit one — the
    same convention the previous LLM-based failsafe path used so downstream
    routing behavior is preserved.
    """
    registry = plan_registry or PlanTemplateRegistry()
    severity = alert.severity_hint or "P3"
    plan = registry.build_plan(alert.rule_family, severity)
    return T1Classification(
        severity_hint=severity,
        alert_family=alert.rule_family,
        investigation_plan=plan,
    )
