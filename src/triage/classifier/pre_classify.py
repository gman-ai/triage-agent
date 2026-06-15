"""T1 pre-classifier per RECONCILED §6 + D31 + R8.

Haiku 4.5, JSON-mode forced output. Emits:
  * severity_hint (closed enum P0..P4)
  * alert_family (matches CanonicalAlertEvent.rule_family closed enum)
  * tier recommendation (fast_t1 / standard_t2 / deep_t3 / storm_group)
  * confidence (0.0-1.0)
  * InvestigationPlan (R8 / §5.1) — required + optional sources + tier_preference

Plan selection: T1 may either accept the rule_family's seeded template (from
PlanTemplateRegistry) or override it. The prototype's T1 prompt instructs
the model to accept the seeded plan and only override when the alert
explicitly signals a different family than the source rule_id suggests.
This keeps Day 3 tests deterministic against fixture replays.
"""

from __future__ import annotations

import json
import uuid

from pydantic import BaseModel, ValidationError

from triage.llm.client import LLMClient, LLMRequest
from triage.schemas.alert import CanonicalAlertEvent, RuleFamily, Severity
from triage.schemas.plan import InvestigationPlan
from triage.schemas.plan_loader import PlanTemplateRegistry

HAIKU_MODEL = "claude-haiku-4-5-20251001"

T1_SYSTEM_PROMPT = """\
You are a security operations pre-classifier. You receive a canonical alert
event and must emit a single JSON object matching the schema below. You do
NOT investigate. You do NOT recommend actions. You produce a routing
classification only.

Constraints:
- severity_hint MUST be one of: P0, P1, P2, P3, P4
- alert_family MUST be one of the canonical rule families
- tier_recommendation MUST be one of: fast_t1, standard_t2, deep_t3
- confidence MUST be a float between 0.0 and 1.0
- override_plan: omit unless you have a specific reason; if omitted, the
  seeded per-family plan template will be used.

Schema:
{
  "severity_hint": "P0" | "P1" | "P2" | "P3" | "P4",
  "alert_family": "<one of the canonical rule families>",
  "tier_recommendation": "fast_t1" | "standard_t2" | "deep_t3",
  "confidence": 0.0..1.0,
  "rationale": "<one short sentence>",
  "override_plan": null  // or {"required_sources": [...], "optional_sources": [...], "tier_preference": [...]}
}
"""


class T1Output(BaseModel):
    severity_hint: Severity
    alert_family: RuleFamily
    tier_recommendation: str
    confidence: float
    rationale: str
    override_plan: dict | None = None


class T1Classification(BaseModel):
    """The full classification produced by T1: model output + selected plan."""

    severity_hint: Severity
    alert_family: RuleFamily
    tier_recommendation: str
    confidence: float
    rationale: str
    investigation_plan: InvestigationPlan
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0


def build_t1_request(alert: CanonicalAlertEvent) -> LLMRequest:
    user_payload = {
        "tenant_id": alert.tenant_id,
        "alert_id": alert.alert_id,
        "source_system": alert.source_system,
        "rule_id": alert.rule_id,
        "rule_family_hint": alert.rule_family,
        "severity_hint_source": alert.severity_hint,
        "summary": alert.summary,
        "primary_assets": [
            {"asset_id": a.asset_id, "asset_type": a.asset_type, "criticality": a.criticality}
            for a in alert.primary_assets
        ],
        "observables": [
            {"type": o.observable_type, "value": o.value} for o in alert.observables
        ],
    }
    return LLMRequest(
        model=HAIKU_MODEL,
        system=T1_SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": json.dumps(user_payload, sort_keys=True, default=str),
            }
        ],
        response_format={"type": "json_object"},
        max_tokens=512,
        temperature=0.0,
    )


def pre_classify(
    alert: CanonicalAlertEvent,
    client: LLMClient,
    plan_registry: PlanTemplateRegistry | None = None,
) -> T1Classification:
    registry = plan_registry or PlanTemplateRegistry()
    request = build_t1_request(alert)
    response = client.complete(request)

    try:
        parsed = T1Output.model_validate_json(response.content)
    except ValidationError as exc:
        # Per §2 degraded taxonomy: T1 schema failure is treated as needs_human
        # downstream. The router catches the classification miss and routes to
        # T2 with `mode="needs_human_urgent"` if severity hints high; otherwise
        # to needs_human. The classifier does NOT raise; it returns a default
        # that makes the router's behavior predictable.
        return _failsafe_classification(alert, registry, reason=str(exc))

    plan = _build_plan(parsed, registry)
    return T1Classification(
        severity_hint=parsed.severity_hint,
        alert_family=parsed.alert_family,
        tier_recommendation=parsed.tier_recommendation,
        confidence=parsed.confidence,
        rationale=parsed.rationale,
        investigation_plan=plan,
        tokens_in=response.tokens_in,
        tokens_out=response.tokens_out,
        cost_usd=response.cost_usd,
    )


def _build_plan(parsed: T1Output, registry: PlanTemplateRegistry) -> InvestigationPlan:
    """Build the plan: use seeded template by default; apply override fields
    when present. override_plan is intentionally a thin override surface — the
    classifier can NOT invent new SourceTypes; Pydantic validation rejects
    out-of-vocabulary tokens.
    """
    base_plan = registry.build_plan(parsed.alert_family, parsed.severity_hint)
    if not parsed.override_plan:
        return base_plan
    return base_plan.model_copy(
        update={
            k: v
            for k, v in parsed.override_plan.items()
            if k in {"required_sources", "optional_sources", "tier_preference"}
        }
    )


def _failsafe_classification(
    alert: CanonicalAlertEvent,
    registry: PlanTemplateRegistry,
    reason: str,
) -> T1Classification:
    """T1 schema failure: classify as the source's rule_family, route to T2.

    This is the §2 degraded-mode behavior. The router treats `confidence=0.0`
    + `tier_recommendation=standard_t2` as a forced-T2 path so the LLM stack
    still has a chance to recover.
    """
    plan = registry.build_plan(
        alert.rule_family if alert.rule_family != "other" else "impossible_travel",
        alert.severity_hint or "P3",
    )
    return T1Classification(
        severity_hint=alert.severity_hint or "P3",
        alert_family=alert.rule_family,
        tier_recommendation="standard_t2",
        confidence=0.0,
        rationale=f"T1 schema failure (failsafe): {reason[:200]}",
        investigation_plan=plan,
    )
