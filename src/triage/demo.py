"""End-to-end demo: one alert through the same pipeline stages used by triage().

Loads a canonical Okta impossible_travel payload and walks adapter, storm
grouping, T1 plan resolution, routing, enrichment fan-out, T2 reasoning, and
output validation — printing a trace at each stage.

The T2 response is canned (built post-fanout so its observed_facts reference
real retrieval IDs from the actual bundle). Cost is computed via cost_for()
from the same pricing table the rest of the engine uses. No latency printed;
no fabricated numbers. The trace shows whatever the actual run emits.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from triage.adapters.registry import get_adapter
from triage.classifier.pre_classify import pre_classify
from triage.enrichment.base import SourceQuery
from triage.enrichment.fanout import build_default_registry, run_fanout
from triage.grouping.storm import get_storm_grouper
from triage.llm.budget import TenantBudget
from triage.llm.client import LLMResponse, SequenceClient, cost_for
from triage.reasoning.agent import reason
from triage.routing.route import route
from triage.schemas.plan_loader import PlanTemplateRegistry
from triage.schemas.verdict import AIMetadata
from triage.validation.validator import run_with_terminal_failsafe


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    payload_path = repo_root / "fixtures" / "okta" / "sample_v1_clean.json"
    payload = json.loads(payload_path.read_text())

    tenant_id = "tenant_a"
    received_at = datetime.now(UTC)

    print(f"[demo] alert: okta impossible_travel, {tenant_id}, severity_hint=P1")

    adapter = get_adapter("okta")
    alert = adapter.to_canonical(payload, tenant_id=tenant_id)
    print(f"[demo] adapter: okta_v1 -> CanonicalAlertEvent (alert_id={alert.alert_id})")

    storm = get_storm_grouper()
    decision = storm.classify(alert)
    storm_label = "individual" if not decision.is_group_attach else "group-attached"
    print(f"[demo] storm: {storm_label}")

    registry = PlanTemplateRegistry()
    classification = pre_classify(alert, registry)
    plan = classification.investigation_plan
    budget = TenantBudget(tenant_id=tenant_id, daily_budget_usd=50.0)
    route_decision = route(alert, classification, budget)
    plan_sources = ", ".join(plan.required_sources + plan.optional_sources)
    print(
        f"[demo] T1 plan: {plan.alert_family} "
        f"(template {plan.plan_template_version}; "
        f"sources: {plan_sources})"
    )
    print(f"[demo] route: {route_decision.outcome}")

    sources = build_default_registry()
    query = SourceQuery(
        tenant_id=tenant_id,
        alert_id=alert.alert_id,
        entity_id=alert.grouping_entity(),
        ioc=alert.primary_ioc(),
        extra={"rule_family": alert.rule_family},
    )
    bundle = run_fanout(plan, query, sources)
    ok_sources = sorted({r.source_type for r in bundle.retrievals})
    failed = list(bundle.enrichments_failed or [])
    parts = [f"{s} ok" for s in ok_sources]
    parts += [f"{s} skipped" for s in failed]
    print(f"[demo] fan-out: {', '.join(parts)}")

    canned_response, tokens_in, tokens_out = _build_canned_response(bundle)
    model = "claude-sonnet-4-6"
    cost = cost_for(model, tokens_in, tokens_out)
    client = SequenceClient(
        [
            LLMResponse(
                content=json.dumps(canned_response),
                stop_reason="end_turn",
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost,
                model=model,
            )
        ]
    )

    response, augmented_bundle, _plan_ext = reason(
        alert, plan, bundle, client, sources=sources
    )
    parsed = json.loads(response.content)
    print(
        f"[demo] T2 reasoning: {parsed['verdict']}, confidence={parsed['confidence']}"
    )

    ai_metadata = AIMetadata(
        route_tier="standard_t2",
        model_chain=["sonnet"],
        cost_usd=cost,
        tokens={"prompt": tokens_in, "completion": tokens_out},
    )
    outcome = run_with_terminal_failsafe(
        first_response_content=response.content,
        retry_callable=lambda: response.content,
        bundle=augmented_bundle,
        triage_id=f"demo_{alert.alert_id}",
        tenant_id=tenant_id,
        alert_id=alert.alert_id,
        investigation_plan_dump=plan.model_dump(),
        received_at=received_at,
        ai_metadata=ai_metadata,
    )
    validator_label = (
        "OK"
        if outcome.ok
        else "FAIL (" + ", ".join(f.layer for f in outcome.failures) + ")"
    )
    print(f"[demo] validator: {validator_label}")

    v = outcome.verdict
    print(f"[demo] verdict: {v.verdict}, severity={v.severity}")
    if v.recommendations:
        rec = v.recommendations[0]
        print(f"[demo] recommendation: {rec.action}")
    print(
        f"[demo]   observed_facts={len(v.observed_facts)}, "
        f"inferences={len(v.inferences)}"
    )
    print(
        f"[demo]   tokens: {tokens_in} in / {tokens_out} out  "
        f"|  cost: ${cost:.4f}  (deterministic replay)"
    )
    return 0


def _build_canned_response(bundle):
    """Build a T2 verdict JSON whose observed_facts cite real retrieval IDs
    from this run's bundle. field_path is relative to ref.payload (e.g.,
    "mfa_enabled" means ref.payload["mfa_enabled"]). The fields below match
    the tenant_a seed data the validator will walk against.
    """
    identity_refs = bundle.by_source("identity_store")
    threat_refs = bundle.by_source("threat_intel")
    if not identity_refs or not threat_refs:
        print(
            "[demo] error: expected identity_store + threat_intel in bundle; "
            f"got identity={len(identity_refs)}, threat={len(threat_refs)}",
            file=sys.stderr,
        )
        sys.exit(1)
    id_ref = identity_refs[0]
    ti_ref = threat_refs[0]

    response = {
        "verdict": "likely_true_positive",
        "confidence": 0.81,
        "severity": "P1",
        "severity_rationale": "Geo anomaly with intact MFA on the affected account.",
        "summary": (
            "User u_acct_lead authenticated from Bulgaria 30s after "
            "Portland session; MFA intact, threat-intel reputation unknown."
        ),
        "attack_chain": [],
        "observed_facts": [
            {
                "fact_id": "f1",
                "claim": "User has MFA enabled.",
                "retrieval_id": id_ref.retrieval_id,
                "field_path": "mfa_enabled",
                "expected_value": True,
                "confidence": 0.95,
            },
            {
                "fact_id": "f2",
                "claim": "Threat intel reputation is unknown.",
                "retrieval_id": ti_ref.retrieval_id,
                "field_path": "reputation",
                "expected_value": "unknown",
                "confidence": 0.45,
            },
        ],
        "inferences": [
            {
                "inference_id": "i1",
                "claim": (
                    "MFA evidence plus geo anomaly fits credential-stuff "
                    "pattern; reputation is unknown so the IP cannot anchor "
                    "a benign verdict."
                ),
                "supported_by_fact_ids": ["f1", "f2"],
                "confidence": 0.78,
            }
        ],
        "recommendations": [
            {
                "priority": 1,
                "action": "force_password_reset",
                "rationale": "Defense in depth pending analyst review.",
                "supported_by_inference_ids": ["i1"],
                "blast_radius": "low",
                "reversible": True,
                "automatable": False,
            }
        ],
        "blast_radius": {"affected_assets": ["u_acct_lead"]},
        "uncertainty": {"missing_enrichments": []},
    }
    return response, 2000, 600


if __name__ == "__main__":
    raise SystemExit(main())
