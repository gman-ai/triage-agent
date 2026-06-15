"""Acceptance gate: T2 reasoning agent end-to-end per IMPL #6 + RECONCILED §4.4.

One alert family (impossible_travel) goes through plan-gated fan-out → T2
with a hand-crafted fixture-replay → validator. Asserts:
  * the response contains observed_facts citing retrievals in the bundle
  * the validator finds zero failures
  * (D14) stale-clean threat intel does NOT produce likely_false_positive
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from triage.enrichment.base import SourceQuery
from triage.enrichment.fanout import build_default_registry, run_fanout
from triage.llm.client import FixtureReplayClient
from triage.reasoning.agent import reason
from triage.schemas.alert import Asset, CanonicalAlertEvent, Observable
from triage.schemas.plan_loader import PlanTemplateRegistry
from triage.schemas.verdict import AIMetadata
from triage.validation.validator import validate_response


def _alert(tenant_id: str = "tenant_a") -> CanonicalAlertEvent:
    return CanonicalAlertEvent(
        tenant_id=tenant_id,
        alert_id="alert_t2_test_001",
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id="okta.impossible_travel.v3",
        rule_family="impossible_travel",
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        detected_at=datetime(2026, 6, 15, 14, 32, 10, tzinfo=UTC),
        severity_hint="P1",
        primary_assets=[
            Asset(asset_id="u_acct_lead", asset_type="user", tenant_id=tenant_id),
        ],
        observables=[
            Observable(
                observable_type="ip",
                value="198.51.100.42",
                source_field_path="client.ipAddress",
            )
        ],
        summary="impossible travel",
    )


def _query(alert: CanonicalAlertEvent) -> SourceQuery:
    return SourceQuery(
        tenant_id=alert.tenant_id,
        alert_id=alert.alert_id,
        entity_id=alert.grouping_entity(),
        ioc=alert.primary_ioc(),
        extra={"rule_family": alert.rule_family},
    )


def _seed_t2_fixture(tmp_path, request, response_obj: dict):
    digest = request.digest()
    (tmp_path / f"{digest}.json").write_text(
        json.dumps(
            {
                "content": json.dumps(response_obj),
                "stop_reason": "end_turn",
                "tool_calls": [],
                "tokens_in": 1800,
                "tokens_out": 600,
                "cost_usd": 0.02,
                "model": "claude-sonnet-4-6",
            }
        )
    )


def _build_t2_response(facts: list[dict], verdict: str, severity: str) -> dict:
    return {
        "verdict": verdict,
        "confidence": 0.78,
        "severity": severity,
        "severity_rationale": "Geo anomaly with no MFA challenge.",
        "summary": "User logged in from Bulgaria; identity store shows previous logins from US.",
        "attack_chain": [],
        "observed_facts": facts,
        "inferences": [
            {
                "inference_id": "i1",
                "claim": "User likely subject to credential compromise or proxy use.",
                "supported_by_fact_ids": [f["fact_id"] for f in facts],
                "confidence": 0.72,
                "counterfactual": None,
            }
        ],
        "recommendations": [
            {
                "priority": 1,
                "action": "force_password_reset",
                "rationale": "Mitigate possible credential compromise.",
                "supported_by_inference_ids": ["i1"],
                "blast_radius": "low",
                "reversible": True,
                "automatable": False,
            }
        ],
        "blast_radius": {"affected_assets": ["u_acct_lead"]},
        "uncertainty": {
            "what_could_change_verdict": "User confirms travel out of band.",
            "missing_enrichments": [],
        },
    }


def test_end_to_end_impossible_travel_clean(tmp_path):
    alert = _alert(tenant_id="tenant_a")
    plan_registry = PlanTemplateRegistry()
    plan = plan_registry.build_plan(alert.rule_family, alert.severity_hint)
    sources = build_default_registry()
    bundle = run_fanout(plan, _query(alert), sources)
    assert len(bundle.retrievals) >= 1

    identity_ref = bundle.by_source("identity_store")[0]
    facts = [
        {
            "fact_id": "f1",
            "claim": "User u_acct_lead has MFA enabled.",
            "retrieval_id": identity_ref.retrieval_id,
            "field_path": "mfa_enabled",
            "expected_value": True,
            "confidence": 0.95,
        }
    ]
    response_obj = _build_t2_response(facts, verdict="likely_true_positive", severity="P1")

    from triage.reasoning.agent import _build_t2_request

    request = _build_t2_request(alert, plan, bundle, [])
    _seed_t2_fixture(tmp_path, request, response_obj)

    client = FixtureReplayClient(fixture_dir=tmp_path)
    response, augmented, extensions = reason(alert, plan, bundle, client, sources=sources)
    assert response.stop_reason == "end_turn"
    assert extensions == []

    outcome = validate_response(
        response.content,
        augmented,
        triage_id="triage_test_001",
        tenant_id=alert.tenant_id,
        alert_id=alert.alert_id,
        investigation_plan_dump=plan.model_dump(),
        received_at=alert.received_at,
        ai_metadata=AIMetadata(route_tier="standard_t2", model_chain=["sonnet"]),
    )
    assert outcome.failures == []
    assert outcome.verdict.verdict == "likely_true_positive"
    # D9: every fact's retrieval_id must be in the bundle's allowlist.
    for fact in outcome.verdict.observed_facts:
        assert fact.retrieval_id in augmented.retrieval_ids()


def test_stale_clean_threat_intel_does_not_produce_likely_false_positive(tmp_path):
    """D14: tenant_a sees the same IOC as low-confidence stale clean. The
    reasoning agent MUST NOT treat this as benign signal strong enough for
    likely_false_positive. The fixture proves the data shape lets the model
    produce the right call.
    """
    alert = _alert(tenant_id="tenant_a")
    plan_registry = PlanTemplateRegistry()
    plan = plan_registry.build_plan(alert.rule_family, alert.severity_hint)
    sources = build_default_registry()
    bundle = run_fanout(plan, _query(alert), sources)

    identity_ref = bundle.by_source("identity_store")[0]
    facts = [
        {
            "fact_id": "f1",
            "claim": "User u_acct_lead has MFA enabled.",
            "retrieval_id": identity_ref.retrieval_id,
            "field_path": "mfa_enabled",
            "expected_value": True,
            "confidence": 0.95,
        }
    ]
    # Verdict is undetermined because the threat intel is stale-clean: not
    # enough to confirm bad, but absence of recent benign signal too.
    response_obj = _build_t2_response(facts, verdict="undetermined", severity="P2")
    response_obj["uncertainty"]["missing_enrichments"] = ["recent_threat_intel"]
    response_obj["summary"] = (
        "Stale clean threat intel cached 90d ago; insufficient to confirm benign."
    )

    from triage.reasoning.agent import _build_t2_request

    request = _build_t2_request(alert, plan, bundle, [])
    _seed_t2_fixture(tmp_path, request, response_obj)

    client = FixtureReplayClient(fixture_dir=tmp_path)
    response, augmented, _ = reason(alert, plan, bundle, client, sources=sources)
    outcome = validate_response(
        response.content,
        augmented,
        triage_id="triage_test_002",
        tenant_id=alert.tenant_id,
        alert_id=alert.alert_id,
        investigation_plan_dump=plan.model_dump(),
        received_at=alert.received_at,
        ai_metadata=AIMetadata(route_tier="standard_t2", model_chain=["sonnet"]),
    )
    assert outcome.verdict.verdict != "likely_false_positive"
    assert outcome.verdict.verdict != "confirmed_false_positive"
