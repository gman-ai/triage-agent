"""T2 plan extension tests via request_additional_source.

T2 emits a tool_use response on the first pass; the orchestrator fetches the
requested source, appends to the bundle, logs the extension, and re-prompts
T2 with the augmented bundle. T2's second pass returns the final verdict.

Uses SequenceClient (returns responses in call order) rather than
FixtureReplayClient because the second request's digest depends on runbook
retrieval_ids that the agent's intermediate fetch generates non-
deterministically. SequenceClient bypasses the digest dependency for
multi-pass orchestration tests.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from triage.enrichment.base import SourceQuery
from triage.enrichment.fanout import build_default_registry, run_fanout
from triage.llm.client import LLMResponse, SequenceClient
from triage.reasoning.agent import reason
from triage.schemas.alert import Asset, CanonicalAlertEvent, Observable
from triage.schemas.plan_loader import PlanTemplateRegistry


def _alert() -> CanonicalAlertEvent:
    return CanonicalAlertEvent(
        tenant_id="tenant_a",
        alert_id="alert_extension_test",
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id="okta.impossible_travel.v3",
        rule_family="impossible_travel",
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        detected_at=datetime(2026, 6, 15, 14, 32, 10, tzinfo=UTC),
        severity_hint="P1",
        primary_assets=[
            Asset(asset_id="u_acct_lead", asset_type="user", tenant_id="tenant_a")
        ],
        observables=[
            Observable(
                observable_type="ip", value="198.51.100.42", source_field_path="client.ipAddress"
            )
        ],
        summary="impossible travel — possible session compromise",
    )


def _query(alert):
    return SourceQuery(
        tenant_id=alert.tenant_id,
        alert_id=alert.alert_id,
        entity_id=alert.grouping_entity(),
        ioc=alert.primary_ioc(),
        extra={"rule_family": alert.rule_family},
    )


def _final_verdict_content() -> str:
    return json.dumps(
        {
            "verdict": "likely_true_positive",
            "confidence": 0.8,
            "severity": "P1",
            "severity_rationale": "Geo anomaly + impossible travel pattern.",
            "summary": "Geo anomaly with runbook-guided response.",
            "attack_chain": [],
            "observed_facts": [],
            "inferences": [],
            "recommendations": [],
            "blast_radius": {},
            "uncertainty": {},
        }
    )


def test_t2_requests_runbook_via_tool_call_and_orchestrator_fetches():
    alert = _alert()
    plan_registry = PlanTemplateRegistry()
    plan = plan_registry.build_plan(alert.rule_family, alert.severity_hint)
    sources = build_default_registry()
    bundle = run_fanout(plan, _query(alert), sources)
    assert "runbook" not in plan.all_planned_sources()
    assert bundle.by_source("runbook") == []

    client = SequenceClient(
        responses=[
            LLMResponse(
                content="Calling tool to request runbook.",
                stop_reason="tool_use",
                tool_calls=[
                    {
                        "name": "request_additional_source",
                        "id": "tool_call_001",
                        "input": {
                            "source_type": "runbook",
                            "rationale": (
                                "Need impossible-travel response runbook to articulate "
                                "containment actions."
                            ),
                        },
                    }
                ],
                tokens_in=1800,
                tokens_out=80,
                cost_usd=0.01,
                model="claude-sonnet-4-6",
            ),
            LLMResponse(
                content=_final_verdict_content(),
                stop_reason="end_turn",
                tool_calls=[],
                tokens_in=2400,
                tokens_out=700,
                cost_usd=0.025,
                model="claude-sonnet-4-6",
            ),
        ]
    )

    response, augmented, extensions = reason(alert, plan, bundle, client, sources=sources)

    assert response.stop_reason == "end_turn"
    assert len(extensions) == 1
    assert extensions[0]["source_type"] == "runbook"
    assert extensions[0]["outcome"] == "fetched_ok"
    assert extensions[0]["rationale"].startswith("Need impossible-travel response runbook")
    # The augmented bundle now has the runbook ref appended.
    runbook_refs_in_bundle = augmented.by_source("runbook")
    assert len(runbook_refs_in_bundle) >= 1


def test_extension_loop_stops_at_hard_cap():
    """MAX_PLAN_EXTENSIONS = 2 prototype constant per DESIGN ONLY #16.
    Once the cap is reached, the agent re-prompts with cap_reached=True and
    expects a final verdict.
    """
    alert = _alert()
    plan_registry = PlanTemplateRegistry()
    plan = plan_registry.build_plan(alert.rule_family, alert.severity_hint)
    sources = build_default_registry()
    bundle = run_fanout(plan, _query(alert), sources)

    def _tool_use_response() -> LLMResponse:
        return LLMResponse(
            content="Calling tool.",
            stop_reason="tool_use",
            tool_calls=[
                {
                    "name": "request_additional_source",
                    "id": "tc",
                    "input": {"source_type": "runbook", "rationale": "more runbook"},
                }
            ],
            tokens_in=100,
            tokens_out=20,
            cost_usd=0.001,
            model="claude-sonnet-4-6",
        )

    client = SequenceClient(
        responses=[
            _tool_use_response(),  # extension #1
            _tool_use_response(),  # extension #2
            _tool_use_response(),  # cap reached; agent re-prompts with cap_reached=True
            LLMResponse(
                content=_final_verdict_content(),
                stop_reason="end_turn",
                tool_calls=[],
                tokens_in=1500,
                tokens_out=400,
                cost_usd=0.02,
                model="claude-sonnet-4-6",
            ),
        ]
    )

    response, augmented, extensions = reason(alert, plan, bundle, client, sources=sources)
    assert response.stop_reason == "end_turn"
    assert len(extensions) == 2  # cap reached at 2 successful fetches


def test_unknown_source_request_is_rejected_in_extension_log():
    """T2 requests a source_type the registry doesn't know. The orchestrator
    logs the rejection in plan_extensions and continues. The fan-out boundary
    soft-fails.
    """
    alert = _alert()
    plan_registry = PlanTemplateRegistry()
    plan = plan_registry.build_plan(alert.rule_family, alert.severity_hint)
    sources = build_default_registry()
    bundle = run_fanout(plan, _query(alert), sources)

    client = SequenceClient(
        responses=[
            LLMResponse(
                content="Calling unknown source.",
                stop_reason="tool_use",
                tool_calls=[
                    {
                        "name": "request_additional_source",
                        "id": "tc_bad",
                        "input": {"source_type": "siem_alert_field", "rationale": "n/a"},
                    }
                ],
                tokens_in=100,
                tokens_out=20,
                cost_usd=0.001,
                model="claude-sonnet-4-6",
            ),
            LLMResponse(
                content=_final_verdict_content(),
                stop_reason="end_turn",
                tool_calls=[],
                tokens_in=1500,
                tokens_out=400,
                cost_usd=0.02,
                model="claude-sonnet-4-6",
            ),
        ]
    )

    response, augmented, extensions = reason(alert, plan, bundle, client, sources=sources)
    assert response.stop_reason == "end_turn"
    assert len(extensions) == 1
    assert extensions[0]["outcome"] == "rejected_unknown_source"
