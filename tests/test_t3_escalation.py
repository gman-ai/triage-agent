"""Acceptance gate: T3 Opus escalation per IMPL #7 + RECONCILED §6 / D6.

One demo run with cost telemetry. No full P95 measurement (IMPL #7
explicit). Self-consistency at sample size 3 (capped): three independent
calls; majority verdict wins.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from triage.enrichment.base import SourceQuery
from triage.enrichment.fanout import build_default_registry, run_fanout
from triage.llm.client import LLMResponse, SequenceClient
from triage.reasoning.escalation import (
    SAMPLE_SIZE,
    escalate_to_t3,
    should_escalate,
)
from triage.schemas.alert import Asset, CanonicalAlertEvent
from triage.schemas.plan_loader import PlanTemplateRegistry


def _alert() -> CanonicalAlertEvent:
    return CanonicalAlertEvent(
        tenant_id="tenant_a",
        alert_id="alert_t3_demo",
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id="okta.ransomware.v1",
        rule_family="ransomware",
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        detected_at=datetime(2026, 6, 15, 14, 32, 10, tzinfo=UTC),
        severity_hint="P0",
        primary_assets=[
            Asset(asset_id="srv_billing_01", asset_type="service", tenant_id="tenant_a")
        ],
        summary="Ransomware indicator with low T2 confidence",
    )


def test_should_escalate_triggers_on_low_conf_p0_deep_family():
    assert should_escalate("P0", "ransomware", 0.42) is True


def test_should_escalate_skips_when_confidence_high():
    assert should_escalate("P0", "ransomware", 0.85) is False


def test_should_escalate_skips_when_family_not_deep():
    assert should_escalate("P0", "impossible_travel", 0.3) is False


def test_should_escalate_skips_when_severity_low():
    assert should_escalate("P2", "ransomware", 0.3) is False


def test_one_demo_escalation_run_returns_majority_verdict_and_cost_telemetry():
    alert = _alert()
    plan_registry = PlanTemplateRegistry()
    plan = plan_registry.build_plan(alert.rule_family, alert.severity_hint)
    sources = build_default_registry()
    query = SourceQuery(
        tenant_id=alert.tenant_id,
        alert_id=alert.alert_id,
        entity_id=alert.grouping_entity(),
        ioc=alert.primary_ioc(),
        extra={"rule_family": alert.rule_family},
    )
    bundle = run_fanout(plan, query, sources)

    def _resp(verdict: str, cost: float) -> LLMResponse:
        return LLMResponse(
            content=json.dumps({"verdict": verdict}),
            stop_reason="end_turn",
            tool_calls=[],
            tokens_in=2200,
            tokens_out=600,
            cost_usd=cost,
            model="claude-opus-4-7",
        )

    # Three samples: two say likely_true_positive, one says undetermined.
    client = SequenceClient(
        responses=[
            _resp("likely_true_positive", 0.05),
            _resp("undetermined", 0.05),
            _resp("likely_true_positive", 0.05),
        ]
    )

    outcome = escalate_to_t3(alert, plan, bundle, client, sample_size=SAMPLE_SIZE)
    assert outcome.majority_verdict == "likely_true_positive"
    assert outcome.cost_usd == pytest.approx(0.15)
    assert outcome.total_tokens == {"prompt": 6600, "completion": 1800}
    assert outcome.sampled_at == ["claude-opus-4-7"] * 3
