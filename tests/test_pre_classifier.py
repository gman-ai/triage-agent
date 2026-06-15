"""Acceptance gate: T1 pre-classifier per IMPL #5 + RECONCILED §6.

Uses FixtureReplayClient against tmp_path fixtures (no live API key needed).
Each test:
  1. Builds the same request the production T1 builds for a given alert
  2. Writes a hand-crafted response fixture keyed on the request's digest
  3. Calls pre_classify; asserts on the parsed T1Classification
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from triage.classifier.pre_classify import (
    T1Classification,
    build_t1_request,
    pre_classify,
)
from triage.llm.client import FixtureReplayClient, FixtureMissingError
from triage.schemas.alert import Asset, CanonicalAlertEvent, Observable


def _make_alert(rule_family="impossible_travel", severity="P1") -> CanonicalAlertEvent:
    return CanonicalAlertEvent(
        tenant_id="tenant_a",
        alert_id="alert_t1_test_001",
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id="okta.impossible_travel.v3",
        rule_family=rule_family,
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        detected_at=datetime(2026, 6, 15, 14, 32, 10, tzinfo=UTC),
        severity_hint=severity,
        primary_assets=[
            Asset(asset_id="u_acct_lead", asset_type="user", tenant_id="tenant_a")
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


def _write_fixture(tmp_path: Path, digest: str, payload: dict) -> None:
    (tmp_path / f"{digest}.json").write_text(json.dumps(payload))


def test_clean_alert_produces_valid_classification(tmp_path):
    alert = _make_alert()
    request = build_t1_request(alert)
    digest = request.digest()

    _write_fixture(
        tmp_path,
        digest,
        {
            "content": json.dumps(
                {
                    "severity_hint": "P1",
                    "alert_family": "impossible_travel",
                    "tier_recommendation": "standard_t2",
                    "confidence": 0.78,
                    "rationale": "Geo anomaly with no MFA challenge.",
                    "override_plan": None,
                }
            ),
            "stop_reason": "end_turn",
            "tool_calls": [],
            "tokens_in": 420,
            "tokens_out": 110,
            "cost_usd": 0.0004,
            "model": "claude-haiku-4-5-20251001",
        },
    )

    client = FixtureReplayClient(fixture_dir=tmp_path)
    result = pre_classify(alert, client)

    assert isinstance(result, T1Classification)
    assert result.severity_hint == "P1"
    assert result.alert_family == "impossible_travel"
    assert result.tier_recommendation == "standard_t2"
    assert 0.7 < result.confidence < 0.85
    # Plan comes from the seeded template — impossible_travel = [hot]
    assert result.investigation_plan.tier_preference == ["hot"]
    assert "identity_store" in result.investigation_plan.required_sources


def test_schema_failure_returns_failsafe_classification(tmp_path):
    alert = _make_alert()
    request = build_t1_request(alert)
    digest = request.digest()

    _write_fixture(
        tmp_path,
        digest,
        {
            "content": json.dumps(
                {
                    "severity_hint": "URGENT",  # not in enum; schema reject
                    "alert_family": "impossible_travel",
                    "tier_recommendation": "standard_t2",
                    "confidence": 0.5,
                    "rationale": "schema-violating output",
                }
            ),
            "stop_reason": "end_turn",
            "tokens_in": 350,
            "tokens_out": 80,
            "cost_usd": 0.0003,
            "model": "claude-haiku-4-5-20251001",
        },
    )

    client = FixtureReplayClient(fixture_dir=tmp_path)
    result = pre_classify(alert, client)

    # Failsafe: confidence 0.0 + standard_t2 forces the router to try T2.
    assert result.confidence == 0.0
    assert result.tier_recommendation == "standard_t2"
    assert result.severity_hint == "P1"
    assert "T1 schema failure" in result.rationale


def test_missing_fixture_raises_explicit_error(tmp_path):
    alert = _make_alert()
    client = FixtureReplayClient(fixture_dir=tmp_path)
    with pytest.raises(FixtureMissingError) as excinfo:
        pre_classify(alert, client)
    assert "claude-haiku-4-5-20251001" in str(excinfo.value)
    assert "fixtures/llm_replays" in str(excinfo.value)


def test_override_plan_modifies_seeded_template(tmp_path):
    """T1 can narrow tier_preference or extend optional_sources via override.
    The Pydantic schema rejects out-of-vocab tokens; the loader applies the
    override on top of the family's seeded template.
    """
    alert = _make_alert()
    request = build_t1_request(alert)
    digest = request.digest()

    _write_fixture(
        tmp_path,
        digest,
        {
            "content": json.dumps(
                {
                    "severity_hint": "P1",
                    "alert_family": "impossible_travel",
                    "tier_recommendation": "standard_t2",
                    "confidence": 0.8,
                    "rationale": "extend optional to include threat_intel for this geo",
                    "override_plan": {
                        "optional_sources": ["asset_cmdb", "threat_intel"],
                        "tier_preference": ["hot", "warm"],
                    },
                }
            ),
            "stop_reason": "end_turn",
            "tokens_in": 410,
            "tokens_out": 130,
            "cost_usd": 0.0004,
            "model": "claude-haiku-4-5-20251001",
        },
    )

    client = FixtureReplayClient(fixture_dir=tmp_path)
    result = pre_classify(alert, client)
    assert result.investigation_plan.tier_preference == ["hot", "warm"]
    assert "threat_intel" in result.investigation_plan.optional_sources
