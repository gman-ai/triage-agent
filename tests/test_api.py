"""Smoke test for the FastAPI surface.

Uses FastAPI's TestClient so no live server is required. Hits /health, the
quarantine path on /triage, a happy-path /triage with an injected
SequenceClient, and the correction + force-review endpoints.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import triage.api.main as api_main
from triage.api.main import app
from triage.llm.client import LLMResponse, SequenceClient

client = TestClient(app)


@pytest.fixture
def sequence_client_with_minimal_verdict():
    """Inject a SequenceClient that returns a schema-valid minimal verdict.

    The verdict has no observed_facts (the schema allows an empty list), so
    citation existence and citation support both vacuously pass. This proves
    the full /triage path runs end-to-end: adapter -> storm grouper -> T1 ->
    router -> fan-out -> T2 (this canned response) -> validator -> audit ->
    emit. The verdict shape mirrors a real Sonnet response.
    """
    canned = {
        "verdict": "likely_true_positive",
        "confidence": 0.7,
        "severity": "P1",
        "severity_rationale": "Geo anomaly; partial evidence.",
        "summary": "API-test canned verdict.",
        "attack_chain": [],
        "observed_facts": [],
        "inferences": [],
        "recommendations": [
            {
                "priority": 1,
                "action": "open_ticket",
                "rationale": "Surface for human review.",
                "supported_by_inference_ids": [],
                "blast_radius": "low",
                "reversible": True,
                "automatable": False,
            }
        ],
        "blast_radius": {"affected_assets": ["u_acct_lead"]},
        "uncertainty": {"missing_enrichments": []},
    }
    seq = SequenceClient(
        [
            LLMResponse(
                content=json.dumps(canned),
                stop_reason="end_turn",
                tokens_in=2000,
                tokens_out=600,
                cost_usd=0.022,
                model="claude-sonnet-4-6",
            )
        ]
        * 2  # one for first pass; one in case the failsafe retries.
    )
    original = api_main._CLIENT
    api_main._CLIENT = seq
    try:
        yield seq
    finally:
        api_main._CLIENT = original


def test_health_returns_ok_with_llm_mode():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["llm_client_mode"] in {"synthetic", "live"}
    assert body["version"] == "0.1.0"


def test_triage_happy_path_with_injected_client(sequence_client_with_minimal_verdict):
    """End-to-end /triage on a clean Okta payload with an injected LLM client.

    Proves the production happy path runs the full pipeline (adapter
    normalization through validator + audit + emit) and returns a structured
    verdict, not just the quarantine path. The injected SequenceClient
    bypasses fixture-replay so the test does not depend on captured digests.
    """
    okta_payload = {
        "uuid": "evt_001",
        "actor": {"id": "u_acct_lead", "type": "User"},
        "client": {"ipAddress": "198.51.100.42"},
        "displayMessage": "Sign-on from Bulgaria 30s after Portland session",
        "eventType": "user.session.start",
        "published": "2026-06-17T14:32:10Z",
        "outcome": {"result": "SUCCESS"},
        "rule": {
            "id": "okta.impossible_travel.v3",
            "family": "impossible_travel",
            "severity": "P1",
        },
    }
    response = client.post(
        "/triage",
        json={
            "raw_payload": okta_payload,
            "tenant_id": "tenant_a",
            "source_system": "okta",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] in {
        "likely_true_positive",
        "needs_human",  # falls back if validator rejects
    }
    assert body["severity"] in {"P0", "P1", "P2", "P3", "P4"}
    assert "triage_id" in body
    assert body["audit_pointer"]
    # Pin the analyst-facing contract: the response must expose the
    # structured reasoning surface, not just the summary envelope.
    for key in (
        "observed_facts",
        "inferences",
        "recommendations",
        "attack_chain",
        "blast_radius",
        "uncertainty",
    ):
        assert key in body, f"response missing analyst-facing field {key!r}"


def test_triage_quarantines_unknown_source_without_hitting_llm():
    """Unknown source_system → DestructiveDrift-style quarantine. The
    pipeline returns a needs_human verdict with degraded=schema_drift; no
    LLM call is made (no fixture needed for this path).
    """
    response = client.post(
        "/triage",
        json={
            "raw_payload": {"event_id": "x"},
            "tenant_id": "tenant_a",
            "source_system": "unknown_vendor",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "needs_human"
    assert body["degraded"] == "schema_drift"


def test_correct_endpoint_round_trip():
    response = client.post(
        "/triage/triage_abc/correct",
        json={
            "triage_id": "triage_abc",
            "tenant_id": "tenant_a",
            "rule_family": "impossible_travel",
            "original_verdict": "confirmed_true_positive",
            "corrected_verdict": "likely_false_positive",
            "analyst_id": "u_analyst_1",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["recorded"] is True
    assert body["triage_id"] == "triage_abc"


def test_correct_endpoint_rejects_mismatched_path_id():
    response = client.post(
        "/triage/triage_xyz/correct",
        json={
            "triage_id": "triage_DIFFERENT",
            "tenant_id": "tenant_a",
            "rule_family": "impossible_travel",
            "original_verdict": "confirmed_true_positive",
            "corrected_verdict": "likely_false_positive",
            "analyst_id": "u_analyst_1",
        },
    )
    assert response.status_code == 400


def test_force_review_endpoint_flips_calibration_state():
    response = client.post(
        "/api/v1/calibration/tenant_a/impossible_travel/force-review",
        json={"engineer_id": "u_det_eng_lead"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["forced_human_review"] is True
    assert body["tenant_id"] == "tenant_a"
    assert body["rule_family"] == "impossible_travel"
