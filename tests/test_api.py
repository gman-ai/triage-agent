"""Smoke test for the FastAPI surface per IMPL #15.

Uses FastAPI's TestClient so no live server is required. Hits /health and the
correction + force-review endpoints. The /triage endpoint requires an LLM
client; defaults to FixtureReplayClient and will raise FixtureMissingError on
a payload without a captured fixture — that's the production posture, not a
test bug, so the smoke covers /triage with a deterministic adversarial-style
quarantine that doesn't hit the LLM.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from triage.api.main import app

client = TestClient(app)


def test_health_returns_ok_with_llm_mode():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["llm_client_mode"] in {"fixture_replay", "live"}
    assert body["version"] == "0.1.0"


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
