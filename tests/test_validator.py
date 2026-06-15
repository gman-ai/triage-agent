"""Acceptance gate: output validator per IMPL #8 + RECONCILED §4.4.

Six malformed outputs rejected. Three layers of grounding defense exercised:
schema, citation existence, citation support.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from triage.schemas.retrieval import EvidenceBundle, RetrievalRef
from triage.schemas.verdict import AIMetadata
from triage.validation.validator import (
    ValidationFailure,
    validate_response,
)


def _bundle() -> EvidenceBundle:
    return EvidenceBundle(
        retrievals=[
            RetrievalRef(
                retrieval_id="ret_asset_001",
                source_type="asset_cmdb",
                source_query="asset_cmdb:srv_billing_01",
                fetched_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
                storage_tier="hot",
                payload={
                    "asset_id": "srv_billing_01",
                    "criticality": "critical",
                    "owner_team": "payments",
                },
            ),
            RetrievalRef(
                retrieval_id="ret_identity_001",
                source_type="identity_store",
                source_query="identity_store:u_acct_lead",
                fetched_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
                storage_tier="hot",
                payload={
                    "user_id": "u_acct_lead",
                    "role": "account_lead",
                    "mfa_enabled": True,
                },
            ),
            RetrievalRef(
                retrieval_id="ret_runbook_001",
                source_type="runbook",
                source_query="runbook:impossible_travel",
                fetched_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
                storage_tier="warm",
                payload={"runbook_id": "rb_xt", "title": "Impossible travel"},
            ),
        ]
    )


def _valid_response_skeleton() -> dict:
    return {
        "verdict": "likely_true_positive",
        "confidence": 0.78,
        "severity": "P1",
        "severity_rationale": "Geo anomaly.",
        "summary": "Test summary.",
        "attack_chain": [],
        "observed_facts": [
            {
                "fact_id": "f1",
                "claim": "Asset is critical.",
                "retrieval_id": "ret_asset_001",
                "field_path": "criticality",
                "expected_value": "critical",
                "confidence": 0.95,
            }
        ],
        "inferences": [
            {
                "inference_id": "i1",
                "claim": "Critical asset implies elevated review.",
                "supported_by_fact_ids": ["f1"],
                "confidence": 0.9,
            }
        ],
        "recommendations": [
            {
                "priority": 1,
                "action": "monitor",
                "rationale": "Watch for related alerts.",
                "supported_by_inference_ids": ["i1"],
                "blast_radius": "low",
                "reversible": True,
                "automatable": False,
            }
        ],
        "blast_radius": {},
        "uncertainty": {},
    }


def _call(content):
    return validate_response(
        content,
        _bundle(),
        triage_id="triage_validator_test",
        tenant_id="tenant_a",
        alert_id="alert_validator_test",
        investigation_plan_dump={"plan_id": "plan_x"},
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        ai_metadata=AIMetadata(route_tier="standard_t2", model_chain=["sonnet"]),
    )


def test_valid_response_has_zero_failures():
    outcome = _call(json.dumps(_valid_response_skeleton()))
    assert outcome.failures == []
    assert outcome.verdict.verdict == "likely_true_positive"


def test_schema_failure_non_json():
    outcome = _call("not even json {")
    assert any(f.layer == "schema" for f in outcome.failures)
    assert outcome.verdict.verdict == "needs_human"
    assert outcome.verdict.degraded == "validation_failure_schema"


def test_schema_failure_invalid_verdict_enum():
    payload = _valid_response_skeleton()
    payload["verdict"] = "definitely_bad"
    outcome = _call(json.dumps(payload))
    assert any(f.layer == "schema" for f in outcome.failures)


def test_citation_existence_failure_fact_cites_unknown_retrieval():
    payload = _valid_response_skeleton()
    payload["observed_facts"][0]["retrieval_id"] = "ret_fabricated_999"
    outcome = _call(json.dumps(payload))
    assert any(f.layer == "citation_existence" for f in outcome.failures)


def test_citation_support_failure_wrong_expected_value():
    payload = _valid_response_skeleton()
    payload["observed_facts"][0]["expected_value"] = "low"  # actual is "critical"
    outcome = _call(json.dumps(payload))
    assert any(f.layer == "citation_support" for f in outcome.failures)


def test_citation_support_failure_field_path_misses():
    payload = _valid_response_skeleton()
    payload["observed_facts"][0]["field_path"] = "nonexistent.deep.path"
    outcome = _call(json.dumps(payload))
    assert any(f.layer == "citation_support" for f in outcome.failures)


def test_prose_evidence_skips_field_support_check():
    """Runbook is in PROSE_SOURCE_TYPES; the validator does NOT check
    field_path support for prose retrievals. Existence still checked.
    """
    payload = _valid_response_skeleton()
    payload["observed_facts"][0] = {
        "fact_id": "f1",
        "claim": "Runbook describes containment steps.",
        "retrieval_id": "ret_runbook_001",
        "field_path": "any.path",
        "expected_value": "any value",
        "confidence": 0.9,
    }
    payload["inferences"][0]["supported_by_fact_ids"] = ["f1"]
    outcome = _call(json.dumps(payload))
    # Existence passes; support is skipped because retrieval is prose.
    assert outcome.failures == []
