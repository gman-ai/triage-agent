"""Validator terminal-failure tests.

Double-failure (first attempt and retry both fail) emits a hardcoded
verdict=needs_human with degraded=validation_failure_schema or
validation_failure_support. The pipeline NEVER raises uncaught at this
boundary.

This is the strongest single defense in the architecture: the agent ships
SOMETHING for every alert, never silently drops, never crashes the
ingestion path.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from triage.schemas.retrieval import EvidenceBundle, RetrievalRef
from triage.schemas.verdict import AIMetadata
from triage.validation.validator import run_with_terminal_failsafe


def _bundle() -> EvidenceBundle:
    return EvidenceBundle(
        retrievals=[
            RetrievalRef(
                retrieval_id="ret_x_001",
                source_type="asset_cmdb",
                source_query="asset_cmdb:srv_x",
                fetched_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
                storage_tier="hot",
                payload={"asset_id": "srv_x", "criticality": "high"},
            )
        ]
    )


def _common_args():
    return dict(
        bundle=_bundle(),
        triage_id="triage_terminal_test",
        tenant_id="tenant_a",
        alert_id="alert_terminal_test",
        investigation_plan_dump={"plan_id": "plan_x"},
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        ai_metadata=AIMetadata(route_tier="standard_t2", model_chain=["sonnet"]),
    )


def test_double_schema_failure_emits_hardcoded_needs_human():
    """First attempt: malformed JSON. Retry: also malformed JSON.
    Outcome: hardcoded verdict=needs_human + degraded=validation_failure_schema.
    No exception raised.
    """

    def retry_returning_more_garbage():
        return "still not valid json {"

    outcome = run_with_terminal_failsafe(
        first_response_content="not json {",
        retry_callable=retry_returning_more_garbage,
        **_common_args(),
    )

    assert outcome.retried is True
    assert outcome.verdict.verdict == "needs_human"
    assert outcome.verdict.degraded == "validation_failure_schema"
    assert outcome.verdict.confidence == 0.0
    # The summary surfaces "manual review required" so the analyst knows why.
    assert "Manual review" in outcome.verdict.summary or "validation" in outcome.verdict.summary


def test_double_support_failure_emits_validation_failure_support():
    """First attempt: schema OK but cites a wrong field_path. Retry: same
    bug. Outcome: hardcoded needs_human + degraded=validation_failure_support.
    """
    bad_response = {
        "verdict": "likely_true_positive",
        "confidence": 0.78,
        "severity": "P1",
        "severity_rationale": "test",
        "summary": "test",
        "attack_chain": [],
        "observed_facts": [
            {
                "fact_id": "f1",
                "claim": "Asset is critical.",
                "retrieval_id": "ret_x_001",
                "field_path": "criticality",
                "expected_value": "critical",  # actual is "high"
                "confidence": 0.9,
            }
        ],
        "inferences": [
            {
                "inference_id": "i1",
                "claim": "x",
                "supported_by_fact_ids": ["f1"],
                "confidence": 0.9,
            }
        ],
        "recommendations": [
            {
                "priority": 1,
                "action": "monitor",
                "rationale": "x",
                "supported_by_inference_ids": ["i1"],
                "blast_radius": "low",
                "reversible": True,
                "automatable": False,
            }
        ],
        "blast_radius": {},
        "uncertainty": {},
    }
    payload = json.dumps(bad_response)

    outcome = run_with_terminal_failsafe(
        first_response_content=payload,
        retry_callable=lambda: payload,
        **_common_args(),
    )

    assert outcome.retried is True
    assert outcome.verdict.verdict == "needs_human"
    assert outcome.verdict.degraded == "validation_failure_support"


def test_retry_recovery_returns_ok_outcome():
    """First attempt: schema failure. Retry: valid response. The validator
    accepts the retry result.
    """
    valid_response = {
        "verdict": "likely_true_positive",
        "confidence": 0.78,
        "severity": "P1",
        "severity_rationale": "test",
        "summary": "test",
        "attack_chain": [],
        "observed_facts": [
            {
                "fact_id": "f1",
                "claim": "Asset is high criticality.",
                "retrieval_id": "ret_x_001",
                "field_path": "criticality",
                "expected_value": "high",
                "confidence": 0.95,
            }
        ],
        "inferences": [
            {
                "inference_id": "i1",
                "claim": "x",
                "supported_by_fact_ids": ["f1"],
                "confidence": 0.9,
            }
        ],
        "recommendations": [
            {
                "priority": 1,
                "action": "monitor",
                "rationale": "x",
                "supported_by_inference_ids": ["i1"],
                "blast_radius": "low",
                "reversible": True,
                "automatable": False,
            }
        ],
        "blast_radius": {},
        "uncertainty": {},
    }

    outcome = run_with_terminal_failsafe(
        first_response_content="garbage {",
        retry_callable=lambda: json.dumps(valid_response),
        **_common_args(),
    )

    assert outcome.retried is True
    assert outcome.ok
    assert outcome.verdict.verdict == "likely_true_positive"
    assert outcome.verdict.degraded is None


def test_retry_path_raising_is_caught_into_terminal_verdict():
    """If retry_callable itself raises (the model crashed mid-retry), the
    validator catches it and emits the hardcoded needs_human. Pipeline never
    leaks an exception at the validation boundary.
    """

    def retry_raising():
        raise RuntimeError("upstream LLM died mid-retry")

    outcome = run_with_terminal_failsafe(
        first_response_content="garbage {",
        retry_callable=retry_raising,
        **_common_args(),
    )

    assert outcome.retried is True
    assert outcome.verdict.verdict == "needs_human"
    assert outcome.verdict.degraded in {
        "validation_failure_schema",
        "validation_failure_support",
    }
    assert "Retry path raised" in outcome.verdict.summary
