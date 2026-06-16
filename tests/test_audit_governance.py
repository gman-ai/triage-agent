"""Acceptance gate: audit governance per IMPL #12 + RECONCILED §4.5.

Three claims:
  1. `reconstruct_decision(triage_id)` returns the verdict + source pointers
     deterministically from hashes
  2. `raw_prompt` is None by default; only forensic_30d retention class
     persists raw payloads
  3. Redaction patterns scrub AWS keys + bearer tokens before raw payloads
     are stored
"""

from __future__ import annotations

from datetime import UTC, datetime

from triage.audit.ledger import AuditLedger
from triage.audit.redaction import redact_dict, redact_text
from triage.schemas.retrieval import EvidenceBundle, RetrievalRef
from triage.schemas.verdict import (
    AIMetadata,
    ObservedFact,
    TriageVerdict,
)


def _bundle() -> EvidenceBundle:
    return EvidenceBundle(
        retrievals=[
            RetrievalRef(
                retrieval_id="ret_a_001",
                source_type="asset_cmdb",
                source_query="asset_cmdb:srv_billing_01",
                fetched_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
                storage_tier="hot",
                payload={"asset_id": "srv_billing_01", "criticality": "critical"},
            ),
            RetrievalRef(
                retrieval_id="ret_i_001",
                source_type="identity_store",
                source_query="identity_store:u_acct_lead",
                fetched_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
                storage_tier="hot",
                payload={"user_id": "u_acct_lead", "mfa_enabled": True},
            ),
        ]
    )


def _verdict() -> TriageVerdict:
    return TriageVerdict(
        triage_id="triage_audit_test_001",
        tenant_id="tenant_a",
        alert_id="alert_audit_test_001",
        received_at=datetime(2026, 6, 15, 14, 32, 11, tzinfo=UTC),
        completed_at=datetime(2026, 6, 15, 14, 32, 18, tzinfo=UTC),
        investigation_plan={"plan_id": "plan_audit_test"},
        verdict="likely_true_positive",
        confidence=0.78,
        severity="P1",
        severity_rationale="test",
        summary="Audit governance test verdict.",
        observed_facts=[
            ObservedFact(
                fact_id="f1",
                claim="Asset is critical.",
                retrieval_id="ret_a_001",
                field_path="criticality",
                expected_value="critical",
                confidence=0.95,
            )
        ],
        ai_metadata=AIMetadata(
            route_tier="standard_t2",
            model_chain=["haiku", "sonnet"],
            cost_usd=0.022,
            latency_ms=4200,
        ),
    )


def test_reconstruct_returns_equivalent_verdict():
    ledger = AuditLedger()
    verdict = _verdict()
    bundle = _bundle()
    ledger.record(
        verdict=verdict,
        bundle=bundle,
        prompt_text="full prompt text — not stored",
        response_text="full response — not stored",
        validation_result="ok",
    )

    reconstructed = ledger.reconstruct_decision(verdict.triage_id)
    assert reconstructed is not None
    assert reconstructed.verdict == verdict.verdict
    assert reconstructed.severity == verdict.severity
    assert reconstructed.confidence == verdict.confidence
    assert reconstructed.model_chain == verdict.ai_metadata.model_chain
    assert len(reconstructed.evidence_source_pointers) == 2
    assert {p["retrieval_id"] for p in reconstructed.evidence_source_pointers} == {
        "ret_a_001",
        "ret_i_001",
    }


def test_raw_prompt_is_none_by_default():
    ledger = AuditLedger()
    verdict = _verdict()
    bundle = _bundle()
    row = ledger.record(
        verdict=verdict,
        bundle=bundle,
        prompt_text="should not be persisted",
        response_text="ditto",
        validation_result="ok",
    )
    assert row.retention_class == "hash_only"
    assert row.raw_prompt is None
    assert row.raw_response is None
    assert row.raw_bundle is None
    # The safe view also omits the raw fields.
    safe = row.safe_dict()
    assert "raw_prompt" not in safe
    assert safe["prompt_hash"] != ""


def test_forensic_retention_stores_redacted_raw_payloads():
    ledger = AuditLedger()
    verdict = _verdict()
    bundle = _bundle()
    sensitive_prompt = (
        "alert details with Bearer abc.def.ghi token and AKIAIOSFODNN7EXAMPLE"
    )
    row = ledger.record(
        verdict=verdict,
        bundle=bundle,
        prompt_text=sensitive_prompt,
        response_text="response",
        validation_result="ok",
        retention_class="forensic_30d",
    )
    assert row.retention_class == "forensic_30d"
    assert row.raw_prompt is not None
    assert "abc.def.ghi" not in row.raw_prompt
    assert "AKIAIOSFODNN7EXAMPLE" not in row.raw_prompt
    assert "[REDACTED]" in row.raw_prompt
    assert "aws_access_key" in row.redaction_hits
    assert "bearer_token" in row.redaction_hits


def test_correction_history_appended_to_audit_row():
    ledger = AuditLedger()
    verdict = _verdict()
    bundle = _bundle()
    ledger.record(
        verdict=verdict,
        bundle=bundle,
        prompt_text="x",
        response_text="y",
        validation_result="ok",
    )
    ledger.append_correction(
        verdict.triage_id,
        {"analyst_id": "u_sre_1", "corrected_verdict": "likely_false_positive"},
    )
    row = ledger.get(verdict.triage_id)
    assert row is not None
    assert len(row.correction_history) == 1
    assert row.correction_history[0]["analyst_id"] == "u_sre_1"


def test_redact_text_handles_aws_and_bearer():
    out, hits = redact_text("token: Bearer abc.def.ghi key: AKIAIOSFODNN7EXAMPLE")
    assert "Bearer" not in out or "Bearer abc.def.ghi" not in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "aws_access_key" in hits
    assert "bearer_token" in hits


def test_redact_text_handles_email():
    out, hits = redact_text("contact analyst.lead+oncall@example.invalid for review")
    assert "analyst.lead+oncall@example.invalid" not in out
    assert "[REDACTED]" in out
    assert "email" in hits


def test_forensic_retention_redacts_email_in_raw_prompt():
    """The email pattern must scrub PII in forensic_30d-retained raw payloads.
    Default hash_only retention persists no raw text, so this assertion is
    specifically about the forensic path.
    """
    ledger = AuditLedger()
    verdict = _verdict()
    bundle = _bundle()
    sensitive_prompt = (
        "alert summary: failed login from acct.lead@example.invalid; "
        "reporter: u_sre_lead@example.invalid"
    )
    row = ledger.record(
        verdict=verdict,
        bundle=bundle,
        prompt_text=sensitive_prompt,
        response_text="response",
        validation_result="ok",
        retention_class="forensic_30d",
    )
    assert row.retention_class == "forensic_30d"
    assert row.raw_prompt is not None
    assert "acct.lead@example.invalid" not in row.raw_prompt
    assert "u_sre_lead@example.invalid" not in row.raw_prompt
    assert "[REDACTED]" in row.raw_prompt
    assert "email" in row.redaction_hits


def test_hash_only_retention_persists_no_raw_payload_for_email_pii():
    """Default retention class drops raw payloads entirely. Email PII in the
    prompt cannot leak through the audit row because there is no raw text
    persisted in the first place.
    """
    ledger = AuditLedger()
    verdict = _verdict()
    bundle = _bundle()
    sensitive_prompt = "victim: acct.lead@example.invalid"
    row = ledger.record(
        verdict=verdict,
        bundle=bundle,
        prompt_text=sensitive_prompt,
        response_text="x",
        validation_result="ok",
    )
    assert row.retention_class == "hash_only"
    assert row.raw_prompt is None
    safe = row.safe_dict()
    assert "raw_prompt" not in safe


def test_redact_dict_walks_nested_structures():
    payload = {
        "level1": {
            "secret": "Bearer xyzpdq",
            "items": ["AKIAIOSFODNN7EXAMPLE", "harmless"],
        }
    }
    redacted, hits = redact_dict(payload)
    assert "xyzpdq" not in redacted["level1"]["secret"]
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted["level1"]["items"][0]
    assert redacted["level1"]["items"][1] == "harmless"
    assert "bearer_token" in hits
    assert "aws_access_key" in hits
