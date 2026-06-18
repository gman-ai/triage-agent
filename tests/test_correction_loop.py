"""Correction loop tests.

Two layers:
  * Soft layer (auto): operational alert + degraded: tenant_calibration_
    warning + verdict capped at likely_* once disagreement rate crosses
    threshold over the window
  * Hard layer (gated): forced_human_review requires detection-engineering
    ack via force_review_ack endpoint
"""

from __future__ import annotations

from datetime import UTC, datetime

from triage.audit.ledger import AuditLedger
from triage.corrections.endpoint import (
    ForceReviewAckRequest,
    SubmitCorrectionRequest,
    force_review_ack,
    submit_correction,
)
from triage.corrections.policy import LIKELY_TP, apply_verdict_cap, evaluate
from triage.corrections.store import CorrectionStore
from triage.schemas.retrieval import EvidenceBundle, RetrievalRef
from triage.schemas.verdict import AIMetadata, TriageVerdict


def _seed_audit_row(ledger: AuditLedger, triage_id: str, tenant_id: str) -> None:
    verdict = TriageVerdict(
        triage_id=triage_id,
        tenant_id=tenant_id,
        alert_id=f"alert_{triage_id}",
        received_at=datetime(2026, 6, 15, 14, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 6, 15, 14, 0, 5, tzinfo=UTC),
        investigation_plan={"plan_id": "plan_test"},
        verdict="confirmed_true_positive",
        confidence=0.9,
        severity="P2",
        severity_rationale="test",
        summary="seed",
        ai_metadata=AIMetadata(route_tier="standard_t2", model_chain=["sonnet"]),
    )
    bundle = EvidenceBundle(
        retrievals=[
            RetrievalRef(
                retrieval_id="ret_x",
                source_type="asset_cmdb",
                source_query="x",
                fetched_at=datetime(2026, 6, 15, 14, 0, 0, tzinfo=UTC),
                storage_tier="hot",
                payload={},
            )
        ]
    )
    ledger.record(
        verdict=verdict, bundle=bundle, prompt_text="x", response_text="y",
        validation_result="ok",
    )


def test_soft_layer_triggers_after_threshold_disagreements():
    """After 8 corrections marking the verdict wrong, the next routing
    decision routes degraded with tenant_calibration_warning.
    """
    store = CorrectionStore()
    audit = AuditLedger()
    tenant = "tenant_a"
    family = "impossible_travel"

    for i in range(8):
        triage_id = f"triage_{i:03d}"
        _seed_audit_row(audit, triage_id, tenant)
        submit_correction(
            SubmitCorrectionRequest(
                triage_id=triage_id,
                tenant_id=tenant,
                rule_family=family,
                original_verdict="confirmed_true_positive",
                corrected_verdict="confirmed_false_positive",
                analyst_id="u_analyst_1",
                timestamp=datetime(2026, 6, 15, 14, i, 0, tzinfo=UTC),
            ),
            store=store,
            audit=audit,
        )

    decision = evaluate(store, tenant, family)
    assert decision.soft_trigger is True
    assert decision.degraded_reason == "tenant_calibration_warning"
    assert decision.operational_event == "correction_threshold_exceeded"
    assert decision.verdict_cap == LIKELY_TP
    # Hard layer is NOT auto: detection-engineering ack required.
    assert decision.forced_human_review is False


def test_verdict_cap_downgrades_confirmed_to_likely():
    """The cap is the mechanism the orchestrator applies before returning
    a verdict for a tenant/rule_family in tenant_calibration_warning state.
    """
    assert apply_verdict_cap("confirmed_true_positive", LIKELY_TP) == "likely_true_positive"
    assert apply_verdict_cap("confirmed_false_positive", LIKELY_TP) == "likely_false_positive"
    assert apply_verdict_cap("undetermined", LIKELY_TP) == "undetermined"
    # No cap means no change.
    assert apply_verdict_cap("confirmed_true_positive", None) == "confirmed_true_positive"


def test_below_threshold_no_soft_trigger():
    store = CorrectionStore()
    audit = AuditLedger()
    tenant = "tenant_a"
    family = "impossible_travel"
    # 5 corrections, below the prototype's min_for_trigger of 8.
    for i in range(5):
        triage_id = f"triage_under_{i}"
        _seed_audit_row(audit, triage_id, tenant)
        submit_correction(
            SubmitCorrectionRequest(
                triage_id=triage_id,
                tenant_id=tenant,
                rule_family=family,
                original_verdict="confirmed_true_positive",
                corrected_verdict="confirmed_false_positive",
                analyst_id="u_analyst_1",
                timestamp=datetime(2026, 6, 15, 14, i, 0, tzinfo=UTC),
            ),
            store=store,
            audit=audit,
        )
    decision = evaluate(store, tenant, family)
    assert decision.soft_trigger is False


def test_hard_layer_requires_detection_engineering_ack():
    """The hard layer is NOT auto. forced_human_review flips True only after
    force_review_ack is invoked. This is DESIGN ONLY #4: the endpoint
    surface is stubbed; the test exercises it through the contract.
    """
    store = CorrectionStore()
    tenant = "tenant_a"
    family = "impossible_travel"
    decision_before = evaluate(store, tenant, family)
    assert decision_before.forced_human_review is False

    force_review_ack(
        ForceReviewAckRequest(
            tenant_id=tenant,
            rule_family=family,
            engineer_id="u_det_eng_lead",
            timestamp=datetime(2026, 6, 15, 16, 0, 0, tzinfo=UTC),
        ),
        store=store,
    )
    decision_after = evaluate(store, tenant, family)
    assert decision_after.forced_human_review is True


def test_correction_persisted_to_audit_history():
    """The correction submitted at the endpoint is appended to the audit
    row's correction_history list for the matching triage_id.
    """
    store = CorrectionStore()
    audit = AuditLedger()
    triage_id = "triage_hist_001"
    _seed_audit_row(audit, triage_id, "tenant_a")
    submit_correction(
        SubmitCorrectionRequest(
            triage_id=triage_id,
            tenant_id="tenant_a",
            rule_family="impossible_travel",
            original_verdict="confirmed_true_positive",
            corrected_verdict="confirmed_false_positive",
            analyst_id="u_analyst_1",
            timestamp=datetime(2026, 6, 15, 14, 0, 0, tzinfo=UTC),
        ),
        store=store,
        audit=audit,
    )
    row = audit.get(triage_id)
    assert row is not None
    assert len(row.correction_history) == 1
    assert row.correction_history[0]["analyst_id"] == "u_analyst_1"
