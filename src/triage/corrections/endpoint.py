"""Correction-loop API surface.

Plain Python functions wired into FastAPI by the API layer.

Endpoints:
- submit_correction(...)
  Backs POST /triage/{triage_id}/correct.
- force_review_ack(...)
  Backs POST /api/v1/calibration/{tenant}/{rule_family}/force-review.
  The hard layer. Detection-engineering invocation
  toggles the hard flag for that tenant/rule_family.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from triage.audit.ledger import AuditLedger
from triage.corrections.store import CorrectionRecord, CorrectionStore


@dataclass
class SubmitCorrectionRequest:
    triage_id: str
    tenant_id: str
    rule_family: str
    original_verdict: str
    corrected_verdict: str
    analyst_id: str
    timestamp: datetime
    analyst_notes: str | None = None


@dataclass
class ForceReviewAckRequest:
    tenant_id: str
    rule_family: str
    engineer_id: str
    timestamp: datetime
    note: str | None = None


def submit_correction(
    request: SubmitCorrectionRequest,
    store: CorrectionStore,
    audit: AuditLedger,
) -> dict:
    record = CorrectionRecord(
        triage_id=request.triage_id,
        tenant_id=request.tenant_id,
        rule_family=request.rule_family,
        original_verdict=request.original_verdict,
        corrected_verdict=request.corrected_verdict,
        timestamp=request.timestamp,
        analyst_id=request.analyst_id,
        analyst_notes=request.analyst_notes,
    )
    store.record_correction(record)
    audit.append_correction(
        request.triage_id,
        correction={
            "tenant_id": request.tenant_id,
            "rule_family": request.rule_family,
            "original_verdict": request.original_verdict,
            "corrected_verdict": request.corrected_verdict,
            "analyst_id": request.analyst_id,
            "timestamp": request.timestamp.isoformat(),
        },
    )
    return {"recorded": True, "triage_id": request.triage_id}


def force_review_ack(
    request: ForceReviewAckRequest,
    store: CorrectionStore,
) -> dict:
    store.acknowledge_force_review(
        tenant_id=request.tenant_id,
        rule_family=request.rule_family,
        engineer_id=request.engineer_id,
    )
    return {
        "tenant_id": request.tenant_id,
        "rule_family": request.rule_family,
        "forced_human_review": True,
        "engineer_id": request.engineer_id,
        "acknowledged_at": request.timestamp.isoformat(),
    }
