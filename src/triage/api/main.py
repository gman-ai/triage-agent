"""FastAPI surface for the triage pipeline.

Endpoints:
  POST /triage                                — full pipeline on a vendor payload
  POST /triage/{triage_id}/correct           — analyst correction (soft layer)
  POST /api/v1/calibration/{tenant}/{rule_family}/force-review
                                              — detection-engineering ack (hard layer)
  GET /health                                 — liveness + LLM client mode

Defaults to a deterministic synthetic client so the surface runs end-to-end
without ANTHROPIC_API_KEY. Set TRIAGE_LIVE_LLM=1 (and ANTHROPIC_API_KEY) to
switch to AnthropicClient for live runs.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from triage.audit.ledger import AuditLedger
from triage.corrections.endpoint import (
    ForceReviewAckRequest,
    SubmitCorrectionRequest,
    force_review_ack,
    submit_correction,
)
from triage.corrections.store import CorrectionStore
from eval.synthetic_llm import EvalSyntheticClient
from triage.llm.client import (
    AnthropicClient,
    LLMClient,
)
from triage.orchestrator.pipeline import triage as run_triage
from triage.schemas.verdict import (
    AttackChain,
    Inference,
    ObservedFact,
    Recommendation,
)

app = FastAPI(title="triage-agent", version="0.1.0")


def _default_synthetic_labels() -> dict[str, dict]:
    """Small label map for the shipped sample alert.

    The default API mode is for portable local review. The sample Okta alert
    should produce the same kind of analyst-facing verdict as `uv run demo`;
    arbitrary alerts still fall back to EvalSyntheticClient's deterministic
    unlabeled behavior.
    """
    return {
        "okta_evt_clean_0001": {
            "expected_verdict": "likely_true_positive",
            "expected_severity": "P1",
            "expected_primary_action": "force_password_reset",
        }
    }


def _resolve_llm_client() -> tuple[LLMClient, str]:
    live = os.environ.get("TRIAGE_LIVE_LLM") == "1"
    if live and os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicClient(), "live"
    return EvalSyntheticClient(expected_by_alert_id=_default_synthetic_labels()), "synthetic"


_AUDIT = AuditLedger()
_CORRECTIONS = CorrectionStore()
_CLIENT, _CLIENT_MODE = _resolve_llm_client()


class TriageRequest(BaseModel):
    raw_payload: dict[str, Any]
    tenant_id: str
    source_system: str


class TriageResponse(BaseModel):
    triage_id: str
    verdict: str
    severity: str
    confidence: float
    degraded: str | None
    metrics: list[str]
    summary: str
    observed_facts: list[ObservedFact]
    inferences: list[Inference]
    recommendations: list[Recommendation]
    attack_chain: list[AttackChain]
    blast_radius: dict
    uncertainty: dict
    audit_pointer: str


class CorrectionRequest(BaseModel):
    triage_id: str
    tenant_id: str
    rule_family: str
    original_verdict: str
    corrected_verdict: str
    analyst_id: str
    analyst_notes: str | None = None


class ForceReviewRequest(BaseModel):
    engineer_id: str
    note: str | None = None


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "llm_client_mode": _CLIENT_MODE,
        "version": "0.1.0",
    }


@app.post("/triage", response_model=TriageResponse)
def triage_endpoint(req: TriageRequest) -> TriageResponse:
    result = run_triage(
        raw_payload=req.raw_payload,
        tenant_id=req.tenant_id,
        source_system=req.source_system,
        client=_CLIENT,
        audit=_AUDIT,
    )
    v = result.verdict
    return TriageResponse(
        triage_id=v.triage_id,
        verdict=v.verdict,
        severity=v.severity,
        confidence=v.confidence,
        degraded=v.degraded,
        metrics=list(result.metrics),
        summary=v.summary,
        observed_facts=v.observed_facts,
        inferences=v.inferences,
        recommendations=v.recommendations,
        attack_chain=v.attack_chain,
        blast_radius=v.blast_radius,
        uncertainty=v.uncertainty,
        audit_pointer=v.audit_pointer or v.triage_id,
    )


@app.post("/triage/{triage_id}/correct")
def correct_endpoint(triage_id: str, req: CorrectionRequest) -> dict:
    if req.triage_id != triage_id:
        raise HTTPException(
            status_code=400,
            detail="triage_id in body must match URL path",
        )
    return submit_correction(
        SubmitCorrectionRequest(
            triage_id=triage_id,
            tenant_id=req.tenant_id,
            rule_family=req.rule_family,
            original_verdict=req.original_verdict,
            corrected_verdict=req.corrected_verdict,
            analyst_id=req.analyst_id,
            timestamp=datetime.now(UTC),
            analyst_notes=req.analyst_notes,
        ),
        store=_CORRECTIONS,
        audit=_AUDIT,
    )


@app.post("/api/v1/calibration/{tenant_id}/{rule_family}/force-review")
def force_review_endpoint(
    tenant_id: str, rule_family: str, req: ForceReviewRequest
) -> dict:
    return force_review_ack(
        ForceReviewAckRequest(
            tenant_id=tenant_id,
            rule_family=rule_family,
            engineer_id=req.engineer_id,
            timestamp=datetime.now(UTC),
            note=req.note,
        ),
        store=_CORRECTIONS,
    )
