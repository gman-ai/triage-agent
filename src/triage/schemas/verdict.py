"""TriageVerdict schema per RECONCILED §7.

Closed-vocabulary output. Every claim is structurally grounded:
  * observed_facts cite a retrieval_id + field_path + expected_value
  * inferences cite fact_ids
  * recommendations cite inference_ids + state blast_radius + reversible

The schema makes ungrounded outputs structurally invalid; the validator
(validation/validator.py) walks the citations and checks that they resolve
in the EvidenceBundle.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Verdict = Literal[
    "confirmed_true_positive",
    "likely_true_positive",
    "undetermined",
    "likely_false_positive",
    "confirmed_false_positive",
    "needs_human",
    "needs_human_urgent",
]

Severity = Literal["P0", "P1", "P2", "P3", "P4"]

DegradedReason = Literal[
    "llm_unavailable",
    "retrieval_partial",
    "cost_cap_reached",
    "schema_drift",
    "storm_mode",
    "needs_human_urgent",
    "tenant_calibration_warning",
    "validation_failure_support",
    "validation_failure_schema",
]

ActionType = Literal[
    "isolate_host",
    "disable_user",
    "rotate_credential",
    "block_ip",
    "block_domain",
    "open_ticket",
    "notify_owner",
    "monitor",
    "escalate_to_tier2",
    "no_action",
    "force_password_reset",
]

RouteTier = Literal["rule_prefilter", "fast_t1", "standard_t2", "deep_t3", "storm_group"]


class ObservedFact(BaseModel):
    fact_id: str
    claim: str
    retrieval_id: str
    field_path: str
    expected_value: str | int | float | bool | list | dict | None
    confidence: float


class Inference(BaseModel):
    inference_id: str
    claim: str
    supported_by_fact_ids: list[str]
    confidence: float
    counterfactual: str | None = None


class Recommendation(BaseModel):
    priority: Literal[1, 2, 3]
    action: ActionType
    rationale: str
    supported_by_inference_ids: list[str]
    blast_radius: Literal["high", "medium", "low"]
    reversible: bool
    automatable: bool = False


class AttackChain(BaseModel):
    tactic: str
    technique: str | None = None
    confidence: float
    supported_by_fact_ids: list[str] = Field(default_factory=list)


class AIMetadata(BaseModel):
    route_tier: RouteTier
    model_chain: list[str]
    tokens: dict[str, int] = Field(default_factory=dict)
    cost_usd: float = 0.0
    latency_ms: int = 0
    retrieval_calls: list[dict] = Field(default_factory=list)
    enrichments_failed: list[str] = Field(default_factory=list)


class TriageVerdict(BaseModel):
    triage_id: str
    tenant_id: str
    alert_id: str
    incident_group_id: str | None = None
    schema_version: Literal["1.0"] = "1.0"
    received_at: datetime
    completed_at: datetime

    investigation_plan: dict  # InvestigationPlan dump; keeps the shape immutable
    plan_extensions: list[dict] = Field(default_factory=list)

    verdict: Verdict
    confidence: float
    severity: Severity
    severity_rationale: str
    severity_supported_by_fact_ids: list[str] = Field(default_factory=list)

    summary: str

    attack_chain: list[AttackChain] = Field(default_factory=list)
    retrievals: list[dict] = Field(default_factory=list)  # RetrievalRef dumps
    observed_facts: list[ObservedFact] = Field(default_factory=list)
    inferences: list[Inference] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)

    blast_radius: dict = Field(default_factory=dict)
    uncertainty: dict = Field(default_factory=dict)

    degraded: DegradedReason | None = None
    forced_human_review: bool = False
    needs_human_urgent: bool = False

    audit_pointer: str = ""
    correction_endpoint: str = "/api/v1/triage/{triage_id}/correct"

    ai_metadata: AIMetadata


def needs_human_terminal(
    *,
    triage_id: str,
    tenant_id: str,
    alert_id: str,
    investigation_plan: dict,
    received_at: datetime,
    completed_at: datetime,
    degraded: DegradedReason,
    audit_pointer: str = "",
    summary: str | None = None,
) -> TriageVerdict:
    """Per R6: hardcoded structurally valid verdict for terminal validation
    failure or unrecoverable degradation. The pipeline never raises uncaught;
    it ships a verdict that surfaces the failure to the analyst.
    """
    return TriageVerdict(
        triage_id=triage_id,
        tenant_id=tenant_id,
        alert_id=alert_id,
        received_at=received_at,
        completed_at=completed_at,
        investigation_plan=investigation_plan,
        verdict="needs_human",
        confidence=0.0,
        severity="P3",
        severity_rationale="Validator terminal failure; severity defaulted to P3 pending human review.",
        summary=summary or "Output validation failed after retry. Manual review required.",
        degraded=degraded,
        audit_pointer=audit_pointer,
        ai_metadata=AIMetadata(
            route_tier="standard_t2",
            model_chain=[],
        ),
    )
