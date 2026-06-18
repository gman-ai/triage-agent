"""Output validator.

Three layers:
  1. Schema validation — Pydantic parse of the LLM JSON into TriageVerdict
  2. Citation existence — every fact's retrieval_id is in the bundle
  3. Citation support — for structured retrievals, the claimed field_path
     resolves and matches expected_value; for prose retrievals (runbook),
     evidence is flagged human_verifiable

Terminal failure:
  After one retry, if the response STILL fails schema or support, the
  validator does NOT raise. It emits a hardcoded TriageVerdict with
  verdict=needs_human and degraded set. The pipeline never raises uncaught
  at the validation boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from triage.schemas.retrieval import EvidenceBundle, RetrievalRef
from triage.schemas.verdict import (
    AIMetadata,
    TriageVerdict,
    needs_human_terminal,
)

PROSE_SOURCE_TYPES = {"runbook"}


@dataclass
class ValidationFailure:
    layer: str  # "schema" | "citation_existence" | "citation_support"
    detail: str


@dataclass
class ValidationOutcome:
    verdict: TriageVerdict
    failures: list[ValidationFailure]
    retried: bool

    @property
    def ok(self) -> bool:
        return not self.failures


def validate_response(
    raw_content: str,
    bundle: EvidenceBundle,
    *,
    triage_id: str,
    tenant_id: str,
    alert_id: str,
    investigation_plan_dump: dict,
    received_at: datetime,
    ai_metadata: AIMetadata,
) -> ValidationOutcome:
    """Single-shot validate. The caller drives the retry loop with
    `run_with_terminal_failsafe`. Returns failures rather than raising so
    the orchestrator can decide whether to retry or terminate.
    """
    failures: list[ValidationFailure] = []
    try:
        candidate = _parse_verdict(
            raw_content,
            triage_id=triage_id,
            tenant_id=tenant_id,
            alert_id=alert_id,
            investigation_plan_dump=investigation_plan_dump,
            received_at=received_at,
            ai_metadata=ai_metadata,
        )
    except (json.JSONDecodeError, ValidationError) as exc:
        failures.append(ValidationFailure(layer="schema", detail=str(exc)[:300]))
        return ValidationOutcome(
            verdict=needs_human_terminal(
                triage_id=triage_id,
                tenant_id=tenant_id,
                alert_id=alert_id,
                investigation_plan=investigation_plan_dump,
                received_at=received_at,
                completed_at=datetime.now(received_at.tzinfo),
                degraded="validation_failure_schema",
            ),
            failures=failures,
            retried=False,
        )

    allowlist = bundle.retrieval_ids()
    ref_by_id = {r.retrieval_id: r for r in bundle.retrievals}

    for fact in candidate.observed_facts:
        if fact.retrieval_id not in allowlist:
            failures.append(
                ValidationFailure(
                    layer="citation_existence",
                    detail=(
                        f"fact {fact.fact_id} cites retrieval_id "
                        f"{fact.retrieval_id} not in bundle"
                    ),
                )
            )
            continue
        ref = ref_by_id[fact.retrieval_id]
        if ref.source_type in PROSE_SOURCE_TYPES:
            # Prose evidence cannot be field-validated; the schema flags it
            # for human verification downstream. No support check.
            continue
        ok, detail = _check_field_support(ref, fact.field_path, fact.expected_value)
        if not ok:
            failures.append(
                ValidationFailure(
                    layer="citation_support",
                    detail=(
                        f"fact {fact.fact_id} field_path={fact.field_path!r} "
                        f"detail: {detail}"
                    ),
                )
            )

    return ValidationOutcome(verdict=candidate, failures=failures, retried=False)


def run_with_terminal_failsafe(
    *,
    first_response_content: str,
    retry_callable,
    bundle: EvidenceBundle,
    triage_id: str,
    tenant_id: str,
    alert_id: str,
    investigation_plan_dump: dict,
    received_at: datetime,
    ai_metadata: AIMetadata,
) -> ValidationOutcome:
    """Validate with one retry. If retry ALSO fails, emit the hardcoded
    needs_human verdict. The pipeline never raises at this boundary.

    `retry_callable` is a no-arg function the caller binds with whatever it
    needs to re-prompt T2 with stricter instructions. It returns the new
    raw content string.
    """
    outcome = validate_response(
        first_response_content,
        bundle,
        triage_id=triage_id,
        tenant_id=tenant_id,
        alert_id=alert_id,
        investigation_plan_dump=investigation_plan_dump,
        received_at=received_at,
        ai_metadata=ai_metadata,
    )
    if outcome.ok:
        return outcome

    try:
        retry_content = retry_callable()
    except Exception as exc:  # noqa: BLE001 — retry path catches everything
        return ValidationOutcome(
            verdict=needs_human_terminal(
                triage_id=triage_id,
                tenant_id=tenant_id,
                alert_id=alert_id,
                investigation_plan=investigation_plan_dump,
                received_at=received_at,
                completed_at=datetime.now(received_at.tzinfo),
                degraded="validation_failure_schema",
                summary=f"Retry path raised: {str(exc)[:200]}. Manual review required.",
            ),
            failures=outcome.failures + [ValidationFailure(layer="retry", detail=str(exc)[:200])],
            retried=True,
        )

    retry_outcome = validate_response(
        retry_content,
        bundle,
        triage_id=triage_id,
        tenant_id=tenant_id,
        alert_id=alert_id,
        investigation_plan_dump=investigation_plan_dump,
        received_at=received_at,
        ai_metadata=ai_metadata,
    )
    if retry_outcome.ok:
        retry_outcome.retried = True
        return retry_outcome

    # Terminal: both attempts failed. Emit hardcoded needs_human verdict.
    terminal_reason = (
        "validation_failure_support"
        if any(f.layer == "citation_support" for f in retry_outcome.failures)
        else "validation_failure_schema"
    )
    return ValidationOutcome(
        verdict=needs_human_terminal(
            triage_id=triage_id,
            tenant_id=tenant_id,
            alert_id=alert_id,
            investigation_plan=investigation_plan_dump,
            received_at=received_at,
            completed_at=datetime.now(received_at.tzinfo),
            degraded=terminal_reason,
        ),
        failures=outcome.failures + retry_outcome.failures,
        retried=True,
    )


def _parse_verdict(
    raw_content: str,
    *,
    triage_id: str,
    tenant_id: str,
    alert_id: str,
    investigation_plan_dump: dict,
    received_at: datetime,
    ai_metadata: AIMetadata,
) -> TriageVerdict:
    parsed = json.loads(raw_content)
    # The model returns the analytical fields; we attach the orchestrator's
    # bookkeeping (triage_id, tenant_id, plan dump, metadata).
    parsed.setdefault("triage_id", triage_id)
    parsed.setdefault("tenant_id", tenant_id)
    parsed.setdefault("alert_id", alert_id)
    parsed.setdefault("investigation_plan", investigation_plan_dump)
    parsed.setdefault("received_at", received_at)
    parsed.setdefault("completed_at", datetime.now(received_at.tzinfo))
    parsed.setdefault("ai_metadata", ai_metadata.model_dump())
    return TriageVerdict.model_validate(parsed)


def _check_field_support(
    ref: RetrievalRef,
    field_path: str,
    expected_value: Any,
) -> tuple[bool, str]:
    """Walk dotted field_path on the retrieval payload and check the
    actual value matches expected_value.

    Numeric expected matches with float equality within 1e-9.
    String expected matches case-insensitively after .strip().
    Lists/dicts use deep equality.
    """
    actual = ref.payload
    for part in field_path.split("."):
        if isinstance(actual, dict) and part in actual:
            actual = actual[part]
        else:
            return False, f"field_path resolves to missing field at {part!r}"

    if isinstance(expected_value, float) and isinstance(actual, (int, float)):
        if abs(float(actual) - expected_value) < 1e-9:
            return True, "ok"
        return False, f"numeric mismatch: actual={actual} expected={expected_value}"
    if isinstance(expected_value, str) and isinstance(actual, str):
        if actual.strip().lower() == expected_value.strip().lower():
            return True, "ok"
        return False, f"string mismatch: actual={actual!r} expected={expected_value!r}"
    if actual == expected_value:
        return True, "ok"
    return False, f"value mismatch: actual={actual!r} expected={expected_value!r}"
