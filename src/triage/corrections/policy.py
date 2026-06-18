"""Correction-loop policy decisions.

The soft layer applies automatically once `should_soft_trigger` returns
True:
  * subsequent verdicts emit `degraded: tenant_calibration_warning`
  * verdicts cap at `likely_*` (never `confirmed_*`) for that
    tenant/rule_family
  * a `correction_threshold_exceeded` operational event is emitted

The hard layer (`forced_human_review`) requires detection-engineering
ack. The acknowledgment toggle lives on CorrectionStore; this module
just reads it.
"""

from __future__ import annotations

from dataclasses import dataclass

from triage.corrections.store import CorrectionStore
from triage.schemas.verdict import Verdict

LIKELY_TP: Verdict = "likely_true_positive"
LIKELY_FP: Verdict = "likely_false_positive"
UNDETERMINED: Verdict = "undetermined"

CONFIRMED_TO_LIKELY: dict[Verdict, Verdict] = {
    "confirmed_true_positive": LIKELY_TP,
    "confirmed_false_positive": LIKELY_FP,
}


@dataclass
class CorrectionPolicyDecision:
    soft_trigger: bool
    forced_human_review: bool
    verdict_cap: Verdict | None
    degraded_reason: str | None
    operational_event: str | None


def evaluate(
    store: CorrectionStore,
    tenant_id: str,
    rule_family: str,
) -> CorrectionPolicyDecision:
    soft = store.should_soft_trigger(tenant_id, rule_family)
    forced = store.is_forced_human_review(tenant_id, rule_family)

    if not soft and not forced:
        return CorrectionPolicyDecision(
            soft_trigger=False,
            forced_human_review=False,
            verdict_cap=None,
            degraded_reason=None,
            operational_event=None,
        )

    return CorrectionPolicyDecision(
        soft_trigger=soft,
        forced_human_review=forced,
        verdict_cap=LIKELY_TP if soft else None,
        degraded_reason="tenant_calibration_warning" if soft else None,
        operational_event="correction_threshold_exceeded" if soft else None,
    )


def apply_verdict_cap(verdict: Verdict, cap: Verdict | None) -> Verdict:
    """If a cap is in force, downgrade confirmed_* to likely_*; leave
    undetermined / needs_human / likely_* unchanged.
    """
    if cap is None:
        return verdict
    if verdict in CONFIRMED_TO_LIKELY:
        return CONFIRMED_TO_LIKELY[verdict]
    return verdict
