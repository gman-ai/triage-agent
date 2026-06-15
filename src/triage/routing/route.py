"""Deterministic router per RECONCILED §6 + D5 + §4.6.

Routing is in code, not in the LLM. The router consumes T1's classification
plus per-tenant budget state and emits a typed RouteDecision the orchestrator
acts on:

  * "rule_fast" — rule prefilter matched a known-FP; emit fast verdict
  * "rule_to_t2" — rule prefilter matched a known-TP; route to T2 directly
  * "t1_fast" — T1 confidence is high AND severity is low; emit fast verdict
  * "t2_standard" — bread and butter
  * "t2_urgent" — P0/P1 deep families during budget exhaustion (D16 override)
  * "t2_escalate_if_low_conf" — high severity; check confidence at T2 exit
  * "skip_low_severity" — budget hard-cap reached, severity not P0/P1
  * "needs_human_urgent" — P0/P1 routed but with the urgent flag set
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from triage.classifier.pre_classify import T1Classification
from triage.llm.budget import (
    DEEP_FAMILIES,
    TenantBudget,
    budget_decision,
)
from triage.schemas.alert import CanonicalAlertEvent

RouteOutcome = Literal[
    "rule_fast",
    "rule_to_t2",
    "t1_fast",
    "t2_standard",
    "t2_urgent",
    "t2_escalate_if_low_conf",
    "skip_low_severity",
]


@dataclass
class RouteDecision:
    outcome: RouteOutcome
    needs_human_urgent: bool = False
    reason: str = ""
    metrics: list[str] = field(default_factory=list)
    # Operator-facing telemetry counters per RECONCILED §4.6. Names match the
    # contract: `budget_exceeded_p0_override` fires when budget is exhausted
    # AND the alert is forced through to T2 anyway. The audit ledger persists
    # them on the triage row so a per-tenant cost dashboard can sum them up.

    @property
    def hits_llm(self) -> bool:
        return self.outcome in {
            "rule_to_t2",
            "t2_standard",
            "t2_urgent",
            "t2_escalate_if_low_conf",
        }


def route(
    alert: CanonicalAlertEvent,
    classification: T1Classification | None,
    budget: TenantBudget,
    *,
    known_benign_rules: frozenset[str] = frozenset(),
    known_malicious_rules: frozenset[str] = frozenset(),
) -> RouteDecision:
    if alert.rule_id in known_benign_rules:
        return RouteDecision(
            outcome="rule_fast",
            reason=f"rule_id {alert.rule_id} on known-benign list",
        )
    if alert.rule_id in known_malicious_rules:
        return RouteDecision(
            outcome="rule_to_t2",
            reason=f"rule_id {alert.rule_id} on known-malicious list; do not trust T1",
        )

    if classification is None:
        # T1 was not run for this alert (e.g. rule prefilter sat in front,
        # then we ran budget check). Fall back to severity-driven routing on
        # the source's severity_hint.
        return _route_without_t1(alert, budget)

    decision = budget_decision(
        budget,
        classification.severity_hint,
        classification.alert_family,
    )
    if decision == "skip_low_severity":
        return RouteDecision(
            outcome="skip_low_severity",
            reason="tenant budget hard-cap reached; severity below override threshold",
        )
    if decision == "p0_override_with_urgent":
        return RouteDecision(
            outcome="t2_urgent",
            needs_human_urgent=True,
            reason="budget exhausted; severity-aware override forces T2 + urgent",
            metrics=["budget_exceeded_p0_override"],
        )

    is_deep = (
        classification.severity_hint == "P0"
        or (
            classification.severity_hint == "P1"
            and classification.alert_family in DEEP_FAMILIES
        )
    )
    if is_deep:
        return RouteDecision(
            outcome="t2_escalate_if_low_conf",
            reason="high severity in deep family; escalate to T3 if low confidence",
        )

    if classification.confidence < 0.6:
        return RouteDecision(
            outcome="t2_standard",
            reason="T1 low confidence; defense-in-depth standard T2",
        )

    if (
        classification.severity_hint in {"P3", "P4"}
        and classification.confidence > 0.85
    ):
        return RouteDecision(
            outcome="t1_fast",
            reason="low severity + high T1 confidence; fast path",
        )

    return RouteDecision(outcome="t2_standard", reason="standard tier")


def _route_without_t1(
    alert: CanonicalAlertEvent,
    budget: TenantBudget,
) -> RouteDecision:
    decision = budget_decision(
        budget,
        alert.severity_hint,
        alert.rule_family,
    )
    if decision == "skip_low_severity":
        return RouteDecision(
            outcome="skip_low_severity",
            reason="budget hard-cap; no T1 ran; severity below override threshold",
        )
    if decision == "p0_override_with_urgent":
        return RouteDecision(
            outcome="t2_urgent",
            needs_human_urgent=True,
            reason="budget exhausted; severity-aware override forces T2",
            metrics=["budget_exceeded_p0_override"],
        )
    if alert.severity_hint == "P0" or (
        alert.severity_hint == "P1" and alert.rule_family in DEEP_FAMILIES
    ):
        return RouteDecision(
            outcome="t2_escalate_if_low_conf",
            reason="high severity (no T1); escalate to T3 if T2 low confidence",
        )
    return RouteDecision(outcome="t2_standard", reason="standard tier (no T1)")
