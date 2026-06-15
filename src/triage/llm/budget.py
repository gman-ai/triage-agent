"""Per-tenant budget envelope per RECONCILED §4.6.

Two thresholds:
  * soft_cap_pct (default 80%) — at or above this, new alerts go T1-only
  * hard_cap_pct (default 100%) — at or above this, severity <= P2 are skipped
                                  and P0/P1 of {ransomware, privesc, exfil}
                                  bypass with needs_human_urgent

Day 3 ships the envelope shape + decision functions; Day 4 adds the audit
ledger row that records budget consumption per triage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from triage.schemas.alert import RuleFamily, Severity

DEEP_FAMILIES: frozenset[RuleFamily] = frozenset(
    {"ransomware", "privilege_escalation", "data_exfil", "dns_exfil"}
)


@dataclass
class TenantBudget:
    tenant_id: str
    daily_budget_usd: float
    soft_cap_pct: float = 0.80
    hard_cap_pct: float = 1.00
    spent_usd: float = 0.0

    def remaining(self) -> float:
        return max(0.0, self.daily_budget_usd - self.spent_usd)

    def soft_exhausted(self) -> bool:
        return self.spent_usd >= self.daily_budget_usd * self.soft_cap_pct

    def hard_exhausted(self) -> bool:
        return self.spent_usd >= self.daily_budget_usd * self.hard_cap_pct

    def record_spend(self, usd: float) -> None:
        self.spent_usd += max(0.0, usd)


BudgetDecision = Literal[
    "proceed_full",
    "downgrade_t1_only",
    "skip_low_severity",
    "p0_override_with_urgent",
]


def budget_decision(
    budget: TenantBudget,
    severity_hint: Severity | None,
    rule_family: RuleFamily,
) -> BudgetDecision:
    """Apply §4.6 severity-aware budget policy.

    P0/P1 of DEEP_FAMILIES always bypass; the routing layer then emits the
    verdict with `needs_human_urgent` and surfaces a metric. Lower severities
    skip when hard-exhausted to protect the daily envelope.
    """
    if budget.hard_exhausted():
        if severity_hint == "P0" or (severity_hint == "P1" and rule_family in DEEP_FAMILIES):
            return "p0_override_with_urgent"
        if severity_hint in {"P2", "P3", "P4", None}:
            return "skip_low_severity"
        return "p0_override_with_urgent"  # remaining P1 of non-deep families
    if budget.soft_exhausted():
        return "downgrade_t1_only"
    return "proceed_full"
