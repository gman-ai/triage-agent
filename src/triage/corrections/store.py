"""Correction loop persistence + drift computation.

The soft layer (this module + policy.py) runs in the prototype. The hard
layer endpoint is in endpoint.py: stubbed for the prototype with the
surface the test exercises.

Aggregation contract:
- disagreement_rate(tenant, rule_family) returns the share of the last
  `window_size` corrections that disagreed with the original verdict
- soft layer triggers at >= 25% disagreement over >= 50 corrections OR
  over 14 days, whichever first (prototype uses count-only for determinism)
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque

DEFAULT_THRESHOLD_PCT = 0.25
DEFAULT_WINDOW_SIZE = 50
PROTOTYPE_MIN_CORRECTIONS_FOR_TRIGGER = 8
# Production would use min 50; the prototype reduces to 8 so test_correction
# _loop.py can validate the threshold-trip behavior in a short sequence.
# DESIGN.md notes the
# production value (50 / 14d).


@dataclass
class CorrectionRecord:
    triage_id: str
    tenant_id: str
    rule_family: str
    original_verdict: str
    corrected_verdict: str
    timestamp: datetime
    analyst_id: str
    analyst_notes: str | None = None

    def is_disagreement(self) -> bool:
        return self.original_verdict != self.corrected_verdict


class CorrectionStore:
    def __init__(
        self,
        threshold_pct: float = DEFAULT_THRESHOLD_PCT,
        window_size: int = DEFAULT_WINDOW_SIZE,
        min_for_trigger: int = PROTOTYPE_MIN_CORRECTIONS_FOR_TRIGGER,
    ) -> None:
        self._lock = threading.Lock()
        self._records: dict[tuple[str, str], Deque[CorrectionRecord]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self._window = window_size
        self._threshold_pct = threshold_pct
        self._min_for_trigger = min_for_trigger
        # Hard-layer engineer ack state. Map (tenant, rule_family) → bool.
        self._forced_human_review: dict[tuple[str, str], bool] = {}

    def record_correction(self, record: CorrectionRecord) -> None:
        with self._lock:
            key = (record.tenant_id, record.rule_family)
            self._records[key].append(record)

    def disagreement_rate(self, tenant_id: str, rule_family: str) -> tuple[float, int]:
        """Return (rate, sample_size)."""
        with self._lock:
            buf = list(self._records.get((tenant_id, rule_family), ()))
        if not buf:
            return 0.0, 0
        n_disagree = sum(1 for r in buf if r.is_disagreement())
        return n_disagree / len(buf), len(buf)

    def should_soft_trigger(self, tenant_id: str, rule_family: str) -> bool:
        rate, n = self.disagreement_rate(tenant_id, rule_family)
        if n < self._min_for_trigger:
            return False
        return rate >= self._threshold_pct

    def acknowledge_force_review(
        self, tenant_id: str, rule_family: str, engineer_id: str
    ) -> None:
        with self._lock:
            self._forced_human_review[(tenant_id, rule_family)] = True

    def is_forced_human_review(self, tenant_id: str, rule_family: str) -> bool:
        with self._lock:
            return self._forced_human_review.get((tenant_id, rule_family), False)
