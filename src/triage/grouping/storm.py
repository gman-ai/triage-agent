"""Storm grouper.

Collapses bursts of similar alerts into a single IncidentGroup before the LLM
tier runs. Grouping key:

    (tenant_id, rule_id, source_system, primary_entity, primary_ioc, time_window_5min)

Prototype implementation is a single-worker in-memory singleton with a sliding
counter map. Production swap to Redis (atomic INCR + TTL) is documented in
DESIGN.md; the contract and tests sit at the grouping-logic boundary so the
production swap is a data-store change, not a logic change.

Behavior:
    * Each alert receives a `decision` of "individual" (process normally) or
      "group_attach" (member attached to an existing IncidentGroup). The first
      alert in a window that later exceeds threshold is the IncidentGroup's
      sample alert.
    * A grouping key transitions to group mode after `threshold_per_window`
      alerts arrive within `window_seconds`. The default threshold is 10 per
      5 minutes.
    * The window is sliding: counters expire when no alert with that key has
      been seen for `window_seconds`.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Deque

from triage.schemas.alert import CanonicalAlertEvent

DEFAULT_THRESHOLD_PER_WINDOW = 10
DEFAULT_WINDOW_SECONDS = 300


@dataclass
class IncidentGroup:
    group_id: str
    grouping_key: tuple
    sample_alert: CanonicalAlertEvent
    member_count: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class GroupingDecision:
    decision: str
    group: IncidentGroup | None
    alert: CanonicalAlertEvent

    @property
    def is_group_attach(self) -> bool:
        return self.decision == "group_attach"


class StormGrouper:
    """Per-process singleton; do NOT instantiate directly outside tests.

    Real callers fetch via `get_storm_grouper()` so the singleton state is
    shared across the deterministic router and the audit ledger.
    """

    def __init__(
        self,
        threshold_per_window: int = DEFAULT_THRESHOLD_PER_WINDOW,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._threshold = threshold_per_window
        self._window = timedelta(seconds=window_seconds)
        self._lock = threading.Lock()
        self._counters: dict[tuple, Deque[datetime]] = {}
        self._groups: dict[tuple, IncidentGroup] = {}
        self._group_seq = 0

    def reset(self) -> None:
        """Test-only clear of all in-memory state."""
        with self._lock:
            self._counters.clear()
            self._groups.clear()
            self._group_seq = 0

    @staticmethod
    def grouping_key(alert: CanonicalAlertEvent, now: datetime) -> tuple:
        bucket = now.replace(second=0, microsecond=0)
        bucket = bucket.replace(minute=(bucket.minute // 5) * 5)
        return (
            alert.tenant_id,
            alert.rule_id,
            alert.source_system,
            alert.grouping_entity(),
            alert.primary_ioc(),
            bucket.isoformat(),
        )

    def classify(self, alert: CanonicalAlertEvent, now: datetime | None = None) -> GroupingDecision:
        now = now or datetime.now(UTC)
        key = self.grouping_key(alert, now)
        with self._lock:
            timestamps = self._counters.setdefault(key, deque())
            cutoff = now - self._window
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()
            timestamps.append(now)
            count = len(timestamps)
            existing_group = self._groups.get(key)
            if existing_group is not None:
                existing_group.member_count += 1
                existing_group.last_seen = now
                return GroupingDecision("group_attach", existing_group, alert)
            if count >= self._threshold:
                # Group forms at the trip point. member_count starts at 1: the
                # triggering alert itself is the first (and sample) member.
                # The (threshold-1) prior alerts in the window were already
                # returned as "individual" decisions — they point at their own
                # verdicts, not this group's, so they aren't members.
                self._group_seq += 1
                group = IncidentGroup(
                    group_id=f"grp_{self._group_seq:08d}",
                    grouping_key=key,
                    sample_alert=alert,
                    member_count=1,
                    first_seen=now,
                    last_seen=now,
                )
                self._groups[key] = group
                return GroupingDecision("group_attach", group, alert)
            return GroupingDecision("individual", None, alert)


_INSTANCE: StormGrouper | None = None
_INSTANCE_LOCK = threading.Lock()


def get_storm_grouper() -> StormGrouper:
    global _INSTANCE
    if _INSTANCE is not None:
        return _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = StormGrouper()
    return _INSTANCE


def reset_storm_grouper() -> None:
    """Test-only: discard the singleton so tests get a clean state."""
    global _INSTANCE
    with _INSTANCE_LOCK:
        _INSTANCE = None
