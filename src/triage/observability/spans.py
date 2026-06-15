"""Observability spans per RECONCILED §2 cross-cutting + Codex Day 2 review fix.

The verdict layer's `enrichments_failed: list[source_type]` keeps the analyst-
facing surface clean. The operator-facing surface (these spans) carries the
forensic detail an SRE needs to reconstruct why a source failed: error_type,
truncated error_message, retry_count, latency_ms.

Day 4 ships the per-source EnrichmentSpan attached to EvidenceBundle. The
audit ledger persists the span set as part of the triage row so post-hoc
investigation has the operator-facing signal.

Production swap (DESIGN.md): replace this list[EnrichmentSpan] with an
OpenTelemetry tracer or structured-log emitter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

SpanOutcome = Literal["ok", "timeout", "upstream_error", "malformed", "rejected"]


@dataclass
class EnrichmentSpan:
    source_type: str
    storage_tier: str | None
    started_at: datetime
    ended_at: datetime
    latency_ms: int
    outcome: SpanOutcome
    retrieved_count: int = 0
    retry_count: int = 0
    error_type: str | None = None
    error_message: str | None = None  # truncated to 240 chars

    def to_audit_row(self) -> dict:
        return {
            "source_type": self.source_type,
            "storage_tier": self.storage_tier,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "latency_ms": self.latency_ms,
            "outcome": self.outcome,
            "retrieved_count": self.retrieved_count,
            "retry_count": self.retry_count,
            "error_type": self.error_type,
            "error_message": self.error_message,
        }


def truncate_error_message(message: str, max_len: int = 240) -> str:
    if len(message) <= max_len:
        return message
    return message[: max_len - 1] + "…"
