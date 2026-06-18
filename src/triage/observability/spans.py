"""Observability spans per source attempt.

The verdict layer's `enrichments_failed: list[source_type]` keeps the analyst-
facing surface clean. The operator-facing surface (these spans) carries the
forensic detail an SRE needs to reconstruct why a source failed.

Span fields:
  * source_type, storage_tier
  * failure_mode (the injected mode that produced the failure, or "clean")
  * exception_class (Python exception class name when an error fired)
  * exception_message (truncated to 240 chars)
  * status_code (set when the failure was HTTP — currently RetrievalUpstreamError)
  * attempt_count (per-source retry count; 0 in prototype)
  * latency_ms

The fan-out attaches one span per source attempt to EvidenceBundle.spans.
The audit ledger persists the span set as part of the triage row so post-hoc
investigation has the operator-facing signal.

Production swap (DESIGN.md): replace this list[EnrichmentSpan] with an
OpenTelemetry tracer or structured-log emitter.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    failure_mode: str = "clean"
    retrieved_count: int = 0
    attempt_count: int = 1
    exception_class: str | None = None
    exception_message: str | None = None  # truncated to 240 chars
    status_code: int | None = None  # set when failure carries an HTTP code

    def to_audit_row(self) -> dict:
        return {
            "source_type": self.source_type,
            "storage_tier": self.storage_tier,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "latency_ms": self.latency_ms,
            "outcome": self.outcome,
            "failure_mode": self.failure_mode,
            "retrieved_count": self.retrieved_count,
            "attempt_count": self.attempt_count,
            "exception_class": self.exception_class,
            "exception_message": self.exception_message,
            "status_code": self.status_code,
        }


def truncate_error_message(message: str, max_len: int = 240) -> str:
    if len(message) <= max_len:
        return message
    return message[: max_len - 1] + "…"
