"""SourceAdapter protocol.

Adapters translate vendor-specific JSON to CanonicalAlertEvent. Each adapter
is versioned so destructive drift surfaces as a quarantine signal an operator
can act on; additive drift (vendor adds a benign field) flows through with a
log entry and does NOT downgrade confidence.

Each adapter implementation must:
  * declare `source_system` (the vendor identifier) and `version` (e.g. "v1")
  * raise DestructiveDriftError when a required canonical field cannot be
    mapped from any documented path
  * collect unmapped paths into CanonicalAlertEvent.raw_unknown_extras and
    flag the alert with additive_drift_fields = [...]
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from triage.schemas.alert import CanonicalAlertEvent


@runtime_checkable
class SourceAdapter(Protocol):
    source_system: str
    version: str

    def to_canonical(self, payload: dict[str, Any], tenant_id: str) -> CanonicalAlertEvent: ...
