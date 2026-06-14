"""Adapter registry per RECONCILED §4.2.

Source systems with no registered adapter are treated as destructive drift:
the alert is quarantined, no LLM call is made. A new vendor onboarding ships
as a new adapter version, not a runtime config toggle.
"""

from __future__ import annotations

from triage.adapters.base import SourceAdapter
from triage.adapters.okta import OktaAdapterV1
from triage.errors import UnknownSourceError

_REGISTRY: dict[str, SourceAdapter] = {
    "okta": OktaAdapterV1(),
}


def get_adapter(source_system: str) -> SourceAdapter:
    adapter = _REGISTRY.get(source_system)
    if adapter is None:
        raise UnknownSourceError(source_system=source_system)
    return adapter


def registered_sources() -> list[str]:
    return sorted(_REGISTRY.keys())
