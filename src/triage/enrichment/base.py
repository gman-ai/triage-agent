"""EnrichmentSource protocol + shared base.

Each source declares its `source_type` (matches SourceType in the plan
schema), its `storage_tier` (per R9 / D33), and its per-source truncation
contract (`record_cap` + `truncation_sort_key`). The `fetch()` method takes
a tenant_id, an alert observable (the thing being looked up), and an
optional failure_mode injection knob; it returns a list of RetrievalRef.

The fan-out (`enrichment/fanout.py`) calls sources per InvestigationPlan
with tier-preference ordering and catches failures into EvidenceBundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

from triage.schemas.plan import SourceType, StorageTier
from triage.schemas.retrieval import RetrievalRef

FailureMode = Literal["clean", "timeout", "upstream_5xx", "malformed"]


@dataclass
class SourceQuery:
    """The shape every source's fetch receives.

    The alert observables (host_id, user_id, ip, etc.) live here, plus the
    tenant context. Sources never see raw vendor payloads; they only see the
    structured query the orchestrator built.
    """

    tenant_id: str
    alert_id: str
    entity_id: str | None = None
    ioc: str | None = None
    extra: dict | None = None


class EnrichmentSource(Protocol):
    source_type: SourceType
    storage_tier: StorageTier
    record_cap: int
    truncation_sort_key: str

    def fetch(
        self,
        query: SourceQuery,
        failure_mode: FailureMode = "clean",
    ) -> list[RetrievalRef]: ...


def now_utc() -> datetime:
    """Helper for deterministic UTC timestamps in source mocks."""
    return datetime.now(UTC)
