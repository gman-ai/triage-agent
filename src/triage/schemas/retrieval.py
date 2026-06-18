"""Retrieval schemas.

RetrievalRef is the typed envelope every enrichment source returns. Every
field carries provenance (source_type, source_query, fetched_at), grounding
hooks (retrieval_id is the allowlist token the LLM may cite), truncation
metadata (retrieval_truncated + truncation_sort_key + total_available), and
storage-tier metadata (storage_tier).

EvidenceBundle is the shape returned by the enrichment fan-out: an ordered
list of RetrievalRef plus per-source failure flags surfaced in the degraded
taxonomy.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from triage.schemas.plan import SourceType, StorageTier


class RetrievalRef(BaseModel):
    retrieval_id: str
    source_type: SourceType
    source_query: str
    fetched_at: datetime
    cached_at: datetime | None = None

    # Threat-intel-shaped provenance fields. Carried on all RetrievalRefs as
    # optionals so the LLM/validator can ground claims against them when
    # present without needing per-source type discrimination.
    provider: str | None = None
    provider_confidence: float | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    conflicts: list[dict] = Field(default_factory=list)

    # Truncation contract.
    retrieval_truncated: bool = False
    truncation_sort_key: str | None = None
    total_available: int | None = None

    # Storage-tier contract.
    storage_tier: StorageTier | None = None

    # Payload is the structured record(s) the source returned. Pydantic dict
    # rather than a closed model because each source's payload schema is its
    # own (asset rows differ from threat_intel rows). The validator and
    # downstream code address payload fields via field_path in ObservedFact.
    payload: dict[str, Any] = Field(default_factory=dict)


class EvidenceBundle(BaseModel):
    """Result of one fan-out pass for one alert.

    retrievals[] is the allowlist for the reasoning agent: every fact emitted
    by the LLM must cite a retrieval_id that appears in this list.
    enrichments_failed[] is the analyst-facing flat list keeping the verdict
    schema clean.
    spans[] is the operator-facing per-source detail (error_type, message,
    retry_count, latency_ms) that an SRE uses to reconstruct WHY a source
    failed.
    """

    retrievals: list[RetrievalRef] = Field(default_factory=list)
    enrichments_failed: list[str] = Field(default_factory=list)
    spans: list[dict] = Field(default_factory=list)

    def by_source(self, source_type: SourceType) -> list[RetrievalRef]:
        return [r for r in self.retrievals if r.source_type == source_type]

    def retrieval_ids(self) -> set[str]:
        return {r.retrieval_id for r in self.retrievals}
