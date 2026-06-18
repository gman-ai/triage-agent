"""Threat intel enrichment mock.

storage_tier=hot: IOC reputation is SIEM-indexed.
record_cap=20; sort by provider_confidence DESC, last_seen DESC.

This is the most contract-loaded source because the reasoning agent
defends against the "stale clean cannot prove benign" failure mode using
seven evidence fields on each retrieval.

Each returned RetrievalRef carries provider, fetched_at, cached_at,
first_seen, last_seen, provider_confidence, and a conflicts[] list of
other-provider disagreements when present.

The seed includes both a known-malicious IP (high-confidence, recent) and a
stale-clean IP (low-confidence, cached three months ago) so the reasoning
agent test can prove the "stale clean cannot prove benign" defense.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from triage.enrichment.base import EnrichmentSource, FailureMode, SourceQuery, now_utc
from triage.enrichment.errors import (
    MalformedRetrievalError,
    RetrievalTimeoutError,
    RetrievalUpstreamError,
)
from triage.schemas.retrieval import RetrievalRef


class ThreatIntelSource:
    source_type = "threat_intel"
    storage_tier = "hot"
    record_cap = 20
    truncation_sort_key = "provider_confidence DESC, last_seen DESC"

    def __init__(self) -> None:
        now = now_utc()
        # The seed includes two IOCs that show up in the tenant_a/tenant_b
        # fixtures. tenant_a sees the IOC as "unknown reputation"; tenant_b sees
        # the same IOC as "known_malicious." This is the collision used by
        # cross-tenant isolation tests.
        self._seed: dict[str, dict[str, list[dict]]] = {
            "tenant_a": {
                "198.51.100.42": [
                    {
                        "ioc": "198.51.100.42",
                        "type": "ip",
                        "provider": "internal_reputation",
                        "reputation": "unknown",
                        "provider_confidence": 0.45,
                        "first_seen": (now - timedelta(days=120)).isoformat(),
                        "last_seen": (now - timedelta(days=90)).isoformat(),
                        "cached_at": (now - timedelta(days=90)).isoformat(),
                        "conflicts": [],
                    },
                ],
            },
            "tenant_b": {
                "198.51.100.42": [
                    {
                        "ioc": "198.51.100.42",
                        "type": "ip",
                        "provider": "feed_alpha",
                        "reputation": "known_malicious",
                        "provider_confidence": 0.92,
                        "first_seen": (now - timedelta(days=30)).isoformat(),
                        "last_seen": (now - timedelta(hours=6)).isoformat(),
                        "cached_at": (now - timedelta(hours=6)).isoformat(),
                        "conflicts": [
                            {
                                "provider": "feed_beta",
                                "reputation": "unknown",
                                "provider_confidence": 0.30,
                            },
                        ],
                    },
                    {
                        "ioc": "198.51.100.42",
                        "type": "ip",
                        "provider": "feed_beta",
                        "reputation": "unknown",
                        "provider_confidence": 0.30,
                        "first_seen": (now - timedelta(days=30)).isoformat(),
                        "last_seen": (now - timedelta(days=2)).isoformat(),
                        "cached_at": (now - timedelta(days=2)).isoformat(),
                        "conflicts": [],
                    },
                ],
            },
        }

    def fetch(
        self,
        query: SourceQuery,
        failure_mode: FailureMode = "clean",
    ) -> list[RetrievalRef]:
        if failure_mode == "timeout":
            raise RetrievalTimeoutError(self.source_type, timeout_ms=2500)
        if failure_mode == "upstream_5xx":
            raise RetrievalUpstreamError(self.source_type, status_code=504)
        if failure_mode == "malformed":
            raise MalformedRetrievalError(self.source_type, reason="missing_provider_field")

        tenant_seed = self._seed.get(query.tenant_id, {})
        rows = list(tenant_seed.get(query.ioc or "", []))
        rows.sort(
            key=lambda r: (-(r["provider_confidence"] or 0.0), r["last_seen"]),
        )
        total = len(rows)
        capped = rows[: self.record_cap]
        truncated = total > self.record_cap

        now = now_utc()
        refs: list[RetrievalRef] = []
        for r in capped:
            refs.append(
                RetrievalRef(
                    retrieval_id=f"ret_ti_{uuid.uuid4().hex[:12]}",
                    source_type=self.source_type,
                    source_query=f"threat_intel:{query.ioc or '*'}",
                    fetched_at=now,
                    cached_at=r["cached_at"],
                    provider=r["provider"],
                    provider_confidence=r["provider_confidence"],
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    conflicts=list(r.get("conflicts", [])),
                    storage_tier=self.storage_tier,
                    retrieval_truncated=truncated,
                    truncation_sort_key=self.truncation_sort_key if truncated else None,
                    total_available=total if truncated else None,
                    payload=r,
                )
            )
        return refs


INSTANCE: EnrichmentSource = ThreatIntelSource()
