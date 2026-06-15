"""Asset CMDB enrichment mock.

storage_tier=hot per v1.3 directive: asset metadata is indexed for fast lookup.
record_cap=10 per §4.8; sort by criticality DESC, then last_seen DESC.

Per-tenant seed data: two tenants with deliberately identical entity IDs
(host srv_billing_01 owned by both tenants, different roles) to make any
cross-tenant leakage at the fan-out boundary detectable.
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

_CRITICALITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class AssetCmdbSource:
    source_type = "asset_cmdb"
    storage_tier = "hot"
    record_cap = 10
    truncation_sort_key = "criticality DESC, last_seen DESC"

    def __init__(self) -> None:
        now = now_utc()
        self._seed: dict[str, list[dict]] = {
            "tenant_a": [
                {
                    "asset_id": "srv_billing_01",
                    "role": "billing_api",
                    "criticality": "critical",
                    "owner_team": "payments",
                    "last_seen": now.isoformat(),
                },
                {
                    "asset_id": "srv_aux_02",
                    "role": "reporting_worker",
                    "criticality": "medium",
                    "owner_team": "data_platform",
                    "last_seen": (now - timedelta(hours=12)).isoformat(),
                },
            ],
            "tenant_b": [
                {
                    "asset_id": "srv_billing_01",
                    "role": "ledger_writer",
                    "criticality": "high",
                    "owner_team": "corp_systems",
                    "last_seen": now.isoformat(),
                },
            ],
        }

    def fetch(
        self,
        query: SourceQuery,
        failure_mode: FailureMode = "clean",
    ) -> list[RetrievalRef]:
        if failure_mode == "timeout":
            raise RetrievalTimeoutError(self.source_type, timeout_ms=2000)
        if failure_mode == "upstream_5xx":
            raise RetrievalUpstreamError(self.source_type, status_code=503)
        if failure_mode == "malformed":
            raise MalformedRetrievalError(self.source_type, reason="non_dict_record")

        rows = self._seed.get(query.tenant_id, [])
        if query.entity_id:
            rows = [r for r in rows if r["asset_id"] == query.entity_id] or rows
        rows = sorted(
            rows,
            key=lambda r: (_CRITICALITY_ORDER.get(r["criticality"], 99), r["last_seen"]),
        )
        total = len(rows)
        capped = rows[: self.record_cap]
        truncated = total > self.record_cap

        now = now_utc()
        refs: list[RetrievalRef] = []
        for r in capped:
            refs.append(
                RetrievalRef(
                    retrieval_id=f"ret_asset_{uuid.uuid4().hex[:12]}",
                    source_type=self.source_type,
                    source_query=f"asset_cmdb:{query.entity_id or '*'}",
                    fetched_at=now,
                    storage_tier=self.storage_tier,
                    retrieval_truncated=truncated,
                    truncation_sort_key=self.truncation_sort_key if truncated else None,
                    total_available=total if truncated else None,
                    payload=r,
                )
            )
        return refs


# Module-level instance used by the fan-out registry.
INSTANCE: EnrichmentSource = AssetCmdbSource()
