"""Identity store enrichment mock.

storage_tier=hot: identity rows are SIEM-resident.
record_cap=5; sort by recency DESC (last_seen).

Like asset_cmdb, two tenants seed identical entity IDs (u_acct_lead in both,
different roles) so cross-tenant leakage at the fan-out boundary is detectable.
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


class IdentityStoreSource:
    source_type = "identity_store"
    storage_tier = "hot"
    record_cap = 5
    truncation_sort_key = "last_seen DESC"

    def __init__(self) -> None:
        now = now_utc()
        self._seed: dict[str, list[dict]] = {
            "tenant_a": [
                {
                    "user_id": "u_acct_lead",
                    "role": "account_lead",
                    "department": "finance",
                    "mfa_enabled": True,
                    "last_password_change": (now - timedelta(days=14)).isoformat(),
                    "last_seen": now.isoformat(),
                    "recent_geo": ["US"],
                },
            ],
            "tenant_b": [
                {
                    "user_id": "u_acct_lead",
                    "role": "account_lead",
                    "department": "research",
                    "mfa_enabled": False,
                    "last_password_change": (now - timedelta(days=180)).isoformat(),
                    "last_seen": now.isoformat(),
                    "recent_geo": ["US"],
                },
            ],
        }

    def fetch(
        self,
        query: SourceQuery,
        failure_mode: FailureMode = "clean",
    ) -> list[RetrievalRef]:
        if failure_mode == "timeout":
            raise RetrievalTimeoutError(self.source_type, timeout_ms=1500)
        if failure_mode == "upstream_5xx":
            raise RetrievalUpstreamError(self.source_type, status_code=502)
        if failure_mode == "malformed":
            raise MalformedRetrievalError(self.source_type, reason="missing_user_id")

        rows = self._seed.get(query.tenant_id, [])
        if query.entity_id:
            rows = [r for r in rows if r["user_id"] == query.entity_id] or rows
        rows = sorted(rows, key=lambda r: r["last_seen"], reverse=True)
        total = len(rows)
        capped = rows[: self.record_cap]
        truncated = total > self.record_cap

        now = now_utc()
        refs: list[RetrievalRef] = []
        for r in capped:
            refs.append(
                RetrievalRef(
                    retrieval_id=f"ret_identity_{uuid.uuid4().hex[:12]}",
                    source_type=self.source_type,
                    source_query=f"identity_store:{query.entity_id or '*'}",
                    fetched_at=now,
                    storage_tier=self.storage_tier,
                    retrieval_truncated=truncated,
                    truncation_sort_key=self.truncation_sort_key if truncated else None,
                    total_available=total if truncated else None,
                    payload=r,
                )
            )
        return refs


INSTANCE: EnrichmentSource = IdentityStoreSource()
