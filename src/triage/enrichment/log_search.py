"""Log back-search enrichment mock.

storage_tier=warm per v1.3 directive: log retention is operational, not
SIEM-indexed.
record_cap=50 per §4.8; sort by time_locality (proximity to the alert's
detected_at).

The plan templates for c2_callback and dns_exfil already reference log_search
(RECONCILED §5.1). This source completes the registry so plan-gating runs
end-to-end on those families.

The mock synthesizes log lines around the alert's IOC: a base set of lines
that flank the (synthetic) event window. Tests can request `synth_line_count`
in query.extra to drive truncation paths.
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


class LogSearchSource:
    source_type = "log_search"
    storage_tier = "warm"
    record_cap = 50
    truncation_sort_key = "time_locality (offset_seconds ASC from event)"

    def __init__(self) -> None:
        # Seed: a small set of synthetic lines per tenant + ioc. Real
        # production swaps to a Splunk back-search REST call (DESIGN ONLY #12).
        now = now_utc()
        self._seed: dict[str, dict[str, list[dict]]] = {
            "tenant_a": {
                "198.51.100.42": [
                    {
                        "line_id": "log_tenant_a_001",
                        "occurred_at": (now - timedelta(seconds=30)).isoformat(),
                        "offset_seconds": -30,
                        "level": "info",
                        "message": "tcp.connect 198.51.100.42:443 dst=outbound",
                    },
                    {
                        "line_id": "log_tenant_a_002",
                        "occurred_at": now.isoformat(),
                        "offset_seconds": 0,
                        "level": "warn",
                        "message": "dns.lookup mismatch hostname=evil.example",
                    },
                    {
                        "line_id": "log_tenant_a_003",
                        "occurred_at": (now + timedelta(seconds=20)).isoformat(),
                        "offset_seconds": 20,
                        "level": "info",
                        "message": "process.exit pid=14422 code=0",
                    },
                ],
            },
            "tenant_b": {
                "198.51.100.42": [
                    {
                        "line_id": "log_tenant_b_001",
                        "occurred_at": (now - timedelta(seconds=5)).isoformat(),
                        "offset_seconds": -5,
                        "level": "error",
                        "message": "policy.block egress dst=198.51.100.42",
                    },
                ],
            },
        }

    def _synthesize_window(self, tenant_id: str, ioc: str, count: int) -> list[dict]:
        """Generate `count` synthetic log lines symmetric around the event."""
        now = now_utc()
        rows: list[dict] = []
        for i in range(count):
            # Spread offsets +/- 1s steps starting at 0.
            offset = i if i % 2 == 0 else -i
            rows.append(
                {
                    "line_id": f"log_{tenant_id}_synth_{i:05d}",
                    "occurred_at": (now + timedelta(seconds=offset)).isoformat(),
                    "offset_seconds": offset,
                    "level": "info",
                    "message": f"synthetic log line {i} ioc={ioc}",
                }
            )
        return rows

    def fetch(
        self,
        query: SourceQuery,
        failure_mode: FailureMode = "clean",
    ) -> list[RetrievalRef]:
        if failure_mode == "timeout":
            raise RetrievalTimeoutError(self.source_type, timeout_ms=4000)
        if failure_mode == "upstream_5xx":
            raise RetrievalUpstreamError(self.source_type, status_code=503)
        if failure_mode == "malformed":
            raise MalformedRetrievalError(self.source_type, reason="missing_offset_seconds")

        synth_count = (query.extra or {}).get("synth_line_count")
        if synth_count:
            rows = self._synthesize_window(query.tenant_id, query.ioc or "*", int(synth_count))
        else:
            tenant_seed = self._seed.get(query.tenant_id, {})
            rows = list(tenant_seed.get(query.ioc or "", []))

        # Sort by absolute time-locality to the event (offset closer to 0 first).
        rows.sort(key=lambda r: abs(r["offset_seconds"]))
        total = len(rows)
        capped = rows[: self.record_cap]
        truncated = total > self.record_cap

        now = now_utc()
        refs: list[RetrievalRef] = []
        for r in capped:
            refs.append(
                RetrievalRef(
                    retrieval_id=f"ret_log_{uuid.uuid4().hex[:12]}",
                    source_type=self.source_type,
                    source_query=f"log_search:{query.ioc or '*'}",
                    fetched_at=now,
                    storage_tier=self.storage_tier,
                    retrieval_truncated=truncated,
                    truncation_sort_key=self.truncation_sort_key if truncated else None,
                    total_available=total if truncated else None,
                    payload=r,
                )
            )
        return refs


INSTANCE: EnrichmentSource = LogSearchSource()
