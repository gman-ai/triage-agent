"""Historical alerts enrichment mock.

storage_tier=warm: pipeline-resident operational logs.
record_cap=10; sort by severity DESC, occurred_at DESC.

The 500-record truncation acceptance gate (test_enrichment_truncation.py)
exercises this source. The mock supports a `synth_burst_count` parameter so
a single tenant_id+ioc query can be made to return arbitrary record counts
for the truncation test, without bloating the static seed.
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

_SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


class HistoricalSource:
    source_type = "historical"
    storage_tier = "warm"
    record_cap = 10
    truncation_sort_key = "severity DESC, occurred_at DESC"

    def __init__(self) -> None:
        now = now_utc()
        # Static seed: small set per tenant for the clean-path test.
        self._seed: dict[str, list[dict]] = {
            "tenant_a": [
                {
                    "alert_id": "hist_tenant_a_0001",
                    "rule_family": "impossible_travel",
                    "severity": "P2",
                    "occurred_at": (now - timedelta(days=5)).isoformat(),
                    "verdict": "likely_false_positive",
                },
                {
                    "alert_id": "hist_tenant_a_0002",
                    "rule_family": "brute_force",
                    "severity": "P3",
                    "occurred_at": (now - timedelta(days=12)).isoformat(),
                    "verdict": "confirmed_false_positive",
                },
            ],
            "tenant_b": [
                {
                    "alert_id": "hist_tenant_b_0001",
                    "rule_family": "ransomware",
                    "severity": "P1",
                    "occurred_at": (now - timedelta(days=3)).isoformat(),
                    "verdict": "likely_true_positive",
                },
            ],
        }

    def _synthesize_burst(self, tenant_id: str, count: int) -> list[dict]:
        """Generate `count` synthetic historical records for the truncation test.

        Severities are intentionally varied so the sort behavior is testable.
        """
        now = now_utc()
        rows: list[dict] = []
        for i in range(count):
            sev = "P0" if i == 0 else f"P{(i % 4) + 1}"
            rows.append(
                {
                    "alert_id": f"hist_{tenant_id}_synth_{i:05d}",
                    "rule_family": "impossible_travel",
                    "severity": sev,
                    "occurred_at": (now - timedelta(minutes=i)).isoformat(),
                    "verdict": "undetermined",
                }
            )
        return rows

    def fetch(
        self,
        query: SourceQuery,
        failure_mode: FailureMode = "clean",
    ) -> list[RetrievalRef]:
        if failure_mode == "timeout":
            raise RetrievalTimeoutError(self.source_type, timeout_ms=3000)
        if failure_mode == "upstream_5xx":
            raise RetrievalUpstreamError(self.source_type, status_code=500)
        if failure_mode == "malformed":
            raise MalformedRetrievalError(self.source_type, reason="invalid_severity_enum")

        synth_count = (query.extra or {}).get("synth_burst_count")
        if synth_count:
            rows = self._synthesize_burst(query.tenant_id, int(synth_count))
        else:
            rows = list(self._seed.get(query.tenant_id, []))

        rows.sort(
            key=lambda r: (_SEVERITY_ORDER.get(r["severity"], 99), r["occurred_at"]),
        )
        total = len(rows)
        capped = rows[: self.record_cap]
        truncated = total > self.record_cap

        now = now_utc()
        refs: list[RetrievalRef] = []
        for r in capped:
            refs.append(
                RetrievalRef(
                    retrieval_id=f"ret_hist_{uuid.uuid4().hex[:12]}",
                    source_type=self.source_type,
                    source_query=f"historical:{query.entity_id or query.ioc or '*'}",
                    fetched_at=now,
                    storage_tier=self.storage_tier,
                    retrieval_truncated=truncated,
                    truncation_sort_key=self.truncation_sort_key if truncated else None,
                    total_available=total if truncated else None,
                    payload=r,
                )
            )
        return refs


INSTANCE: EnrichmentSource = HistoricalSource()
