"""Runbook KB enrichment mock.

storage_tier=warm per v1.3 directive: knowledge-base prose lives in warm
operational storage.
record_cap=3 per §4.8; sort by semantic_similarity DESC (mocked as a static
relevance score keyed off rule_family).

Per §4.4 evidence-support contract, runbook prose is flagged human_verifiable
in downstream evidence validation; this Day 2 mock just produces the
RetrievalRef shape. The human_verifiable tagging logic lands Day 3 with the
validator.
"""

from __future__ import annotations

import uuid

from triage.enrichment.base import EnrichmentSource, FailureMode, SourceQuery, now_utc
from triage.enrichment.errors import (
    MalformedRetrievalError,
    RetrievalTimeoutError,
    RetrievalUpstreamError,
)
from triage.schemas.retrieval import RetrievalRef


class RunbookSource:
    source_type = "runbook"
    storage_tier = "warm"
    record_cap = 3
    truncation_sort_key = "semantic_similarity DESC"

    def __init__(self) -> None:
        # Runbooks are tenant-agnostic; the seed is keyed on rule_family. The
        # rule_family arrives via query.extra so the source can still honor
        # per-tenant routing if a future tenant overrides default runbooks.
        self._seed: dict[str, list[dict]] = {
            "impossible_travel": [
                {
                    "runbook_id": "rb_impossible_travel_v3",
                    "title": "Impossible travel response",
                    "summary": (
                        "Disable session, force MFA re-challenge, confirm with user "
                        "via out-of-band channel before re-enabling."
                    ),
                    "semantic_similarity": 0.92,
                    "owner_team": "identity_ops",
                },
            ],
            "ransomware": [
                {
                    "runbook_id": "rb_ransomware_isolation_v2",
                    "title": "Ransomware host isolation",
                    "summary": (
                        "Isolate host from network, capture volatile memory, notify "
                        "incident commander."
                    ),
                    "semantic_similarity": 0.95,
                    "owner_team": "incident_response",
                },
            ],
            "privilege_escalation": [
                {
                    "runbook_id": "rb_privesc_v1",
                    "title": "Privilege escalation containment",
                    "summary": (
                        "Revoke transient grant, audit role lineage, notify owner team."
                    ),
                    "semantic_similarity": 0.88,
                    "owner_team": "identity_ops",
                },
            ],
        }

    def fetch(
        self,
        query: SourceQuery,
        failure_mode: FailureMode = "clean",
    ) -> list[RetrievalRef]:
        if failure_mode == "timeout":
            raise RetrievalTimeoutError(self.source_type, timeout_ms=1000)
        if failure_mode == "upstream_5xx":
            raise RetrievalUpstreamError(self.source_type, status_code=502)
        if failure_mode == "malformed":
            raise MalformedRetrievalError(self.source_type, reason="missing_title_field")

        rule_family = (query.extra or {}).get("rule_family", "")
        rows = list(self._seed.get(rule_family, []))
        rows.sort(key=lambda r: r["semantic_similarity"], reverse=True)
        total = len(rows)
        capped = rows[: self.record_cap]
        truncated = total > self.record_cap

        now = now_utc()
        refs: list[RetrievalRef] = []
        for r in capped:
            refs.append(
                RetrievalRef(
                    retrieval_id=f"ret_runbook_{uuid.uuid4().hex[:12]}",
                    source_type=self.source_type,
                    source_query=f"runbook:{rule_family}",
                    fetched_at=now,
                    storage_tier=self.storage_tier,
                    retrieval_truncated=truncated,
                    truncation_sort_key=self.truncation_sort_key if truncated else None,
                    total_available=total if truncated else None,
                    payload=r,
                )
            )
        return refs


INSTANCE: EnrichmentSource = RunbookSource()
