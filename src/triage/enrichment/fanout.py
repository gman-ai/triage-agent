"""Plan-gated tier-ordered enrichment fan-out per R8 + R9.

Inputs:
- InvestigationPlan: the typed plan emitted by T1 (R8).
- SourceQuery: tenant + alert + observable details.
- Registered EnrichmentSource instances (one per source_type).
- Optional failure_modes dict: per-source FailureMode override for test
  injection.

Behavior:
- Plan-gating: only sources in `plan.all_planned_sources()` are fetched.
  Sources outside the plan are NEVER called for this alert.
- Tier-ordered: the orchestrator iterates `plan.tier_preference` in order
  and fetches each tier's sources before advancing. A required source
  whose tier is not in tier_preference is skipped and reported in
  enrichments_failed[].
- Failure containment: each source's exception is captured into
  EvidenceBundle.enrichments_failed[] and the fan-out continues. The
  pipeline never raises uncaught at this boundary.
- Observability (Codex Day 2 review fold-in): each source attempt emits
  an EnrichmentSpan with error_type, error_message, retry_count, and
  latency_ms. The flat enrichments_failed[] keeps the verdict schema
  clean; the spans[] carry the SRE-facing detail.

The result is an `EvidenceBundle` with the merged retrievals[] (the
retrieval_id allowlist for the LLM), per-source failure flags, and a
spans list the audit ledger persists.

Call-order observability:
- Tests can pass a `call_recorder` list; the orchestrator appends each
  source_type as it issues the fetch. This is how `test_plan_gating.py`
  proves tier-ordered fetch without relying on timestamps.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import MutableSequence

from triage.enrichment.base import EnrichmentSource, FailureMode, SourceQuery
from triage.observability.spans import EnrichmentSpan, truncate_error_message
from triage.schemas.plan import InvestigationPlan, SourceType
from triage.schemas.retrieval import EvidenceBundle, RetrievalRef


def run_fanout(
    plan: InvestigationPlan,
    query: SourceQuery,
    sources: dict[SourceType, EnrichmentSource],
    failure_modes: dict[SourceType, FailureMode] | None = None,
    call_recorder: MutableSequence[SourceType] | None = None,
) -> EvidenceBundle:
    failure_modes = failure_modes or {}
    bundle = EvidenceBundle()
    planned = plan.all_planned_sources()

    for tier in plan.tier_preference:
        # All planned sources whose storage_tier matches this pass.
        tier_sources = [
            (st, src)
            for st, src in sources.items()
            if st in planned and src.storage_tier == tier
        ]
        # Stable order within a tier: required first, then optional.
        required_set = set(plan.required_sources)
        tier_sources.sort(key=lambda item: 0 if item[0] in required_set else 1)

        for source_type, src in tier_sources:
            if call_recorder is not None:
                call_recorder.append(source_type)
            mode: FailureMode = failure_modes.get(source_type, "clean")
            started_at = datetime.now(UTC)
            try:
                refs: list[RetrievalRef] = src.fetch(query, failure_mode=mode)
            except Exception as exc:
                ended_at = datetime.now(UTC)
                bundle.enrichments_failed.append(source_type)
                bundle.spans.append(
                    EnrichmentSpan(
                        source_type=source_type,
                        storage_tier=src.storage_tier,
                        started_at=started_at,
                        ended_at=ended_at,
                        latency_ms=int((ended_at - started_at).total_seconds() * 1000),
                        outcome=_classify_outcome(exc),
                        retrieved_count=0,
                        retry_count=0,
                        error_type=type(exc).__name__,
                        error_message=truncate_error_message(str(exc)),
                    ).to_audit_row()
                )
                continue
            ended_at = datetime.now(UTC)
            bundle.retrievals.extend(refs)
            bundle.spans.append(
                EnrichmentSpan(
                    source_type=source_type,
                    storage_tier=src.storage_tier,
                    started_at=started_at,
                    ended_at=ended_at,
                    latency_ms=int((ended_at - started_at).total_seconds() * 1000),
                    outcome="ok",
                    retrieved_count=len(refs),
                ).to_audit_row()
            )

    # Surface plan sources whose tier is NOT in tier_preference. The plan says
    # to fetch them, the tier policy says not to. The verdict needs to know.
    allowed_tiers = set(plan.tier_preference)
    for source_type in planned:
        src = sources.get(source_type)
        if src is None:
            bundle.enrichments_failed.append(source_type)
            bundle.spans.append(
                {
                    "source_type": source_type,
                    "storage_tier": None,
                    "outcome": "rejected",
                    "latency_ms": 0,
                    "retry_count": 0,
                    "error_type": "UnregisteredSource",
                    "error_message": (
                        f"source {source_type!r} is in plan but not in registry"
                    ),
                }
            )
            continue
        if src.storage_tier not in allowed_tiers:
            bundle.enrichments_failed.append(source_type)
            bundle.spans.append(
                {
                    "source_type": source_type,
                    "storage_tier": src.storage_tier,
                    "outcome": "rejected",
                    "latency_ms": 0,
                    "retry_count": 0,
                    "error_type": "TierPolicyExcluded",
                    "error_message": (
                        f"source tier {src.storage_tier!r} not in plan "
                        f"tier_preference {plan.tier_preference!r}"
                    ),
                }
            )

    return bundle


def _classify_outcome(exc: Exception) -> str:
    name = type(exc).__name__
    if name == "RetrievalTimeoutError":
        return "timeout"
    if name == "RetrievalUpstreamError":
        return "upstream_error"
    if name == "MalformedRetrievalError":
        return "malformed"
    return "upstream_error"


def build_default_registry() -> dict[SourceType, EnrichmentSource]:
    """Default per-process source registry.

    Day 2 ships the five sources named in IMPLEMENTATION_SCOPE.md item #9.
    Day 3+ may extend (e.g. log_search), at which point this registry is the
    single registration point — the fan-out reads from it.
    """
    from triage.enrichment import (
        asset_cmdb,
        historical,
        identity_store,
        runbook,
        threat_intel,
    )

    return {
        asset_cmdb.INSTANCE.source_type: asset_cmdb.INSTANCE,
        identity_store.INSTANCE.source_type: identity_store.INSTANCE,
        historical.INSTANCE.source_type: historical.INSTANCE,
        threat_intel.INSTANCE.source_type: threat_intel.INSTANCE,
        runbook.INSTANCE.source_type: runbook.INSTANCE,
    }
