"""Acceptance gate: plan-gated tier-ordered fan-out per IMPL #9 + R8 + R9.

Three claims:
  1. Plan-gating — only sources listed in plan.all_planned_sources() are
     fetched. A source outside the plan is NEVER called.
  2. Tier-ordered — the orchestrator fetches sources in the order given by
     plan.tier_preference. Hot before warm. A [hot] plan does not fetch any
     warm source even if it's required.
  3. Failure containment — a per-source failure goes into
     enrichments_failed[] and the fan-out continues with the remaining
     sources.
"""

from __future__ import annotations

from triage.enrichment.base import SourceQuery
from triage.enrichment.fanout import build_default_registry, run_fanout
from triage.schemas.plan_loader import PlanTemplateRegistry


def _query(tenant_id: str = "tenant_a") -> SourceQuery:
    return SourceQuery(
        tenant_id=tenant_id,
        alert_id="alert_plan_gating_test",
        entity_id="u_acct_lead",
        ioc="198.51.100.42",
        extra={"rule_family": "ransomware"},
    )


def test_only_sources_in_plan_are_fetched():
    """The ransomware plan: required=[asset_cmdb, threat_intel, historical],
    optional=[identity_store, runbook]. log_search is NOT in the plan; it's
    also not in the Day 2 registry, but the assertion holds for any source
    not in plan.
    """
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P1")
    sources = build_default_registry()

    call_recorder: list = []
    bundle = run_fanout(plan, _query(), sources, call_recorder=call_recorder)

    planned = plan.all_planned_sources()
    for called in call_recorder:
        assert called in planned, (
            f"source {called!r} was fetched but not in plan {planned!r}"
        )


def test_fanout_attempts_sources_in_tier_preference_order():
    """The ransomware plan has tier_preference=[hot, warm]. All hot-tier
    sources in the plan must be called before any warm-tier source.
    """
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P1")
    sources = build_default_registry()

    call_recorder: list = []
    run_fanout(plan, _query(), sources, call_recorder=call_recorder)

    # Map each call to its tier.
    tier_per_call = [sources[st].storage_tier for st in call_recorder]
    # Find the first warm call; assert no hot call follows it.
    first_warm = next((i for i, t in enumerate(tier_per_call) if t == "warm"), None)
    if first_warm is not None:
        later = tier_per_call[first_warm + 1 :]
        assert "hot" not in later, (
            f"hot-tier source called AFTER a warm-tier source: {tier_per_call}"
        )


def test_hot_only_plan_does_not_fetch_warm_sources():
    """impossible_travel plan: tier_preference=[hot]. Even if the plan lists
    a warm source as required/optional (it doesn't here), the fan-out must
    NOT fetch warm sources.
    """
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("impossible_travel", "P1")
    sources = build_default_registry()

    call_recorder: list = []
    bundle = run_fanout(plan, _query(), sources, call_recorder=call_recorder)

    for called in call_recorder:
        assert sources[called].storage_tier == "hot", (
            f"warm-tier source {called!r} fetched under [hot]-only plan"
        )

    # impossible_travel plan: required=[identity_store, historical],
    # optional=[asset_cmdb, threat_intel]. tier_preference=[hot].
    # historical is warm-tier; with a hot-only plan, historical must NOT be
    # called even though it's required. It should land in enrichments_failed.
    assert "historical" in bundle.enrichments_failed


def test_per_source_failure_is_contained_and_logged():
    """A source that raises is caught; other sources still run."""
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P1")
    sources = build_default_registry()

    bundle = run_fanout(
        plan,
        _query(),
        sources,
        failure_modes={"threat_intel": "upstream_5xx"},
    )

    assert "threat_intel" in bundle.enrichments_failed
    # asset_cmdb is also hot-tier and required; it ran successfully and is
    # reflected in retrievals[].
    asset_refs = bundle.by_source("asset_cmdb")
    assert len(asset_refs) >= 1


def test_per_source_failure_span_carries_full_error_detail():
    """Per Codex Day 2 fold-in / Day 4 directive: when a source fails inside
    plan-gated fan-out, the bundle's span carries source_type, storage_tier,
    failure_mode, exception_class, exception_message, status_code (when HTTP),
    attempt_count, latency_ms. The verdict-layer `enrichments_failed` stays
    flat; this is the SRE-facing surface.
    """
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P1")
    sources = build_default_registry()
    bundle = run_fanout(
        plan,
        _query(),
        sources,
        failure_modes={"threat_intel": "upstream_5xx"},
    )

    failed_spans = [s for s in bundle.spans if s["source_type"] == "threat_intel"]
    assert len(failed_spans) == 1
    span = failed_spans[0]
    assert span["source_type"] == "threat_intel"
    assert span["storage_tier"] == "hot"
    assert span["failure_mode"] == "upstream_5xx"
    assert span["exception_class"] == "RetrievalUpstreamError"
    assert span["exception_message"] is not None
    assert isinstance(span["status_code"], int)
    assert 500 <= span["status_code"] < 600
    assert span["attempt_count"] == 1
    assert isinstance(span["latency_ms"], int)
    assert "threat_intel" in bundle.enrichments_failed


def test_evidence_bundle_retrieval_ids_form_allowlist():
    """The bundle's retrieval_ids() set is what the reasoning agent will
    cite from. Every retrieval has a unique id; the set has no duplicates.
    """
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P1")
    sources = build_default_registry()
    bundle = run_fanout(plan, _query(), sources)

    ids = bundle.retrieval_ids()
    assert len(ids) == len(bundle.retrievals)
    for ref in bundle.retrievals:
        assert ref.retrieval_id in ids
