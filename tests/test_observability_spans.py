"""Acceptance gate: enrichment fan-out spans per Codex Day 2 fold-in.

The verdict layer's `enrichments_failed: list[source_type]` is unchanged.
What's new: per-source spans with error_type, error_message, retry_count,
latency_ms. SRE can now reconstruct WHY a source failed.
"""

from __future__ import annotations

from triage.enrichment.base import SourceQuery
from triage.enrichment.fanout import build_default_registry, run_fanout
from triage.schemas.plan_loader import PlanTemplateRegistry


def _query() -> SourceQuery:
    return SourceQuery(
        tenant_id="tenant_a",
        alert_id="alert_obs_test",
        entity_id="u_acct_lead",
        ioc="198.51.100.42",
        extra={"rule_family": "ransomware"},
    )


def test_clean_run_emits_ok_spans_for_each_called_source():
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P1")
    sources = build_default_registry()
    bundle = run_fanout(plan, _query(), sources)

    ok_spans = [s for s in bundle.spans if s["outcome"] == "ok"]
    assert len(ok_spans) >= 1
    for span in ok_spans:
        assert span["source_type"] in plan.all_planned_sources()
        assert "started_at" in span
        assert "ended_at" in span
        assert "latency_ms" in span
        assert span["retrieved_count"] >= 0
        assert span["attempt_count"] >= 1
        assert span["failure_mode"] == "clean"
        assert span["exception_class"] is None
        assert span["exception_message"] is None
        assert span["status_code"] is None


def test_timeout_failure_emits_span_with_exception_detail():
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P1")
    sources = build_default_registry()
    bundle = run_fanout(
        plan,
        _query(),
        sources,
        failure_modes={"threat_intel": "timeout"},
    )

    failed = [s for s in bundle.spans if s["source_type"] == "threat_intel"]
    assert len(failed) == 1
    span = failed[0]
    assert span["outcome"] == "timeout"
    assert span["failure_mode"] == "timeout"
    assert span["exception_class"] == "RetrievalTimeoutError"
    assert "timed out" in (span["exception_message"] or "").lower()
    assert span["retrieved_count"] == 0
    assert span["attempt_count"] == 1
    assert span["status_code"] is None
    assert "threat_intel" in bundle.enrichments_failed


def test_upstream_5xx_failure_emits_status_code_on_span():
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P1")
    sources = build_default_registry()
    bundle = run_fanout(
        plan,
        _query(),
        sources,
        failure_modes={"asset_cmdb": "upstream_5xx"},
    )

    failed = [s for s in bundle.spans if s["source_type"] == "asset_cmdb"]
    assert len(failed) == 1
    assert failed[0]["outcome"] == "upstream_error"
    assert failed[0]["exception_class"] == "RetrievalUpstreamError"
    assert failed[0]["failure_mode"] == "upstream_5xx"
    # status_code is the HTTP code the source raised with.
    assert isinstance(failed[0]["status_code"], int)
    assert 500 <= failed[0]["status_code"] < 600


def test_malformed_failure_emits_malformed_outcome():
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P1")
    sources = build_default_registry()
    bundle = run_fanout(
        plan,
        _query(),
        sources,
        failure_modes={"runbook": "malformed"},
    )

    failed = [s for s in bundle.spans if s["source_type"] == "runbook"]
    assert len(failed) == 1
    assert failed[0]["outcome"] == "malformed"
    assert failed[0]["exception_class"] == "MalformedRetrievalError"
    assert failed[0]["failure_mode"] == "malformed"
    assert failed[0]["status_code"] is None


def test_tier_policy_rejection_surfaces_in_spans():
    """impossible_travel plan = [hot]. The required `historical` source is
    warm-tier; tier policy excludes it. The span surfaces this with
    outcome=rejected and exception_class=TierPolicyExcluded so SRE sees a
    different shape than an upstream error.
    """
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("impossible_travel", "P1")
    sources = build_default_registry()
    bundle = run_fanout(plan, _query(), sources)

    rejection_spans = [
        s
        for s in bundle.spans
        if s["source_type"] == "historical" and s["outcome"] == "rejected"
    ]
    assert len(rejection_spans) == 1
    assert rejection_spans[0]["exception_class"] == "TierPolicyExcluded"
    assert "tier_preference" in (rejection_spans[0]["exception_message"] or "")
