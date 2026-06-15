"""Acceptance gate: enrichment sources per IMPL #9 + RECONCILED §4.8 + R9.

For each of the 5 sources mocked on Day 2:
  * clean path returns RetrievalRef instances with storage_tier set
  * timeout failure raises RetrievalTimeoutError
  * upstream 5xx failure raises RetrievalUpstreamError
  * malformed failure raises MalformedRetrievalError

Also pins D14 evidence fields on threat_intel: provider, fetched_at,
cached_at, first_seen, last_seen, provider_confidence, conflicts.
"""

from __future__ import annotations

import pytest

from triage.enrichment import (
    asset_cmdb,
    historical,
    identity_store,
    runbook,
    threat_intel,
)
from triage.enrichment.base import SourceQuery
from triage.enrichment.errors import (
    MalformedRetrievalError,
    RetrievalTimeoutError,
    RetrievalUpstreamError,
)

ALL_SOURCES = [
    ("asset_cmdb", asset_cmdb.INSTANCE, "hot", 10),
    ("identity_store", identity_store.INSTANCE, "hot", 5),
    ("historical", historical.INSTANCE, "warm", 10),
    ("threat_intel", threat_intel.INSTANCE, "hot", 20),
    ("runbook", runbook.INSTANCE, "warm", 3),
]


def _query(tenant_id: str = "tenant_a", **overrides) -> SourceQuery:
    base = dict(
        tenant_id=tenant_id,
        alert_id="alert_test",
        entity_id="u_acct_lead",
        ioc="198.51.100.42",
        extra={"rule_family": "impossible_travel"},
    )
    base.update(overrides)
    return SourceQuery(**base)


@pytest.mark.parametrize("name, source, tier, cap", ALL_SOURCES)
def test_source_declares_storage_tier_and_record_cap(name, source, tier, cap):
    """R9: each source declares its tier; §4.8: each source declares its cap."""
    assert source.storage_tier == tier, f"{name} expected tier={tier}"
    assert source.record_cap == cap, f"{name} expected record_cap={cap}"
    assert source.truncation_sort_key != ""


@pytest.mark.parametrize("name, source, tier, cap", ALL_SOURCES)
def test_source_clean_path_returns_refs_with_storage_tier(name, source, tier, cap):
    refs = source.fetch(_query())
    assert isinstance(refs, list)
    # Asset/identity/threat_intel/runbook clean returns >=1 for the seeded
    # tenant_a query; historical also has seed entries. Any non-empty result
    # carries storage_tier per R9.
    for ref in refs:
        assert ref.storage_tier == tier
        assert ref.fetched_at is not None
        assert ref.source_type == source.source_type
        assert ref.retrieval_id.startswith("ret_")


@pytest.mark.parametrize("name, source, tier, cap", ALL_SOURCES)
def test_source_timeout_raises(name, source, tier, cap):
    with pytest.raises(RetrievalTimeoutError) as excinfo:
        source.fetch(_query(), failure_mode="timeout")
    assert excinfo.value.source == name


@pytest.mark.parametrize("name, source, tier, cap", ALL_SOURCES)
def test_source_upstream_5xx_raises(name, source, tier, cap):
    with pytest.raises(RetrievalUpstreamError) as excinfo:
        source.fetch(_query(), failure_mode="upstream_5xx")
    assert excinfo.value.source == name
    assert 500 <= excinfo.value.status_code < 600


@pytest.mark.parametrize("name, source, tier, cap", ALL_SOURCES)
def test_source_malformed_raises(name, source, tier, cap):
    with pytest.raises(MalformedRetrievalError) as excinfo:
        source.fetch(_query(), failure_mode="malformed")
    assert excinfo.value.source == name
    assert excinfo.value.reason != ""


def test_threat_intel_evidence_fields_populated_per_d14():
    """D14: provider, fetched_at, cached_at, first_seen, last_seen,
    provider_confidence, conflicts are all populated for threat intel.
    """
    refs = threat_intel.INSTANCE.fetch(_query(tenant_id="tenant_b"))
    assert len(refs) >= 1
    primary = refs[0]
    assert primary.provider == "feed_alpha"
    assert primary.provider_confidence == 0.92
    assert primary.cached_at is not None
    assert primary.first_seen is not None
    assert primary.last_seen is not None
    # Multi-provider conflict surfaces in conflicts[].
    assert len(primary.conflicts) >= 1
    assert primary.conflicts[0]["provider"] == "feed_beta"


def test_threat_intel_stale_clean_is_not_treated_as_benign_signal():
    """tenant_a sees the same IOC as 'unknown' with a 90-day-old cached_at.
    The reasoning agent on Day 3 must not treat this as benign. Day 2 pins
    the data shape that defends the claim: the ref has provider_confidence
    < 0.5 AND cached_at is older than 30 days from fetched_at. Both signals
    together are what makes "stale clean" distinct from "benign."
    """
    from datetime import timedelta

    refs = threat_intel.INSTANCE.fetch(_query(tenant_id="tenant_a"))
    assert len(refs) == 1
    ref = refs[0]
    assert ref.payload["reputation"] == "unknown"
    # Low provider confidence: this is not a strong clean signal.
    assert ref.provider_confidence is not None
    assert ref.provider_confidence < 0.5
    # cached_at is well in the past relative to fetched_at. The 30-day
    # threshold is a Day-3 reasoning-prompt concern; here we pin that the
    # mock returns staleness for the validator + reasoning tests to consume.
    assert ref.cached_at is not None
    age = ref.fetched_at - ref.cached_at
    assert age > timedelta(days=30), (
        f"tenant_a's threat_intel seed should be > 30d stale; got age={age}"
    )
