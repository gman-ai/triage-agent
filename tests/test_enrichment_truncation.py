"""Acceptance gate: enrichment truncation per RECONCILED §4.8 + R3.

The 500-record historical burst is the canonical test from §4.8: an
indicator with 500 matching historical rows must return the per-source cap
(10 for historical), the retrieval_truncated flag set, the truncation_sort_key
disclosed, and total_available populated.

The Day 3 reasoning prompt will reference these fields to tell the model the
data is a sample sorted by `<key>`, so the model doesn't claim
"comprehensive review" when it only saw the top N.
"""

from __future__ import annotations

from triage.enrichment.base import SourceQuery
from triage.enrichment.historical import INSTANCE as HISTORICAL


def test_historical_500_record_burst_capped_at_record_cap():
    query = SourceQuery(
        tenant_id="tenant_a",
        alert_id="alert_truncation_test",
        ioc="198.51.100.42",
        extra={"synth_burst_count": 500},
    )
    refs = HISTORICAL.fetch(query)

    # §4.8: result is capped at the per-source cap.
    assert len(refs) == HISTORICAL.record_cap == 10

    # Every returned ref carries the truncation contract.
    for ref in refs:
        assert ref.retrieval_truncated is True
        assert ref.truncation_sort_key == "severity DESC, occurred_at DESC"
        assert ref.total_available == 500
        assert ref.storage_tier == "warm"


def test_historical_under_cap_does_not_set_truncated_flag():
    """tenant_a's static seed has 2 historical rows; well under the cap of 10.
    The truncation contract should NOT mis-fire on small result sets.
    """
    query = SourceQuery(
        tenant_id="tenant_a",
        alert_id="alert_small_test",
        ioc="198.51.100.42",
    )
    refs = HISTORICAL.fetch(query)
    assert 0 < len(refs) <= 2
    for ref in refs:
        assert ref.retrieval_truncated is False
        assert ref.truncation_sort_key is None
        assert ref.total_available is None
