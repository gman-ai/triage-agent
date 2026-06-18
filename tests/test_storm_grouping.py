"""Storm grouper tests.

1000-alert burst where 950 share the grouping key, 50 are distinct. The
LLM-tier path observes a single IncidentGroup for the 950, and the 50
distinct alerts route individually.

The test stays inside the grouping boundary; it does NOT call the LLM. It
asserts on the grouper's classification decisions.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from triage.grouping.storm import StormGrouper
from triage.schemas.alert import Asset, CanonicalAlertEvent, Observable


def _build_alert(
    *,
    alert_id: str,
    tenant_id: str,
    rule_id: str,
    asset_id: str,
    ip: str,
    detected_at: datetime,
) -> CanonicalAlertEvent:
    return CanonicalAlertEvent(
        tenant_id=tenant_id,
        alert_id=alert_id,
        source_system="okta",
        source_adapter_version="okta_v1",
        rule_id=rule_id,
        rule_family="impossible_travel",
        received_at=detected_at,
        detected_at=detected_at,
        severity_hint="P2",
        primary_assets=[
            Asset(asset_id=asset_id, asset_type="user", tenant_id=tenant_id),
        ],
        observables=[
            Observable(observable_type="ip", value=ip, source_field_path="client.ipAddress"),
        ],
        summary="storm test alert",
    )


def test_burst_1000_alerts_collapses_shared_key_into_one_group(fresh_storm_grouper):
    grouper = StormGrouper(threshold_per_window=10, window_seconds=300)
    base = datetime(2026, 6, 15, 14, 30, 0)
    decisions = []

    # 950 alerts that share rule + entity + ioc (one group expected)
    for i in range(950):
        alert = _build_alert(
            alert_id=f"a_shared_{i:04d}",
            tenant_id="tenant_a",
            rule_id="okta.noisy_rule.v1",
            asset_id="u_acct_lead",
            ip="198.51.100.42",
            detected_at=base + timedelta(milliseconds=60 * i),
        )
        decisions.append(grouper.classify(alert, now=base + timedelta(milliseconds=60 * i)))

    # 50 distinct alerts (different rule_id each) — individual path
    for i in range(50):
        alert = _build_alert(
            alert_id=f"a_distinct_{i:04d}",
            tenant_id="tenant_a",
            rule_id=f"okta.unique_rule.{i:03d}",
            asset_id=f"u_other_{i:03d}",
            ip=f"203.0.113.{i + 1}",
            detected_at=base + timedelta(milliseconds=60 * (950 + i)),
        )
        decisions.append(grouper.classify(alert, now=base + timedelta(milliseconds=60 * (950 + i))))

    shared_decisions = decisions[:950]
    distinct_decisions = decisions[950:]

    # First 9 shared alerts arrive before the threshold trips. The 10th is the
    # transition point: it itself becomes a group_attach because the contract
    # makes the threshold inclusive ("on or above N triggers group mode"),
    # which also serves as the IncidentGroup sample alert.
    individual_shared = [d for d in shared_decisions if d.decision == "individual"]
    group_attach_shared = [d for d in shared_decisions if d.decision == "group_attach"]
    assert len(individual_shared) == 9
    assert len(group_attach_shared) == 941

    # Exactly one IncidentGroup spans the 941 group_attach decisions.
    groups_seen = {d.group.group_id for d in group_attach_shared}
    assert len(groups_seen) == 1
    only_group = next(iter(group_attach_shared)).group
    assert only_group.member_count == 941

    # The 50 distinct alerts ALL go individual; the grouper never collapses them.
    assert all(d.decision == "individual" for d in distinct_decisions)


def test_grouping_key_partitions_tenants(fresh_storm_grouper):
    grouper = StormGrouper(threshold_per_window=3, window_seconds=300)
    base = datetime(2026, 6, 15, 14, 30, 0)
    decisions_a, decisions_b = [], []
    for i in range(5):
        a = _build_alert(
            alert_id=f"a_{i}",
            tenant_id="tenant_a",
            rule_id="r1",
            asset_id="same_entity",
            ip="198.51.100.42",
            detected_at=base + timedelta(seconds=i),
        )
        b = _build_alert(
            alert_id=f"b_{i}",
            tenant_id="tenant_b",
            rule_id="r1",
            asset_id="same_entity",
            ip="198.51.100.42",
            detected_at=base + timedelta(seconds=i),
        )
        decisions_a.append(grouper.classify(a, now=base + timedelta(seconds=i)))
        decisions_b.append(grouper.classify(b, now=base + timedelta(seconds=i)))

    a_groups = {d.group.group_id for d in decisions_a if d.decision == "group_attach"}
    b_groups = {d.group.group_id for d in decisions_b if d.decision == "group_attach"}
    assert a_groups.isdisjoint(b_groups)
