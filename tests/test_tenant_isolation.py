"""Acceptance gate subset: tenant isolation per RECONCILED §4.1 + IMPL #11.

The full §4.1 test runs the same alert through the whole pipeline for two
tenants and asserts no cross-tenant rows leak through retrieval. That arrives
on Day 2 when the enrichment layer exists. This Day 1 subset exercises the
boundary the retrieval layer will sit behind: TenantScopedStore.

Two tenants seed records with IDENTICAL entity IDs on purpose so accidental
leakage is detectable (per §4.1: "same host_id, same user_id, same IOC
values"). The test asserts:

  1. Reading with the wrong tenant_id either returns None or raises
     TenantIsolationError; it never silently returns the other tenant's row.
  2. list_for_tenant() returns ONLY that tenant's records.
  3. "Broken application code" — code that forgets to pass tenant_id at all
     — returns empty, not the union of all tenants.
"""

from __future__ import annotations

import pytest

from triage.errors import TenantIsolationError
from triage.tenants.store import TenantScopedStore


def test_same_entity_id_in_two_tenants_does_not_cross_leak(tenant_a_id, tenant_b_id):
    store: TenantScopedStore[str] = TenantScopedStore(resource="identities")
    store.put(tenant_a_id, "u_acct_lead", "tenant_a_profile")
    store.put(tenant_b_id, "u_acct_lead", "tenant_b_profile")

    # Each tenant sees its own profile.
    assert store.get(tenant_a_id, "u_acct_lead") == "tenant_a_profile"
    assert store.get(tenant_b_id, "u_acct_lead") == "tenant_b_profile"


def test_query_with_wrong_tenant_id_raises(tenant_a_id):
    store: TenantScopedStore[str] = TenantScopedStore(resource="identities")
    store.put(tenant_a_id, "u_acct_lead", "tenant_a_profile")

    with pytest.raises(TenantIsolationError) as excinfo:
        store.get("tenant_wrong", "u_acct_lead")
    err = excinfo.value
    assert err.queried_tenant == "tenant_wrong"
    assert err.row_tenant == tenant_a_id
    assert err.resource == "identities"


def test_broken_application_code_forgetting_tenant_returns_empty(tenant_a_id, tenant_b_id):
    """Defense-in-depth check: caller does not supply tenant_id at all.

    This simulates the §4.1 scenario where application code "deliberately
    broken" omits the tenant filter on one retrieval call. The store must
    return empty/None rather than fall through to the union of all tenants.
    """
    store: TenantScopedStore[str] = TenantScopedStore(resource="assets")
    store.put(tenant_a_id, "srv_billing_01", "tenant_a_asset")
    store.put(tenant_b_id, "srv_billing_01", "tenant_b_asset")

    assert store.get("", "srv_billing_01") is None
    assert store.list_for_tenant("") == []


def test_list_for_tenant_does_not_include_other_tenants(tenant_a_id, tenant_b_id):
    store: TenantScopedStore[str] = TenantScopedStore(resource="iocs")
    store.put(tenant_a_id, "198.51.100.42", "tenant_a_reputation")
    store.put(tenant_b_id, "198.51.100.42", "tenant_b_reputation")
    store.put(tenant_a_id, "198.51.100.43", "tenant_a_other")

    a_records = store.list_for_tenant(tenant_a_id)
    a_payloads = [r.payload for r in a_records]
    assert "tenant_a_reputation" in a_payloads
    assert "tenant_a_other" in a_payloads
    assert "tenant_b_reputation" not in a_payloads
    assert len(a_records) == 2
