"""Tenant-scoped store per RECONCILED §4.1.

A minimal storage abstraction that enforces tenant isolation at the read
boundary. Application code that "forgets" to filter by tenant_id receives
an empty result, not another tenant's rows. If a caller queries with the
wrong tenant_id, the store raises TenantIsolationError (defense in depth on
top of the empty-result behavior).

This is the Day 1 contract that the Day 2 enrichment adapters implement.
Day 4 wires the production swap notes into DESIGN.md (Supabase RLS,
current_setting('app.tenant_id'), per-tenant DB roles).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from triage.errors import TenantIsolationError

T = TypeVar("T")


@dataclass
class TenantRecord(Generic[T]):
    tenant_id: str
    entity_id: str
    payload: T


@dataclass
class TenantScopedStore(Generic[T]):
    """In-memory store keyed by (tenant_id, entity_id).

    The empty-result behavior is the primary defense: a forgotten filter
    means the caller does not present a tenant_id when reading, and the read
    returns []. Raising on tenant mismatch is the secondary defense, when a
    caller presents a tenant_id that does not match the stored record.
    """

    resource: str
    _rows: dict[str, dict[str, TenantRecord[T]]] = field(default_factory=lambda: defaultdict(dict))

    def put(self, tenant_id: str, entity_id: str, payload: T) -> None:
        if not tenant_id:
            raise ValueError("tenant_id is required for store writes")
        self._rows[tenant_id][entity_id] = TenantRecord(
            tenant_id=tenant_id, entity_id=entity_id, payload=payload
        )

    def get(self, tenant_id: str, entity_id: str) -> T | None:
        if not tenant_id:
            return None
        # 1. Look up the queried tenant's own partition first.
        partition = self._rows.get(tenant_id)
        if partition is not None and entity_id in partition:
            return partition[entity_id].payload
        # 2. Defense in depth: if the entity exists under a DIFFERENT tenant,
        #    raise instead of returning None. The empty-result and the raise
        #    both protect isolation; the raise additionally surfaces buggy
        #    application code at the storage boundary.
        for stored_tenant, p in self._rows.items():
            if stored_tenant == tenant_id:
                continue
            if entity_id in p:
                raise TenantIsolationError(
                    queried_tenant=tenant_id,
                    row_tenant=stored_tenant,
                    resource=self.resource,
                )
        return None

    def list_for_tenant(self, tenant_id: str) -> list[TenantRecord[T]]:
        if not tenant_id:
            return []
        return list(self._rows.get(tenant_id, {}).values())

    def all_tenants(self) -> list[str]:
        return sorted(self._rows.keys())
