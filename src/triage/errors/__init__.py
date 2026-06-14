from __future__ import annotations


class DestructiveDriftError(Exception):
    """Required canonical field could not be mapped from source payload.

    Treatment per RECONCILED §4.2 / R4: alert is quarantined with
    verdict=needs_human, degraded=schema_drift. No LLM call, no budget consumed.
    """

    def __init__(self, source_system: str, missing_field: str, attempted_paths: list[str]) -> None:
        self.source_system = source_system
        self.missing_field = missing_field
        self.attempted_paths = attempted_paths
        super().__init__(
            f"destructive drift in {source_system}: required canonical field "
            f"{missing_field!r} not found at any of {attempted_paths}"
        )


class UnknownSourceError(Exception):
    """Source system has no registered adapter.

    Treated as destructive drift per §4.2.
    """

    def __init__(self, source_system: str) -> None:
        self.source_system = source_system
        super().__init__(f"no adapter registered for source_system={source_system!r}")


class TenantIsolationError(Exception):
    """Cross-tenant access attempt detected at the storage boundary.

    Last line of defense per §4.1; raised by the store when application code
    attempts to read with a tenant_id that does not match the row's tenant_id.
    """

    def __init__(self, queried_tenant: str, row_tenant: str, resource: str) -> None:
        self.queried_tenant = queried_tenant
        self.row_tenant = row_tenant
        self.resource = resource
        super().__init__(
            f"tenant isolation violation: tenant={queried_tenant!r} attempted "
            f"to read {resource!r} owned by tenant={row_tenant!r}"
        )
