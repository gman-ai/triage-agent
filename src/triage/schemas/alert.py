"""Canonical alert contract per RECONCILED §5.

Source adapters translate vendor-specific payloads to this shape; everything
downstream of the adapter layer (grouper, router, T1, T2, validator, audit)
consumes only CanonicalAlertEvent. The LLM never sees raw vendor JSON.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

AssetType = Literal["host", "user", "service", "container", "iam_role", "cloud_resource"]
ObservableType = Literal[
    "ip", "domain", "hash", "url", "email", "user_id", "host_id", "process_name"
]
Criticality = Literal["critical", "high", "medium", "low"]
Severity = Literal["P0", "P1", "P2", "P3", "P4"]

RuleFamily = Literal[
    "impossible_travel",
    "brute_force",
    "suspicious_process",
    "c2_callback",
    "dns_exfil",
    "privilege_escalation",
    "data_exfil",
    "ransomware",
    "malware",
    "other",
]


class Asset(BaseModel):
    asset_id: str
    asset_type: AssetType
    role: str | None = None
    criticality: Criticality | None = None
    owner_team: str | None = None
    tenant_id: str


class Observable(BaseModel):
    observable_type: ObservableType
    value: str
    source_field_path: str


class CanonicalAlertEvent(BaseModel):
    """Single shape every downstream component consumes.

    `source_adapter_version` is required so drift is auditable and reversible.
    `summary` is marked untrusted in the reasoning layer (prompt-injection vector).
    `raw_unknown_extras` captures fields the adapter could not map without
    silently dropping them (additive drift per §4.2 / R4).
    """

    tenant_id: str
    alert_id: str
    source_system: str
    source_adapter_version: str
    rule_id: str
    rule_family: RuleFamily
    received_at: datetime
    detected_at: datetime
    severity_hint: Severity | None = None
    primary_assets: list[Asset] = Field(default_factory=list)
    observables: list[Observable] = Field(default_factory=list)
    summary: str = ""
    raw_unknown_extras: dict = Field(default_factory=dict)
    schema_drift_detected: bool = False
    additive_drift_fields: list[str] = Field(default_factory=list)
    schema_version: Literal["1.0"] = "1.0"

    def grouping_entity(self) -> str | None:
        """Primary entity for storm grouping key.

        Returns the first primary asset's ID; falls back to the first observable
        value. Returning None is valid for alerts with no entity (the grouper
        treats them as ungrouped).
        """
        if self.primary_assets:
            return self.primary_assets[0].asset_id
        if self.observables:
            return self.observables[0].value
        return None

    def primary_ioc(self) -> str | None:
        """Primary IOC observable for storm grouping key.

        IP/domain/hash take precedence over user/host. None if no IOC present.
        """
        ioc_priority: tuple[ObservableType, ...] = ("hash", "domain", "ip", "url", "email")
        by_type = {o.observable_type: o.value for o in self.observables}
        for kind in ioc_priority:
            if kind in by_type:
                return by_type[kind]
        return None
