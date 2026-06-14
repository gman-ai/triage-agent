"""Okta source adapter v1 per RECONCILED §4.2.

Maps Okta-shaped JSON to CanonicalAlertEvent. Destructive drift = a required
canonical field cannot be mapped from the documented paths. Additive drift =
the payload contains field paths the adapter does not recognize; those land
in raw_unknown_extras and additive_drift_fields, and the alert flows.

The adapter does NOT downgrade confidence on additive drift; that decision
is downstream of T1.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from triage.errors import DestructiveDriftError
from triage.schemas.alert import (
    Asset,
    CanonicalAlertEvent,
    Observable,
    RuleFamily,
    Severity,
)

OKTA_EVENT_TYPE_TO_FAMILY: dict[str, RuleFamily] = {
    "policy.evaluate_sign_on": "impossible_travel",
    "user.authentication.auth_via_mfa": "brute_force",
    "user.session.start": "impossible_travel",
    "user.account.privilege.grant": "privilege_escalation",
}

OKTA_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "P0",
    "HIGH": "P1",
    "MEDIUM": "P2",
    "LOW": "P3",
    "INFO": "P4",
}

# Paths that the v1 adapter understands. Anything outside this set in the
# payload is collected into raw_unknown_extras as additive drift.
KNOWN_TOP_LEVEL_FIELDS = {
    "uuid",
    "published",
    "eventType",
    "severity",
    "actor",
    "client",
    "outcome",
    "displayMessage",
    "transaction",
    "_rule_id",
    "_detected_at",
}
KNOWN_CLIENT_FIELDS = {"ipAddress", "geographicalContext", "userAgent"}
KNOWN_GEO_FIELDS = {"country", "city", "state"}
KNOWN_ACTOR_FIELDS = {"id", "alternateId", "displayName", "type"}


class OktaAdapterV1:
    source_system = "okta"
    version = "v1"

    def to_canonical(self, payload: dict[str, Any], tenant_id: str) -> CanonicalAlertEvent:
        alert_id = self._require(payload, "uuid", ["uuid"])
        published = self._require(payload, "published", ["published"])
        event_type = self._require(payload, "eventType", ["eventType"])
        actor = self._require(payload, "actor", ["actor"])
        actor_id = self._require(actor, "id", ["actor.id"])
        client = self._require(payload, "client", ["client"])

        # geographicalContext.country is required for the geo dimension every
        # downstream rule_family the v1 adapter classifies depends on. If a
        # vendor schema change moves it to a different nested path the
        # adapter doesn't know, that's destructive drift.
        geo = client.get("geographicalContext") or {}
        if "country" not in geo:
            raise DestructiveDriftError(
                source_system=self.source_system,
                missing_field="client.geographicalContext.country",
                attempted_paths=["client.geographicalContext.country"],
            )
        country = geo["country"]
        source_ip = client.get("ipAddress")

        rule_id = payload.get("_rule_id") or event_type
        family = OKTA_EVENT_TYPE_TO_FAMILY.get(event_type, "other")
        severity = OKTA_SEVERITY_MAP.get(payload.get("severity", ""), None)
        detected_at_raw = payload.get("_detected_at") or published

        primary_assets = [
            Asset(
                asset_id=actor_id,
                asset_type="user",
                role=actor.get("displayName"),
                tenant_id=tenant_id,
            )
        ]
        observables: list[Observable] = []
        if source_ip:
            observables.append(
                Observable(
                    observable_type="ip",
                    value=source_ip,
                    source_field_path="client.ipAddress",
                )
            )
        observables.append(
            Observable(
                observable_type="user_id",
                value=actor_id,
                source_field_path="actor.id",
            )
        )

        additive_fields = self._collect_additive(payload)

        return CanonicalAlertEvent(
            tenant_id=tenant_id,
            alert_id=alert_id,
            source_system=self.source_system,
            source_adapter_version=f"{self.source_system}_{self.version}",
            rule_id=rule_id,
            rule_family=family,
            received_at=datetime.now(UTC),
            detected_at=self._parse_dt(detected_at_raw),
            severity_hint=severity,
            primary_assets=primary_assets,
            observables=observables,
            summary=payload.get("displayMessage", ""),
            raw_unknown_extras={k: payload[k] for k in additive_fields if k in payload},
            additive_drift_fields=additive_fields,
        )

    @staticmethod
    def _require(d: dict, key: str, attempted_paths: list[str]) -> Any:
        if key not in d:
            raise DestructiveDriftError(
                source_system="okta",
                missing_field=attempted_paths[0],
                attempted_paths=attempted_paths,
            )
        return d[key]

    @staticmethod
    def _parse_dt(raw: str | datetime) -> datetime:
        if isinstance(raw, datetime):
            return raw
        # Okta uses ISO 8601 with Z suffix; fromisoformat handles both forms in
        # 3.11+ but we normalize the Z to +00:00 for safety.
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))

    def _collect_additive(self, payload: dict[str, Any]) -> list[str]:
        unknown: list[str] = []
        for k in payload:
            if k not in KNOWN_TOP_LEVEL_FIELDS:
                unknown.append(k)
        client = payload.get("client") or {}
        for k in client:
            if k not in KNOWN_CLIENT_FIELDS:
                unknown.append(f"client.{k}")
        geo = (client.get("geographicalContext") or {})
        for k in geo:
            if k not in KNOWN_GEO_FIELDS:
                unknown.append(f"client.geographicalContext.{k}")
        actor = payload.get("actor") or {}
        for k in actor:
            if k not in KNOWN_ACTOR_FIELDS:
                unknown.append(f"actor.{k}")
        return unknown
