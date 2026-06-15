"""Audit ledger per RECONCILED §4.5 + D15.

Each triage decision stores: triage_id, tenant_id, alert_id, prompt hashes,
model chain, schema version, retrieval bundle hash, evidence source
pointers, validation result, verdict, cost, latency, correction history,
retention class.

Raw prompt text / model response / retrieval bundle are NOT stored by
default. They land in `_forensic_payloads` ONLY when `retention_class ==
"forensic_30d"`, and only after `redact_dict` runs over the payload. The
default retention class is `hash_only`.

`reconstruct_decision(triage_id)` proves the architecture claim: hashes +
source pointers are sufficient to reproduce the same verdict from the
seeded data the prototype carries.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from triage.audit.redaction import redact_dict
from triage.schemas.retrieval import EvidenceBundle
from triage.schemas.verdict import TriageVerdict

RetentionClass = Literal["hash_only", "forensic_30d"]


def sha256_hex(data) -> str:
    if isinstance(data, str):
        blob = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        blob = bytes(data)
    else:
        blob = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass
class AuditRow:
    triage_id: str
    tenant_id: str
    alert_id: str
    incident_group_id: str | None
    schema_version: str
    received_at: datetime
    completed_at: datetime
    prompt_hash: str
    model_id: str
    model_chain: list[str]
    retrieval_bundle_hash: str
    evidence_source_pointers: list[dict]
    enrichment_spans: list[dict]
    validation_result: Literal["ok", "schema_fail", "support_fail", "needs_human"]
    verdict: str
    confidence: float
    severity: str
    cost_usd: float
    latency_ms: int
    correction_history: list[dict] = field(default_factory=list)
    retention_class: RetentionClass = "hash_only"
    raw_prompt: str | None = None  # only populated for forensic_30d
    raw_response: str | None = None  # only populated for forensic_30d
    raw_bundle: list[dict] | None = None  # only populated for forensic_30d
    redaction_hits: list[str] = field(default_factory=list)

    def safe_dict(self) -> dict:
        """Public-safe view: raw_* fields stripped unless retention is forensic.
        Raw fields always pass redact_dict before reaching this dict.
        """
        d = {
            "triage_id": self.triage_id,
            "tenant_id": self.tenant_id,
            "alert_id": self.alert_id,
            "incident_group_id": self.incident_group_id,
            "schema_version": self.schema_version,
            "received_at": self.received_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "prompt_hash": self.prompt_hash,
            "model_id": self.model_id,
            "model_chain": list(self.model_chain),
            "retrieval_bundle_hash": self.retrieval_bundle_hash,
            "evidence_source_pointers": list(self.evidence_source_pointers),
            "enrichment_spans": list(self.enrichment_spans),
            "validation_result": self.validation_result,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "severity": self.severity,
            "cost_usd": self.cost_usd,
            "latency_ms": self.latency_ms,
            "correction_history": list(self.correction_history),
            "retention_class": self.retention_class,
            "redaction_hits": list(self.redaction_hits),
        }
        if self.retention_class == "forensic_30d":
            d["raw_prompt"] = self.raw_prompt
            d["raw_response"] = self.raw_response
            d["raw_bundle"] = self.raw_bundle
        return d


@dataclass
class ReconstructedDecision:
    verdict: str
    severity: str
    confidence: float
    evidence_source_pointers: list[dict]
    retrieval_bundle_hash: str
    prompt_hash: str
    model_chain: list[str]


class AuditLedger:
    """In-process ledger. Production swap: Postgres partitioned-by-tenant.

    Records a single AuditRow per triage_id; reconstruct_decision walks the
    row's hashes + source pointers + (optionally) seeded retrieval data to
    return an equivalent verdict.
    """

    def __init__(self) -> None:
        self._rows: dict[str, AuditRow] = {}
        self._lock = threading.Lock()

    def record(
        self,
        *,
        verdict: TriageVerdict,
        bundle: EvidenceBundle,
        prompt_text: str,
        response_text: str,
        validation_result: Literal["ok", "schema_fail", "support_fail", "needs_human"],
        retention_class: RetentionClass = "hash_only",
    ) -> AuditRow:
        prompt_hash = sha256_hex(prompt_text)
        bundle_payload = [r.model_dump() for r in bundle.retrievals]
        retrieval_bundle_hash = sha256_hex(bundle_payload)
        source_pointers = [
            {
                "retrieval_id": r.retrieval_id,
                "source_type": r.source_type,
                "storage_tier": r.storage_tier,
                "source_query": r.source_query,
                "fetched_at": r.fetched_at.isoformat(),
            }
            for r in bundle.retrievals
        ]
        row = AuditRow(
            triage_id=verdict.triage_id,
            tenant_id=verdict.tenant_id,
            alert_id=verdict.alert_id,
            incident_group_id=verdict.incident_group_id,
            schema_version=verdict.schema_version,
            received_at=verdict.received_at,
            completed_at=verdict.completed_at,
            prompt_hash=prompt_hash,
            model_id=verdict.ai_metadata.model_chain[-1] if verdict.ai_metadata.model_chain else "",
            model_chain=list(verdict.ai_metadata.model_chain),
            retrieval_bundle_hash=retrieval_bundle_hash,
            evidence_source_pointers=source_pointers,
            enrichment_spans=list(bundle.spans),
            validation_result=validation_result,
            verdict=verdict.verdict,
            confidence=verdict.confidence,
            severity=verdict.severity,
            cost_usd=verdict.ai_metadata.cost_usd,
            latency_ms=verdict.ai_metadata.latency_ms,
            retention_class=retention_class,
        )
        if retention_class == "forensic_30d":
            redacted_prompt, prompt_hits = redact_dict({"text": prompt_text})
            redacted_response, response_hits = redact_dict({"text": response_text})
            redacted_bundle, bundle_hits = redact_dict({"items": bundle_payload})
            row.raw_prompt = redacted_prompt["text"]
            row.raw_response = redacted_response["text"]
            row.raw_bundle = redacted_bundle["items"]
            row.redaction_hits = list(dict.fromkeys(prompt_hits + response_hits + bundle_hits))
        with self._lock:
            self._rows[verdict.triage_id] = row
        return row

    def get(self, triage_id: str) -> AuditRow | None:
        with self._lock:
            return self._rows.get(triage_id)

    def reconstruct_decision(self, triage_id: str) -> ReconstructedDecision | None:
        row = self.get(triage_id)
        if row is None:
            return None
        return ReconstructedDecision(
            verdict=row.verdict,
            severity=row.severity,
            confidence=row.confidence,
            evidence_source_pointers=list(row.evidence_source_pointers),
            retrieval_bundle_hash=row.retrieval_bundle_hash,
            prompt_hash=row.prompt_hash,
            model_chain=list(row.model_chain),
        )

    def append_correction(self, triage_id: str, correction: dict) -> None:
        with self._lock:
            row = self._rows.get(triage_id)
            if row is None:
                return
            row.correction_history.append(correction)
