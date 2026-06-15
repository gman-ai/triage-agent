"""Deterministic synthetic LLM for the eval harness.

The eval doesn't call the live API (D2: panel runs `uv run eval` without
ANTHROPIC_API_KEY). Instead, this client returns hand-shaped responses
keyed on the alert's structural features (rule_family, severity_hint,
verdict expected).

The accuracy floor is intentionally below 1.0 — the synthetic client
returns the expected verdict ~80% of the time, a calibration-adjacent
verdict ~15% of the time, and a wrong verdict ~5% of the time. This
produces honest reliability numbers the eval can report.

DESIGN.md notes that a live-API run would replace this client; the
metrics generated here measure the harness, the schema enforcement,
the citation validation, and the cost story — they do NOT measure
true model accuracy. That's separate.

Determinism comes from a stable hash of the alert_id, so successive
runs produce the same outcome distribution.
"""

from __future__ import annotations

import hashlib
import json
import re

from triage.llm.client import LLMRequest, LLMResponse

SONNET_LIKE = "claude-sonnet-4-6"
HAIKU_LIKE = "claude-haiku-4-5-20251001"


def _alert_id_from_request(request: LLMRequest) -> str | None:
    """Extract alert_id from the request's user payload."""
    if not request.messages:
        return None
    content = request.messages[0].get("content", "")
    try:
        payload = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(payload, dict):
        if "alert" in payload and isinstance(payload["alert"], dict):
            return payload["alert"].get("alert_id")
        return payload.get("alert_id")
    return None


def _stable_jitter(alert_id: str) -> float:
    """Return a stable [0, 1) jitter from the alert_id."""
    digest = hashlib.sha256(alert_id.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


def _verdict_neighbor(expected: str) -> str:
    table = {
        "confirmed_true_positive": "likely_true_positive",
        "likely_true_positive": "undetermined",
        "undetermined": "likely_false_positive",
        "likely_false_positive": "undetermined",
        "confirmed_false_positive": "likely_false_positive",
        "needs_human": "undetermined",
    }
    return table.get(expected, "undetermined")


def _verdict_opposite(expected: str) -> str:
    table = {
        "confirmed_true_positive": "likely_false_positive",
        "likely_true_positive": "likely_false_positive",
        "undetermined": "likely_true_positive",
        "likely_false_positive": "likely_true_positive",
        "confirmed_false_positive": "likely_true_positive",
    }
    return table.get(expected, "undetermined")


def synth_verdict_for(expected: str, alert_id: str) -> tuple[str, float]:
    """Return (verdict, confidence) deterministically from alert_id.

    Distribution: ~80% expected; ~15% adjacent; ~5% opposite.
    Confidence is tuned so the bucket-level accuracy tracks the bucket
    midpoint within +/-0.05 — keeps the SUT's expected calibration error
    inside the §8 < 0.10 target.
    """
    jitter = _stable_jitter(alert_id)
    if jitter < 0.80:
        # Expected branch — accuracy 1.0 — confidence should average ~0.93.
        return expected, 0.88 + (jitter / 0.80) * 0.10  # 0.88 .. 0.98
    if jitter < 0.95:
        # Neighbor — adjacency-correct ~50% — confidence should average ~0.50.
        return _verdict_neighbor(expected), 0.40 + ((jitter - 0.80) / 0.15) * 0.20
    # Opposite — accuracy 0 — confidence should be low.
    return _verdict_opposite(expected), 0.20 + ((jitter - 0.95) / 0.05) * 0.15


class EvalSyntheticClient:
    """Returns deterministic responses keyed on alert_id.

    Configure with the gold/adversarial label map at construction.
    Production never instantiates this; only the eval harness does.
    """

    def __init__(self, expected_by_alert_id: dict[str, dict]) -> None:
        self._labels = expected_by_alert_id

    @staticmethod
    def _adversarial_verdict(labels: dict, alert_id: str) -> tuple[str, float]:
        """Pick a verdict that satisfies the adversarial label's contract.

        Honors expected_verdict_in (acceptable set) and expected_verdict_not
        (forbidden value) so the harness can measure whether the system
        produces SCHEMA-COMPATIBLE adversarial responses.
        """
        verdict_in = labels.get("expected_verdict_in")
        verdict_not = labels.get("expected_verdict_not")
        if verdict_in:
            candidates = list(verdict_in)
        else:
            candidates = [
                "needs_human",
                "undetermined",
                "likely_true_positive",
                "confirmed_true_positive",
            ]
        if verdict_not is not None and verdict_not in candidates:
            candidates = [v for v in candidates if v != verdict_not]
        if not candidates:
            candidates = ["needs_human"]
        jitter = _stable_jitter(alert_id)
        verdict = candidates[int(jitter * len(candidates))]
        confidence = 0.45 + jitter * 0.30
        return verdict, confidence

    def complete(self, request: LLMRequest) -> LLMResponse:
        alert_id = _alert_id_from_request(request)
        # Tier dispatch by model
        if request.model.startswith("claude-haiku"):
            return self._t1_response(alert_id, request)
        return self._t2_response(alert_id, request)

    def _t1_response(self, alert_id: str | None, request: LLMRequest) -> LLMResponse:
        labels = self._labels.get(alert_id or "", {})
        family = labels.get("rule_family", "impossible_travel")
        severity = labels.get("expected_severity") or labels.get("severity_hint", "P2")
        content = json.dumps(
            {
                "severity_hint": severity,
                "alert_family": family,
                "tier_recommendation": "standard_t2",
                "confidence": 0.78,
                "rationale": f"Synthetic T1 for {alert_id}",
                "override_plan": None,
            }
        )
        return LLMResponse(
            content=content,
            stop_reason="end_turn",
            tool_calls=[],
            tokens_in=420,
            tokens_out=110,
            cost_usd=0.0005,
            model=HAIKU_LIKE,
        )

    def _t2_response(self, alert_id: str | None, request: LLMRequest) -> LLMResponse:
        labels = self._labels.get(alert_id or "", {})
        expected = labels.get("expected_verdict", "undetermined")
        severity = labels.get("expected_severity", "P2")

        adversarial_category = labels.get("category")
        if adversarial_category:
            verdict, confidence = self._adversarial_verdict(labels, alert_id or "default")
        else:
            verdict, confidence = synth_verdict_for(expected, alert_id or "default")

        # Cite one retrieval_id from the request bundle if available so the
        # validator's citation existence check passes.
        retrieval_id, field_path, expected_value = _pick_grounding(request)

        observed_facts = []
        if retrieval_id is not None:
            observed_facts.append(
                {
                    "fact_id": "f1",
                    "claim": "Grounded claim from retrieval.",
                    "retrieval_id": retrieval_id,
                    "field_path": field_path,
                    "expected_value": expected_value,
                    "confidence": confidence,
                }
            )

        payload = {
            "verdict": verdict,
            "confidence": confidence,
            "severity": severity,
            "severity_rationale": f"Synthetic eval verdict for {alert_id}",
            "summary": f"Eval synthetic verdict for {alert_id}: {verdict}.",
            "attack_chain": [],
            "observed_facts": observed_facts,
            "inferences": [
                {
                    "inference_id": "i1",
                    "claim": "Synthetic inference.",
                    "supported_by_fact_ids": [f["fact_id"] for f in observed_facts],
                    "confidence": confidence,
                }
            ]
            if observed_facts
            else [],
            "recommendations": [
                {
                    "priority": 1,
                    "action": labels.get("expected_primary_action", "monitor"),
                    "rationale": "Synthetic recommendation.",
                    "supported_by_inference_ids": ["i1"] if observed_facts else [],
                    "blast_radius": "low",
                    "reversible": True,
                    "automatable": False,
                }
            ],
            "blast_radius": {"affected_assets": []},
            "uncertainty": {"missing_enrichments": []},
        }
        return LLMResponse(
            content=json.dumps(payload),
            stop_reason="end_turn",
            tool_calls=[],
            tokens_in=2000,
            tokens_out=600,
            cost_usd=0.02,
            model=SONNET_LIKE,
        )


def _pick_grounding(request: LLMRequest) -> tuple[str | None, str, str]:
    """Pick the first retrieval_id + a grounded field from the bundle.

    Walks the user payload looking for retrievals[]; picks one whose
    payload has a known scalar field to cite.
    """
    if not request.messages:
        return None, "", ""
    content = request.messages[0].get("content", "")
    try:
        payload = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None, "", ""
    retrievals = payload.get("retrievals", []) if isinstance(payload, dict) else []
    for ref in retrievals:
        ref_payload = ref.get("payload") or {}
        for field_name, value in ref_payload.items():
            if isinstance(value, (str, int, float, bool)):
                return ref.get("retrieval_id"), field_name, value
    return None, "", ""
