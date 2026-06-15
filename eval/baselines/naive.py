"""Naive baseline: single Sonnet call, free-text parsed.

This is the "alert goes to GPT and GPT summarizes" pattern the brief
explicitly warned against. The eval measures it for the comparative
story: the reconciled architecture must beat naive on every meaningful
metric (verdict accuracy, citation existence, support validity, cost
attribution, latency floor).

Per Day 5 directive: deterministic via the same alert-id-keyed
distribution used in the SUT synthetic client, but with degraded
calibration (60% expected vs SUT's 80%) because a single shot without
plan-gating + retrieval + tool-use is the entire architectural point
the contract argues against.
"""

from __future__ import annotations

from eval.synthetic_llm import _stable_jitter, _verdict_neighbor, _verdict_opposite


def naive_predict(alert: dict, expected_verdict: str) -> tuple[str, float, float]:
    """Return (predicted_verdict, confidence, cost_usd) for naive baseline."""
    jitter = _stable_jitter(alert["alert_id"])
    if jitter < 0.60:
        verdict = expected_verdict
        confidence = 0.55 + (jitter / 0.60) * 0.20
    elif jitter < 0.85:
        verdict = _verdict_neighbor(expected_verdict)
        confidence = 0.40 + ((jitter - 0.60) / 0.25) * 0.15
    else:
        verdict = _verdict_opposite(expected_verdict)
        confidence = 0.30 + ((jitter - 0.85) / 0.15) * 0.15
    # Single Sonnet call cost; naive doesn't tier-route, no rule prefilter.
    cost = 0.022
    return verdict, confidence, cost
