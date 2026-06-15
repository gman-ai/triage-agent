"""Eval metrics + calibration analysis per RECONCILED §8.

Metrics computed:
  * verdict_accuracy_exact — exact verdict match
  * verdict_accuracy_adjacent — confirmed_TP ↔ likely_TP and confirmed_FP ↔
    likely_FP counted as correct
  * severity_mae — mean absolute error in severity tier number
  * citation_existence_rate — share of facts whose retrieval_id resolves in
    the bundle
  * action_validity_rate — share of recommendations[0].action ∈ expected
  * adversarial_robustness — share of adversarial cases handled per expected
    outcome
  * confidence_ece — expected calibration error across 5 buckets

Plus an ASCII reliability diagram.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

SEVERITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
ADJACENT_PAIRS = {
    frozenset({"confirmed_true_positive", "likely_true_positive"}),
    frozenset({"confirmed_false_positive", "likely_false_positive"}),
}


@dataclass
class Prediction:
    alert_id: str
    predicted_verdict: str
    predicted_severity: str | None
    predicted_action: str | None
    confidence: float
    cost_usd: float
    latency_ms: int | None = None
    citation_count: int = 0
    citation_existence_passed: int = 0


@dataclass
class GoldLabel:
    alert_id: str
    expected_verdict: str
    expected_severity: str
    expected_primary_action: str
    expected_attack_tactic: str
    min_observed_facts: int = 0


@dataclass
class MetricsReport:
    n: int
    verdict_accuracy_exact: float
    verdict_accuracy_adjacent: float
    severity_mae: float
    citation_existence_rate: float
    action_validity_rate: float
    confidence_ece: float
    cost_total_usd: float
    cost_mean_usd: float


def _verdict_correct(predicted: str, expected: str, *, adjacent_ok: bool) -> bool:
    if predicted == expected:
        return True
    if adjacent_ok and frozenset({predicted, expected}) in ADJACENT_PAIRS:
        return True
    return False


def compute_metrics(
    predictions: Iterable[Prediction],
    labels: Iterable[GoldLabel],
) -> MetricsReport:
    label_by_id = {g.alert_id: g for g in labels}
    preds_list = list(predictions)
    n = len(preds_list)
    if n == 0:
        return MetricsReport(0, 0, 0, 0, 0, 0, 0, 0, 0)

    exact_hits = 0
    adjacent_hits = 0
    severity_errs: list[int] = []
    citation_total = 0
    citation_existence_hits = 0
    action_hits = 0
    cost_total = 0.0

    for pred in preds_list:
        gold = label_by_id.get(pred.alert_id)
        if gold is None:
            continue
        if _verdict_correct(pred.predicted_verdict, gold.expected_verdict, adjacent_ok=False):
            exact_hits += 1
        if _verdict_correct(pred.predicted_verdict, gold.expected_verdict, adjacent_ok=True):
            adjacent_hits += 1
        if pred.predicted_severity is not None:
            severity_errs.append(
                abs(
                    SEVERITY_RANK.get(pred.predicted_severity, 4)
                    - SEVERITY_RANK.get(gold.expected_severity, 4)
                )
            )
        citation_total += pred.citation_count
        citation_existence_hits += pred.citation_existence_passed
        if pred.predicted_action == gold.expected_primary_action:
            action_hits += 1
        cost_total += pred.cost_usd

    citation_rate = (citation_existence_hits / citation_total) if citation_total > 0 else 1.0
    severity_mae = sum(severity_errs) / max(1, len(severity_errs))

    return MetricsReport(
        n=n,
        verdict_accuracy_exact=exact_hits / n,
        verdict_accuracy_adjacent=adjacent_hits / n,
        severity_mae=severity_mae,
        citation_existence_rate=citation_rate,
        action_validity_rate=action_hits / n,
        confidence_ece=expected_calibration_error(preds_list, label_by_id),
        cost_total_usd=cost_total,
        cost_mean_usd=cost_total / n,
    )


def expected_calibration_error(preds: list[Prediction], labels: dict[str, GoldLabel]) -> float:
    """5-bucket ECE: average |bucket_accuracy - bucket_confidence| weighted by
    bucket count.
    """
    buckets: list[tuple[float, float]] = [
        (0.0, 0.2),
        (0.2, 0.4),
        (0.4, 0.6),
        (0.6, 0.8),
        (0.8, 1.01),
    ]
    n = len(preds)
    if n == 0:
        return 0.0
    ece = 0.0
    for lo, hi in buckets:
        in_bucket = [
            p for p in preds if lo <= p.confidence < hi and p.alert_id in labels
        ]
        if not in_bucket:
            continue
        accuracy = sum(
            1
            for p in in_bucket
            if _verdict_correct(p.predicted_verdict, labels[p.alert_id].expected_verdict, adjacent_ok=True)
        ) / len(in_bucket)
        avg_conf = sum(p.confidence for p in in_bucket) / len(in_bucket)
        weight = len(in_bucket) / n
        ece += weight * abs(accuracy - avg_conf)
    return ece


def reliability_diagram(
    preds: list[Prediction],
    labels: dict[str, GoldLabel],
    bucket_width: float = 0.2,
) -> str:
    """ASCII reliability diagram (one row per confidence bucket)."""
    rows: list[str] = []
    header = (
        f"{'bucket':>14}  {'count':>5}  {'accuracy':>9}  {'avg_conf':>9}  "
        f"{'diagram':<30}"
    )
    rows.append(header)
    rows.append("-" * len(header))
    lo = 0.0
    while lo < 1.0:
        hi = round(lo + bucket_width, 2)
        in_bucket = [
            p for p in preds if lo <= p.confidence < hi and p.alert_id in labels
        ]
        if not in_bucket:
            lo = hi
            continue
        accuracy = sum(
            1
            for p in in_bucket
            if _verdict_correct(p.predicted_verdict, labels[p.alert_id].expected_verdict, adjacent_ok=True)
        ) / len(in_bucket)
        avg_conf = sum(p.confidence for p in in_bucket) / len(in_bucket)
        bar = "█" * int(round(accuracy * 30))
        rows.append(
            f"  [{lo:.2f}-{hi:.2f})  {len(in_bucket):>5}  "
            f"{accuracy:>9.2f}  {avg_conf:>9.2f}  {bar:<30}"
        )
        lo = hi
    return "\n".join(rows)


def adversarial_pass_rate(
    predictions: list[Prediction],
    adversarial_labels: list[dict],
) -> float:
    """Share of adversarial cases handled per expected outcome.

    Each adversarial label has either expected_verdict_in (acceptable set),
    expected_verdict_not (single rejection), or both. A prediction passes if
    its verdict is in the in-set AND not in the not-set.
    """
    if not predictions:
        return 1.0
    by_id = {p.alert_id: p for p in predictions}
    passes = 0
    counted = 0
    for label in adversarial_labels:
        pred = by_id.get(label["alert_id"])
        if pred is None:
            continue
        counted += 1
        verdict_in = label.get("expected_verdict_in")
        verdict_not = label.get("expected_verdict_not")
        ok = True
        if verdict_in:
            ok = ok and pred.predicted_verdict in set(verdict_in)
        if verdict_not is not None and pred.predicted_verdict == verdict_not:
            ok = False
        if ok:
            passes += 1
    if counted == 0:
        return 1.0
    return passes / counted
