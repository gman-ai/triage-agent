"""Smoke test: eval harness loads + produces a metrics report meeting §8 targets.

Not a per-metric assertion — that's what eval/run.py's report writer does. This
test just confirms the harness can be imported and the gold + adversarial sets
load + parse + the synthetic client and baselines produce predictions.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from eval.baselines.naive import naive_predict
from eval.baselines.rule_only import rule_only_predict
from eval.metrics import GoldLabel, Prediction, compute_metrics
from eval.run import ADVERSARIAL_PATH, GOLD_PATH, load_jsonl


def test_gold_set_loads_with_30_alerts():
    rows = load_jsonl(GOLD_PATH)
    assert len(rows) == 30
    families = {r["rule_family"] for r in rows}
    assert families == {
        "impossible_travel",
        "ransomware",
        "c2_callback",
        "dns_exfil",
        "privilege_escalation",
    }
    # Exactly 6 per family
    from collections import Counter
    family_counts = Counter(r["rule_family"] for r in rows)
    for family, n in family_counts.items():
        assert n == 6, f"family={family} has {n}, expected 6"


def test_adversarial_set_loads_with_12_alerts_across_categories():
    rows = load_jsonl(ADVERSARIAL_PATH)
    assert len(rows) == 12
    categories = {r["category"] for r in rows}
    assert {
        "prompt_injection_summary",
        "prompt_injection_runbook",
        "prompt_injection_logs",
        "missing_fields",
        "ioc_not_in_threat_intel",
        "stale_clean",
        "corrupt_payload",
        "oversized_payload",
        "replay",
        "cross_tenant_collision",
        "storm_burst",
        "schema_drift",
    } == categories


def test_naive_baseline_returns_verdict_confidence_cost():
    rows = load_jsonl(GOLD_PATH)
    verdict, confidence, cost = naive_predict(rows[0], rows[0]["expected_verdict"])
    assert isinstance(verdict, str)
    assert 0.0 <= confidence <= 1.0
    assert cost > 0


def test_rule_only_baseline_returns_zero_cost():
    rows = load_jsonl(GOLD_PATH)
    verdict, confidence, cost = rule_only_predict(rows[0])
    assert cost == 0
    assert verdict in {
        "confirmed_true_positive",
        "likely_true_positive",
        "undetermined",
        "likely_false_positive",
    }


def test_metrics_compute_on_minimal_input():
    preds = [
        Prediction(
            alert_id="gold_it_01",
            predicted_verdict="likely_true_positive",
            predicted_severity="P1",
            predicted_action="force_password_reset",
            confidence=0.9,
            cost_usd=0.02,
            citation_count=1,
            citation_existence_passed=1,
        )
    ]
    labels = [
        GoldLabel(
            alert_id="gold_it_01",
            expected_verdict="likely_true_positive",
            expected_severity="P1",
            expected_primary_action="force_password_reset",
            expected_attack_tactic="TA0001",
        )
    ]
    metrics = compute_metrics(preds, labels)
    assert metrics.n == 1
    assert metrics.verdict_accuracy_exact == 1.0
    assert metrics.citation_existence_rate == 1.0


def test_reports_dir_has_at_least_one_eval_run():
    """If `uv run eval` ran during the build, a report file exists."""
    reports_dir = Path(__file__).resolve().parents[1] / "eval" / "reports"
    if not reports_dir.exists():
        pytest.skip("no reports dir yet; harness has not run")
    reports = list(reports_dir.glob("eval_*.md"))
    if not reports:
        pytest.skip("reports dir empty; harness has not run")
    # Read the latest report and confirm it contains the §8 marker section.
    latest = max(reports, key=lambda p: p.stat().st_mtime)
    text = latest.read_text()
    assert "§8 targets" in text
    assert "Reliability diagram" in text
