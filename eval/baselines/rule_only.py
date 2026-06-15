"""Rule-only baseline: Sigma-style rules + threshold logic, no LLM.

The eval measures rule-only as the floor the system improves over. It's
deterministic and cheap; what it cannot do is articulate WHY a verdict
fires, produce grounded evidence, or explain uncertainty. That's the
walkthrough story.

Rules:
  * known-malicious IOC + severity P0/P1 → confirmed_true_positive
  * known-malicious IOC + severity P2/P3 → likely_true_positive
  * known-benign IOC → likely_false_positive
  * privilege_escalation + P0/P1 → likely_true_positive (default cautious)
  * ransomware + P0 → confirmed_true_positive
  * otherwise → undetermined

Cost is zero; latency is constant.
"""

from __future__ import annotations

KNOWN_MALICIOUS_IOCS = {"evil.example.invalid", "hash_a1b2c3d4"}
KNOWN_BENIGN_IOCS = {"hash_known_benign", "cdn.example.invalid", "telemetry.example.invalid", "deploy.example.invalid"}


def rule_only_predict(alert: dict) -> tuple[str, float, float]:
    """Return (predicted_verdict, confidence, cost_usd)."""
    severity = alert.get("severity_hint", "P3")
    family = alert.get("rule_family", "other")
    ioc = alert.get("ioc")

    if ioc in KNOWN_BENIGN_IOCS:
        return "likely_false_positive", 0.7, 0.0
    if ioc in KNOWN_MALICIOUS_IOCS:
        if severity in {"P0", "P1"}:
            return "confirmed_true_positive", 0.8, 0.0
        return "likely_true_positive", 0.65, 0.0
    if family == "ransomware" and severity == "P0":
        return "confirmed_true_positive", 0.75, 0.0
    if family == "privilege_escalation" and severity in {"P0", "P1"}:
        return "likely_true_positive", 0.6, 0.0
    return "undetermined", 0.5, 0.0
