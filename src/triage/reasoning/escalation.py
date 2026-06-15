"""T3 Opus escalation per RECONCILED §6 + D6 + IMPL #7.

Escalation triggers when:
  * T2 returned `confidence < 0.6` AND
  * severity in {P0, P1} AND
  * rule_family in DEEP_FAMILIES

Self-consistency at sample size 3 (capped). The prototype ships ONE demo
run with cost telemetry; the contract does not require full P95
measurement (IMPL #7).

The agent calls the same T2-style prompt against Opus and asks for a
single best verdict. For prototype scope, "sample 3" is implemented as 3
independent calls (the test fixture provides 3 responses); the majority
verdict among the three is the output. Production swap (DESIGN.md): a
single multi-attempt call with temperature variation.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass

from triage.llm.client import LLMClient, LLMRequest, LLMResponse
from triage.reasoning.agent import T2_SYSTEM_PROMPT
from triage.schemas.alert import CanonicalAlertEvent
from triage.schemas.plan import InvestigationPlan
from triage.schemas.retrieval import EvidenceBundle

OPUS_MODEL = "claude-opus-4-7"
SAMPLE_SIZE = 3


@dataclass
class EscalationOutcome:
    raw_responses: list[LLMResponse]
    majority_verdict: str
    cost_usd: float
    total_tokens: dict[str, int]
    sampled_at: list[str]


def should_escalate(severity: str | None, alert_family: str, confidence: float) -> bool:
    DEEP_FAMILIES = {"ransomware", "privilege_escalation", "data_exfil", "dns_exfil"}
    return (
        confidence < 0.6
        and severity in {"P0", "P1"}
        and alert_family in DEEP_FAMILIES
    )


def escalate_to_t3(
    alert: CanonicalAlertEvent,
    plan: InvestigationPlan,
    bundle: EvidenceBundle,
    client: LLMClient,
    sample_size: int = SAMPLE_SIZE,
) -> EscalationOutcome:
    request = _build_t3_request(alert, plan, bundle)
    responses: list[LLMResponse] = []
    verdicts: list[str] = []
    for _ in range(sample_size):
        response = client.complete(request)
        responses.append(response)
        try:
            parsed = json.loads(response.content)
            verdicts.append(str(parsed.get("verdict", "needs_human")))
        except json.JSONDecodeError:
            verdicts.append("needs_human")
    majority = Counter(verdicts).most_common(1)[0][0]
    cost = sum(r.cost_usd for r in responses)
    return EscalationOutcome(
        raw_responses=responses,
        majority_verdict=majority,
        cost_usd=cost,
        total_tokens={
            "prompt": sum(r.tokens_in for r in responses),
            "completion": sum(r.tokens_out for r in responses),
        },
        sampled_at=[r.model for r in responses],
    )


def _build_t3_request(
    alert: CanonicalAlertEvent,
    plan: InvestigationPlan,
    bundle: EvidenceBundle,
) -> LLMRequest:
    user_payload = {
        "alert": {
            "alert_id": alert.alert_id,
            "rule_family": alert.rule_family,
            "severity_hint": alert.severity_hint,
            "summary": alert.summary,
        },
        "plan": plan.model_dump(),
        "retrievals": [r.model_dump() for r in bundle.retrievals],
        "task": (
            "T2 returned low confidence on a high-severity deep-family alert. "
            "Produce a single TriageVerdict-shaped JSON. Be decisive: choose "
            "the most probable verdict, ground every fact in retrieval_ids "
            "from the provided list, and surface remaining uncertainty in the "
            "uncertainty field. Do NOT request additional sources; T3 is a "
            "terminal pass."
        ),
    }
    return LLMRequest(
        model=OPUS_MODEL,
        system=T2_SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": json.dumps(user_payload, sort_keys=True, default=str),
            }
        ],
        tools=[],  # T3 does NOT extend plan
        response_format={"type": "json_object"},
        max_tokens=4096,
        temperature=0.0,
    )
