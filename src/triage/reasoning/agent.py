"""T2 reasoning agent.

Inputs: CanonicalAlertEvent + InvestigationPlan + EvidenceBundle + LLM client.
Outputs: raw model response (handed to the validator) + plan_extensions log
+ updated EvidenceBundle (if T2 emitted request_additional_source).

T2 NEVER acts on the world; the only tool exposed is request_additional_source
which the orchestrator handles by routing through the enrichment fan-out.

Plan-extension loop bounds:
- Hard cap of 2 extensions per alert (constant in the prototype). Beyond
  the cap, T2's tool_use is ignored and the agent is asked to produce a
  final verdict with what it has.
- Each extension goes through the SAME tier policy as the initial fan-out;
  request_additional_source can target a tier outside the plan (cold), but
  the orchestrator-level budget envelope decides whether to grant it.
"""

from __future__ import annotations

import json

from triage.enrichment.base import EnrichmentSource, FailureMode, SourceQuery
from triage.enrichment.fanout import run_fanout
from triage.llm.client import LLMClient, LLMRequest, LLMResponse
from triage.reasoning.tools import T2_TOOLS
from triage.schemas.alert import CanonicalAlertEvent
from triage.schemas.plan import InvestigationPlan, SourceType
from triage.schemas.retrieval import EvidenceBundle

SONNET_MODEL = "claude-sonnet-4-6"
MAX_PLAN_EXTENSIONS = 2

T2_SYSTEM_PROMPT = """\
You are a security operations reasoning agent. You receive an alert,
its InvestigationPlan, and an EvidenceBundle of structured retrievals.
You produce a single JSON object matching the TriageVerdict schema.

Grounding rules (binding):
- Every observed_fact MUST cite a retrieval_id that appears in the
  retrievals[] list provided. NEVER invent retrieval_ids.
- Every observed_fact MUST include field_path and expected_value so the
  validator can check the claim against the actual retrieval payload.
- Every inference MUST cite at least one supported_by_fact_id from your
  observed_facts.
- Every recommendation MUST cite at least one supported_by_inference_id.
- If the evidence is insufficient and you cannot reach a confident verdict,
  emit verdict: "undetermined" or "needs_human" with open_questions.

Tools:
- If you need an additional enrichment source to ground a verdict, you may
  call request_additional_source(source_type, rationale). Cold-tier sources
  are permitted when the rationale is justified.

Schema constraints:
- verdict ∈ {confirmed_true_positive, likely_true_positive, undetermined,
              likely_false_positive, confirmed_false_positive,
              needs_human, needs_human_urgent}
- severity ∈ {P0, P1, P2, P3, P4}
- recommendation.action MUST be from the canonical action enum.
"""


def reason(
    alert: CanonicalAlertEvent,
    plan: InvestigationPlan,
    bundle: EvidenceBundle,
    client: LLMClient,
    sources: dict[SourceType, EnrichmentSource] | None = None,
    failure_modes: dict[SourceType, FailureMode] | None = None,
    max_extensions: int = MAX_PLAN_EXTENSIONS,
) -> tuple[LLMResponse, EvidenceBundle, list[dict]]:
    """Run the plan-extension loop. Returns the final LLM response (with the
    JSON content the validator parses), the augmented evidence bundle, and
    the list of plan_extensions for the verdict's audit pointer.
    """
    plan_extensions: list[dict] = []
    augmented_bundle = bundle
    extensions_used = 0

    while True:
        request = _build_t2_request(alert, plan, augmented_bundle, plan_extensions)
        response = client.complete(request)
        if response.stop_reason != "tool_use" or not response.tool_calls:
            return response, augmented_bundle, plan_extensions

        if extensions_used >= max_extensions:
            # Tell the model: cap reached; produce a final verdict now.
            request = _build_t2_request(
                alert,
                plan,
                augmented_bundle,
                plan_extensions,
                cap_reached=True,
            )
            response = client.complete(request)
            return response, augmented_bundle, plan_extensions

        for call in response.tool_calls:
            if call.get("name") != "request_additional_source":
                continue
            input_args = call.get("input", {})
            requested = input_args.get("source_type")
            rationale = input_args.get("rationale", "")
            if not requested or sources is None or requested not in sources:
                plan_extensions.append(
                    {
                        "source_type": requested,
                        "rationale": rationale,
                        "outcome": "rejected_unknown_source",
                    }
                )
                continue

            # Run a tiny one-source fan-out for the requested source.
            ext_query = SourceQuery(
                tenant_id=alert.tenant_id,
                alert_id=alert.alert_id,
                entity_id=alert.grouping_entity(),
                ioc=alert.primary_ioc(),
                extra={"rule_family": alert.rule_family},
            )
            try:
                refs = sources[requested].fetch(
                    ext_query,
                    failure_mode=(failure_modes or {}).get(requested, "clean"),
                )
            except Exception:  # noqa: BLE001 — fan-out boundary swallows
                augmented_bundle.enrichments_failed.append(requested)
                plan_extensions.append(
                    {
                        "source_type": requested,
                        "rationale": rationale,
                        "outcome": "fetched_failed",
                    }
                )
                continue
            augmented_bundle.retrievals.extend(refs)
            plan_extensions.append(
                {
                    "source_type": requested,
                    "rationale": rationale,
                    "outcome": "fetched_ok",
                    "added_retrievals": [r.retrieval_id for r in refs],
                }
            )
            extensions_used += 1


def _build_t2_request(
    alert: CanonicalAlertEvent,
    plan: InvestigationPlan,
    bundle: EvidenceBundle,
    plan_extensions: list[dict],
    cap_reached: bool = False,
) -> LLMRequest:
    user_payload = {
        "alert": {
            "tenant_id": alert.tenant_id,
            "alert_id": alert.alert_id,
            "source_system": alert.source_system,
            "rule_id": alert.rule_id,
            "rule_family": alert.rule_family,
            "severity_hint": alert.severity_hint,
            "summary": alert.summary,
            "primary_assets": [
                {"asset_id": a.asset_id, "asset_type": a.asset_type} for a in alert.primary_assets
            ],
            "observables": [
                {"type": o.observable_type, "value": o.value} for o in alert.observables
            ],
        },
        "investigation_plan": {
            "plan_id": plan.plan_id,
            "required_sources": list(plan.required_sources),
            "optional_sources": list(plan.optional_sources),
            "tier_preference": list(plan.tier_preference),
            "rationale": plan.rationale,
        },
        "retrievals": [
            {
                "retrieval_id": r.retrieval_id,
                "source_type": r.source_type,
                "fetched_at": r.fetched_at.isoformat(),
                "cached_at": r.cached_at.isoformat() if r.cached_at else None,
                "provider": r.provider,
                "provider_confidence": r.provider_confidence,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "conflicts": r.conflicts,
                "retrieval_truncated": r.retrieval_truncated,
                "truncation_sort_key": r.truncation_sort_key,
                "total_available": r.total_available,
                "storage_tier": r.storage_tier,
                "payload": r.payload,
            }
            for r in bundle.retrievals
        ],
        "enrichments_failed": bundle.enrichments_failed,
        "plan_extensions_so_far": plan_extensions,
        "cap_reached": cap_reached,
    }
    return LLMRequest(
        model=SONNET_MODEL,
        system=T2_SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": json.dumps(user_payload, sort_keys=True, default=str),
            }
        ],
        tools=T2_TOOLS if not cap_reached else [],
        response_format={"type": "json_object"} if cap_reached else None,
        max_tokens=4096,
        temperature=0.0,
    )
