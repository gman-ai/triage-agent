# Architecture Decisions

This document records the load-bearing architecture decisions for the triage agent. Each decision states the choice, the rationale, and what alternatives it rejects. Decisions are numbered for stable reference (D1, D2, …) and the numbering does not reset when a decision is superseded — supersessions are recorded inline.

The companion design narrative lives in [`DESIGN.md`](DESIGN.md); this file is the structured commitment log a reviewer can use to audit the build. The complete contract is enforced by the test suite under [`tests/`](tests/) — every decision below has at least one acceptance test that breaks if the contract is violated.

---

## D1 — Triage as an alert-trigger AI layer, not a chatbot or inline pipeline

**Choice.** The agent is invoked when an alert fires — either pushed by the upstream pipeline or pulled on-demand by an analyst with an `alert_id`. It produces a structured `TriageVerdict` and emits it back to the SIEM (or returns it via API). It does not operate as a conversational interface and does not block the ingestion path.

**Rationale.** Triage acceleration is the demonstrable value: compress the analyst's manual orchestration from 10 minutes to a 30-second verdict read. A conversational interface adds latency, cost, and unpredictable UX without serving the bounded triage task. Inline ingestion enrichment is the wrong scope for 15-30s LLM reasoning loops — that's the streaming-AI slot (extraction, tagging), not the alert-stage slot (grounded reasoning).

**Rejects.** Multi-turn chatbot UX. Synchronous in-stream alert processing during ingestion.

---

## D2 — Local-first, reproducible build

**Choice.** The full evaluation harness runs on a clean checkout with `uv sync && uv run pytest` plus `uv run python -m eval.run`. No live API key required for tests; live API capture is an explicit opt-in via `scripts/capture_t3_fixture.py`.

**Rationale.** A reviewer must be able to verify the system without provisioning hosted services or burning API credits. Determinism comes from bounded local clients (`SequenceClient` for the notebook, `FixtureReplayClient` for tests, `EvalSyntheticClient` for eval and the default local API). The captured live-API fixture proves real Opus output without making every CI run an expensive API hit.

**Rejects.** Hosted runtime as a precondition for evaluation. Reliance on a live API for tests.

---

## D3 — Per-source adapter layer over a canonical alert schema

**Choice.** Vendor JSON is translated into `CanonicalAlertEvent` by a per-source adapter (Okta v1 shipped, protocol documented for the rest). Downstream code never sees vendor-specific shapes. The adapter version is recorded on every alert so schema-drift forensics is possible.

**Rationale.** Schema drift is the hidden failure mode that breaks SOC tooling silently. A canonical contract at the boundary means the rest of the engine is vendor-agnostic; new sources are an adapter, not a rewrite.

**Rejects.** Assuming pre-normalized input. Vendor-specific shape leakage past the adapter layer.

---

## D4 — Storm grouper before LLM routing

**Choice.** Alerts that share a structural key — `(tenant_id, rule_family, source_system, primary_entity, IOC, 5-minute window)` — are collapsed to a single investigation. The first alert in a window is the sample; subsequent member alerts emit a degraded verdict pointing at the group, with no LLM spend.

**Rationale.** Burst floods are common in SecOps (misconfig push, bulk policy change, brute-force attack). Triaging each alert independently burns LLM cost on identical reasoning and overwhelms the analyst queue with N copies of the same finding. The grouper turns N alerts into one investigation while preserving the audit trail.

**Rejects.** Per-alert LLM routing under burst load. Silently dropping member alerts (each is still audited; only LLM triage is deduplicated).

**Production note.** Prototype uses an in-process cache; a Redis-backed cache is the day-one production change for multi-worker deployment.

---

## D5 — Deterministic router; LLM never decides routing

**Choice.** A pure-Python router consumes the alert, the T1 classification, and per-tenant budget state and emits a typed `RouteDecision` from a closed enum: `rule_fast`, `rule_to_t2`, `t2_standard`, `t2_urgent`, `t2_escalate_if_low_conf`, `skip_low_severity`. Routing is in code, not in the model.

**Rationale.** LLM-decided routing is unreliable on critical alerts and expensive at volume. P0 silent skip under budget pressure is unacceptable; that's a detection failure, not a cost-control win. A deterministic router is auditable and predictable per-alert.

**Rejects.** ReAct-style autonomous routing agents. A single LLM call that "decides everything" downstream.

---

## D6 — T1 plan resolution is deterministic; the LLM enters at T2

**Choice.** T1 is a YAML lookup keyed on `(rule_family, severity_hint)` against the plan-template registry. It produces the `InvestigationPlan` (required sources, optional sources, tier preference) without an LLM call. Two LLM tiers remain: T2 Sonnet for reasoning, T3 Opus for low-confidence critical-family escalation.

**Rationale.** Plan selection is finite, rule-shaped policy. Detection engineers know which evidence types matter per alert family; that knowledge belongs in YAML where SecOps teams own it. LLMs are good at probabilistic judgment over evidence — not at policy decisions where consistency and auditability matter. An LLM-driven planner is a defensible future iteration once plan-quality eval infrastructure exists; it is not the right shape for a production-ready prototype.

**Rejects.** An LLM at T1 emitting plan structure. A separate Planner Agent in a multi-agent topology.

**History.** An earlier revision of this design routed plan emission through a Haiku call as a Pydantic field on T1 output. Review showed the LLM was rubber-stamping a deterministic decision, so T1 was made deterministic explicitly. The investigation engine shape did not change; the T1 implementation moved from LLM-based to policy lookup.

---

## D7 — Single agent + bounded tool-use loop

**Choice.** One Sonnet reasoning pass with one tool — `request_additional_source` — used when reasoning identifies a gap. The loop is capped at 2 plan extensions per alert, after which the agent must emit a final verdict.

**Rationale.** Multi-agent supervisor-worker architectures (e.g., LangGraph SentinelFlow) add orchestration latency and cost without measurable accuracy gain on bounded single-investigation alerts. A bounded loop preserves the Plan → Reason → Re-plan → Reason cycle that real investigations follow, with a hard cap on cost and latency. The "is this really an agent" framing is a vocabulary question; the architecture is a bounded agent with one tool.

**Rejects.** LangGraph supervisor-worker fan-out. Unbounded autonomous tool loops.

---

## D8 — Tool calling for structured live data; RAG for institutional prose

**Choice.** Six enrichment sources are exposed as tool-call retrievals: `asset_cmdb`, `identity_store`, `historical`, `threat_intel`, `runbook`, `log_search`. Structured sources return typed payloads; the runbook source can wrap a RAG retrieval over policy prose when the customer's runbooks are unstructured.

**Rationale.** Structured live data needs tool-call shape — it carries provenance metadata (provider, cached_at, first_seen) the validator depends on. Vector RAG over everything makes citation validation impossible and erodes grounding. Different data shapes need different access patterns.

**Rejects.** Vector RAG as the universal retrieval mechanism. Free-text retrieval where structured data exists.

---

## D9 — Application-generated retrieval IDs

**Choice.** Every `RetrievalRef` carries a `retrieval_id` minted by the engine, not by the source system. The reasoning prompt presents this allowlist; the model selects IDs from it but cannot mint its own. The validator enforces existence against the same allowlist.

**Rationale.** If the model could emit arbitrary retrieval IDs, a prompt-injection attack via source-controlled fields could plant fake IDs in retrievals and have them surface in cited evidence. App-generated IDs make hallucinated citations structurally impossible — any cited ID that isn't on the allowlist is a validator failure.

**Rejects.** Source-system IDs surfaced directly to the model. Model-generated retrieval IDs.

---

## D10 — Forced JSON schema + closed-vocabulary enums

**Choice.** T2 output is forced into a Pydantic `TriageVerdict` schema with closed `Literal` enums on `verdict` (5 values + needs_human), `severity` (P0..P4), action (11 values mapped to SOAR API targets), `blast_radius` (low/medium/high), and tactic IDs (MITRE ATT&CK). The model emits JSON the schema parses or the validator rejects it.

**Rationale.** Closed vocabularies make automation tractable: downstream SOAR systems consume specific strings; audit queries filter by exact enum match; per-family eval rolls up cleanly. Free-text + post-hoc parsing creates an unbounded vocabulary that no consumer can rely on. The LLM does judgment within slots; the schema constrains the surface.

**Rejects.** Free-text output with post-hoc parsing. Open-ended action vocabulary.

---

## D11 — Three-tier evidence model: facts cite retrievals, inferences cite facts, recommendations cite inferences

**Choice.** The verdict carries `observed_facts[]` (each with `retrieval_id`, `field_path`, `expected_value`), `inferences[]` (each with `supported_by_fact_ids`), and `recommendations[]` (each with `supported_by_inference_ids`). The chain terminates at a real retrieval.

**Rationale.** Splitting facts, inferences, and recommendations into separate typed slots prevents the common LLM failure of hypothesis-as-fact. Every claim has a parent; recommendations cannot appear from nowhere; inferences cannot float free of evidence. The schema is a reasoning contract, not just an output shape.

**Rejects.** A single flat `evidence[]` list. Recommendations without grounding chains.

---

## D12 — Citation **support** validation, not just existence

**Choice.** The validator runs three passes: (1) schema check, (2) citation existence — every cited `retrieval_id` is in the bundle, (3) **citation support** — for each observed_fact, walk the cited retrieval's payload at `field_path` and confirm `expected_value` matches. Existence-only validation is the published-SOC-agent norm; support validation is the differentiator.

**Rationale.** Existence-only validation catches one class of hallucination (fake retrieval IDs) but misses the more dangerous class: the model citing a real retrieval while claiming something the retrieval doesn't say. Walking the payload at the cited path catches "real ID, wrong content" attacks programmatically.

**Rejects.** Existence-only validation. LLM-as-judge as primary correctness mechanism (demoted to secondary metric per D22).

---

## D13 — Multi-tenancy is first-class throughout

**Choice.** `tenant_id` is present on every alert, retrieval, span, prompt, audit row, and cache key. Cross-tenant isolation is an acceptance gate: a fixture test proves data from `tenant_a` never appears in `tenant_b`'s pipeline.

**Rationale.** Multi-tenant deployment (MSSPs running N customer SOCs through shared infrastructure, or enterprise customers running multiple business units on the same engine) is a hard requirement for any production triage layer in this space. Bolting tenancy on later means refactoring every cache, every span, every audit row.

**Rejects.** Single-tenant prototype. Tenant_id as a downstream filter applied after data is already mixed.

---

## D14 — Stale-clean threat intel cannot prove benign

**Choice.** Threat intel retrievals carry `provider`, `fetched_at`, `cached_at`, `first_seen`, `last_seen`, `provider_confidence`, and `conflicts[]`. The reasoning agent downgrades evidentiary weight on clean-reputation findings older than the freshness threshold (default 30 days). A 47-day-old "clean" verdict on an IP does not anchor a `likely_false_positive` verdict.

**Rationale.** Threat reclassification windows for active campaigns are minutes to hours, not days. A long-stale clean-reputation cache hides recently-weaponized infrastructure. TTL-only freshness is insufficient; the agent must reason explicitly about evidence age.

**Rejects.** TTL-only freshness. Treating cached clean reputation as definitive regardless of age.

---

## D15 — Audit by hash; raw payloads behind retention class with redaction

**Choice.** Each triage writes one `AuditRow` carrying the verdict, `prompt_hash`, `retrieval_bundle_hash`, per-source evidence pointers, `model_chain`, cost, spans, and plan extensions. Default retention is `hash_only`. Raw payloads land in `forensic_30d` only behind an explicit retention class, with regex redaction for AWS access keys, AWS secrets, bearer tokens, generic API keys, and email PII.

**Rationale.** Storing raw prompts and responses indefinitely as JSONB turns the audit ledger into a compliance liability and a data swamp. Hash-by-default is reconstructable (an auditor with the seeded retrieval data can recompute the bundle hash to verify integrity) without creating new exposure.

**Rejects.** Raw prompt + response + retrieval as JSONB. Unbounded retention without redaction.

---

## D16 — Per-tenant budget envelope with severity-aware override

**Choice.** Per-tenant daily budget with soft (80%) and hard (100%) caps. The hard cap triggers `skip_low_severity` for P2/P3/P4 alerts. P0 alerts and P1 alerts in deep families (`ransomware`, `privilege_escalation`, `data_exfil`, `dns_exfil`) override the cap and emit `needs_human_urgent` plus a `budget_exceeded_p0_override` metric.

**Rationale.** Money is a soft constraint; severity is a hard signal. Silently skipping a P0 ransomware alert because earlier-day noise burned the daily budget is the kind of detection failure customers cannot tolerate. The override is bounded (it only fires on critical families) and observable (the metric surfaces it to ops).

**Rejects.** Uniform budget cap that suppresses all alerts equally. Silent budget enforcement without metric.

---

## D17 — Degraded-mode taxonomy on every verdict

**Choice.** Every `TriageVerdict` can carry one of a closed set of degraded reasons: `llm_unavailable`, `retrieval_partial`, `cost_cap_reached`, `schema_drift`, `storm_mode`, `needs_human_urgent`, `tenant_calibration_warning`. The pipeline never raises uncaught; the worst case is a structured degraded verdict.

**Rationale.** Analysts and operators need to see *why* confidence dropped or *why* a verdict went to needs_human. A single boolean `degraded` flag loses information; an unhandled exception drops the alert entirely. The closed-enum taxonomy makes degraded-state reporting machine-readable.

**Rejects.** Single boolean degraded flag. Uncaught exceptions that drop alerts.

---

## D18 — Validator terminal failsafe

**Choice.** When the validator rejects T2 output, the agent retries Sonnet once with the validation errors in the prompt. If the retry also fails, the agent emits a hardcoded valid `TriageVerdict` with `verdict: needs_human` and `degraded: validation_failure_schema`. The pipeline never raises uncaught at this boundary.

**Rationale.** Schema failure that drops the alert is worse than a degraded verdict that surfaces "human, look at this." One retry gives the model a chance to recover; the failsafe ensures the audit trail is always complete.

**Rejects.** Raise on retry failure. Drop the alert on schema failure.

---

## D19 — Provider-agnostic LLM client abstraction

**Choice.** Production uses Anthropic Sonnet 4.6 (T2) and Opus 4.7 (T3) via a `LLMClient` protocol. Test/eval clients (`FixtureReplayClient`, `SequenceClient`, `EvalSyntheticClient`) implement the same protocol. Switching to Bedrock, Vertex, or Azure OpenAI is a client-class change, not a reasoning-code change.

**Rationale.** Provider lock-in at the reasoning layer prevents customers from choosing their deployment surface. Tool-use discipline is strongest on Anthropic at this date, which is why production targets Anthropic; the abstraction preserves optionality.

**Rejects.** Lock-in to a single provider with no abstraction. Switching providers requires rewriting reasoning code.

---

## D20 — Local-first observability

**Choice.** The agent emits structured-log spans by default (stdout JSON + persisted trace JSON in the audit ledger). A live observability cockpit can wrap spans when an env var is present, but is never a deployment dependency.

**Rationale.** A reviewer evaluating the build on a clean machine should see complete observability without provisioning external services. Hosted observability dependencies become a barrier to evaluation and a single point of failure in production.

**Rejects.** Hosted observability as a required runtime. Spans only emitted when remote collector is reachable.

---

## D21 — Eval harness with calibration + adversarial set + baselines

**Choice.** 30-alert gold dataset + 12-alert adversarial set + naive LLM-only baseline + rule-only baseline. The harness reports exact accuracy, adjacency-correct accuracy, expected calibration error, action validity, and adversarial pass rate. Reports land in `eval/reports/`; the harness gates prompt/model/schema changes.

**Rationale.** Eyeball validation does not survive scrutiny. Baselines prove the claim (the agent is meaningfully better than a single Sonnet call AND a rule-only system). Calibration distinguishes "model returns a number" from "the number actually means something" — without it, the confidence field is decorative.

**Rejects.** Eyeball validation. Single accuracy number without baselines.

---

## D22 — LLM-as-judge demoted to secondary metric

**Choice.** Primary correctness comes from deterministic checks (schema, citation existence, citation support, action allowlist). LLM-as-judge can be enabled as a secondary metric for human spot-check assistance but is never load-bearing.

**Rationale.** LLM-as-judge as primary correctness is too weak for production claims — the judge model has the same failure modes as the system under test. Deterministic validation gives stronger guarantees and produces a reproducible answer to "how do you know?"

**Rejects.** LLM-as-judge as the primary correctness signal.

---

## D23 — No heavyweight framework dependency

**Choice.** The agent is built on the Anthropic SDK + Pydantic + FastAPI + pytest. No LangChain, no LlamaIndex, no CrewAI, no AutoGen.

**Rationale.** Heavyweight orchestration frameworks add abstraction layers the reviewer cannot debug and a vendor lock-in the customer cannot exit. Every architectural choice in this build has a one-sentence defense; framework hand-waving loses that property. The Anthropic SDK is the minimum surface needed for tool use; everything else is straight Python.

**Rejects.** LangChain / LlamaIndex / CrewAI / AutoGen as orchestration substrate.

---

## D24 — Async return semantics on the pipeline-trigger path

**Choice.** When the agent is invoked automatically by a pipeline trigger, the verdict can attach asynchronously to the SIEM alert via upsert or webhook. The SIEM ingestion path is not held up by 15-30s LLM reasoning. The analyst-initiated path is synchronous — the analyst is already waiting on that alert.

**Rationale.** Inline synchronous enrichment that takes 15-40s creates catastrophic backpressure in a high-throughput ingestion pipeline. Async attach preserves ingestion throughput while delivering the verdict to the analyst in time to matter. Same engine, different return semantics per bookend.

**Rejects.** Synchronous inline triage on the ingestion path.

---

## D25 — Plan-gated retrieval with truncation contract

**Choice.** The fan-out fetches only sources listed in the active plan. Each source has a per-source record cap; overflow sets `retrieval_truncated: true` on the `RetrievalRef` and records the sort key applied (e.g., `severity DESC, occurred_at DESC`) plus the full count when known.

**Rationale.** "Pull 30d historical alerts" without a cap blows the LLM token budget and triggers lost-in-the-middle. Truncation must be explicit, not silent: the model sees `retrieval_truncated: true` and can request a tighter window via plan extension if reasoning requires it.

**Rejects.** Unbounded retrievals injected into the prompt. Silent truncation without flag.

---

## D26 — Schema drift split: destructive vs additive

**Choice.** Destructive drift (a required field disappeared) quarantines the alert with `verdict: needs_human` and `degraded: schema_drift`. Additive drift (a new unmapped field appeared) is logged and the alert flows through without confidence downgrade.

**Rationale.** Vendor benign field additions happen routinely and should not drown the SOC in drift false-positives. Required-field disappearance is a real detection failure mode that must surface as needs_human. The split separates "vendor added a column" from "the contract is broken."

**Rejects.** Treat all drift as destructive. Treat all drift as additive.

---

## D27 — Correction loop with soft and hard layers

**Choice.** Analyst corrections enter via a per-tenant endpoint. The soft layer fires automatically: operational alert to detection engineering, `degraded: tenant_calibration_warning`, future verdicts on the same pattern capped at `likely_*` (cannot emit `confirmed_*`). The hard layer (`forced_human_review` flag changing routing thresholds) is gated behind a detection-engineering ACK.

**Rationale.** Analyst bulk-FP closing can poison routing thresholds if it auto-degrades policy. Soft layer protects the system from lazy correction; hard layer preserves the ability for thoughtful corrections to change behavior. Both layers are tenant-scoped — corrections from `tenant_a` cannot influence `tenant_b`.

**Rejects.** Auto-degrade routing on analyst threshold. Endpoint without policy.

---

## D28 — Exponential backoff with jitter on enrichment retries

**Choice.** Every source retry uses exponential backoff with jitter; the retry count is recorded in the span. Failure containment is graceful — a timed-out source lands in `enrichments_failed[]` and the bundle proceeds with partial evidence.

**Rationale.** Naive retry loops thunder-herd against rate-limited internal APIs and amplify partial outages into full outages. Jitter prevents synchronized retry storms; the failure-containment policy ensures partial outage does not block triage.

**Rejects.** Naive retry loops without backoff. Source failure aborts the bundle.

---

## D29 — Storage tier awareness on retrievals and plans

**Choice.** Every `RetrievalRef` carries `storage_tier` (hot / warm / cold). Every `InvestigationPlan` carries `tier_preference` as an ordered list. The fan-out attempts sources in tier order; sources whose tier is not in `tier_preference` are refused with a `TierPolicyExcluded` span.

**Rationale.** Customer storage architectures route alerts to hot tables (queryable, expensive), warm tables (cheaper, slower), and cold archives (cheapest, slowest) per relevance and retention policy. Making the tier visible at the retrieval and plan layers means the cost story is in code, not just prose. The fan-out respects the tier policy explicitly rather than blindly querying.

**Rejects.** Single-cost-class enrichment that treats all sources as equal cost. Implicit tier choice hidden inside source implementations.

---

## D30 — Cold tier is opt-in, never default

**Choice.** Cold tier is not included in any per-family plan template default. Cold-tier pulls happen only via T2 plan extension when reasoning identifies a justified gap. The default investigation path is hot-only or hot-and-warm depending on family.

**Rationale.** Default-cold explodes triage cost and latency. Cheap-first / extend-when-justified is the right pattern: the agent investigates with cheap evidence first and pays the cold-tier cost only when reasoning shows a real gap. The customer pays predictable cost on the default path and accepts variable cost on the rare extension path.

**Rejects.** Cold tier in family defaults for "completeness." Implicit cold-tier fallback during fan-out.

---

# Decisions deferred from the prototype

The following are documented gaps. Each has a specific fix path and is named here so the prototype's scope is explicit. The trade-off in each case is "ship the substantive contract; defer the polish."

## D31 — Required-source enforcement is currently soft

**Current state.** When a source listed in `required_sources` ends up in `enrichments_failed[]` (tier policy refusal, timeout, upstream error), the agent surfaces the missing list in the T2 prompt but does not structurally force a confidence cap on the resulting verdict.

**Production fix.** Verdict capped at `likely_*` (never `confirmed_*`) when any required source is missing; `uncertainty.missing_enrichments` forced non-empty; validator enforces. ~30 lines of code.

**Why deferred.** Graceful degradation is consistent with the rest of the engine (validator terminal failsafe, schema-drift quarantine, budget override); the gap is enforcement strength, not behavior shape. T2 has the missing-list in its prompt and reasons over partial evidence today.

---

## D32 — Policy citations on recommendations

**Current state.** Recommendations cite policy in free-text `rationale`. The validator's citation-support pass walks `observed_facts[]` citations against retrievals but does not walk policy citations against runbook retrievals.

**Production fix.** Add `policy_citations[]` to the `Recommendation` schema; each entry points at a runbook `retrieval_id` with an optional `section_path`. The validator walks them the same way it walks `observed_facts`. ~6 lines schema + ~10 lines validator.

**Why deferred.** The `runbook` source is registered and exercised in plan templates; the closed-vocabulary action enum maps to SOAR API targets. Closing the citation loop on policy is additive — the substantive contract (recommendations cite inferences, inferences cite facts, facts cite retrievals) is in place.

---

## D33 — Redis-backed storm grouper for production

**Current state.** Storm grouper holds the group cache in process memory. A process restart drops state; multi-worker deployment fragments state silently.

**Production fix.** Redis-backed cache, state survives restart, state is shared across workers. Same grouping logic, distributed substrate.

**Why deferred.** Single-worker in-process is correct scope for prototype; the test suite proves grouping behavior independent of cache substrate. Redis is the day-one production change, not a redesign.

---

## D34 — Confidence calibration via labeled outcomes

**Current state.** Confidence is whatever the LLM emits. The engine uses it for routing decisions (T3 escalation threshold, auto-close threshold) without recalibration.

**Production fix.** Once production produces labeled outcomes (true positive / false positive disposition by analyst), fit a calibration function on `(LLM confidence, citation pass, severity hint, source quality) → actual correctness rate`. Periodic reliability-diagram evals per family surface drift to detection engineering.

**Why deferred.** Calibration requires labeled outcomes the prototype does not have. Citation-support validation, T3 self-consistency sampling, and forced human review compensate for uncalibrated confidence in the meantime — the safety posture does not depend on confidence being well-calibrated today.

---

# How this document is used

A reviewer should be able to:

1. Open the repo and find the architectural commitments without reading the full design narrative.
2. Trace any decision to the code that implements it (file paths in `DESIGN.md`; tests under `tests/`).
3. See what was explicitly considered and rejected for the major design choices.
4. See what was deferred and what the fix path looks like.

The decisions above are load-bearing. Smaller tradeoffs (specific Pydantic field names, retry counts, default thresholds) live in `DESIGN.md` as prose. Both documents are the source of truth for the build; the test suite is the enforcement layer.
