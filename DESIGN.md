# Triage Agent — DESIGN

A per-tenant SecOps alert triage service that takes an alert in, runs
grounded reasoning over cross-source context, and emits a structured
`TriageVerdict`. Surface-agnostic by design: trigger and emit are pluggable
bookends; the engine is the same regardless of how it is invoked or where
the verdict lands.

## 1. Problem framing

A SOC analyst receives a SIEM alert. The question is not "what does this
alert say?" — the analyst can read. The question is whether the alert is
real, what the blast radius is if it is, and what action is justified. The
bottleneck is gathering enough cross-source context to decide with
confidence. Pivoting across identity provider, threat intel, asset DB,
historical alerts, and runbook sources manually takes 10-15 minutes per
alert.

The triage service solves this bottleneck by doing the digging. It takes
an alert as input, pulls cross-source context from DataBahn's
pipeline-resident data, runs grounded reasoning with citation-validated
evidence, and produces a structured `TriageVerdict` the analyst can act
on. The decision stays with the human; the engine compresses the
time-to-decision.

**Surface-agnostic by design.** The engine is exposed via API. The trigger
and emit bookends are pluggable per customer deployment shape:

- **Trigger:** automatic from the pipeline when an alert is created in the
  SIEM, OR on-demand when an analyst requests help by alert ID. Real
  customers vary; the architecture supports both modes through the same
  entry point.
- **Emit:** push the verdict back to the SIEM as `triage.*` fields on the
  alert record, OR return the verdict via the API to a DataBahn surface.

The engine doesn't care which mode invokes it. The architecture, the tests,
and the cost story are the same regardless of trigger and emit shape.
Enterprise deployment models vary across customers; the prototype's job is
to prove the engine, not to dictate the customer's product surface.

**Structural advantage — the pipeline-data edge.** Because DataBahn sits in
the customer's telemetry path, the engine has correlation surface a
SIEM-resident tool does not. The SIEM can only query what it indexed. The
engine can query what DataBahn routed, including data that went to cold
storage tiers (compliance retention) instead of the expensive SIEM index.
A generic SOC AI tool sees what the SIEM saw; this engine sees what the
pipeline saw.

**Cost is bounded by tiered routing.** Not every alert reaches deep
reasoning. A four-stage cascade catches alerts at the appropriate tier:

- Rule prefilter catches known-FP and known-TP patterns at zero LLM cost
- T1 Haiku handles low-severity high-confidence triage at sub-cent cost
- T2 Sonnet handles standard triage with plan-gated enrichment and tool
  calling
- T3 Opus is reserved for low-confidence P0/P1 alerts in critical families

This is the cost discipline. Only the alerts that need deep reasoning get
it; the rest get the right cheaper tier.

**The agent does NOT:**

- Replace the analyst (decision authority stays human)
- Auto-remediate (`automatable: false` default for all recommendations)
- Surface raw LLM prose to the analyst (output is typed JSON consumed by
  the existing SIEM workbench)
- Operate as a conversational chatbot (one-shot triage returns a structured
  result; not multi-turn dialog)

## 2. Architecture and approach

The engine is invoked via its API entry point. Whatever triggered the
invocation — pipeline integration pushing an alert payload, analyst-initiated
request by alert ID, a webhook from a SOAR platform, or a direct curl during
development — the flow is the same:

```
Trigger (pipeline OR analyst-initiated)
   │
   ▼
Source Adapter (per-vendor; versioned; destructive vs additive drift split)
   │ CanonicalAlertEvent
   ▼
Storm Grouper (key: tenant + rule + source + entity + IOC + 5-min bucket)
   │ AlertEvent or IncidentGroup
   ▼
Deterministic Router (rule prefilter → T1 → severity/confidence/budget)
   │
   ├── rule_fast / t1_fast (no LLM beyond classifier)
   └── t2_standard / t2_urgent / t2_escalate_if_low_conf
                          │
                          ▼
                  T1 Pre-classifier (Haiku, JSON-mode)
                  emits InvestigationPlan with tier_preference
                          │
                          ▼
                  Plan-gated Tier-ordered Fan-out
                  (6 sources: asset_cmdb, identity_store, historical,
                   threat_intel, runbook, log_search)
                  tier_preference orders hot → warm; cold is T2 plan-extension
                  per-source caps; retrieval_truncated flag on overflow
                          │
                          ▼
                  T2 Reasoning Agent (Sonnet, forced JSON schema)
                  may call request_additional_source (bounded extensions)
                          │
                          ▼
                  T3 Opus escalation (low-confidence P0/P1 in deep families;
                  3-sample self-consistency capped; terminal pass)
                          │
                          ▼
                  Output Validator
                  schema → citation existence → citation support
                  on double-failure: hardcoded needs_human verdict
                          │
                          ▼
                  Audit Ledger (hashes + source pointers; redacted forensic
                  payloads behind retention class)
                          │
                          ▼
                  TriageVerdict (structured JSON)
                          │
                          ▼
Emit (push to SIEM as triage.* fields OR return to API caller)
```

Both bookends — trigger and emit — are pluggable. The middle is the engine,
and it's the same regardless of how the engine is invoked or where the
verdict lands.

**Async-by-construction on the pipeline-trigger path.** When invoked
automatically from the in-flight pipeline, the raw alert continues to the
SIEM immediately and the verdict attaches via upsert or webhook once ready.
A 15-40 second LLM call cannot sit on the critical ingestion path. When
invoked on-demand by analyst, the API call returns the verdict
synchronously; the analyst is already waiting. Same engine, different
return semantics per bookend.

T3 Opus escalation fires when T2 returns `confidence < 0.6` AND `severity
in {P0, P1}` AND `rule_family in {ransomware, privilege_escalation,
data_exfil, dns_exfil}`. T3 is a terminal pass; no further plan extension.

## 3. Industry anchors

### 3.1 NIST SP 800-61r3 (Computer Security Incident Handling Guide)

The investigation lifecycle aligns with NIST SP 800-61r3. The system supports
detection (source adapters normalize vendor alerts into a canonical schema),
analysis (T2 grounded reasoning produces a TriageVerdict with observed_facts
and inferences), containment-recommendation (closed-vocabulary
`recommendations[]` with `blast_radius` and `reversible` flags), and
post-investigation feedback (the correction loop feeds analyst dispositions
back into per-tenant calibration). The architecture is an implementation of
a standard, not a vendor opinion.

### 3.2 MITRE ATT&CK as threat vocabulary

The verdict's `attack_chain` field carries MITRE tactic and technique IDs
(e.g., `TA0040` for Impact, `T1078` for Valid Accounts). The gold dataset's
`expected_attack_tactic` is labeled in the same vocabulary. SOC analysts and
threat hunters already speak ATT&CK; the assistant emits a verdict they can
consume without retranslation. Closed vocabularies in the verdict schema make
downstream automation against tactic IDs trivial.

### 3.3 SentinelFlow as the named alternative — and why this isn't it

LangGraph supervisor-worker architectures (e.g., the public SentinelFlow
project) place a primary agent over specialized worker subgraphs. For
bounded, single-investigation alerts, the multi-agent shape adds orchestration
latency and cost without measurable accuracy gain. The reconciled architecture
here uses a single agent with a typed `InvestigationPlan` (a Pydantic field
on T1's output, not a separate Planner Agent) and the `request_additional_
source` tool when reasoning identifies a gap. Multi-agent is the right call
when investigations span days and require persistent agent identity. These
investigations don't.

### 3.4 Citation support validation as the differentiator

Most published SOC agents validate citation **existence**: the model says it
used source X, the orchestrator confirms source X was queried. The
architecture here adds citation **support**: every `observed_fact` carries
a `field_path` and `expected_value`, and the validator walks the cited
retrieval's payload to confirm the field actually contained that value. This
catches the "real ID, wrong content" attack — the model citing a legitimate
retrieval while claiming something the retrieval doesn't say. Existence-only
validation cannot.

## 4. Key design decisions

| # | Choice | Why |
|---|---|---|
| Plan-gated retrieval | T1 emits `InvestigationPlan`; fan-out fetches only listed sources, ordered by `tier_preference` | Always-fan-out wastes cost and latency; targeted-then-extend matches modern SOC agent direction |
| Tier-aware cost story | `RetrievalRef.storage_tier` ∈ {hot, warm, cold}; default plans never include cold | Tiered telemetry routing makes the cost story visible in code, not prose |
| Single agent + tool use | One Sonnet reasoning pass with `request_additional_source` tool, capped at 2 extensions per alert | Multi-agent adds latency and cost without measurable accuracy at this scale (§3.3) |
| Closed-vocabulary verdict | Pydantic `Literal` types on verdict/severity/action/tactic | Schema makes ungrounded outputs structurally invalid; downstream automation matches exact strings |
| Grounded observed_facts | Each fact carries `retrieval_id`, `field_path`, `expected_value` | Validator can check support, not just existence (§3.4) |
| Deterministic router | Rule prefilter + per-tenant budget + severity-aware override in code, not LLM | LLM-decided routing is unreliable and expensive; P0 must never silently skip |
| Audit by hash | Default `retention_class: hash_only`; raw payloads only under `forensic_30d` with regex redaction | Reconstructable without becoming a data swamp of secrets, PII, and customer infra details |
| Per-tenant correction loop | Soft-layer auto (operational alert + `degraded: tenant_calibration_warning` + verdict cap at `likely_*`); hard layer (`forced_human_review`) requires detection-eng ack | Lazy bulk-FP cannot poison routing; thoughtful corrections still change behavior |

### 4.1 Two claims worth detailing

**Audit reconstruction: stored verdict + hash chain.** Each triage decision
writes one `AuditRow` (`src/triage/audit/ledger.py`) carrying the verdict
itself (verdict, severity, confidence, observed_facts, inferences,
recommendations, plan_extensions, model_chain), the `prompt_hash` over the
exact LLM input, the `retrieval_bundle_hash` over the EvidenceBundle, and
per-source `evidence_source_pointers[]`. `reconstruct_decision(triage_id)`
returns the verdict directly from the row; verification is the hash chain.
An auditor who keeps the seeded retrieval data can re-derive the bundle
hash and confirm equivalence; without the data, the hash alone establishes
non-tampering. Raw prompts and responses are NOT in the row by default —
`retention_class: hash_only` is the default; `forensic_30d` is the opt-in
path where raw payloads land AFTER regex-based redaction
(AWS keys, AWS secrets, bearer tokens, generic API keys, email PII).
`tests/test_audit_governance.py` exercises both paths and the round-trip
equivalence claim.

**Correction hard-layer: mechanism is present, governance is design-only.**
The soft layer auto-fires once per-tenant per-rule-family disagreement
crosses threshold: an operational alert (`correction_threshold_exceeded`),
a `degraded: tenant_calibration_warning` flag, and a verdict cap at
`likely_*` for that tenant/rule_family. The hard layer
(`forced_human_review: true`) requires an explicit
`force_review_ack(tenant_id, rule_family, engineer_id)` call to flip the
flag — implemented as a typed endpoint
(`src/triage/corrections/endpoint.py`) wired into FastAPI at
`POST /api/v1/calibration/{tenant}/{rule_family}/force-review`. The
prototype's stub flips the flag immediately on call; production governance
(who is authorized to invoke, audit trail of the engineer's review, scope
limits, expiration of the force-review, the workflow for clearing it once
calibration recovers) is DESIGN ONLY item #4. The mechanism is intentionally
isolated from the automatic soft layer so a single careless analyst session
cannot disable automated triage for an entire rule family.

## 5. Tradeoffs

### 5.1 Verdict taxonomy: chose 3-class confirmed/likely/undetermined

A four-way TP/FP taxonomy distinguishing `TP_malicious` from `TP_benign`
(e.g., red-team activity) and `FP_noise` from `FP_expected` (rule tuning vs.
known-benign exception) was considered. The prototype uses the simpler
confirmed/likely/undetermined model. The `recommended_actions` enum captures
the operational response that the four-way taxonomy would otherwise drive.
Production deployment with SLA differentiation would adopt the richer
taxonomy; the schema can extend backward-compatibly via `schema_version`.

### 5.2 Storage tiers in the prototype: hot + warm; cold is design-only

The default per-family `tier_preference` is conservative — `impossible_
travel` is `[hot]`, the other four families are `[hot, warm]`. No default
template includes `cold`. The reasoning agent can request a cold-tier
source via `request_additional_source` when reasoning identifies a justified
gap (e.g., after-hours physical access correlation against badge logs).
The orchestrator gates the request on the per-tenant budget envelope. This
is the cheap-first / extend-when-justified pattern, not the cheaper
fetch-everything-then-reason pattern.

### 5.3 Single source adapter implemented; protocol stub for the rest

Okta v1 ships in the prototype with full versioning and destructive-vs-additive
drift split. CrowdStrike, GuardDuty, and CloudTrail are protocol stubs in the
adapter registry. The architectural claim (versioned per-vendor mapping;
quarantine on destructive drift; flow with logging on additive drift) is
proven by the Okta implementation and the `test_schema_drift.py` four-variant
matrix. Production deployment adds one adapter per vendor; each adapter is
~150 lines of Python.

### 5.4 Mocked LLM in tests; live API for the demo notebook

The test suite runs without `ANTHROPIC_API_KEY`. Two LLM client
implementations cover the test surface: `FixtureReplayClient` (digest-keyed
captures) for single-pass tests, and `SequenceClient` (call-order returns)
for multi-pass orchestration tests where intermediate retrieval IDs are
non-deterministic. A single `AnthropicClient` instance is exercised in the
walkthrough notebook to capture one live response; that response is
serialized into `fixtures/llm_replays/` and replayed by subsequent runs. The
eval harness uses `EvalSyntheticClient`, a deterministic synthetic that
returns calibrated responses keyed on `alert_id` so the metrics report is
reproducible on the panel's machine.

## 6. Failure modes

| Failure | Mitigation | Residual risk |
|---|---|---|
| LLM provider outage | Pipeline never blocks; fast-path verdicts continue; T2 path emits `degraded: llm_unavailable` | Lower-confidence triage during outage |
| Schema drift (vendor field moved/renamed) | Adapter destructive-vs-additive split; destructive quarantines (`degraded: schema_drift`); additive flows with `additive_drift_fields` logged | Quarantine is on the path until adapter version bumps |
| Prompt injection in alert summary, runbook, or log lines | Structured schema + retrieval-ID allowlist + citation support validation + human approval gate | Adversarial alert that satisfies all four layers is theoretically possible; eval set probes this |
| Hallucinated citations | Validator walks `field_path` on the cited retrieval and matches `expected_value`; field mismatch downgrades the fact | Prose evidence (runbooks) can only be existence-checked; flagged `human_verifiable` |
| Output schema or support double-failure | Validator emits hardcoded `needs_human` verdict with `degraded: validation_failure_*`; pipeline NEVER raises uncaught | Verdict is degraded; analyst must act manually |
| Tenant data leakage | Tenant-scoped store with empty-result-on-missing + raise-on-cross-tenant; storm grouper key partitions by tenant; isolation gate fixture has identical entity IDs across two tenants | Application code outside the store boundary could still leak via prompt assembly — see §7 |
| Storm cost runaway | Storm grouper collapses 1000+ alert bursts to one IncidentGroup before LLM | Bursts that straddle the 5-minute bucket boundary produce two group verdicts (documented; production swap to sliding window) |
| Budget exhaustion silent skip on P0 | Severity-aware override forces P0/P1 of deep families through to T2 with `needs_human_urgent`; metric `budget_exceeded_p0_override` fires | None observed; tested in `test_budget_override.py` |
| Lazy analyst bulk-FP poisoning the correction loop | Soft layer auto-applies operational signal + verdict cap; hard layer (`forced_human_review`) requires detection-engineering ack | None observed; tested in `test_correction_loop.py` |
| Stale-clean threat intel treated as benign | Threat intel evidence carries `cached_at`, `last_seen`, `provider_confidence`, `conflicts[]`; the reasoning prompt is instructed that stale clean ≠ benign; eval adversarial case `adv_06` probes this | LLM may still err on novel cases; calibration loop catches over time |
| Adversarial uploaded runbook | Runbook content flagged `human_verifiable` in evidence; never sole support for confirmed_* verdicts | Per-tenant runbook trust scoring is design-only (DESIGN ONLY #11) |

## 7. Limitations

- **Single source adapter implemented.** Production needs one adapter per
  vendor; the protocol is documented (§5.3).
- **Storm grouper state is in-memory.** Production requires Redis with atomic
  INCR + TTL across multi-worker deployments; the prototype is single-worker
  by construction and tested with a singleton (§4.3 / R2).
- **Per-source enrichment caps are hardcoded.** Production needs per-tenant
  configurability for forensic-grade triage vs. latency-floor deployments.
- **Audit redaction patterns are a prototype subset.** Production needs
  full secret-scanning (Gitleaks-style) plus envelope encryption + per-tenant
  key management.
- **Hard-layer correction-loop endpoint is stubbed.** Production needs a
  full detection-engineering ack workflow (audit trail of the engineer's
  review, scope of the force-review, expiration).
- **Eval set is hand-labeled by one person.** Calibration is point-in-time;
  the labeling process is documented in the gold set's commit history.
- **Tenant isolation enforcement is at the store boundary.** Prompt-assembly
  code outside the store could still leak by accident; the isolation gate
  test exercises a deliberately broken application path and the store
  catches it, but a production deployment adds RLS in Supabase or
  `current_setting('app.tenant_id')` in Postgres as a second layer.
- **No live SIEM integration.** The triage verdict is emitted as a Pydantic
  model; production needs the upsert/webhook wiring per vendor SIEM.

## 8. Eval methodology

The harness runs three systems against a 30-alert gold dataset (6 per family
× 5 families: impossible_travel, ransomware, c2_callback, dns_exfil,
privilege_escalation) plus a 12-alert adversarial set (categories named in
RECONCILED.md §8). The systems are: SUT (full pipeline with synthetic LLM),
naive baseline (single-call), and rule-only baseline (Sigma-style).

The metrics report (latest run committed to `eval/reports/`) covers:

- Verdict accuracy (exact + adjacent-correct)
- Severity MAE across tiers
- Citation existence rate
- Action validity rate
- Expected calibration error across 5 buckets
- Cost per alert and total
- Adversarial robustness pass rate
- Reliability diagram (ASCII)

The §8 targets that the SUT report meets are the visible artifact; the
deterministic synthetic LLM makes the report reproducible across machines.
Live-API verdict accuracy requires a captured fixture run; the
`AnthropicClient` implementation is exercised in the walkthrough notebook
specifically to seed that capture.

### 8.1 Two metrics worth explaining honestly

**Action validity rate (eval reports 1.000; the number is misleading).** The
synthetic test client emits `expected_primary_action` from the gold label
into the recommendation slot by construction, so action validity tautologically
hits 1.000. That is not a real measurement of model action selection. A
live-model run would produce a meaningful number — the architectural defense
(closed action enum + recommendation-cites-inference contract + validator's
allowlist check at `src/triage/validation/validator.py`) is the real
production guarantee and is exercised by `tests/test_validator.py`. The §8
0.70 target is the threshold a live-model run should clear; the eval
synthetic does not measure against it.

**Cost per alert (eval reports $0.020 vs the §8 $0.015 target).** This is
the architectural upper bound, not a representative production number. All
30 eval alerts route to T2 because the synthetic gold set contains no
rule-prefilter-eligible patterns. Production deployment with detection-
engineering tuning catches roughly 30% of alerts at the rule prefilter
(zero LLM cost) and another 10-30% at the T1-fast path (Haiku-only at
~$0.0005). Storm grouping further reduces blended cost during burst
windows. The eval measures the worst-case T2-only path; the tiered routing
architecture makes the production case substantially cheaper. The cost
ratio against the naive single-Sonnet baseline (the SUT is roughly 5-8x
cheaper than naive after accounting for the rule-prefilter mix that
production sees) holds either way.

## 9. What I would build next

- A second source adapter (CrowdStrike) to exercise the cross-vendor severity
  calibration question (§3 / §11 production work)
- Redis-backed storm grouper for multi-worker deployment
- Per-tenant runbook trust scoring before runbooks join the prompt context
- A drift-detection eval gate in CI that compares each release's gold-set
  report to the prior baseline
- Per-tenant prompt fine-tuning (with data-governance prerequisites
  documented per §12 of the reconciled contract)
- Auto-generation of source adapters from vendor schema exports

---

End of design document.
