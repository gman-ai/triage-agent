# Triage Agent — DESIGN

A per-tenant SecOps alert triage service that takes an alert in, runs
grounded reasoning over cross-source context, and emits a structured
`TriageVerdict`. Surface-agnostic by design: trigger and emit are pluggable
bookends; the engine is the same regardless of how it is invoked or where
the verdict lands.

This document is the architectural narrative. The structured commitment log
— each load-bearing decision with rationale and rejected alternatives —
lives in [`ARCHITECTURE-DECISIONS.md`](ARCHITECTURE-DECISIONS.md).

**TL;DR.** Per-tenant SecOps triage engine: deterministic T1 plan resolution,
tier-ordered enrichment, T2 Sonnet reasoning with cited evidence, T3 Opus
escalation for low-confidence critical cases, schema validation, and audit
ledger.

| Submission signal | Result |
|---|---:|
| Tests | 179 passing |
| Eval gates | PASS |
| SUT exact match | 0.933 |
| Calibration error | 0.085 ECE |
| Adversarial pass rate | 1.000 |
| LLM control-plane calls | 0 |

**Reader path.** The brief maps directly to §1.1 assumptions, §2 architecture,
§5 tradeoffs, and §6–§7 failure modes and limitations. The remaining sections
document validation evidence (§3, §4) and eval methodology (§8).

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
(pipeline integration or analyst-initiated) and emit (push back to SIEM or
return to API caller) bookends are pluggable per customer deployment shape;
the architecture, the tests, and the cost story are the same regardless. The
§2 flow diagram shows both paths.

**Structural advantage — the pipeline-data edge.** Because DataBahn sits in
the customer's telemetry path, the engine has correlation surface a
SIEM-resident tool does not. The SIEM can only query what it indexed. The
engine can query what DataBahn routed, including data that went to cold
storage tiers (compliance retention) instead of the expensive SIEM index.
A generic SOC AI tool sees what the SIEM saw; this engine sees what the
pipeline saw.

**Cost is bounded by a four-layer cascade**, each catching alerts that
don't need deeper reasoning:

1. **Rule prefilter** — known-FP and known-TP patterns at zero LLM cost
2. **Storm grouping** — burst-window deduplication once the per-key
   threshold trips; the first alerts that share a key still route
   individually, then subsequent member alerts attach to the group and
   bypass the LLM tier
3. **Deterministic plan lookup at T1** — YAML-resolved investigation
   plan keyed on `(rule_family, severity_hint)`; zero LLM cost
4. **T2 Sonnet** — only when evidence-backed reasoning over the enriched
   bundle is needed
5. **T3 Opus** — only for critical low-confidence cases (P0/P1 in deep
   families); self-consistency sample 3

This is the cost discipline. Only the alerts that need deep reasoning
get it; the rest get the right cheaper tier. LLMs enter the system only
where probabilistic judgment over evidence matters; routing and plan
selection are detection-engineering policy encoded in YAML.

**The agent does NOT:**

- Replace the analyst (decision authority stays human)
- Auto-remediate (`automatable: false` default for all recommendations)
- Surface raw LLM prose to the analyst (output is typed JSON consumed by
  the existing SIEM workbench)
- Operate as a conversational chatbot (one-shot triage returns a structured
  result; not multi-turn dialog)

### 1.1 Key assumptions

Four assumptions are load-bearing. If any is wrong for a deployment, the
architecture changes.

- **The analyst stays the decision-maker.** Triage's bottleneck is
  cross-source context gathering, not alert comprehension. The verdict
  schema separates `recommended_actions` (advisory) from any concept of
  auto-execution; every recommendation ships `automatable: false`. The
  audit ledger captures the analyst's correction rather than treating
  the engine's verdict as final.

- **Pipeline position is the data advantage.** The engine assumes read
  access to telemetry already routed through the pipeline, including
  cold-tier history a SIEM-resident tool can't reach cheaply. The
  three-tier storage model (hot / warm / cold) is the architectural
  expression of this; cold is opt-in via T2 plan extension, never the
  default.

- **Alert investigations are bounded.** Most alerts need one focused
  evidence-gathering loop, not a long-running multi-agent investigation.
  The engine uses one Sonnet reasoning pass with a
  `request_additional_source` tool, capped at two plan extensions. If
  alerts required cross-investigation coordination, a supervisor pattern
  would become correct.

- **Routing is deterministic, not learned.** First-pass tier selection
  is YAML-resolved plans plus severity-aware overrides in code. LLMs
  aren't trusted with control-plane decisions — which tier runs, which
  source fires, when to escalate — only with reasoning over the
  evidence those decisions surface.

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
T1 Deterministic Plan Resolver (YAML lookup keyed on rule_family + severity_hint)
   │ InvestigationPlan
   ▼
Deterministic Router (rule prefilter → severity/confidence/budget)
   │
   ├── rule_fast (no LLM)
   └── t2_standard / t2_urgent / t2_escalate_if_low_conf
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

**Return semantics differ per trigger.** On the pipeline-trigger path the
verdict can attach asynchronously to the SIEM alert via upsert or webhook,
so the analyst's view of the alert is not held up by a 15-40 second LLM
call. On the analyst-initiated path the API call returns the verdict
synchronously — the analyst is already waiting on that specific alert.
Same engine; different return semantics per bookend.

T3 Opus escalation fires when T2 returns `confidence < 0.6` AND `severity
in {P0, P1}` AND `rule_family in {ransomware, privilege_escalation,
data_exfil, dns_exfil}`. T3 is a terminal pass; no further plan extension.

## 3. Industry anchors

### 3.1 Standards and prior art

The investigation lifecycle follows NIST SP 800-61r3's detection → analysis →
containment-recommendation → post-incident framing. The verdict's `attack_chain`
field carries MITRE ATT&CK tactic and technique IDs (e.g., `TA0040`, `T1078`) so
downstream automation against tactic strings is trivial.

### 3.2 Why not a supervisor-worker architecture

LangGraph supervisor-worker architectures (e.g., the public SentinelFlow
project) place a primary agent over specialized worker subgraphs. For bounded
single-investigation alerts, the multi-agent shape adds orchestration latency
and cost without measurable accuracy gain at this scale. The architecture here
uses a single agent with a typed `InvestigationPlan` resolved deterministically
from `(rule_family, severity_hint)` against a YAML template registry, plus the
`request_additional_source` tool when reasoning identifies a gap. Multi-agent
is the right call when investigations span days and require persistent agent
identity; these don't.

### 3.3 Citation support validation as the differentiator

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
| Plan-gated retrieval | T1 selects `InvestigationPlan` via YAML lookup; fan-out fetches only listed sources, ordered by `tier_preference` | Always-fan-out wastes cost and latency; targeted-then-extend matches modern SOC agent direction; deterministic plan policy stays with detection engineering |
| Tier-aware cost story | `RetrievalRef.storage_tier` ∈ {hot, warm, cold}; default plans never include cold | Tiered telemetry routing makes the cost story visible in code, not prose |
| Single agent + tool use | One Sonnet reasoning pass with `request_additional_source` tool, capped at 2 extensions per alert | Multi-agent adds latency and cost without measurable accuracy at this scale (§3.2) |
| Closed-vocabulary verdict | Pydantic `Literal` types on verdict/severity/action/tactic | Schema makes ungrounded outputs structurally invalid; downstream automation matches exact strings |
| Grounded observed_facts | Each fact carries `retrieval_id`, `field_path`, `expected_value` | Validator can check support, not just existence (§3.3) |
| Deterministic router | Rule prefilter + per-tenant budget + severity-aware override in code, not LLM | LLM-decided routing is unreliable and expensive; P0 must never silently skip |
| Audit by hash | Default `retention_class: hash_only`; raw payloads only under `forensic_30d` with regex redaction | Reconstructable without becoming a data swamp of secrets, PII, and customer infra details |
| Per-tenant correction loop | Soft-layer auto (operational alert + `degraded: tenant_calibration_warning` + verdict cap at `likely_*`); hard layer (`forced_human_review`) requires detection-eng ack | Lazy bulk-FP cannot poison routing; thoughtful corrections still change behavior |

## 5. Tradeoffs

Each row names the choice, the alternative considered, and the reasoning. The
schema versions forward; richer taxonomies and additional adapters extend
backward-compatibly.

| Tradeoff | Choice | Alternative considered | Why |
|---|---|---|---|
| Verdict taxonomy | 3-class (confirmed/likely/undetermined) | 4-way TP_malicious / TP_benign / FP_noise / FP_expected | `recommended_actions` enum already captures the operational response the 4-way would drive; richer taxonomy extends backward-compatibly via `schema_version` if SLA differentiation needs it |
| Storage tiers | Hot + warm in default plans; cold via T2 plan extension | Always-include-cold by default | Cheap-first / extend-when-justified beats fetch-everything-then-reason; per-tenant budget gates the extension |
| Source adapters | Okta v1 full; CrowdStrike / GuardDuty / CloudTrail are protocol stubs | All-vendors-shipped | Versioning, destructive-vs-additive drift split, and the 4-variant drift matrix are proven by Okta + `test_schema_drift.py`; each additional adapter is ~150 lines |
| LLM in tests | `FixtureReplayClient` + `SequenceClient` for tests; `AnthropicClient` exercised once for the notebook capture | Live-API in every test | Test suite runs without `ANTHROPIC_API_KEY`; eval harness uses deterministic synthetic for reproducibility; one captured fixture proves the live-API path |

## 6. Failure modes

| Failure | Mitigation | Residual risk |
|---|---|---|
| LLM provider outage | Pipeline never blocks; fast-path verdicts continue; T2 path emits `degraded: llm_unavailable` | Lower-confidence triage during outage |
| Schema drift (vendor field moved/renamed) | Adapter destructive-vs-additive split; destructive quarantines (`degraded: schema_drift`); additive flows with `additive_drift_fields` logged | Quarantine is on the path until adapter version bumps |
| Prompt injection in alert summary, runbook, or log lines | Structured schema + retrieval-ID allowlist + citation support validation + human approval gate | Adversarial alert that satisfies all four layers is theoretically possible; eval set probes this |
| Hallucinated citations | Validator walks `field_path` on the cited retrieval and matches `expected_value`; field mismatch downgrades the fact | Prose evidence (runbooks) can only be existence-checked; flagged `human_verifiable` |
| Output schema or support double-failure | Validator emits hardcoded `needs_human` verdict with `degraded: validation_failure_*`; pipeline NEVER raises uncaught | Verdict is degraded; analyst must act manually |
| Tenant data leakage | Tenant-scoped store with empty-result-on-missing + raise-on-cross-tenant; storm grouper key partitions by tenant; isolation gate fixture has identical entity IDs across two tenants | Application code outside the store boundary could still leak via prompt assembly — see §7 |
| Storm cost runaway | Storm grouper collapses burst tails after the trip threshold (member alerts attach to an IncidentGroup and bypass LLM); the first alerts that share a key still route individually | Pre-trip alerts each pay one LLM round; bursts that straddle the 5-minute bucket boundary or vary IOC under the key produce additional group verdicts (production swap to sliding window + Redis backing) |
| Budget exhaustion silent skip on P0 | Severity-aware override forces P0/P1 of deep families through to T2 with `needs_human_urgent`; metric `budget_exceeded_p0_override` fires | None observed; tested in `test_budget_override.py` |
| Lazy analyst bulk-FP poisoning the correction loop | Soft layer auto-applies operational signal + verdict cap; hard layer (`forced_human_review`) requires detection-engineering ack | None observed; tested in `test_correction_loop.py` |
| Stale-clean threat intel treated as benign | Threat intel evidence carries `cached_at`, `last_seen`, `provider_confidence`, `conflicts[]`; the reasoning prompt is instructed that stale clean ≠ benign; eval adversarial case `adv_06` probes this | LLM may still err on novel cases; calibration loop catches over time |
| Adversarial uploaded runbook | Runbook content flagged `human_verifiable` in evidence; never sole support for confirmed_* verdicts | Per-tenant runbook trust scoring is design-only (DESIGN ONLY #11) |

## 7. Limitations

- **Single source adapter implemented.** Production needs one adapter per
  vendor; the protocol is documented in the §5 tradeoffs table.
- **Storm grouper state is in-memory.** Production requires Redis with atomic
  INCR + TTL across multi-worker deployments; the prototype is single-worker
  by construction and tested with a singleton.
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
privilege_escalation) plus a 12-alert adversarial set. The systems are: SUT
(full pipeline with synthetic LLM), naive baseline (single-call), and
rule-only baseline (Sigma-style).

The metrics report (regenerated under `eval/reports/` on every `uv run eval`) covers:

- Verdict accuracy (exact + adjacent-correct)
- Severity MAE across tiers
- Citation existence rate
- Action validity rate
- Expected calibration error across 5 buckets
- Cost per alert and total
- Adversarial robustness pass rate
- Reliability diagram (ASCII)

The targets that the SUT report meets are the visible artifact; the
deterministic synthetic LLM makes the report reproducible across machines.
Live-API verdict accuracy requires a captured fixture run; the
`AnthropicClient` implementation is exercised in the walkthrough notebook
specifically to seed that capture.

### 8.1 Known measurement limits

**Action validity rate (eval reports 1.000; misleading).** The synthetic test
client emits the gold label's `expected_primary_action` into the recommendation
slot by construction, so the metric measures the test client, not the model. A
live-model run produces the meaningful number; the structural defense (closed
action enum + recommendation-cites-inference contract + validator's allowlist
check) enforces correctness in production.

**Cost per alert ($0.020 vs $0.015 target).** This is the architectural upper
bound under the eval's T2-only routing mix, not a production projection. All 30
gold alerts route to T2 because none are rule-prefilter-eligible. Production
cost depends on prefilter coverage and burst characteristics. The independently
measurable claim — SUT is roughly 5-8x cheaper than the single-Sonnet naive
baseline — holds in this eval. Deterministic T1 adds zero LLM cost.

---

End of design document.
