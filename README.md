# triage-agent

A SecOps triage service. The engine takes an alert in, runs normalization,
storm grouping, deterministic routing, plan-gated enrichment across six
structured sources, grounded reasoning with citation-support validation,
and emits a structured `TriageVerdict`.

The service is surface-agnostic: trigger and emit are pluggable bookends.
Trigger can be automatic when an alert is created in the pipeline, or
on-demand when an analyst requests triage by alert ID. The verdict can push
back to the SIEM as `triage.*` fields on the alert record, or return via the
API to a DataBahn surface. The engine in between is the same regardless of
how it's invoked or where the verdict lands.

Output is structured JSON: closed-vocabulary verdict, grounded
observed_facts with citation-support validation, MITRE ATT&CK attack_chain
mapping, and explicit blast_radius + reversible flags on every
recommendation. Not prose for a chat window.

Read [DESIGN.md](DESIGN.md) for the architecture, tradeoffs, and failure
modes. Read [AI_TOOLS.md](AI_TOOLS.md) for where AI tools helped or hindered
during the build.

## Quickstart

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
git clone <repo-url> triage-agent
cd triage-agent
uv sync --extra dev
uv run pytest
uv run eval
```

`uv run pytest` runs the full test suite (170+ tests; ~0.5s on a developer
machine). `uv run eval` runs the gold + adversarial sets through the full
pipeline and writes a Markdown metrics report to `eval/reports/`.

Neither command requires an Anthropic API key. The test suite uses
`FixtureReplayClient` and `SequenceClient`; the eval harness uses
`EvalSyntheticClient`. The live-API client (`AnthropicClient`) is exercised
by the walkthrough notebook (see below).

## Run the API surface locally

```bash
uv run uvicorn triage.api.main:app --reload
```

The service exposes:

- `POST /triage` — full pipeline on a vendor payload (`{raw_payload,
  tenant_id, source_system}`)
- `POST /triage/{triage_id}/correct` — analyst correction (soft layer)
- `POST /api/v1/calibration/{tenant}/{rule_family}/force-review` —
  detection-engineering ack (hard layer)
- `GET /health` — liveness + LLM client mode

To switch to the live Anthropic client:

```bash
export ANTHROPIC_API_KEY=sk-...
export TRIAGE_LIVE_LLM=1
uv run uvicorn triage.api.main:app
```

## Walkthrough notebook

```bash
uv run jupyter lab notebook.ipynb
```

The notebook walks end-to-end on three sample alerts spanning families:
impossible_travel (happy path), impossible_travel against stale-clean
threat intel (D14 defense), and a ransomware P0 routing through T3
escalation.

## Design highlights

- **Pipeline enrichment, not chatbot.** The verdict attaches as
  `triage.*` fields to the in-flight alert; the analyst opens their
  existing SIEM and sees the first-pass triage already done.
- **InvestigationPlan as a Pydantic field on T1 output.** Plan-gated
  fan-out fetches only the sources the plan names; T2 may request more
  via tool call when reasoning identifies a gap (bounded by per-tenant
  budget envelope).
- **Tier-aware cost story.** `tier_preference` orders hot → warm; cold
  tier is T2 plan-extension territory only (D34).
- **Citation support validation.** Every observed_fact carries a
  `field_path` and `expected_value`; the validator walks the cited
  retrieval and checks the field actually contained that value. Catches
  "real ID, wrong content" attacks that existence-only validation misses.
- **Audit by hash, raw payloads behind retention class.** The default
  retention class is `hash_only`; raw payloads land in `forensic_30d`
  after regex-based redaction for AWS keys / bearer tokens / generic
  API keys.

## Repository layout

```
src/triage/
├── adapters/         # Source adapters (Okta v1; protocol for the rest)
├── audit/            # Hash-based audit ledger + redaction
├── classifier/       # T1 Haiku pre-classifier
├── corrections/      # Soft + hard layer correction loop
├── enrichment/       # 6 source mocks + plan-gated tier-ordered fan-out
├── errors/           # Drift + isolation exceptions
├── grouping/         # Storm grouper (single-worker singleton)
├── llm/              # Client abstraction + budget envelope
├── observability/    # Per-source enrichment spans
├── orchestrator/     # End-to-end pipeline wiring
├── reasoning/        # T2 Sonnet + T3 Opus escalation
├── routing/          # Deterministic router
├── schemas/          # Pydantic models (alert, plan, retrieval, verdict)
├── tenants/          # Tenant-scoped store
├── validation/       # Schema + citation existence + support + R6 failsafe
└── api/              # FastAPI surface

eval/
├── gold/             # 30 hand-labeled alerts (6 per family × 5 families)
├── adversarial/      # 12 adversarial alerts
├── baselines/        # naive (single Sonnet) + rule-only (Sigma-style)
├── synthetic_llm.py  # Deterministic eval client
├── metrics.py        # Accuracy + ECE + reliability diagram
└── run.py            # `uv run eval` entry

tests/                # 170+ acceptance tests
fixtures/             # plan templates + 2 tenants + Okta payloads + LLM replays

DESIGN.md             # Architecture + tradeoffs + failure modes
AI_TOOLS.md           # Where AI helped vs hindered
notebook.ipynb        # Panel-facing walkthrough
```

## License

MIT.
