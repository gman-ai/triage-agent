# triage-agent

A SecOps triage service. The engine takes an alert in, runs normalization,
storm grouping, deterministic routing, plan-gated enrichment across six
structured sources, grounded reasoning with citation-support validation,
and emits a structured `TriageVerdict`.

## Reviewer quickstart

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). No Anthropic API
key required.

```bash
uv sync
uv run demo     # one alert through T1 -> enrichment -> T2 -> validation -> verdict
uv run eval     # gold + adversarial sets; writes a report to eval/reports/
uv run pytest   # 179 tests in ~1.5s
```

Run `uv run eval` first on a fresh clone — one test asserts that a report
exists, so a `pytest`-first run will show that test skipped.

Tests use `FixtureReplayClient` and `SequenceClient`; eval and the default
local API use `EvalSyntheticClient` so review runs are deterministic and do
not require an API key. The live Anthropic path was exercised once and the
captured Opus response lives at
[`fixtures/llm_replays/cd8a1be0d7d1e45f1148e61c.json`](fixtures/llm_replays/cd8a1be0d7d1e45f1148e61c.json)
with `live_api: true`, `captured_at: 2026-06-16T04:29:49Z`, and real token
counts in the fixture metadata. The notebook's T3 cell replays that
captured response.

## What it is

The service is surface-agnostic: trigger and emit are pluggable bookends.
Trigger can be automatic when an alert is created in the pipeline, or
on-demand when an analyst requests triage by alert ID. The verdict can push
back to the SIEM as `triage.*` fields on the alert record, or return via the
API. Same engine, different bookends per deployment.

Output is structured JSON: closed-vocabulary verdict, grounded
observed_facts with citation-support validation, MITRE ATT&CK attack_chain
mapping, and explicit blast_radius + reversible flags on every
recommendation.

See [DESIGN.md](DESIGN.md) for the architecture and tradeoffs,
[ARCHITECTURE-DECISIONS.md](ARCHITECTURE-DECISIONS.md) for the numbered
commitment log, and [AI_TOOLS.md](AI_TOOLS.md) for how AI tools were used
during the build.

## Run the API surface locally

```bash
uv run uvicorn triage.api.main:app --reload
```

By default, the API uses deterministic synthetic LLM responses so `/triage`
works locally without `ANTHROPIC_API_KEY`. The live Anthropic client is
opt-in via the environment variables below.

The service exposes:

- `POST /triage` — full pipeline on a vendor payload (`{raw_payload,
  tenant_id, source_system}`)
- `POST /triage/{triage_id}/correct` — analyst correction (soft layer)
- `POST /api/v1/calibration/{tenant}/{rule_family}/force-review` —
  detection-engineering ack (hard layer)
- `GET /health` — liveness + LLM client mode

In another terminal, smoke-test the local API:

```bash
curl http://127.0.0.1:8000/health

uv run python -c 'import json; from pathlib import Path; payload=json.loads(Path("fixtures/okta/sample_v1_clean.json").read_text()); body={"raw_payload":payload,"tenant_id":"tenant_a","source_system":"okta"}; Path("/tmp/triage_api_smoke.json").write_text(json.dumps(body))'

curl -X POST http://127.0.0.1:8000/triage \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/triage_api_smoke.json
```

Expected: `/health` reports `llm_client_mode: synthetic`, and `/triage` returns a structured verdict for `okta_evt_clean_0001`.

To switch to the live Anthropic client:

```bash
export ANTHROPIC_API_KEY=sk-...
export TRIAGE_LIVE_LLM=1
uv run uvicorn triage.api.main:app
```

## Walkthrough notebook

[`notebook.ipynb`](notebook.ipynb) walks end-to-end on three sample alerts:
impossible_travel (happy path), impossible_travel against stale-clean
threat intel, and a ransomware P0 routing through T3 escalation. It renders
on GitHub directly; run locally with `uv run jupyter lab notebook.ipynb` to
re-execute the cells.

## Design highlights

- **Surface-agnostic triage service — trigger and emit are pluggable per
  deployment.** Automatic from the pipeline OR on-demand by alert ID; verdict
  pushes to the SIEM as `triage.*` fields OR returns via API. Same engine
  regardless of how invoked or where the verdict lands.
- **InvestigationPlan resolved deterministically per `(rule_family, severity_hint)`.**
  T1 is a YAML lookup, not an LLM call — detection-engineering policy stays
  with detection engineers. Plan-gated fan-out fetches only the sources the
  plan names; T2 may request more via tool call when reasoning identifies
  a gap (bounded by per-tenant budget envelope).
- **Tier-aware cost story.** `tier_preference` orders hot → warm; cold
  tier is opt-in via T2 plan extension only, never the default.
- **Citation support validation.** Every observed_fact carries a
  `field_path` and `expected_value`; the validator walks the cited
  retrieval and checks the field actually contained that value. Catches
  "real ID, wrong content" attacks that existence-only validation misses.
- **Audit by hash, raw payloads behind retention class.** The default
  retention class is `hash_only`; raw payloads land in `forensic_30d`
  after regex-based redaction for AWS keys, AWS secrets, bearer tokens,
  generic API keys, and email PII.

## Documentation

- [`DESIGN.md`](DESIGN.md) — architecture, tradeoffs, failure modes
- [`ARCHITECTURE-DECISIONS.md`](ARCHITECTURE-DECISIONS.md) — numbered architecture decisions (D1–D34): the choice, the rationale, and what was rejected
- [`AI_TOOLS.md`](AI_TOOLS.md) — how AI tools were used during planning and implementation
- [`notebook.ipynb`](notebook.ipynb) — three-scenario walkthrough

## Repository layout

```
src/triage/
├── adapters/         # Source adapters (Okta v1; protocol for the rest)
├── audit/            # Hash-based audit ledger + redaction
├── classifier/       # T1 deterministic plan resolver (YAML lookup)
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
├── validation/       # Schema + citation existence + support + terminal failsafe
└── api/              # FastAPI surface

eval/
├── gold/             # 30 hand-labeled alerts (6 per family × 5 families)
├── adversarial/      # 12 adversarial alerts
├── baselines/        # naive (single Sonnet) + rule-only (Sigma-style)
├── synthetic_llm.py  # Deterministic eval client
├── metrics.py        # Accuracy + ECE + reliability diagram
└── run.py            # `uv run eval` entry

tests/                # ~180 tests covering adapters, routing, validation, audit, API
fixtures/             # plan templates + 2 tenants + Okta payloads + LLM replays

DESIGN.md                    # Architecture + tradeoffs + failure modes
ARCHITECTURE-DECISIONS.md    # Numbered architecture decisions (D1–D34)
AI_TOOLS.md                  # How AI tools were used during the build
notebook.ipynb               # End-to-end walkthrough
```

## License

MIT.
