"""Capture one live-API T3 escalation response as a replay fixture.

Per DESIGN.md §4.4: the test suite runs without `ANTHROPIC_API_KEY` and uses
fixture-replay; one live capture seeds the replay so `uv run pytest` is
reproducible across machines without anyone paying for API calls.

Usage:
    uv run python scripts/capture_t3_fixture.py

Reads ANTHROPIC_API_KEY from environment OR from `.env` at the repo root.
Fires one call against the live Anthropic API for the canonical T3
escalation request. Writes the response to
`fixtures/llm_replays/<digest>.json` with the standard schema plus two
extra markers:
  * `captured_at`: ISO-8601 timestamp when the live call was made
  * `live_api`: true

The fixture file's content is what `FixtureReplayClient` consumes; the
captured_at + live_api markers are forensic metadata an auditor uses to
confirm a fixture is real (not a hand-shaped placeholder).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = REPO_ROOT / ".env"
FIXTURE_DIR = REPO_ROOT / "fixtures" / "llm_replays"

# Anthropic published pricing as of build date, USD per million tokens.
# Update this table when capturing against a different model snapshot.
_MODEL_PRICING_PER_MTOK = {
    # Opus 4.x family
    "claude-opus-4-7": (15.00, 75.00),
    "claude-opus-4-8": (15.00, 75.00),
    # Sonnet 4.6
    "claude-sonnet-4-6": (3.00, 15.00),
    # Haiku 4.5
    "claude-haiku-4-5-20251001": (0.25, 1.25),
}


def _cost_for(model: str, tokens_in: int, tokens_out: int) -> float:
    if not model:
        return 0.0
    for prefix, (in_per_m, out_per_m) in _MODEL_PRICING_PER_MTOK.items():
        if model.startswith(prefix):
            return round(
                (tokens_in * in_per_m + tokens_out * out_per_m) / 1_000_000, 6
            )
    return 0.0


def _load_env_file(path: Path) -> None:
    """Minimal .env loader. KEY=VALUE per line; ignores comments + blanks."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _build_canonical_t3_request():
    """Build the exact T3 request the notebook walkthrough cell would fire.

    Kept in sync with the notebook's escalate_to_t3 invocation so the
    captured fixture replays cleanly when the notebook's third demo cell
    runs through SequenceClient against the same alert+plan+bundle shape.
    """
    from triage.enrichment.base import SourceQuery
    from triage.enrichment.fanout import build_default_registry, run_fanout
    from triage.reasoning.escalation import _build_t3_request
    from triage.schemas.alert import Asset, CanonicalAlertEvent
    from triage.schemas.plan_loader import PlanTemplateRegistry

    alert = CanonicalAlertEvent(
        tenant_id="tenant_a",
        alert_id="nb_demo_03",
        source_system="crowdstrike",
        source_adapter_version="crowdstrike_v1",
        rule_id="cs.ransomware.v2",
        rule_family="ransomware",
        received_at=datetime(2026, 6, 17, 14, 32, 11, tzinfo=UTC),
        detected_at=datetime(2026, 6, 17, 14, 32, 10, tzinfo=UTC),
        severity_hint="P0",
        primary_assets=[
            Asset(asset_id="srv_billing_01", asset_type="service", tenant_id="tenant_a")
        ],
        summary="Mass file rename + entropy spike on billing host",
    )
    registry = PlanTemplateRegistry()
    plan = registry.build_plan("ransomware", "P0")
    sources = build_default_registry()
    query = SourceQuery(
        tenant_id="tenant_a",
        alert_id=alert.alert_id,
        entity_id="srv_billing_01",
        ioc=None,
        extra={"rule_family": "ransomware"},
    )
    bundle = run_fanout(plan, query, sources)
    return _build_t3_request(alert, plan, bundle)


def main() -> int:
    _load_env_file(ENV_PATH)
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "[capture] ANTHROPIC_API_KEY not in env and not in .env at "
            f"{ENV_PATH}. Set it, then re-run.",
            file=sys.stderr,
        )
        return 1

    from triage.llm.client import AnthropicClient

    request = _build_canonical_t3_request()
    digest = request.digest()
    print(f"[capture] firing live T3 request, digest={digest} model={request.model}")
    started_at = datetime.now(UTC)
    client = AnthropicClient(api_key=api_key)
    response = client.complete(request)
    captured_at = datetime.now(UTC)

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    fixture_path = FIXTURE_DIR / f"{digest}.json"
    computed_cost = _cost_for(response.model, response.tokens_in, response.tokens_out)
    cost_usd = response.cost_usd if response.cost_usd else computed_cost
    fixture_payload = {
        "content": response.content,
        "stop_reason": response.stop_reason,
        "tool_calls": response.tool_calls,
        "tokens_in": response.tokens_in,
        "tokens_out": response.tokens_out,
        "cost_usd": cost_usd,
        "cost_computed_from": "tokens_in/out * published anthropic pricing",
        "model": response.model,
        "captured_at": captured_at.isoformat(),
        "live_api": True,
        "started_at": started_at.isoformat(),
        "latency_ms": int((captured_at - started_at).total_seconds() * 1000),
    }
    fixture_path.write_text(json.dumps(fixture_payload, indent=2, sort_keys=True))
    print(f"[capture] wrote {fixture_path}")
    print(f"[capture] tokens_in={response.tokens_in} tokens_out={response.tokens_out}")
    print(f"[capture] latency_ms={fixture_payload['latency_ms']}")
    print(f"[capture] response model={response.model}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
