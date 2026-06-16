"""LLM client abstraction + fixture-replay mock per Day 3 directive.

Production deployment routes against Anthropic's API; the prototype's test
suite never calls the live API (D2: `git clone && uv sync && uv run pytest`
runs on the panel's machine without an injected key).

This module ships two implementations of the LLMClient Protocol:

  * `AnthropicClient` — production shape, expects ANTHROPIC_API_KEY in env;
     not exercised by the test suite. The notebook walkthrough on Day 5 makes
     one demo call against this client and captures the response as a
     fixture; tests replay from the fixture.
  * `FixtureReplayClient` — deterministic. Hashes the request and looks the
     hash up under `fixtures/llm_replays/<digest>.json`. Found → returns the
     recorded response. Missing → raises with a clear message about how to
     capture the fixture. Tests use this client exclusively.

The hashing input is stable across runs: model + system + tool defs + each
message's role and serialized content. Tool defs are sorted by name; messages
serialized in order.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

FIXTURE_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "llm_replays"


@dataclass
class LLMRequest:
    model: str
    system: str
    messages: list[dict]
    tools: list[dict] = field(default_factory=list)
    response_format: dict | None = None
    max_tokens: int = 2048
    temperature: float = 0.0

    def digest(self) -> str:
        canonical = {
            "model": self.model,
            "system": self.system,
            "messages": self.messages,
            "tools": sorted(self.tools, key=lambda t: t.get("name", "")),
            "response_format": self.response_format,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        blob = json.dumps(canonical, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()[:24]


@dataclass
class LLMResponse:
    content: str
    stop_reason: str = "end_turn"
    tool_calls: list[dict] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    model: str = ""


class FixtureMissingError(Exception):
    def __init__(self, digest: str, model: str) -> None:
        self.digest = digest
        self.model = model
        super().__init__(
            f"LLM fixture missing: model={model} digest={digest}. "
            f"Record by capturing the API response to "
            f"fixtures/llm_replays/{digest}.json"
        )


class LLMClient(Protocol):
    def complete(self, request: LLMRequest) -> LLMResponse: ...


class FixtureReplayClient:
    """Reads recorded responses keyed on request digest.

    Used by every Day 3+ test. The fixture file shape is:

        {
            "content": "<JSON or prose>",
            "stop_reason": "end_turn" | "tool_use",
            "tool_calls": [{"name": "...", "input": {...}, "id": "..."}],
            "tokens_in": int,
            "tokens_out": int,
            "cost_usd": float,
            "model": "<model id>"
        }
    """

    def __init__(self, fixture_dir: Path | None = None) -> None:
        self._dir = fixture_dir or FIXTURE_DIR

    def complete(self, request: LLMRequest) -> LLMResponse:
        digest = request.digest()
        fixture_path = self._dir / f"{digest}.json"
        if not fixture_path.exists():
            raise FixtureMissingError(digest=digest, model=request.model)
        with fixture_path.open() as fh:
            payload = json.load(fh)
        return LLMResponse(
            content=payload.get("content", ""),
            stop_reason=payload.get("stop_reason", "end_turn"),
            tool_calls=list(payload.get("tool_calls", [])),
            tokens_in=int(payload.get("tokens_in", 0)),
            tokens_out=int(payload.get("tokens_out", 0)),
            cost_usd=float(payload.get("cost_usd", 0.0)),
            model=payload.get("model", request.model),
        )


class SequenceClient:
    """Returns a pre-loaded sequence of responses in call order.

    For tests of multi-pass flows (e.g. T2 plan extension) where pre-computing
    the digest of the second request is brittle because the bundle contents
    depend on the orchestrator's intermediate calls. Test seeds the sequence;
    SequenceClient returns them in order without inspecting the request.
    """

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self._cursor = 0
        self.calls_seen: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls_seen.append(request)
        if self._cursor >= len(self._responses):
            raise IndexError(
                f"SequenceClient exhausted after {self._cursor} calls; "
                f"test seeded only {len(self._responses)} responses."
            )
        response = self._responses[self._cursor]
        self._cursor += 1
        return response


class AnthropicClient:
    """Live Anthropic client. Not exercised by tests.

    Day 5's notebook uses this for one demo run; the resulting response is
    serialized into the fixture directory keyed on its request digest, and
    tests then replay it.
    """

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    def complete(self, request: LLMRequest) -> LLMResponse:  # pragma: no cover
        # Import here so the test suite never imports the SDK.
        import anthropic  # type: ignore[import-not-found]

        client = anthropic.Anthropic(api_key=self._api_key)
        kwargs: dict[str, Any] = dict(
            model=request.model,
            system=request.system,
            messages=request.messages,
            max_tokens=request.max_tokens,
        )
        # Some Anthropic models (e.g. claude-opus-4-7 / 4-8) reject the
        # `temperature` parameter as deprecated. Omit when the request
        # carries the deterministic default; pass through for non-zero
        # values where a caller is intentionally sampling.
        if request.temperature and request.temperature > 0.0:
            kwargs["temperature"] = request.temperature
        if request.tools:
            kwargs["tools"] = request.tools
        result = client.messages.create(**kwargs)
        return LLMResponse(
            content=_join_anthropic_text_blocks(result.content),
            stop_reason=str(result.stop_reason or "end_turn"),
            tool_calls=_extract_tool_calls(result.content),
            tokens_in=int(result.usage.input_tokens),
            tokens_out=int(result.usage.output_tokens),
            cost_usd=0.0,
            model=str(result.model),
        )


def _join_anthropic_text_blocks(blocks: list) -> str:  # pragma: no cover
    parts: list[str] = []
    for b in blocks:
        if getattr(b, "type", None) == "text":
            parts.append(b.text)
    return "".join(parts)


def _extract_tool_calls(blocks: list) -> list[dict]:  # pragma: no cover
    out: list[dict] = []
    for b in blocks:
        if getattr(b, "type", None) == "tool_use":
            out.append({"name": b.name, "input": b.input, "id": b.id})
    return out
