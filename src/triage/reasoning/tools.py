"""T2 tool definitions per RECONCILED §5.1 + R8.

T2's only mutating tool is `request_additional_source` — and even that does
NOT mutate the world. It signals the orchestrator to fetch an additional
enrichment source (subject to budget + tier policy) and append the result
to the evidence bundle for the next reasoning pass.

D9 / §4.4: T2 cites retrieval_ids from the bundle the orchestrator
generated. T2 never mints retrieval_ids; the validator rejects any cited ID
that isn't in the allowlist.
"""

from __future__ import annotations

from typing import Any

REQUEST_ADDITIONAL_SOURCE_TOOL: dict[str, Any] = {
    "name": "request_additional_source",
    "description": (
        "Request that an additional enrichment source be fetched and appended "
        "to the evidence bundle. Use ONLY when the current bundle is "
        "insufficient to ground a confident verdict. Cold-tier sources are "
        "permitted here when reasoning identifies a justified gap (e.g., "
        "after-hours physical access correlation, prior-quarter retention)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "source_type": {
                "type": "string",
                "enum": [
                    "asset_cmdb",
                    "identity_store",
                    "historical",
                    "threat_intel",
                    "runbook",
                    "log_search",
                ],
            },
            "rationale": {
                "type": "string",
                "description": (
                    "One sentence: what evidence gap this source closes."
                ),
            },
        },
        "required": ["source_type", "rationale"],
    },
}

T2_TOOLS: list[dict[str, Any]] = [REQUEST_ADDITIONAL_SOURCE_TOOL]
