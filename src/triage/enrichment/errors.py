"""Failure injection errors for enrichment sources.

Each enrichment source supports three injected failure modes: timeout
(network silently slow), upstream 5xx (vendor API crashed), malformed
(vendor returned non-JSON or schema-violating payload). The fan-out
catches these and degrades the verdict via enrichments_failed[] rather
than raising up the pipeline.
"""

from __future__ import annotations


class RetrievalTimeoutError(Exception):
    def __init__(self, source: str, timeout_ms: int) -> None:
        self.source = source
        self.timeout_ms = timeout_ms
        super().__init__(f"{source} retrieval timed out after {timeout_ms}ms")


class RetrievalUpstreamError(Exception):
    def __init__(self, source: str, status_code: int) -> None:
        self.source = source
        self.status_code = status_code
        super().__init__(f"{source} upstream returned HTTP {status_code}")


class MalformedRetrievalError(Exception):
    def __init__(self, source: str, reason: str) -> None:
        self.source = source
        self.reason = reason
        super().__init__(f"{source} returned malformed payload: {reason}")
