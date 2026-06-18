"""Notebook execution guardrail.

`notebook.ipynb` is the primary walkthrough surface. Any drift in upstream
code, fixture digests, or cell content that would break notebook execution
must be caught at test time, not at walkthrough time.

This test runs `notebook.ipynb` end-to-end via `nbclient.NotebookClient` and
asserts that no cell raises. It must run without an Anthropic API key — the
T3 cell uses call-order `SequenceClient` (not digest-based
`FixtureReplayClient`) so the bundle's non-deterministic retrieval_ids and
`fetched_at` fields do not break replay.

If this test breaks in CI or pre-submission, the bug is in one of:
  * an upstream change to `LLMRequest.digest()` shape (shouldn't matter for
    the T3 cell anymore, but other cells could regress)
  * a new cell added without re-executing the notebook locally
  * a model name mismatch between cell code and captured fixture
  * the captured fixture file was moved or renamed
"""

from __future__ import annotations

from pathlib import Path

import nbclient
import nbformat
import pytest

NOTEBOOK_PATH = Path(__file__).resolve().parents[1] / "notebook.ipynb"


@pytest.fixture(scope="module")
def executed_notebook() -> nbformat.NotebookNode:
    """Execute the notebook once per test module; reuse across assertions."""
    nb = nbformat.read(NOTEBOOK_PATH, as_version=4)
    client = nbclient.NotebookClient(
        nb,
        timeout=60,
        kernel_name="python3",
        resources={"metadata": {"path": str(NOTEBOOK_PATH.parent)}},
    )
    client.execute()
    return nb


def test_notebook_executes_end_to_end(executed_notebook: nbformat.NotebookNode) -> None:
    """Every code cell runs without raising; no `error` outputs surface.

    nbclient.NotebookClient.execute() raises CellExecutionError on cell
    failure already, so reaching this line means execution succeeded. The
    output walk is the belt-and-suspenders backstop.
    """
    for i, cell in enumerate(executed_notebook.cells):
        if cell.cell_type != "code":
            continue
        for output in cell.get("outputs", []):
            assert output.get("output_type") != "error", (
                f"cell {i} produced an error output: "
                f"{output.get('ename')}: {output.get('evalue')}"
            )


def test_notebook_t3_cell_replays_captured_live_response(
    executed_notebook: nbformat.NotebookNode,
) -> None:
    """The T3 cell's stdout shows the live-captured majority verdict line.

    This pins the architectural decision documented in DESIGN.md §5.4:
    SequenceClient is fed with the response content loaded from the
    captured fixture file. If the cell ever reverts to digest-based
    FixtureReplayClient over the non-deterministic bundle, this test
    breaks loudly.
    """
    code_cells = [c for c in executed_notebook.cells if c.cell_type == "code"]
    # Find the T3 cell by content match rather than index, so cell reorders
    # don't silently break this assertion.
    t3_cell = next(
        (c for c in code_cells if "escalate_to_t3" in "".join(c.source) and "live_replay" in "".join(c.source)),
        None,
    )
    assert t3_cell is not None, "could not locate T3 cell by content match"
    output_text = ""
    for out in t3_cell.get("outputs", []):
        output_text += out.get("text", "")
        data = out.get("data", {}) if isinstance(out.get("data"), dict) else {}
        output_text += data.get("text/plain", "")
    assert "T3 live-captured majority verdict" in output_text, (
        "T3 cell did not produce the live-captured replay line; "
        f"got output:\n{output_text[:500]}"
    )


def test_notebook_title_locked() -> None:
    """The notebook title is `Triage Agent — Walkthrough`. Pinned to prevent
    regression to earlier phrasings.
    """
    nb = nbformat.read(NOTEBOOK_PATH, as_version=4)
    first_cell_text = "".join(nb.cells[0].source)
    assert first_cell_text.startswith("# Triage Agent — Walkthrough"), (
        f"notebook title regressed; first line: {first_cell_text.splitlines()[0]!r}"
    )
