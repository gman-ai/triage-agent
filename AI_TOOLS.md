# AI tools used

## Planning and research

I used AI assistants during planning to research modern SecOps AI patterns,
compare architecture options, and stress-test the design before writing
code. That's where most of the value came from: cycling through plan-then-
fetch vs always-fan-out, single-agent vs multi-agent, citation-existence
vs citation-support validation, and the cost/quality trade-offs of tiered
routing. It helped me avoid the obvious "alert goes to an LLM and gets
summarized" pattern and converge on a deterministic-first architecture
where the LLM only enters when evidence synthesis is the right call.

## Implementation assistance

I used coding assistants for repetitive scaffolding: Pydantic models,
parametrized pytest cases, fixture generation, the YAML plan templates,
and eval-report formatting. The shape was AI-drafted in those spots; the
contracts, names, and edge cases were reviewed and corrected by hand
before commit.

## Runtime model usage

The prototype has two bounded LLM reasoning stages, with deterministic T1 routing:

- **T1 — deterministic.** YAML lookup keyed on `(rule_family,
  severity_hint)`. No LLM.
- **T2 — Sonnet 4.6.** Evidence-backed reasoning over the enriched bundle.
  Forced JSON schema; bounded tool-use loop for plan extensions.
- **T3 — Opus 4.7.** Self-consistency escalation, fires only on
  low-confidence P0/P1 alerts in deep families.

Everything else — adapters, storm grouping, routing, validator, audit
ledger, action enum — is deterministic code.

## Where AI was limiting

AI assistance needed careful human review around the parts of the system
where engineering judgment matters most:

- **Tenant isolation.** Storage-boundary enforcement and cross-tenant
  fixture design needed deliberate human design.
- **Citation support validation.** The walk-payload-at-field-path-and-
  match-expected-value contract is the differentiator; getting the
  semantics right (and the failure shape correct) was hand-designed.
- **Cost and routing boundaries.** Severity-aware budget override,
  per-tenant envelope, P0 cannot be silently dropped — these are policy
  decisions, not AI-suggestable defaults.
- **Eval calibration.** Synthetic-LLM distributions, expected calibration
  error, and the gating threshold required iteration against measured
  output, not pattern matching.
- **Failure-mode handling.** Schema-drift quarantine, validator terminal
  failsafe, retry semantics, degraded-mode taxonomy — every path that
  ends in a structured `needs_human` verdict was specified by hand.

## Final takeaway

AI helped accelerate the build, but the production contract is
deterministic: LLMs reason over evidence; code controls access, routing,
validation, cost, and audit.
