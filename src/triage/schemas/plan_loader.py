"""Plan template loader for InvestigationPlan seeds per RECONCILED §5.1.

Loads fixtures/plan_templates.yaml at process start and exposes a
build_plan(rule_family, severity_hint) helper. T1 (Day 3) calls this to
seed its plan output; this Day 1 module makes the seeding deterministic
and testable in isolation.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import yaml

from triage.schemas.alert import RuleFamily, Severity
from triage.schemas.plan import InvestigationPlan, SourceType

_DEFAULT_TEMPLATE_PATH = Path(__file__).resolve().parents[3] / "fixtures" / "plan_templates.yaml"


class PlanTemplateRegistry:
    def __init__(self, path: Path = _DEFAULT_TEMPLATE_PATH) -> None:
        with path.open() as fh:
            doc = yaml.safe_load(fh)
        self._version: str = doc["version"]
        self._families: dict[str, dict] = doc["families"]

    @property
    def version(self) -> str:
        return self._version

    def families(self) -> list[str]:
        return list(self._families.keys())

    def get(self, rule_family: RuleFamily) -> dict | None:
        return self._families.get(rule_family)

    def build_plan(
        self,
        rule_family: RuleFamily,
        severity_hint: Severity,
        plan_id: str | None = None,
    ) -> InvestigationPlan:
        template = self.get(rule_family)
        if template is None:
            raise KeyError(f"no plan template for rule_family={rule_family!r}")
        kwargs = dict(
            plan_id=plan_id or str(uuid.uuid4()),
            alert_family=rule_family,
            severity_hint=severity_hint,
            required_sources=list(template["required_sources"]),
            optional_sources=list(template.get("optional_sources", [])),
            expected_fact_categories=list(template.get("expected_fact_categories", [])),
            rationale=template["rationale"].strip(),
            plan_template_version=self._version,
        )
        # R9 / D33: tier_preference is an optional template field. When seeded,
        # the loader propagates it; when omitted, the InvestigationPlan default
        # ["hot", "warm", "cold"] applies.
        if "tier_preference" in template:
            kwargs["tier_preference"] = list(template["tier_preference"])
        return InvestigationPlan(**kwargs)
