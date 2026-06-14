"""Shared pytest fixtures for Day 1 acceptance gates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage.adapters.okta import OktaAdapterV1
from triage.grouping.storm import reset_storm_grouper
from triage.schemas.plan_loader import PlanTemplateRegistry

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
OKTA_DIR = FIXTURES_DIR / "okta"
TENANT_DIR = FIXTURES_DIR / "tenants"


def _load_json(name: str) -> dict:
    with (OKTA_DIR / name).open() as fh:
        return json.load(fh)


@pytest.fixture
def okta_payload_clean() -> dict:
    return _load_json("sample_v1_clean.json")


@pytest.fixture
def okta_payload_destructive() -> dict:
    return _load_json("sample_drift_destructive.json")


@pytest.fixture
def okta_payload_additive() -> dict:
    return _load_json("sample_drift_additive.json")


@pytest.fixture
def unknown_source_payload() -> dict:
    return _load_json("sample_unknown_source.json")


@pytest.fixture
def okta_adapter() -> OktaAdapterV1:
    return OktaAdapterV1()


@pytest.fixture
def plan_registry() -> PlanTemplateRegistry:
    return PlanTemplateRegistry()


@pytest.fixture
def fresh_storm_grouper():
    reset_storm_grouper()
    yield
    reset_storm_grouper()


@pytest.fixture
def tenant_a_id() -> str:
    return "tenant_a"


@pytest.fixture
def tenant_b_id() -> str:
    return "tenant_b"
