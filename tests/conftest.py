"""Shared fixtures: a small system builder and paths to the examples."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from agent_threat_model.catalogue import load_catalogue
from agent_threat_model.engine import Analysis, analyse
from agent_threat_model.loader import system_from_dict
from agent_threat_model.predicates import Context

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
EXAMPLE_NAMES = ["support-bot", "coding-agent", "finance-agent", "masoon-governed"]

BASE: dict[str, Any] = {
    "system": {"name": "Test system", "description": "Fixture", "owner": "tests"},
    "principals": [],
    "agents": [
        {
            "id": "bot",
            "autonomy": "act",
            "memory": "none",
            "model_pinned": True,
            "inputs": ["chat"],
            "tools": ["reader"],
        }
    ],
    "channels": [{"id": "chat", "kind": "chat", "trusted": True, "origin": "internal"}],
    "tools": [
        {
            "id": "reader",
            "kind": "read",
            "auth": "short-lived",
            "scope": "read one table",
            "pinned": True,
            "sandboxed": True,
        }
    ],
    "data_stores": [],
    "controls": [],
}


def build(**overrides: Any) -> dict[str, Any]:
    """Return a deep copy of the base system with top-level keys replaced."""
    data = copy.deepcopy(BASE)
    data.update(overrides)
    return data


@pytest.fixture
def catalogue():
    return load_catalogue()


@pytest.fixture
def make_system():
    def _make(**overrides: Any):
        return system_from_dict(build(**overrides), source="fixture.yaml")

    return _make


@pytest.fixture
def make_context(make_system):
    def _make(**overrides: Any) -> Context:
        return Context(make_system(**overrides))

    return _make


@pytest.fixture
def analysed(make_system):
    def _run(**overrides: Any) -> Analysis:
        return analyse(make_system(**overrides), source="fixture.yaml")

    return _run


@pytest.fixture
def example_path():
    def _path(name: str) -> Path:
        return EXAMPLES / f"{name}.yaml"

    return _path
