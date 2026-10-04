import json
from pathlib import Path

import pytest

from agent_threat_model.loader import SystemLoadError, system_from_dict
from agent_threat_model.schema import AgentSystem, json_schema
from tests.conftest import ROOT, build


def test_minimal_system_validates():
    system = system_from_dict(build())
    assert system.agents[0].id == "bot"
    assert system.tool("reader").kind.value == "read"


def test_unknown_channel_reference_is_rejected():
    data = build()
    data["agents"][0]["inputs"] = ["nope"]
    with pytest.raises(SystemLoadError) as info:
        system_from_dict(data)
    assert "not a channel id" in str(info.value)


def test_unknown_tool_reference_is_rejected():
    data = build()
    data["agents"][0]["tools"] = ["ghost"]
    with pytest.raises(SystemLoadError, match="not a tool id"):
        system_from_dict(data)


def test_bad_enum_value_is_rejected():
    data = build()
    data["agents"][0]["autonomy"] = "yolo"
    with pytest.raises(SystemLoadError) as info:
        system_from_dict(data)
    assert "agents.0.autonomy" in info.value.problems[0]


def test_duplicate_ids_across_groups_are_rejected():
    data = build(data_stores=[{"id": "chat", "sensitivity": "public"}])
    with pytest.raises(SystemLoadError, match="duplicate id 'chat'"):
        system_from_dict(data)


def test_unknown_field_is_rejected():
    data = build()
    data["agents"][0]["colour"] = "blue"
    with pytest.raises(SystemLoadError, match="colour"):
        system_from_dict(data)


def test_self_delegation_is_rejected():
    data = build()
    data["agents"][0]["delegates_to"] = ["bot"]
    with pytest.raises(SystemLoadError, match="cannot delegate to itself"):
        system_from_dict(data)


def test_unknown_control_id_is_rejected_by_loader():
    with pytest.raises(SystemLoadError, match="unknown control id 'magic'"):
        system_from_dict(build(controls=["magic"]))


def test_tool_target_links_to_data_store():
    data = build(data_stores=[{"id": "crm", "sensitivity": "confidential"}])
    data["tools"][0]["target"] = "crm"
    system = system_from_dict(data)
    assert [s.id for s in system.tool_stores(system.tool("reader"))] == ["crm"]


def test_committed_json_schema_matches_models():
    committed = json.loads((ROOT / "schema" / "system.schema.json").read_text(encoding="utf-8"))
    assert committed == json_schema(), "run: python scripts/gen_schema.py"
    assert committed["$schema"].startswith("https://json-schema.org/")
    assert "AgentSystem" in committed.get("title", "") or committed["title"]


def test_model_json_schema_has_required_sections():
    schema = AgentSystem.model_json_schema()
    assert set(schema["properties"]) >= {
        "system",
        "principals",
        "agents",
        "channels",
        "tools",
        "data_stores",
        "controls",
    }
    assert Path(ROOT / "schema" / "system.schema.json").exists()
