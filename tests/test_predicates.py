"""One test per predicate, each with a positive and a negative case."""

from __future__ import annotations

from agent_threat_model.predicates import REGISTRY, predicate_names, scope_is_broad
from tests.conftest import build


def _call(ctx, name, **kwargs):
    return REGISTRY[name](ctx, **{k: tuple(v) for k, v in kwargs.items()})


def _untrusted(data):
    data["channels"][0]["trusted"] = False
    data["channels"][0]["origin"] = "third-party"
    return data


def _with_tool(data, **tool):
    tool.setdefault("auth", "short-lived")
    tool.setdefault("pinned", True)
    tool.setdefault("scope", "narrow")
    data["tools"].append(tool)
    data["agents"][0]["tools"].append(tool["id"])
    return data


def test_registry_lists_all_predicates():
    assert len(predicate_names()) >= 20
    assert "untrusted_channel_in_agent_inputs" in predicate_names()


def test_untrusted_channel_in_agent_inputs(make_context):
    assert not _call(make_context(), "untrusted_channel_in_agent_inputs").matched
    hit = _call(make_context(**_untrusted(build())), "untrusted_channel_in_agent_inputs")
    assert hit.matched and set(hit.elements) == {"bot", "chat"}
    assert "untrusted channel 'chat'" in hit.reasons[0]


def test_agent_has_input_of_origin(make_context):
    ctx = make_context()
    assert not _call(ctx, "agent_has_input_of_origin", origin=["user"]).matched
    assert _call(ctx, "agent_has_input_of_origin", origin=["internal", "user"]).matched


def test_agent_has_channel_kind(make_context):
    ctx = make_context()
    assert _call(ctx, "agent_has_channel_kind", kinds=["chat"]).matched
    assert not _call(ctx, "agent_has_channel_kind", kinds=["rag"]).matched
    assert not _call(ctx, "agent_has_channel_kind", kinds=["chat"], untrusted=["true"]).matched
    ctx2 = make_context(**_untrusted(build()))
    assert _call(ctx2, "agent_has_channel_kind", kinds=["chat"], untrusted=["true"]).matched


def test_low_trust_principal_feeds_agent(make_context):
    assert not _call(make_context(), "low_trust_principal_feeds_agent").matched
    ctx = make_context(
        principals=[{"id": "anon", "kind": "human", "trust": "low", "channels": ["chat"]}]
    )
    hit = _call(ctx, "low_trust_principal_feeds_agent")
    assert hit.matched and "anon" in hit.elements


def test_agent_has_any_tool(make_context):
    assert _call(make_context(), "agent_has_any_tool").matched
    data = build()
    data["agents"][0]["tools"] = []
    assert not _call(make_context(**data), "agent_has_any_tool").matched


def test_agent_has_tool_kind(make_context):
    ctx = make_context()
    assert _call(ctx, "agent_has_tool_kind", kinds=["read"]).matched
    assert not _call(ctx, "agent_has_tool_kind", kinds=["exec", "payment"]).matched


def test_agent_autonomy_in(make_context):
    ctx = make_context()
    assert _call(ctx, "agent_autonomy_in", autonomy=["act"]).matched
    assert not _call(ctx, "agent_autonomy_in", autonomy=["suggest"]).matched


def test_agent_memory_is(make_context):
    assert not _call(make_context(), "agent_memory_is", memory=["persistent"]).matched
    data = build()
    data["agents"][0]["memory"] = "persistent"
    assert _call(make_context(**data), "agent_memory_is", memory=["persistent"]).matched


def test_agent_delegates_to_agent(make_context):
    assert not _call(make_context(), "agent_delegates_to_agent").matched
    data = build()
    data["agents"].append({"id": "worker", "autonomy": "act", "tools": [], "inputs": []})
    data["agents"][0]["delegates_to"] = ["worker"]
    hit = _call(make_context(**data), "agent_delegates_to_agent")
    assert hit.matched and set(hit.elements) == {"bot", "worker"}


def test_agent_model_unpinned(make_context):
    assert not _call(make_context(), "agent_model_unpinned").matched
    data = build()
    data["agents"][0]["model_pinned"] = False
    assert _call(make_context(**data), "agent_model_unpinned").matched


def test_agent_reaches_sensitive_store(make_context):
    data = build(data_stores=[{"id": "crm", "sensitivity": "confidential"}])
    data["tools"][0]["data_stores"] = ["crm"]
    ctx = make_context(**data)
    hit = _call(ctx, "agent_reaches_sensitive_store", min=["confidential"])
    assert hit.matched and "crm" in hit.elements
    assert not _call(ctx, "agent_reaches_sensitive_store", min=["regulated"]).matched
    assert not _call(make_context(), "agent_reaches_sensitive_store").matched


def test_tool_kind_without_approval(make_context):
    data = _with_tool(build(), id="pay", kind="payment", approval="none")
    assert _call(make_context(**data), "tool_kind_without_approval", kinds=["payment"]).matched
    data["tools"][-1]["approval"] = "always"
    assert not _call(make_context(**data), "tool_kind_without_approval", kinds=["payment"]).matched
    data["tools"][-1]["approval"] = "none"
    data["agents"][0]["autonomy"] = "suggest"
    assert not _call(make_context(**data), "tool_kind_without_approval", kinds=["payment"]).matched


def test_tool_kind_not_sandboxed(make_context):
    data = _with_tool(build(), id="sh", kind="exec", sandboxed=False)
    assert _call(make_context(**data), "tool_kind_not_sandboxed", kinds=["exec"]).matched
    data["tools"][-1]["sandboxed"] = True
    assert not _call(make_context(**data), "tool_kind_not_sandboxed", kinds=["exec"]).matched


def test_tool_auth_in(make_context):
    data = _with_tool(build(), id="api", kind="network", auth="static-key")
    ctx = make_context(**data)
    assert _call(ctx, "tool_auth_in", auth=["static-key"]).matched
    assert _call(ctx, "tool_auth_in", auth=["static-key"], kinds=["network"]).matched
    assert not _call(ctx, "tool_auth_in", auth=["static-key"], kinds=["payment"]).matched
    assert not _call(ctx, "tool_auth_in", auth=["none"]).matched


def test_unreachable_tool_is_ignored(make_context):
    data = build()
    data["tools"].append({"id": "orphan", "kind": "exec", "auth": "none", "sandboxed": False})
    assert not _call(make_context(**data), "tool_kind_not_sandboxed", kinds=["exec"]).matched


def test_third_party_tool(make_context):
    assert not _call(make_context(), "third_party_tool").matched
    data = _with_tool(build(), id="ext", kind="read", provider="third-party")
    assert _call(make_context(**data), "third_party_tool").matched


def test_scope_is_broad_heuristics():
    assert scope_is_broad("")
    assert scope_is_broad("repo:*")
    assert scope_is_broad("Admin on all projects")
    assert not scope_is_broad("read orders table for the current customer")


def test_tool_scope_broad(make_context):
    assert not _call(make_context(), "tool_scope_broad").matched
    data = build()
    data["tools"][0]["scope"] = "full access"
    assert _call(make_context(**data), "tool_scope_broad").matched


def test_tool_unpinned(make_context):
    assert not _call(make_context(), "tool_unpinned").matched
    data = build()
    data["tools"][0]["pinned"] = False
    assert _call(make_context(**data), "tool_unpinned").matched


def test_approval_always_tool_count_at_least(make_context):
    data = build()
    for n in range(3):
        _with_tool(data, id=f"w{n}", kind="write", approval="always")
    assert _call(make_context(**data), "approval_always_tool_count_at_least", min=["3"]).matched
    assert not _call(make_context(**data), "approval_always_tool_count_at_least", min=["4"]).matched


def test_store_sensitivity_at_least(make_context):
    ctx = make_context(data_stores=[{"id": "pii", "sensitivity": "regulated"}])
    assert _call(ctx, "store_sensitivity_at_least", min=["regulated"]).matched
    assert not _call(make_context(), "store_sensitivity_at_least", min=["public"]).matched


def test_control_missing_and_present(make_context):
    ctx = make_context(controls=["audit-log"])
    assert not _call(ctx, "control_missing", control=["audit-log"]).matched
    assert _call(ctx, "control_missing", control=["kill-switch"]).matched
    assert _call(ctx, "control_present", control=["audit-log"]).matched
    assert not _call(ctx, "control_present", control=["kill-switch"]).matched
    assert _call(ctx, "control_missing", control=["audit-log"]).elements == ()
