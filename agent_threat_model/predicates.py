"""Named predicate functions used by catalogue rules.

Every predicate takes the :class:`Context` and keyword arguments whose values
are tuples of strings (as parsed from the rule text) and returns a
:class:`~agent_threat_model.rules.Match` that lists the affected element ids
and a human readable reason for each hit. Predicates only look at tools that
at least one agent can reach; a tool nobody calls is not a threat surface.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from agent_threat_model.rules import Match
from agent_threat_model.schema import (
    SENSITIVITY_ORDER,
    Agent,
    AgentSystem,
    Autonomy,
    Sensitivity,
    Tool,
    TrustLevel,
)

Args = tuple[str, ...]
REGISTRY: dict[str, Callable[..., Match]] = {}

BROAD_SCOPE_TOKENS = {"*", "all", "admin", "any", "full", "owner", "root", "unrestricted"}


@dataclass(frozen=True)
class Context:
    """What predicates can see: the validated system description."""

    system: AgentSystem

    def reachable_tools(self) -> list[tuple[Tool, list[Agent]]]:
        out: list[tuple[Tool, list[Agent]]] = []
        for tool in self.system.tools:
            users = self.system.agents_using_tool(tool.id)
            if users:
                out.append((tool, users))
        return out


def predicate(fn: Callable[..., Match]) -> Callable[..., Match]:
    """Register a predicate under its function name."""
    REGISTRY[fn.__name__] = fn
    return fn


def _set(values: Args | None, default: Args = ()) -> set[str]:
    return set(values) if values else set(default)


def _one(values: Args | None, default: str) -> str:
    return values[0] if values else default


def _tool_label(tool: Tool) -> str:
    return f"tool '{tool.id}' ({tool.kind.value})"


# Channel and input predicates ------------------------------------------


@predicate
def untrusted_channel_in_agent_inputs(ctx: Context) -> Match:
    """An agent reads at least one channel marked trusted: false."""
    elements: list[str] = []
    reasons: list[str] = []
    for agent in ctx.system.agents:
        for channel_id in agent.inputs:
            channel = ctx.system.channel(channel_id)
            if not channel.trusted:
                elements += [agent.id, channel.id]
                reasons.append(
                    f"agent '{agent.id}' reads untrusted channel '{channel.id}' "
                    f"({channel.kind.value}, origin {channel.origin.value})"
                )
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def agent_has_input_of_origin(ctx: Context, origin: Args | None = None) -> Match:
    """An agent reads a channel whose origin is one of the given values."""
    wanted = _set(origin, ("user",))
    elements: list[str] = []
    reasons: list[str] = []
    for agent in ctx.system.agents:
        for channel_id in agent.inputs:
            channel = ctx.system.channel(channel_id)
            if channel.origin.value in wanted:
                elements += [agent.id, channel.id]
                reasons.append(
                    f"agent '{agent.id}' reads channel '{channel.id}' "
                    f"with origin {channel.origin.value}"
                )
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def agent_has_channel_kind(
    ctx: Context, kinds: Args | None = None, untrusted: Args | None = None
) -> Match:
    """An agent reads a channel of one of the given kinds (optionally only untrusted ones)."""
    wanted = _set(kinds)
    only_untrusted = _one(untrusted, "false") == "true"
    elements: list[str] = []
    reasons: list[str] = []
    for agent in ctx.system.agents:
        for channel_id in agent.inputs:
            channel = ctx.system.channel(channel_id)
            if channel.kind.value in wanted and (not only_untrusted or not channel.trusted):
                elements += [agent.id, channel.id]
                trust = "trusted" if channel.trusted else "untrusted"
                reasons.append(
                    f"agent '{agent.id}' reads {trust} {channel.kind.value} channel '{channel.id}'"
                )
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def low_trust_principal_feeds_agent(ctx: Context) -> Match:
    """A principal with trust: low speaks on a channel an agent reads."""
    elements: list[str] = []
    reasons: list[str] = []
    for principal in ctx.system.principals:
        if principal.trust != TrustLevel.LOW:
            continue
        for agent in ctx.system.agents:
            shared = [c for c in principal.channels if c in agent.inputs]
            for channel_id in shared:
                elements += [principal.id, agent.id, channel_id]
                reasons.append(
                    f"low-trust principal '{principal.id}' reaches agent '{agent.id}' "
                    f"through channel '{channel_id}'"
                )
    return Match.of(elements, reasons) if elements else Match.no()


# Agent predicates --------------------------------------------------------


@predicate
def agent_has_any_tool(ctx: Context) -> Match:
    elements = [a.id for a in ctx.system.agents if a.tools]
    reasons = [
        f"agent '{a.id}' can call {len(a.tools)} tool(s)" for a in ctx.system.agents if a.tools
    ]
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def agent_has_tool_kind(ctx: Context, kinds: Args | None = None) -> Match:
    """An agent can call a tool of one of the given kinds."""
    wanted = _set(kinds)
    elements: list[str] = []
    reasons: list[str] = []
    for agent in ctx.system.agents:
        for tool_id in agent.tools:
            tool = ctx.system.tool(tool_id)
            if tool.kind.value in wanted:
                elements += [agent.id, tool.id]
                reasons.append(f"agent '{agent.id}' can call {_tool_label(tool)}")
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def agent_autonomy_in(ctx: Context, autonomy: Args | None = None) -> Match:
    wanted = _set(autonomy, ("act",))
    hits = [a for a in ctx.system.agents if a.autonomy.value in wanted]
    return (
        Match.of(
            [a.id for a in hits],
            [f"agent '{a.id}' has autonomy {a.autonomy.value}" for a in hits],
        )
        if hits
        else Match.no()
    )


@predicate
def agent_memory_is(ctx: Context, memory: Args | None = None) -> Match:
    wanted = _set(memory, ("persistent",))
    hits = [a for a in ctx.system.agents if a.memory.value in wanted]
    return (
        Match.of(
            [a.id for a in hits],
            [f"agent '{a.id}' keeps {a.memory.value} memory" for a in hits],
        )
        if hits
        else Match.no()
    )


@predicate
def agent_delegates_to_agent(ctx: Context) -> Match:
    elements: list[str] = []
    reasons: list[str] = []
    for agent in ctx.system.agents:
        for target in agent.delegates_to:
            elements += [agent.id, target]
            reasons.append(f"agent '{agent.id}' delegates tasks to agent '{target}'")
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def agent_model_unpinned(ctx: Context) -> Match:
    hits = [a for a in ctx.system.agents if not a.model_pinned]
    return (
        Match.of(
            [a.id for a in hits],
            [f"agent '{a.id}' does not declare a pinned model version" for a in hits],
        )
        if hits
        else Match.no()
    )


@predicate
def agent_reaches_sensitive_store(ctx: Context, min: Args | None = None) -> Match:
    """An agent can reach, through a tool, a data store at or above the given sensitivity."""
    threshold = SENSITIVITY_ORDER[Sensitivity(_one(min, "confidential"))]
    elements: list[str] = []
    reasons: list[str] = []
    for agent in ctx.system.agents:
        for tool_id in agent.tools:
            tool = ctx.system.tool(tool_id)
            for store in ctx.system.tool_stores(tool):
                if SENSITIVITY_ORDER[store.sensitivity] >= threshold:
                    elements += [agent.id, tool.id, store.id]
                    reasons.append(
                        f"agent '{agent.id}' reaches {store.sensitivity.value} store "
                        f"'{store.id}' through {_tool_label(tool)}"
                    )
    return Match.of(elements, reasons) if elements else Match.no()


# Tool predicates ---------------------------------------------------------


@predicate
def tool_kind_without_approval(ctx: Context, kinds: Args | None = None) -> Match:
    """A reachable tool of the given kind needs no approval and its agent may act."""
    wanted = _set(kinds, ("write", "exec", "payment"))
    elements: list[str] = []
    reasons: list[str] = []
    for tool, users in ctx.reachable_tools():
        if tool.kind.value not in wanted or tool.approval.value != "none":
            continue
        acting = [a for a in users if a.autonomy != Autonomy.SUGGEST]
        for agent in acting:
            elements += [agent.id, tool.id]
            reasons.append(
                f"agent '{agent.id}' ({agent.autonomy.value}) can call {_tool_label(tool)} "
                "with approval: none"
            )
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def tool_kind_not_sandboxed(ctx: Context, kinds: Args | None = None) -> Match:
    wanted = _set(kinds, ("exec",))
    elements: list[str] = []
    reasons: list[str] = []
    for tool, users in ctx.reachable_tools():
        if tool.kind.value in wanted and not tool.sandboxed:
            elements += [tool.id, *[a.id for a in users]]
            reasons.append(f"{_tool_label(tool)} runs without a sandbox")
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def tool_auth_in(ctx: Context, auth: Args | None = None, kinds: Args | None = None) -> Match:
    """A reachable tool authenticates with one of the given methods (optionally of given kinds)."""
    wanted_auth = _set(auth, ("static-key",))
    wanted_kinds = _set(kinds)
    elements: list[str] = []
    reasons: list[str] = []
    for tool, users in ctx.reachable_tools():
        if tool.auth.value not in wanted_auth:
            continue
        if wanted_kinds and tool.kind.value not in wanted_kinds:
            continue
        elements += [tool.id, *[a.id for a in users]]
        reasons.append(f"{_tool_label(tool)} uses auth: {tool.auth.value}")
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def third_party_tool(ctx: Context) -> Match:
    elements: list[str] = []
    reasons: list[str] = []
    for tool, users in ctx.reachable_tools():
        if tool.provider.value == "third-party":
            elements += [tool.id, *[a.id for a in users]]
            reasons.append(f"{_tool_label(tool)} and its description come from a third party")
    return Match.of(elements, reasons) if elements else Match.no()


def scope_is_broad(scope: str) -> bool:
    """True for an empty scope or one containing a wildcard or an admin-style token."""
    if not scope.strip():
        return True
    tokens = {t for t in re.split(r"[^a-z0-9*]+", scope.lower()) if t}
    return bool(tokens & BROAD_SCOPE_TOKENS) or "*" in scope


@predicate
def tool_scope_broad(ctx: Context) -> Match:
    elements: list[str] = []
    reasons: list[str] = []
    for tool, users in ctx.reachable_tools():
        if scope_is_broad(tool.scope):
            elements += [tool.id, *[a.id for a in users]]
            shown = tool.scope.strip() or "(not declared)"
            reasons.append(f"{_tool_label(tool)} has a broad scope: {shown}")
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def tool_unpinned(ctx: Context) -> Match:
    elements: list[str] = []
    reasons: list[str] = []
    for tool, users in ctx.reachable_tools():
        if not tool.pinned:
            elements += [tool.id, *[a.id for a in users]]
            reasons.append(f"{_tool_label(tool)} version or description is not pinned")
    return Match.of(elements, reasons) if elements else Match.no()


@predicate
def approval_always_tool_count_at_least(ctx: Context, min: Args | None = None) -> Match:
    """At least N reachable tools require approval on every call (fatigue risk)."""
    threshold = int(_one(min, "3"))
    always = [(t, u) for t, u in ctx.reachable_tools() if t.approval.value == "always"]
    if len(always) < threshold:
        return Match.no()
    elements = [t.id for t, _ in always] + [a.id for _, u in always for a in u]
    reasons = [
        f"{len(always)} tools require approval on every call: " + ", ".join(t.id for t, _ in always)
    ]
    return Match.of(elements, reasons)


# Data store and control predicates ----------------------------------------


@predicate
def store_sensitivity_at_least(ctx: Context, min: Args | None = None) -> Match:
    threshold = SENSITIVITY_ORDER[Sensitivity(_one(min, "regulated"))]
    hits = [s for s in ctx.system.data_stores if SENSITIVITY_ORDER[s.sensitivity] >= threshold]
    return (
        Match.of(
            [s.id for s in hits],
            [f"data store '{s.id}' is classified {s.sensitivity.value}" for s in hits],
        )
        if hits
        else Match.no()
    )


@predicate
def control_missing(ctx: Context, control: Args | None = None) -> Match:
    """None of the given controls is listed in the system's controls."""
    wanted = list(control or ())
    missing = [c for c in wanted if not ctx.system.has_control(c)]
    if len(missing) != len(wanted) or not wanted:
        return Match.no()
    return Match(True, (), tuple(f"control '{c}' is not in place" for c in missing))


@predicate
def control_present(ctx: Context, control: Args | None = None) -> Match:
    wanted = list(control or ())
    present = [c for c in wanted if ctx.system.has_control(c)]
    if not present:
        return Match.no()
    return Match(True, (), tuple(f"control '{c}' is in place" for c in present))


def predicate_names() -> list[str]:
    return sorted(REGISTRY)
