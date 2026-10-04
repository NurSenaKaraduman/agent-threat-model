"""Mermaid system diagram.

Principals, channels, agents, tools and data stores are drawn as five
subgraphs. Trusted channels connect to agents with dashed edges; untrusted
channels use solid red edges so the attack surface is visible at a glance.
"""

from __future__ import annotations

import re

from agent_threat_model.schema import AgentSystem

UNTRUSTED_STYLE = "stroke:#c0392b,stroke-width:2px"


def node_id(prefix: str, raw: str) -> str:
    return f"{prefix}_{re.sub(r'[^A-Za-z0-9_]', '_', raw)}"


def _label(*parts: str) -> str:
    text = "<br/>".join(p for p in parts if p)
    return text.replace('"', "'")


def mermaid(system: AgentSystem) -> str:
    """Return a Mermaid ``flowchart LR`` definition for the system."""
    lines: list[str] = ["flowchart LR"]
    edges: list[str] = []
    red_edges: list[int] = []
    untrusted_nodes: list[str] = []

    def add_edge(text: str, red: bool = False) -> None:
        if red:
            red_edges.append(len(edges))
        edges.append(text)

    if system.principals:
        lines.append('  subgraph principals["Principals"]')
        for p in system.principals:
            label = _label(p.id, f"{p.kind.value}, trust {p.trust.value}")
            lines.append(f'    {node_id("p", p.id)}(["{label}"])')
        lines.append("  end")
    if system.channels:
        lines.append('  subgraph channels["Channels"]')
        for c in system.channels:
            trust = "trusted" if c.trusted else "untrusted"
            label = _label(c.id, f"{c.kind.value}, {c.origin.value}, {trust}")
            lines.append(f'    {node_id("c", c.id)}[/"{label}"/]')
            if not c.trusted:
                untrusted_nodes.append(node_id("c", c.id))
        lines.append("  end")
    lines.append('  subgraph agents["Agents"]')
    for a in system.agents:
        memory = f"memory {a.memory.value}" if a.memory.value != "none" else "no memory"
        lines.append(f'    {node_id("a", a.id)}[["{_label(a.id, a.autonomy.value, memory)}"]]')
    lines.append("  end")
    if system.tools:
        lines.append('  subgraph tools["Tools"]')
        for t in system.tools:
            extra = f"approval {t.approval.value}" if t.approval.value != "none" else "no approval"
            label = _label(t.id, f"{t.kind.value}, auth {t.auth.value}", extra)
            lines.append(f'    {node_id("t", t.id)}("{label}")')
        lines.append("  end")
    if system.data_stores:
        lines.append('  subgraph stores["Data stores"]')
        for s in system.data_stores:
            lines.append(f'    {node_id("s", s.id)}[("{_label(s.id, s.sensitivity.value)}")]')
        lines.append("  end")

    for p in system.principals:
        for channel_id in p.channels:
            add_edge(f"  {node_id('p', p.id)} --> {node_id('c', channel_id)}")
    for a in system.agents:
        for channel_id in a.inputs:
            channel = system.channel(channel_id)
            if channel.trusted:
                add_edge(f"  {node_id('c', channel_id)} -.-> {node_id('a', a.id)}")
            else:
                add_edge(f"  {node_id('c', channel_id)} ==> {node_id('a', a.id)}", red=True)
        for tool_id in a.tools:
            add_edge(f"  {node_id('a', a.id)} --> {node_id('t', tool_id)}")
        for target in a.delegates_to:
            add_edge(f"  {node_id('a', a.id)} -- delegates --> {node_id('a', target)}")
    for t in system.tools:
        for store in system.tool_stores(t):
            add_edge(f"  {node_id('t', t.id)} --> {node_id('s', store.id)}")

    lines.extend(edges)
    if untrusted_nodes:
        lines.append(f"  classDef untrusted {UNTRUSTED_STYLE},stroke-dasharray:0;")
        lines.append(f"  class {','.join(untrusted_nodes)} untrusted;")
    for index in red_edges:
        lines.append(f"  linkStyle {index} {UNTRUSTED_STYLE};")
    return "\n".join(lines) + "\n"
