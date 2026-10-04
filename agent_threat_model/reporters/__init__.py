"""Report renderers. Every renderer takes an :class:`Analysis` and returns text."""

from __future__ import annotations

from collections.abc import Callable

from agent_threat_model.engine import Analysis
from agent_threat_model.reporters.html import render_html
from agent_threat_model.reporters.jsonout import render_json
from agent_threat_model.reporters.markdown import render_markdown
from agent_threat_model.reporters.sarif import render_sarif
from agent_threat_model.reporters.table import render_table

RENDERERS: dict[str, Callable[[Analysis], str]] = {
    "table": render_table,
    "markdown": render_markdown,
    "json": render_json,
    "sarif": render_sarif,
    "html": render_html,
}

FORMATS = tuple(RENDERERS)


def render(analysis: Analysis, fmt: str) -> str:
    try:
        renderer = RENDERERS[fmt]
    except KeyError as exc:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}") from exc
    return renderer(analysis)


__all__ = [
    "FORMATS",
    "RENDERERS",
    "render",
    "render_html",
    "render_json",
    "render_markdown",
    "render_sarif",
    "render_table",
]
