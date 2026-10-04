"""Ranked table for the terminal: rich when available, plain text otherwise."""

from __future__ import annotations

import io
from typing import Any

from agent_threat_model.engine import Analysis
from agent_threat_model.reporters.common import (
    band_label,
    stride_title,
    summary_sentence,
    top_missing_controls,
)

try:  # rich is a declared dependency, but the renderer degrades gracefully
    from rich.console import Console
    from rich.table import Table

    HAVE_RICH = True
except ImportError:  # pragma: no cover - exercised only when rich is absent
    HAVE_RICH = False

BAND_COLOURS = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}


def _rows(analysis: Analysis) -> list[tuple[str, ...]]:
    rows: list[tuple[str, ...]] = []
    for rank, finding in enumerate(analysis.findings, start=1):
        rows.append(
            (
                str(rank),
                finding.threat_id,
                stride_title(finding.stride),
                ", ".join(finding.owasp_llm) or "-",
                f"{finding.inherent} {band_label(finding.inherent_band)}",
                f"{finding.residual:g} {band_label(finding.residual_band)}",
                ", ".join(finding.elements[:4]) + (" ..." if len(finding.elements) > 4 else ""),
            )
        )
    return rows


HEADERS = ("#", "Threat", "STRIDE", "OWASP LLM", "Inherent", "Residual", "Affected")


def render_plain(analysis: Analysis) -> str:
    rows = _rows(analysis)
    widths = [len(h) for h in HEADERS]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(row: tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()

    lines = [f"Threat model: {analysis.system.system.name}", ""]
    lines.append(fmt(HEADERS))
    lines.append("  ".join("-" * w for w in widths))
    lines.extend(fmt(r) for r in rows)
    lines.append("")
    lines.append(summary_sentence(analysis))
    missing = top_missing_controls(analysis)
    if missing:
        lines.append("")
        lines.append("Highest-leverage missing controls:")
        for control_id, title, count in missing:
            lines.append(f"  - {control_id}: {title} (mitigates {count} applicable threat(s))")
    return "\n".join(lines) + "\n"


def print_rich(analysis: Analysis, console: Any) -> None:
    table = Table(title=f"Threat model: {analysis.system.system.name}", show_lines=False)
    for header in HEADERS:
        if header == "Affected":
            table.add_column(header, overflow="fold")
        else:
            table.add_column(header, no_wrap=True, justify="right" if header == "#" else "left")
    for row in _rows(analysis):
        inherent_band = row[4].split()[-1].lower()
        residual_band = row[5].split()[-1].lower()
        styled = list(row)
        styled[4] = f"[{BAND_COLOURS[inherent_band]}]{row[4]}[/]"
        styled[5] = f"[{BAND_COLOURS[residual_band]}]{row[5]}[/]"
        table.add_row(*styled)
    console.print(table)
    console.print(summary_sentence(analysis))
    missing = top_missing_controls(analysis)
    if missing:
        console.print("\n[bold]Highest-leverage missing controls[/bold]")
        for control_id, title, count in missing:
            console.print(f"  - [cyan]{control_id}[/cyan]: {title} (mitigates {count})")


def render_table(analysis: Analysis, plain: bool = False, width: int = 150) -> str:
    """Render the ranked table as text (no ANSI codes)."""
    if plain or not HAVE_RICH:
        return render_plain(analysis)
    buffer = io.StringIO()
    console = Console(file=buffer, width=width, force_terminal=False, color_system=None)
    print_rich(analysis, console)
    return buffer.getvalue()
