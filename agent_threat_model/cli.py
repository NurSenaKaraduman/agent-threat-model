"""Command line interface: ``atm`` and ``agent-threat-model``."""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from agent_threat_model import __version__
from agent_threat_model.catalogue import EFFORT_ORDER, load_catalogue
from agent_threat_model.diagram import mermaid
from agent_threat_model.diff import Diff, diff_analyses
from agent_threat_model.engine import BAND_ORDER, Analysis, analyse
from agent_threat_model.loader import SystemLoadError, load_system
from agent_threat_model.reporters import render
from agent_threat_model.reporters.table import HAVE_RICH, print_rich
from agent_threat_model.schema import json_schema
from agent_threat_model.template import TEMPLATE

app = typer.Typer(
    name="atm",
    help="Deterministic STRIDE and OWASP threat modelling for LLM-agent systems described in YAML.",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2


class Format(StrEnum):
    table = "table"
    markdown = "markdown"
    json = "json"
    sarif = "sarif"
    html = "html"


class FailOn(StrEnum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class CatalogueSection(StrEnum):
    all = "all"
    threats = "threats"
    controls = "controls"


class TextFormat(StrEnum):
    table = "table"
    markdown = "markdown"
    json = "json"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"agent-threat-model {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Deterministic STRIDE and OWASP threat modelling for LLM-agent systems."""


def _load(path: Path) -> Analysis:
    try:
        system = load_system(path)
    except SystemLoadError as error:
        typer.echo(f"error: {error.source} is not a valid system description", err=True)
        for problem in error.problems:
            typer.echo(f"  - {problem}", err=True)
        raise typer.Exit(EXIT_INPUT) from error
    analysis = analyse(system, source=str(path))
    analysis.source_text = path.read_text(encoding="utf-8")
    return analysis


def _write(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    typer.echo(f"wrote {output}", err=True)


def _exceeds(analysis: Analysis, fail_on: FailOn) -> bool:
    if fail_on == FailOn.none or not analysis.findings:
        return False
    worst = min(BAND_ORDER[f.residual_band] for f in analysis.findings)
    return worst <= BAND_ORDER[fail_on.value]


@app.command("analyse")
@app.command("analyze", hidden=True)
def analyse_command(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="System YAML file.")],
    fmt: Annotated[
        Format, typer.Option("--format", "-f", help="Output format.", case_sensitive=False)
    ] = Format.table,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report here instead of stdout.")
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on", help="Exit 1 when a threat of this residual severity or worse applies."
        ),
    ] = FailOn.none,
    plain: Annotated[
        bool, typer.Option("--plain", help="Plain text table without colours.")
    ] = False,
) -> None:
    """Analyse a system description and print a ranked threat table or a report."""
    analysis = _load(file)
    if fmt == Format.table and output is None:
        if plain or not HAVE_RICH or not sys.stdout.isatty():
            sys.stdout.write(render(analysis, "table") if not plain else _plain(analysis))
        else:
            from rich.console import Console

            print_rich(analysis, Console())
    else:
        _write(render(analysis, fmt.value), output)
    if _exceeds(analysis, fail_on):
        typer.echo(
            f"fail-on {fail_on.value}: at least one applicable threat is {fail_on.value} or worse",
            err=True,
        )
        raise typer.Exit(EXIT_FINDINGS)


def _plain(analysis: Analysis) -> str:
    from agent_threat_model.reporters.table import render_table

    return render_table(analysis, plain=True)


@app.command("validate")
def validate_command(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="System YAML file.")],
) -> None:
    """Validate a system description against the schema and the control catalogue."""
    try:
        system = load_system(file)
    except SystemLoadError as error:
        typer.echo(f"invalid: {error.source}", err=True)
        for problem in error.problems:
            typer.echo(f"  - {problem}", err=True)
        raise typer.Exit(EXIT_INPUT) from error
    typer.echo(
        f"ok: {file} ({len(system.agents)} agent(s), {len(system.channels)} channel(s), "
        f"{len(system.tools)} tool(s), {len(system.data_stores)} data store(s), "
        f"{len(system.controls)} control(s))"
    )


@app.command("diagram")
def diagram_command(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="System YAML file.")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the diagram here instead of stdout."),
    ] = None,
) -> None:
    """Print a Mermaid diagram of a system description."""
    try:
        system = load_system(file)
    except SystemLoadError as error:
        typer.echo(f"invalid: {error.source}", err=True)
        for problem in error.problems:
            typer.echo(f"  - {problem}", err=True)
        raise typer.Exit(EXIT_INPUT) from error
    _write(mermaid(system), output)


@app.command("init")
def init_command(
    path: Annotated[Path, typer.Argument(help="Where to write the starter file.")] = Path(
        "system.yaml"
    ),
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write an example system description to start from."""
    if path.exists() and not force:
        typer.echo(f"error: {path} exists; use --force to overwrite", err=True)
        raise typer.Exit(EXIT_INPUT)
    path.write_text(TEMPLATE, encoding="utf-8")
    typer.echo(f"wrote {path}; next: atm analyse {path}")


@app.command("catalogue")
@app.command("catalog", hidden=True)
def catalogue_command(
    section: Annotated[
        CatalogueSection, typer.Argument(help="threats, controls or all.", case_sensitive=False)
    ] = CatalogueSection.all,
    fmt: Annotated[
        TextFormat, typer.Option("--format", "-f", help="Output format.", case_sensitive=False)
    ] = TextFormat.table,
) -> None:
    """List the threats and controls in the bundled catalogue."""
    catalogue = load_catalogue()
    threats = list(catalogue.threats.values())
    controls = sorted(catalogue.controls.values(), key=lambda c: (EFFORT_ORDER[c.effort], c.id))
    show_threats = section in (CatalogueSection.all, CatalogueSection.threats)
    show_controls = section in (CatalogueSection.all, CatalogueSection.controls)
    if fmt == TextFormat.json:
        payload: dict = {}
        if show_threats:
            payload["threats"] = [t.model_dump(mode="json") for t in threats]
        if show_controls:
            payload["controls"] = [c.model_dump(mode="json") for c in controls]
        typer.echo(json.dumps(payload, indent=2))
        return
    lines: list[str] = []
    if show_threats:
        lines.append(f"Threats ({len(threats)})")
        if fmt == TextFormat.markdown:
            lines += ["", "| Id | Title | STRIDE | OWASP LLM | L x I |", "|---|---|---|---|---|"]
            lines += [
                f"| `{t.id}` | {t.title} | {t.stride.value} | {', '.join(t.owasp_llm) or '-'} | "
                f"{t.likelihood} x {t.impact} |"
                for t in threats
            ]
        else:
            width = max(len(t.id) for t in threats)
            lines += [
                f"  {t.id.ljust(width)}  {t.likelihood}x{t.impact}  {t.stride.value:<22}  {t.title}"
                for t in threats
            ]
        lines.append("")
    if show_controls:
        lines.append(f"Controls ({len(controls)})")
        if fmt == TextFormat.markdown:
            lines += ["", "| Id | Title | Type | Effort |", "|---|---|---|---|"]
            lines += [
                f"| `{c.id}` | {c.title} | {c.type.value} | {c.effort.value} |" for c in controls
            ]
        else:
            width = max(len(c.id) for c in controls)
            lines += [
                f"  {c.id.ljust(width)}  {c.effort.value:<6}  {c.type.value:<10}  {c.title}"
                for c in controls
            ]
        lines.append("")
    typer.echo("\n".join(lines).rstrip())


def _diff_text(diff: Diff) -> str:
    lines = [f"Diff: {diff.old_source} -> {diff.new_source}", ""]
    lines.append(
        f"Residual risk score: {diff.old_score} ({diff.old_rating}) -> "
        f"{diff.new_score} ({diff.new_rating}), change {diff.score_delta:+d}"
    )
    lines.append(f"Residual total: {diff.old_residual_total:g} -> {diff.new_residual_total:g}")
    if diff.controls_added:
        lines.append("Controls added: " + ", ".join(diff.controls_added))
    if diff.controls_removed:
        lines.append("Controls removed: " + ", ".join(diff.controls_removed))
    lines.append("")
    lines.append(f"New threats ({len(diff.added)})")
    lines += [f"  + {f.threat_id}  {f.residual:g} {f.residual_band}  {f.title}" for f in diff.added]
    lines.append(f"Removed threats ({len(diff.removed)})")
    lines += [
        f"  - {f.threat_id}  {f.residual:g} {f.residual_band}  {f.title}" for f in diff.removed
    ]
    lines.append(f"Changed threats ({len(diff.changed)})")
    for c in diff.changed:
        detail = []
        if c.mitigations_now_present:
            detail.append("now mitigated by " + ", ".join(c.mitigations_now_present))
        if c.mitigations_now_missing:
            detail.append("lost " + ", ".join(c.mitigations_now_missing))
        if c.elements_added:
            detail.append("affects also " + ", ".join(c.elements_added))
        if c.elements_removed:
            detail.append("no longer affects " + ", ".join(c.elements_removed))
        lines.append(
            f"  ~ {c.threat_id}  {c.old_residual:g} {c.old_band} -> {c.new_residual:g} "
            f"{c.new_band} ({c.delta:+g})" + (": " + "; ".join(detail) if detail else "")
        )
    lines.append(f"Unchanged threats: {diff.unchanged}")
    return "\n".join(lines) + "\n"


def _diff_markdown(diff: Diff) -> str:
    lines = [f"# Threat register diff: `{diff.old_source}` to `{diff.new_source}`", ""]
    lines.append(
        f"Residual risk score **{diff.old_score}** ({diff.old_rating}) to "
        f"**{diff.new_score}** ({diff.new_rating}), change {diff.score_delta:+d}."
    )
    lines.append("")
    if diff.controls_added:
        lines.append("Controls added: " + ", ".join(f"`{c}`" for c in diff.controls_added))
    if diff.controls_removed:
        lines.append("Controls removed: " + ", ".join(f"`{c}`" for c in diff.controls_removed))
    lines.append("")
    lines += ["| Change | Threat | Before | After |", "|---|---|---|---|"]
    lines += [
        f"| added | `{f.threat_id}` {f.title} | - | {f.residual:g} {f.residual_band} |"
        for f in diff.added
    ]
    lines += [
        f"| removed | `{f.threat_id}` {f.title} | {f.residual:g} {f.residual_band} | - |"
        for f in diff.removed
    ]
    lines += [
        f"| changed | `{c.threat_id}` {c.title} | {c.old_residual:g} {c.old_band} | "
        f"{c.new_residual:g} {c.new_band} |"
        for c in diff.changed
    ]
    lines.append("")
    lines.append(f"Unchanged threats: {diff.unchanged}")
    return "\n".join(lines) + "\n"


def _diff_json(diff: Diff) -> str:
    from dataclasses import asdict

    payload = {
        "old_source": diff.old_source,
        "new_source": diff.new_source,
        "old_score": diff.old_score,
        "new_score": diff.new_score,
        "score_delta": diff.score_delta,
        "old_rating": diff.old_rating,
        "new_rating": diff.new_rating,
        "controls_added": diff.controls_added,
        "controls_removed": diff.controls_removed,
        "added": [asdict(f) | {"residual_band": f.residual_band} for f in diff.added],
        "removed": [asdict(f) | {"residual_band": f.residual_band} for f in diff.removed],
        "changed": [asdict(c) | {"delta": c.delta} for c in diff.changed],
        "unchanged": diff.unchanged,
    }
    return json.dumps(payload, indent=2) + "\n"


@app.command("diff")
def diff_command(
    old: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Previous system YAML.")],
    new: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Current system YAML.")],
    fmt: Annotated[
        TextFormat, typer.Option("--format", "-f", help="Output format.", case_sensitive=False)
    ] = TextFormat.table,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    fail_on_regression: Annotated[
        bool,
        typer.Option(
            "--fail-on-regression", help="Exit 1 when threats were added or the score rose."
        ),
    ] = False,
) -> None:
    """Show what changed in the threat register between two system descriptions."""
    diff = diff_analyses(_load(old), _load(new))
    renderers = {
        TextFormat.table: _diff_text,
        TextFormat.markdown: _diff_markdown,
        TextFormat.json: _diff_json,
    }
    _write(renderers[fmt](diff), output)
    if fail_on_regression and (diff.added or diff.score_delta > 0):
        typer.echo("regression: new threats or a higher residual risk score", err=True)
        raise typer.Exit(EXIT_FINDINGS)


@app.command("schema")
def schema_command(
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Print the JSON Schema for system descriptions."""
    _write(json.dumps(json_schema(), indent=2) + "\n", output)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
