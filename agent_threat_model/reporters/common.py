"""Helpers shared by renderers."""

from __future__ import annotations

import re

from agent_threat_model.catalogue import STRIDE_TITLES, Stride
from agent_threat_model.catalogue.references import OWASP_AGENTIC_2026, OWASP_LLM_2025
from agent_threat_model.engine import Analysis, Finding

BAND_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def stride_title(value: str) -> str:
    return STRIDE_TITLES[Stride(value)]


def owasp_labels(ids: list[str]) -> list[str]:
    return [f"{i} {OWASP_LLM_2025.get(i, '')}".strip() for i in ids]


def agentic_labels(ids: list[str]) -> list[str]:
    return [f"{i} {OWASP_AGENTIC_2026.get(i, '')}".strip() for i in ids]


def band_label(band: str) -> str:
    return BAND_LABELS.get(band, band)


def severity_text(finding: Finding) -> str:
    return (
        f"{finding.inherent} ({band_label(finding.inherent_band)}) -> "
        f"{finding.residual:g} ({band_label(finding.residual_band)})"
    )


def summary_sentence(analysis: Analysis) -> str:
    counts = analysis.band_counts()
    n = len(analysis.findings)
    system = analysis.system
    parts = [
        f"{n} of the catalogue threats apply to '{system.system.name}'",
        f"({counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low after mitigations).",
        f"Residual risk score {analysis.residual_risk_score}/100 ({band_label(analysis.rating)}).",
    ]
    if system.controls:
        parts.append(
            f"The {len(system.controls)} control(s) in place reduce modelled risk by "
            f"{analysis.reduction_percent}% compared with the same system with no controls."
        )
    else:
        parts.append("No controls are declared, so inherent and residual risk are equal.")
    return " ".join(parts)


def top_missing_controls(analysis: Analysis, limit: int = 5) -> list[tuple[str, str, int]]:
    """Missing controls ordered by how many applicable threats they mitigate."""
    missing = sorted(
        analysis.controls_missing(), key=lambda c: (-len(c.threats), c.effort_rank, c.id)
    )
    return [(c.id, c.title, len(c.threats)) for c in missing[:limit]]


def line_of_element(text: str | None, element_id: str) -> int | None:
    """1-based line number of ``id: <element_id>`` in YAML text, if present."""
    if not text:
        return None
    pattern = re.compile(rf"^\s*-?\s*id:\s*['\"]?{re.escape(element_id)}['\"]?\s*(#.*)?$")
    for number, line in enumerate(text.splitlines(), start=1):
        if pattern.match(line):
            return number
    return None
