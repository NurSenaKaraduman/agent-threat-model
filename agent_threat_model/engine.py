"""Analysis engine: evaluate the catalogue against a system and score the result.

Scoring is deliberately simple and fully explainable:

* inherent severity = likelihood x impact (1..25), straight from the catalogue;
* impact is raised by one (to at most 5) when a regulated data store is among
  the affected elements;
* each control in place that the threat lists as a mitigation contributes a
  weight (preventive 1.0, detective 0.6, corrective 0.5); coverage is the sum
  of present weights over the sum of all listed weights;
* residual severity = inherent x (1 - 0.8 x coverage), so a fully mitigated
  threat keeps 20 percent of its inherent score because no control is perfect;
* the residual risk score (0..100) is the residual total divided by the
  inherent total the same system would have with no controls at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_threat_model import __version__
from agent_threat_model.catalogue import (
    EFFORT_ORDER,
    Catalogue,
    Control,
    ControlType,
    Threat,
    load_catalogue,
)
from agent_threat_model.predicates import REGISTRY, Context
from agent_threat_model.rules import evaluate
from agent_threat_model.schema import AgentSystem, Sensitivity

CONTROL_WEIGHT: dict[ControlType, float] = {
    ControlType.PREVENTIVE: 1.0,
    ControlType.DETECTIVE: 0.6,
    ControlType.CORRECTIVE: 0.5,
}
MAX_REDUCTION = 0.8
SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (20, "critical"),
    (12, "high"),
    (6, "medium"),
    (0, "low"),
)
BAND_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
SCORE_RATINGS: tuple[tuple[int, str], ...] = (
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (0, "low"),
)


def severity_band(score: float) -> str:
    """Map a 1..25 severity score to critical, high, medium or low."""
    for floor, name in SEVERITY_BANDS:
        if score >= floor:
            return name
    return "low"


def score_rating(score: int) -> str:
    for floor, name in SCORE_RATINGS:
        if score >= floor:
            return name
    return "low"


@dataclass
class Finding:
    """One applicable threat with its scoring and the evidence behind it."""

    threat_id: str
    title: str
    description: str
    stride: str
    owasp_llm: list[str]
    owasp_agentic: list[str]
    mitre_atlas: list[str]
    rule: str
    likelihood: int
    impact: int
    impact_adjusted: bool
    inherent: int
    elements: list[str]
    reasons: list[str]
    mitigations_present: list[str]
    mitigations_missing: list[str]
    coverage: float
    residual: float
    references: list[str] = field(default_factory=list)

    @property
    def inherent_band(self) -> str:
        return severity_band(self.inherent)

    @property
    def residual_band(self) -> str:
        return severity_band(self.residual)

    @property
    def sort_key(self) -> tuple[float, int, str]:
        return (-self.residual, -self.inherent, self.threat_id)


@dataclass
class ControlStatus:
    id: str
    title: str
    type: str
    effort: str
    present: bool
    threats: list[str]

    @property
    def effort_rank(self) -> int:
        return EFFORT_ORDER[self.effort]  # type: ignore[index]


@dataclass
class Analysis:
    system: AgentSystem
    source: str
    findings: list[Finding]
    controls: list[ControlStatus]
    inherent_total: float
    residual_total: float
    baseline_total: float
    residual_risk_score: int
    rating: str
    tool_version: str = __version__
    source_text: str | None = None

    def band_counts(self, residual: bool = True) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            counts[finding.residual_band if residual else finding.inherent_band] += 1
        return counts

    def finding(self, threat_id: str) -> Finding | None:
        return next((f for f in self.findings if f.threat_id == threat_id), None)

    def controls_missing(self) -> list[ControlStatus]:
        return sorted(
            (c for c in self.controls if not c.present),
            key=lambda c: (c.effort_rank, -len(c.threats), c.id),
        )

    def controls_present(self) -> list[ControlStatus]:
        return sorted((c for c in self.controls if c.present), key=lambda c: c.id)

    @property
    def reduction_percent(self) -> int:
        return max(0, 100 - self.residual_risk_score)


def _coverage(
    threat: Threat, system: AgentSystem, catalogue: Catalogue
) -> tuple[float, list, list]:
    present: list[str] = []
    missing: list[str] = []
    weight_total = 0.0
    weight_present = 0.0
    for control_id in threat.mitigations:
        control: Control = catalogue.control(control_id)
        weight = CONTROL_WEIGHT[control.type]
        weight_total += weight
        if system.has_control(control_id):
            present.append(control_id)
            weight_present += weight
        else:
            missing.append(control_id)
    coverage = weight_present / weight_total if weight_total else 0.0
    return coverage, present, missing


def _findings(system: AgentSystem, catalogue: Catalogue) -> list[Finding]:
    context = Context(system)
    regulated = {s.id for s in system.data_stores if s.sensitivity == Sensitivity.REGULATED}
    findings: list[Finding] = []
    for threat in catalogue.threats.values():
        match = evaluate(threat.rule, context, REGISTRY)
        if not match.matched:
            continue
        impact = threat.impact
        adjusted = False
        if regulated & set(match.elements) and impact < 5:
            impact += 1
            adjusted = True
        inherent = threat.likelihood * impact
        coverage, present, missing = _coverage(threat, system, catalogue)
        residual = round(inherent * (1 - MAX_REDUCTION * coverage), 1)
        findings.append(
            Finding(
                threat_id=threat.id,
                title=threat.title,
                description=threat.description,
                stride=threat.stride.value,
                owasp_llm=list(threat.owasp_llm),
                owasp_agentic=list(threat.owasp_agentic),
                mitre_atlas=list(threat.mitre_atlas),
                rule=threat.rule.text(),
                likelihood=threat.likelihood,
                impact=impact,
                impact_adjusted=adjusted,
                inherent=inherent,
                elements=list(match.elements),
                reasons=list(match.reasons),
                mitigations_present=present,
                mitigations_missing=missing,
                coverage=round(coverage, 3),
                residual=residual,
                references=list(threat.references),
            )
        )
    findings.sort(key=lambda f: f.sort_key)
    return findings


def analyse(
    system: AgentSystem, catalogue: Catalogue | None = None, source: str = "system.yaml"
) -> Analysis:
    """Run every catalogue rule against the system and score the result."""
    catalogue = catalogue or load_catalogue()
    findings = _findings(system, catalogue)
    baseline_system = system.model_copy(update={"controls": []})
    baseline_total = float(sum(f.inherent for f in _findings(baseline_system, catalogue)))
    inherent_total = float(sum(f.inherent for f in findings))
    residual_total = round(sum(f.residual for f in findings), 1)
    score = round(100 * residual_total / baseline_total) if baseline_total else 0
    score = max(0, min(100, score))

    relevant: dict[str, ControlStatus] = {}
    for finding in findings:
        for control_id in finding.mitigations_present + finding.mitigations_missing:
            control = catalogue.control(control_id)
            status = relevant.setdefault(
                control_id,
                ControlStatus(
                    id=control.id,
                    title=control.title,
                    type=control.type.value,
                    effort=control.effort.value,
                    present=system.has_control(control_id),
                    threats=[],
                ),
            )
            status.threats.append(finding.threat_id)
    for control_id in system.controls:
        if control_id not in relevant:
            control = catalogue.control(control_id)
            relevant[control_id] = ControlStatus(
                id=control.id,
                title=control.title,
                type=control.type.value,
                effort=control.effort.value,
                present=True,
                threats=[],
            )

    return Analysis(
        system=system,
        source=source,
        findings=findings,
        controls=sorted(relevant.values(), key=lambda c: c.id),
        inherent_total=inherent_total,
        residual_total=residual_total,
        baseline_total=baseline_total,
        residual_risk_score=score,
        rating=score_rating(score),
    )
