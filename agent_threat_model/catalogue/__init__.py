"""Threat and control catalogue: YAML files validated into pydantic models."""

from __future__ import annotations

import functools
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_threat_model.catalogue.references import (
    ATLAS_TECHNIQUES,
    OWASP_AGENTIC_2026,
    OWASP_LLM_2025,
)
from agent_threat_model.predicates import REGISTRY
from agent_threat_model.rules import Rule, parse_rule

OWASP_LLM_PATTERN = r"^LLM(0[1-9]|10)$"
OWASP_AGENTIC_PATTERN = r"^ASI(0[1-9]|10)$"
ATLAS_PATTERN = r"^AML\.T\d{4}(\.\d{3})?$"
CONTROL_ID_PATTERN = r"^[a-z0-9][a-z0-9-]*$"
THREAT_ID_PATTERN = r"^[a-z0-9][a-z0-9-]*$"


class Stride(StrEnum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information-disclosure"
    DENIAL_OF_SERVICE = "denial-of-service"
    ELEVATION_OF_PRIVILEGE = "elevation-of-privilege"


STRIDE_TITLES: dict[Stride, str] = {
    Stride.SPOOFING: "Spoofing",
    Stride.TAMPERING: "Tampering",
    Stride.REPUDIATION: "Repudiation",
    Stride.INFORMATION_DISCLOSURE: "Information disclosure",
    Stride.DENIAL_OF_SERVICE: "Denial of service",
    Stride.ELEVATION_OF_PRIVILEGE: "Elevation of privilege",
}


class ControlType(StrEnum):
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"


class Effort(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


EFFORT_ORDER: dict[Effort, int] = {Effort.LOW: 0, Effort.MEDIUM: 1, Effort.HIGH: 2}


class CatalogueModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Threat(CatalogueModel):
    id: Annotated[str, Field(pattern=THREAT_ID_PATTERN)]
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    stride: Stride
    owasp_llm: list[Annotated[str, Field(pattern=OWASP_LLM_PATTERN)]] = Field(default_factory=list)
    owasp_agentic: list[Annotated[str, Field(pattern=OWASP_AGENTIC_PATTERN)]] = Field(
        default_factory=list
    )
    mitre_atlas: list[Annotated[str, Field(pattern=ATLAS_PATTERN)]] = Field(default_factory=list)
    applies_when: Any
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    mitigations: list[Annotated[str, Field(pattern=CONTROL_ID_PATTERN)]] = Field(min_length=1)
    references: list[str] = Field(default_factory=list)

    @field_validator("applies_when")
    @classmethod
    def _parseable(cls, value: Any) -> Any:
        parse_rule(value)
        return value

    @field_validator("owasp_agentic")
    @classmethod
    def _known_agentic(cls, value: list[str]) -> list[str]:
        unknown = [v for v in value if v not in OWASP_AGENTIC_2026]
        if unknown:
            raise ValueError(f"unknown OWASP Agentic ids {unknown}; see references.py")
        return value

    @field_validator("mitre_atlas")
    @classmethod
    def _known_atlas(cls, value: list[str]) -> list[str]:
        unknown = [v for v in value if v not in ATLAS_TECHNIQUES]
        if unknown:
            raise ValueError(f"unknown MITRE ATLAS ids {unknown}; add them to references.py")
        return value

    @property
    def rule(self) -> Rule:
        return parse_rule(self.applies_when)

    @property
    def inherent_score(self) -> int:
        return self.likelihood * self.impact

    def owasp_llm_labels(self) -> list[str]:
        return [f"{i}: {OWASP_LLM_2025[i]}" for i in self.owasp_llm]

    def owasp_agentic_labels(self) -> list[str]:
        return [f"{i}: {OWASP_AGENTIC_2026[i]}" for i in self.owasp_agentic]


class Control(CatalogueModel):
    id: Annotated[str, Field(pattern=CONTROL_ID_PATTERN)]
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    type: ControlType
    effort: Effort
    references: list[str] = Field(default_factory=list)


class CatalogueError(ValueError):
    """Raised when the catalogue files are inconsistent."""


class Catalogue(BaseModel):
    model_config = ConfigDict(frozen=True)

    threats: dict[str, Threat]
    controls: dict[str, Control]

    @classmethod
    def from_lists(cls, threats: list[Threat], controls: list[Control]) -> Catalogue:
        threat_map: dict[str, Threat] = {}
        for threat in threats:
            if threat.id in threat_map:
                raise CatalogueError(f"duplicate threat id {threat.id}")
            threat_map[threat.id] = threat
        control_map: dict[str, Control] = {}
        for control in controls:
            if control.id in control_map:
                raise CatalogueError(f"duplicate control id {control.id}")
            control_map[control.id] = control
        problems: list[str] = []
        for threat in threats:
            for name in threat.rule.predicate_names():
                if name not in REGISTRY:
                    problems.append(f"threat {threat.id} uses unknown predicate {name}")
            for control_id in threat.mitigations:
                if control_id not in control_map:
                    problems.append(f"threat {threat.id} cites unknown control {control_id}")
        if problems:
            raise CatalogueError("; ".join(problems))
        return cls(threats=threat_map, controls=control_map)

    def threats_mitigated_by(self, control_id: str) -> list[Threat]:
        return [t for t in self.threats.values() if control_id in t.mitigations]

    def control(self, control_id: str) -> Control:
        return self.controls[control_id]


def _read_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def catalogue_dir() -> Path:
    """Directory holding the bundled YAML files."""
    return Path(str(resources.files("agent_threat_model.catalogue")))


def load_catalogue_from(directory: Path) -> Catalogue:
    threats_raw = _read_yaml(directory / "threats.yaml") or {}
    controls_raw = _read_yaml(directory / "controls.yaml") or {}
    threats = [Threat.model_validate(item) for item in threats_raw.get("threats", [])]
    controls = [Control.model_validate(item) for item in controls_raw.get("controls", [])]
    return Catalogue.from_lists(threats, controls)


@functools.lru_cache(maxsize=1)
def load_catalogue() -> Catalogue:
    """Load and cache the bundled catalogue."""
    return load_catalogue_from(catalogue_dir())
