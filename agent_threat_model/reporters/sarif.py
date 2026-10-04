"""SARIF 2.1.0 output, suitable for GitHub code scanning upload.

One rule per catalogue threat that applies, one result per finding. The
location points at the line of the first affected element's ``id:`` in the
source YAML when the text is available, otherwise at line 1.
"""

from __future__ import annotations

import hashlib
import json

from agent_threat_model.catalogue.references import OWASP_LLM_URL, atlas_url
from agent_threat_model.engine import Analysis, Finding
from agent_threat_model.reporters.common import (
    agentic_labels,
    line_of_element,
    owasp_labels,
    stride_title,
)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/basitalisandhu/agent-threat-model"
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _rule_name(threat_id: str) -> str:
    return "".join(part.capitalize() for part in threat_id.split("-"))


def _security_severity(finding: Finding) -> str:
    """Scale 1..25 residual severity to the 0..10 scale code scanning displays."""
    return f"{min(10.0, round(finding.residual / 2.5, 1)):.1f}"


def _help_markdown(finding: Finding) -> str:
    lines = [f"**{finding.title}**", "", finding.description, ""]
    lines.append(f"STRIDE: {stride_title(finding.stride)}")
    if finding.owasp_llm:
        lines.append(f"OWASP LLM Top 10 (2025): {', '.join(owasp_labels(finding.owasp_llm))}")
    if finding.owasp_agentic:
        lines.append(
            "OWASP Top 10 for Agentic Applications (2026): "
            + ", ".join(agentic_labels(finding.owasp_agentic))
        )
    if finding.mitre_atlas:
        lines.append(
            "MITRE ATLAS: " + ", ".join(f"[{i}]({atlas_url(i)})" for i in finding.mitre_atlas)
        )
    lines.append("")
    lines.append(
        "Mitigations: " + ", ".join(finding.mitigations_present + finding.mitigations_missing)
    )
    return "\n".join(lines)


def _rule(finding: Finding) -> dict:
    tags = ["security", f"stride/{finding.stride}"]
    tags += [f"owasp-llm/{i}" for i in finding.owasp_llm]
    tags += [f"owasp-agentic/{i}" for i in finding.owasp_agentic]
    tags += [f"mitre-atlas/{i}" for i in finding.mitre_atlas]
    help_uri = finding.references[0] if finding.references else OWASP_LLM_URL
    return {
        "id": finding.threat_id,
        "name": _rule_name(finding.threat_id),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.description, "markdown": _help_markdown(finding)},
        "helpUri": help_uri,
        "defaultConfiguration": {"level": LEVELS[finding.residual_band]},
        "properties": {
            "tags": tags,
            "security-severity": _security_severity(finding),
            "precision": "medium",
            "problem.severity": LEVELS[finding.residual_band],
        },
    }


def _locations(analysis: Analysis, finding: Finding) -> list[dict]:
    uri = analysis.source.replace("\\", "/")
    locations: list[dict] = []
    for element in finding.elements[:5]:
        line = line_of_element(analysis.source_text, element)
        if line is None:
            continue
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line, "startColumn": 1},
                },
                "logicalLocations": [{"name": element, "kind": "object"}],
            }
        )
    if not locations:
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }
        )
    return locations


def _result(analysis: Analysis, finding: Finding, rule_index: int) -> dict:
    missing = ", ".join(finding.mitigations_missing) or "none"
    message = (
        f"{finding.title}: residual severity {finding.residual:g} "
        f"({finding.residual_band}). {finding.reasons[0]}. "
        f"Missing mitigations: {missing}."
    )
    fingerprint = hashlib.sha256(
        (finding.threat_id + "|" + ",".join(sorted(finding.elements))).encode()
    ).hexdigest()[:32]
    return {
        "ruleId": finding.threat_id,
        "ruleIndex": rule_index,
        "level": LEVELS[finding.residual_band],
        "message": {"text": message},
        "locations": _locations(analysis, finding),
        "partialFingerprints": {"threatElements/v1": fingerprint},
        "properties": {
            "inherent": finding.inherent,
            "residual": finding.residual,
            "elements": finding.elements,
            "reasons": finding.reasons,
            "mitigationsPresent": finding.mitigations_present,
            "mitigationsMissing": finding.mitigations_missing,
        },
    }


def sarif_document(analysis: Analysis) -> dict:
    rules = [_rule(f) for f in analysis.findings]
    results = [_result(analysis, f, i) for i, f in enumerate(analysis.findings)]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-threat-model",
                        "version": analysis.tool_version,
                        "semanticVersion": analysis.tool_version,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": results,
                "properties": {
                    "residualRiskScore": analysis.residual_risk_score,
                    "rating": analysis.rating,
                    "systemName": analysis.system.system.name,
                },
            }
        ],
    }


def render_sarif(analysis: Analysis) -> str:
    return json.dumps(sarif_document(analysis), indent=2) + "\n"
