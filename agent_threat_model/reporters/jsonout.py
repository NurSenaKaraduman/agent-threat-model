"""JSON report: everything a downstream tool might want, with a stable schema version."""

from __future__ import annotations

import json
from dataclasses import asdict

from agent_threat_model.engine import Analysis

JSON_SCHEMA_VERSION = "1"


def analysis_to_dict(analysis: Analysis) -> dict:
    findings = []
    for rank, finding in enumerate(analysis.findings, start=1):
        data = asdict(finding)
        data["rank"] = rank
        data["inherent_band"] = finding.inherent_band
        data["residual_band"] = finding.residual_band
        findings.append(data)
    controls = [asdict(c) for c in analysis.controls]
    return {
        "report_schema_version": JSON_SCHEMA_VERSION,
        "tool": {"name": "agent-threat-model", "version": analysis.tool_version},
        "source": analysis.source,
        "system": analysis.system.model_dump(mode="json"),
        "summary": {
            "findings": len(analysis.findings),
            "residual_bands": analysis.band_counts(),
            "inherent_bands": analysis.band_counts(residual=False),
            "inherent_total": analysis.inherent_total,
            "residual_total": analysis.residual_total,
            "baseline_total": analysis.baseline_total,
            "residual_risk_score": analysis.residual_risk_score,
            "rating": analysis.rating,
            "reduction_percent": analysis.reduction_percent,
        },
        "findings": findings,
        "controls": controls,
    }


def render_json(analysis: Analysis) -> str:
    return json.dumps(analysis_to_dict(analysis), indent=2, sort_keys=False) + "\n"
