from agent_threat_model.engine import MAX_REDUCTION, score_rating, severity_band
from tests.conftest import build


def test_severity_bands():
    assert severity_band(25) == "critical"
    assert severity_band(20) == "critical"
    assert severity_band(19.9) == "high"
    assert severity_band(12) == "high"
    assert severity_band(11.9) == "medium"
    assert severity_band(6) == "medium"
    assert severity_band(5.9) == "low"
    assert severity_band(1) == "low"


def test_score_rating_bands():
    assert score_rating(100) == "critical"
    assert score_rating(75) == "critical"
    assert score_rating(74) == "high"
    assert score_rating(50) == "high"
    assert score_rating(49) == "medium"
    assert score_rating(24) == "low"


def _exec_system(**extra):
    data = build(**extra)
    data["tools"].append(
        {
            "id": "sh",
            "kind": "exec",
            "auth": "none",
            "sandboxed": False,
            "pinned": True,
            "scope": "narrow",
        }
    )
    data["agents"][0]["tools"].append("sh")
    return data


def test_inherent_equals_likelihood_times_impact(analysed, catalogue):
    analysis = analysed(**_exec_system())
    finding = analysis.finding("unsandboxed-exec")
    threat = catalogue.threats["unsandboxed-exec"]
    assert finding is not None
    assert finding.inherent == threat.likelihood * threat.impact == 20
    assert finding.residual == finding.inherent  # no controls declared
    assert analysis.residual_risk_score == 100


def test_controls_reduce_residual_with_type_weights(analysed, catalogue):
    without = analysed(**_exec_system())
    with_control = analysed(**_exec_system(controls=["sandboxed-execution"]))
    before = without.finding("unsandboxed-exec")
    after = with_control.finding("unsandboxed-exec")
    assert after.residual < before.residual
    weights = {"preventive": 1.0, "detective": 0.6, "corrective": 0.5}
    threat = catalogue.threats["unsandboxed-exec"]
    total = sum(weights[catalogue.control(c).type.value] for c in threat.mitigations)
    expected = round(before.inherent * (1 - MAX_REDUCTION * (1.0 / total)), 1)
    assert after.residual == expected
    assert after.mitigations_present == ["sandboxed-execution"]
    assert with_control.residual_risk_score < without.residual_risk_score


def test_full_mitigation_keeps_twenty_percent(analysed, catalogue):
    threat = catalogue.threats["unsandboxed-exec"]
    analysis = analysed(**_exec_system(controls=list(threat.mitigations)))
    finding = analysis.finding("unsandboxed-exec")
    assert finding.coverage == 1.0
    assert finding.residual == round(finding.inherent * (1 - MAX_REDUCTION), 1)


def test_regulated_store_raises_impact(analysed):
    data = build(data_stores=[{"id": "pii", "sensitivity": "regulated"}])
    data["tools"][0]["data_stores"] = ["pii"]
    finding = analysed(**data).finding("sensitive-data-disclosure")
    assert finding is not None
    assert finding.impact_adjusted is True
    assert finding.impact == 5
    data["data_stores"][0]["sensitivity"] = "confidential"
    finding2 = analysed(**data).finding("sensitive-data-disclosure")
    assert finding2.impact_adjusted is False and finding2.impact == 4


def test_findings_are_ranked_by_residual_then_inherent(analysed):
    analysis = analysed(**_exec_system())
    residuals = [f.residual for f in analysis.findings]
    assert residuals == sorted(residuals, reverse=True)


def test_control_that_removes_threat_lowers_score(analysed):
    no_audit = analysed()
    audited = analysed(controls=["audit-log"])
    assert no_audit.finding("missing-audit-trail") is not None
    assert audited.finding("missing-audit-trail") is None
    assert audited.residual_risk_score < no_audit.residual_risk_score
    assert audited.baseline_total == no_audit.baseline_total
