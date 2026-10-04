import re

from agent_threat_model.catalogue import Catalogue, CatalogueError, Control, Threat, load_catalogue
from agent_threat_model.catalogue.references import OWASP_AGENTIC_2026
from agent_threat_model.predicates import REGISTRY

REQUIRED_THREATS = {
    "indirect-prompt-injection",
    "tool-poisoning",
    "credential-exfiltration-via-tool-args",
    "excessive-agency",
    "ssrf-via-url-tool",
    "data-exfiltration-via-messaging",
    "memory-poisoning",
    "unsandboxed-exec",
    "static-long-lived-credentials",
    "missing-audit-trail",
    "missing-kill-switch",
    "rag-poisoning",
    "over-permissive-scopes",
    "approval-fatigue",
    "insecure-output-handling",
    "supply-chain-unpinned",
    "no-rate-limits",
    "cross-agent-trust",
    "hitl-bypass",
    "denial-of-wallet",
}


def test_catalogue_sizes(catalogue):
    assert len(catalogue.threats) >= 25
    assert len(catalogue.controls) >= 20


def test_required_threats_present(catalogue):
    assert set(catalogue.threats) >= REQUIRED_THREATS


def test_every_mitigation_and_predicate_resolves(catalogue):
    for threat in catalogue.threats.values():
        assert threat.mitigations, threat.id
        for control_id in threat.mitigations:
            assert control_id in catalogue.controls, (threat.id, control_id)
        for name in threat.rule.predicate_names():
            assert name in REGISTRY, (threat.id, name)


def test_every_control_is_cited_and_has_real_references(catalogue):
    cited = {m for t in catalogue.threats.values() for m in t.mitigations}
    for control in catalogue.controls.values():
        assert control.id in cited, f"control {control.id} mitigates nothing"
        assert control.references, control.id
        for ref in control.references:
            assert re.match(r"^https://[a-z0-9.-]+/", ref), ref


def test_identifier_formats(catalogue):
    for threat in catalogue.threats.values():
        for owasp in threat.owasp_llm:
            assert re.fullmatch(r"LLM(0[1-9]|10)", owasp)
        for atlas in threat.mitre_atlas:
            assert re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", atlas)
        for agentic in threat.owasp_agentic:
            assert re.fullmatch(r"ASI(0[1-9]|10)", agentic)
            assert agentic in OWASP_AGENTIC_2026
        assert 1 <= threat.likelihood <= 5 and 1 <= threat.impact <= 5


def test_loader_rejects_dangling_mitigation():
    threat = Threat(
        id="t",
        title="t",
        description="d",
        stride="tampering",
        applies_when="agent_has_any_tool",
        likelihood=1,
        impact=1,
        mitigations=["nope"],
    )
    try:
        Catalogue.from_lists([threat], [])
    except CatalogueError as error:
        assert "unknown control nope" in str(error)
    else:
        raise AssertionError("expected CatalogueError")


def test_loader_rejects_unknown_atlas_id():
    try:
        Threat(
            id="t",
            title="t",
            description="d",
            stride="tampering",
            mitre_atlas=["AML.T9999"],
            applies_when="agent_has_any_tool",
            likelihood=1,
            impact=1,
            mitigations=["audit-log"],
        )
    except ValueError as error:
        assert "AML.T9999" in str(error)
    else:
        raise AssertionError("expected validation error")


def test_control_model_round_trip():
    control = Control(
        id="x", title="X", description="d", type="preventive", effort="low", references=[]
    )
    assert control.model_dump()["type"] == "preventive"
    assert load_catalogue() is load_catalogue()  # cached


def test_owasp_agentic_allowlist_and_coverage(catalogue):
    assert len(OWASP_AGENTIC_2026) == 10
    assert OWASP_AGENTIC_2026["ASI01"] == "Agent Goal Hijack"
    assert OWASP_AGENTIC_2026["ASI10"] == "Rogue Agents"
    mapped = [t for t in catalogue.threats.values() if t.owasp_agentic]
    assert len(mapped) >= 25
    used = {i for t in mapped for i in t.owasp_agentic}
    assert used == set(OWASP_AGENTIC_2026), "every ASI entry should be used at least once"
    assert catalogue.threats["indirect-prompt-injection"].owasp_agentic_labels() == [
        "ASI01: Agent Goal Hijack"
    ]


def test_loader_rejects_unknown_agentic_id():
    try:
        Threat(
            id="t",
            title="t",
            description="d",
            stride="tampering",
            owasp_agentic=["ASI11"],
            applies_when="agent_has_any_tool",
            likelihood=1,
            impact=1,
            mitigations=["audit-log"],
        )
    except ValueError as error:
        assert "ASI11" in str(error) or "pattern" in str(error)
    else:
        raise AssertionError("expected validation error")
