import pytest

from agent_threat_model.engine import analyse
from agent_threat_model.loader import load_system
from agent_threat_model.reporters import render
from agent_threat_model.template import TEMPLATE
from tests.conftest import EXAMPLE_NAMES, EXAMPLES, ROOT


@pytest.mark.parametrize("name", EXAMPLE_NAMES)
def test_example_analyses_without_error(name, example_path):
    system = load_system(example_path(name))
    analysis = analyse(system, source=f"examples/{name}.yaml")
    assert analysis.findings, "every example should trigger at least one threat"
    assert 0 <= analysis.residual_risk_score <= 100
    for fmt in ("table", "markdown", "json", "sarif", "html"):
        assert render(analysis, fmt)


def test_masoon_governed_has_lower_residual_risk_than_finance(example_path):
    finance = analyse(load_system(example_path("finance-agent")))
    governed = analyse(load_system(example_path("masoon-governed")))
    assert governed.residual_risk_score < finance.residual_risk_score - 30
    assert governed.residual_total < finance.residual_total
    assert len(governed.findings) < len(finance.findings)
    assert governed.rating in {"low", "medium"}
    assert finance.rating in {"high", "critical"}


def test_support_bot_hits_the_obvious_threats(example_path):
    analysis = analyse(load_system(example_path("support-bot")))
    ids = {f.threat_id for f in analysis.findings}
    assert {
        "indirect-prompt-injection",
        "data-exfiltration-via-messaging",
        "rag-poisoning",
        "static-long-lived-credentials",
        "missing-audit-trail",
    } <= ids


def test_coding_agent_hits_exec_threats(example_path):
    analysis = analyse(load_system(example_path("coding-agent")))
    ids = {f.threat_id for f in analysis.findings}
    assert {"unsandboxed-exec", "tool-poisoning", "ssrf-via-url-tool", "memory-poisoning"} <= ids
    assert analysis.findings[0].threat_id == "unsandboxed-exec"


def test_init_template_matches_support_bot_example():
    assert (EXAMPLES / "support-bot.yaml").read_text(encoding="utf-8") == TEMPLATE


@pytest.mark.parametrize("name", EXAMPLE_NAMES)
@pytest.mark.parametrize("fmt,suffix", [("markdown", "md"), ("json", "json"), ("sarif", "sarif")])
def test_committed_reports_are_current(name, fmt, suffix, example_path):
    path = example_path(name)
    analysis = analyse(load_system(path), source=f"examples/{name}.yaml")
    analysis.source_text = path.read_text(encoding="utf-8")
    committed = ROOT / "examples" / "reports" / f"{name}.{suffix}"
    assert committed.exists(), "run: make reports"
    assert committed.read_text(encoding="utf-8") == render(analysis, fmt), "run: make reports"
