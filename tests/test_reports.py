import json

from agent_threat_model.diagram import mermaid
from agent_threat_model.engine import analyse
from agent_threat_model.loader import load_system
from agent_threat_model.reporters import render
from agent_threat_model.reporters.sarif import sarif_document
from agent_threat_model.reporters.table import render_plain, render_table


def _support_bot(example_path):
    path = example_path("support-bot")
    analysis = analyse(load_system(path), source="examples/support-bot.yaml")
    analysis.source_text = path.read_text(encoding="utf-8")
    return analysis


def test_sarif_basic_structure(example_path):
    doc = sarif_document(_support_bot(example_path))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "agent-threat-model" and driver["version"]
    rule_ids = [r["id"] for r in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert run["results"], "expected at least one result"
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert driver["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        assert result["message"]["text"]
        for location in result["locations"]:
            region = location["physicalLocation"]["region"]
            assert region["startLine"] >= 1
            assert location["physicalLocation"]["artifactLocation"]["uri"] == (
                "examples/support-bot.yaml"
            )
    tags = {tag for rule in driver["rules"] for tag in rule["properties"]["tags"]}
    assert any(tag.startswith("owasp-agentic/ASI") for tag in tags)
    for rule in driver["rules"]:
        severity = float(rule["properties"]["security-severity"])
        assert 0.0 <= severity <= 10.0
        assert rule["shortDescription"]["text"]
        assert rule["helpUri"].startswith("https://")


def test_sarif_locations_point_at_element_lines(example_path):
    analysis = _support_bot(example_path)
    doc = sarif_document(analysis)
    results = doc["runs"][0]["results"]
    result = next(r for r in results if r["ruleId"] == "indirect-prompt-injection")
    lines = [loc["physicalLocation"]["region"]["startLine"] for loc in result["locations"]]
    assert all(line > 1 for line in lines)
    assert json.loads(render(analysis, "sarif")) == doc


def test_markdown_contains_expected_sections(example_path):
    text = render(_support_bot(example_path), "markdown")
    for heading in (
        "# Threat model: Customer support assistant",
        "## Executive summary",
        "## System diagram",
        "```mermaid",
        "## Threat register",
        "## Control checklist",
        "### Low effort",
        "## Residual risk",
        "Residual risk score:",
    ):
        assert heading in text, heading
    assert "indirect-prompt-injection" in text
    assert "| OWASP Agentic Top 10 (2026) | ASI01 Agent Goal Hijack |" in text
    assert "- [x] `output-encoding`" in text
    assert "- [ ] `approval-gates`" in text


def test_json_report_structure(example_path):
    data = json.loads(render(_support_bot(example_path), "json"))
    assert data["tool"]["name"] == "agent-threat-model"
    assert data["summary"]["residual_risk_score"] == data["summary"]["residual_risk_score"]
    assert data["findings"][0]["rank"] == 1
    assert {"threat_id", "residual", "elements", "mitigations_missing"} <= set(data["findings"][0])
    assert data["system"]["system"]["name"] == "Customer support assistant"


def test_html_report_is_self_contained(example_path):
    text = render(_support_bot(example_path), "html")
    assert text.startswith("<!doctype html>")
    assert "<title>Threat model: Customer support assistant</title>" in text
    assert 'class="mermaid"' in text
    assert "indirect-prompt-injection" in text
    assert "<script" in text and "</html>" in text


def test_table_rich_and_plain_agree_on_content(example_path):
    analysis = _support_bot(example_path)
    rich_text = render_table(analysis)
    plain_text = render_plain(analysis)
    for finding in analysis.findings[:5]:
        assert finding.threat_id in rich_text
        assert finding.threat_id in plain_text
    assert "Residual risk score" in plain_text
    assert "\x1b[" not in rich_text


def test_mermaid_marks_untrusted_channels_red_and_trusted_dashed(example_path):
    system = load_system(example_path("support-bot"))
    text = mermaid(system)
    assert text.startswith("flowchart LR")
    assert "c_knowledge_base -.-> a_support_bot" in text
    assert "c_inbound_email ==> a_support_bot" in text
    assert "linkStyle" in text and "#c0392b" in text
    assert 'subgraph stores["Data stores"]' in text
    assert "t_lookup_customer --> s_crm" in text
