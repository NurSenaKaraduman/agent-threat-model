import json

from typer.testing import CliRunner

from agent_threat_model import __version__
from agent_threat_model.cli import app
from tests.conftest import EXAMPLES

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_analyse_table_default(example_path):
    result = runner.invoke(app, ["analyse", str(example_path("support-bot"))])
    assert result.exit_code == 0, result.output
    assert "indirect-prompt-injection" in result.output
    assert "Residual risk score" in result.output


def test_analyze_alias_and_plain(example_path):
    result = runner.invoke(app, ["analyze", str(example_path("support-bot")), "--plain"])
    assert result.exit_code == 0
    assert "Threat model: Customer support assistant" in result.output


def test_analyse_writes_sarif_file(tmp_path, example_path):
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        app, ["analyse", str(example_path("coding-agent")), "--format", "sarif", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"


def test_analyse_fail_on_exit_code(example_path):
    result = runner.invoke(app, ["analyse", str(example_path("support-bot")), "--fail-on", "high"])
    assert result.exit_code == 1
    ok = runner.invoke(app, ["analyse", str(example_path("masoon-governed")), "--fail-on", "high"])
    assert ok.exit_code == 0, ok.output


def test_validate_ok_and_invalid(tmp_path, example_path):
    ok = runner.invoke(app, ["validate", str(example_path("finance-agent"))])
    assert ok.exit_code == 0 and ok.output.startswith("ok:")
    bad = tmp_path / "bad.yaml"
    bad.write_text("system: {name: x}\nagents: [{id: a, autonomy: act, inputs: [missing]}]\n")
    result = runner.invoke(app, ["validate", str(bad)])
    assert result.exit_code == 2
    assert "not a channel id" in result.output


def test_init_writes_example_and_refuses_overwrite(tmp_path):
    target = tmp_path / "system.yaml"
    first = runner.invoke(app, ["init", str(target)])
    assert first.exit_code == 0 and target.exists()
    assert target.read_text(encoding="utf-8") == (EXAMPLES / "support-bot.yaml").read_text(
        encoding="utf-8"
    )
    second = runner.invoke(app, ["init", str(target)])
    assert second.exit_code == 2
    forced = runner.invoke(app, ["init", str(target), "--force"])
    assert forced.exit_code == 0
    assert runner.invoke(app, ["validate", str(target)]).exit_code == 0


def test_catalogue_listing_formats():
    table = runner.invoke(app, ["catalogue"])
    assert table.exit_code == 0 and "Threats (" in table.output and "Controls (" in table.output
    md = runner.invoke(app, ["catalogue", "threats", "--format", "markdown"])
    assert md.exit_code == 0 and "| Id | Title |" in md.output
    js = runner.invoke(app, ["catalogue", "controls", "--format", "json"])
    data = json.loads(js.output)
    assert len(data["controls"]) >= 20 and "threats" not in data


def test_diff_command_and_regression_flag(example_path):
    result = runner.invoke(
        app, ["diff", str(example_path("finance-agent")), str(example_path("masoon-governed"))]
    )
    assert result.exit_code == 0
    assert "Residual risk score: 90" in result.output or "Residual risk score:" in result.output
    regress = runner.invoke(
        app,
        [
            "diff",
            str(example_path("masoon-governed")),
            str(example_path("finance-agent")),
            "--fail-on-regression",
        ],
    )
    assert regress.exit_code == 1


def test_schema_command_outputs_json_schema():
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0
    assert json.loads(result.output)["title"]
