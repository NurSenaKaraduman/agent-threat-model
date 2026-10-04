from agent_threat_model.diff import diff_analyses
from agent_threat_model.engine import analyse
from agent_threat_model.loader import load_system
from tests.conftest import build


def test_diff_detects_added_threat(analysed):
    before = analysed()
    data = build()
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
    after = analysed(**data)
    diff = diff_analyses(before, after)
    assert "unsandboxed-exec" in {f.threat_id for f in diff.added}
    assert not diff.removed
    assert diff.score_delta >= 0
    assert not diff.is_empty


def test_diff_detects_removed_threat_and_controls(analysed):
    before = analysed()
    after = analysed(controls=["audit-log", "kill-switch"])
    diff = diff_analyses(before, after)
    removed = {f.threat_id for f in diff.removed}
    assert {"missing-audit-trail", "missing-kill-switch"} <= removed
    assert diff.controls_added == ["audit-log", "kill-switch"]
    assert diff.new_score < diff.old_score


def test_diff_reports_mitigation_changes(analysed):
    before = analysed()
    after = analysed(controls=["rate-limiting"])
    diff = diff_analyses(before, after)
    assert "no-rate-limits" in {f.threat_id for f in diff.removed}
    change = next(c for c in diff.changed if c.threat_id == "denial-of-wallet")
    assert change.mitigations_now_present == ["rate-limiting"]
    assert change.new_residual < change.old_residual
    assert change.delta < 0


def test_identical_systems_produce_empty_diff(analysed):
    diff = diff_analyses(analysed(), analysed())
    assert diff.is_empty
    assert diff.unchanged == len(analysed().findings)


def test_example_diff_finance_to_governed(example_path):
    old = analyse(load_system(example_path("finance-agent")), source="finance")
    new = analyse(load_system(example_path("masoon-governed")), source="governed")
    diff = diff_analyses(old, new)
    assert diff.score_delta < -30
    assert "brokered-credentials" in diff.controls_added
    assert {"static-long-lived-credentials", "missing-audit-trail"} <= {
        f.threat_id for f in diff.removed
    }
