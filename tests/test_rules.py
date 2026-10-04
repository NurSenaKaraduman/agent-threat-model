import pytest

from agent_threat_model.rules import Match, Rule, RuleSyntaxError, evaluate, parse_rule


def _registry():
    return {
        "yes": lambda ctx, **kw: Match.of(["a"], ["yes matched"]),
        "no": lambda ctx, **kw: Match.no(),
        "echo": lambda ctx, **kw: Match.of(list(kw.get("kinds", ())), [str(kw)]),
    }


def test_parse_plain_call():
    rule = parse_rule("yes")
    assert rule.op == "call"
    assert rule.call is not None
    assert rule.call.name == "yes"
    assert rule.text() == "yes"


def test_parse_call_with_arguments_and_alternatives():
    rule = parse_rule("echo(kinds=exec|write, min=3)")
    assert rule.call is not None
    assert rule.call.kwargs() == {"kinds": ("exec", "write"), "min": ("3",)}
    assert rule.text() == "echo(kinds=exec|write, min=3)"


def test_parse_nested_mapping():
    rule = parse_rule({"all": ["yes", {"any": ["no", "yes"]}, {"not": "no"}]})
    assert rule.op == "all"
    assert rule.predicate_names() == {"yes", "no"}
    assert rule.text() == "all(yes, any(no, yes), not(no))"


@pytest.mark.parametrize(
    "bad",
    ["Yes", "yes(", "yes(kinds)", "yes(Kind=x)", {"all": []}, {"xor": ["yes"]}, {"all": "yes"}, 3],
)
def test_syntax_errors(bad):
    with pytest.raises(RuleSyntaxError):
        parse_rule(bad)


def test_evaluate_all_any_not_semantics():
    registry = _registry()
    assert evaluate(parse_rule({"all": ["yes", "no"]}), None, registry).matched is False
    hit = evaluate(parse_rule({"any": ["no", "yes"]}), None, registry)
    assert hit.matched and hit.elements == ("a",) and hit.reasons == ("yes matched",)
    assert evaluate(parse_rule({"not": "no"}), None, registry).matched is True
    assert evaluate(parse_rule({"not": "yes"}), None, registry).matched is False


def test_evaluate_passes_arguments_and_merges_elements():
    registry = _registry()
    hit = evaluate(parse_rule({"all": ["yes", "echo(kinds=x|y)"]}), None, registry)
    assert hit.matched
    assert hit.elements == ("a", "x", "y")


def test_unknown_predicate_raises():
    with pytest.raises(KeyError, match="unknown predicate"):
        evaluate(Rule("call", call=parse_rule("missing").call), None, {})
