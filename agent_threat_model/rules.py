"""A small rule DSL that decides when a catalogue threat applies.

A rule is one of:

* a string naming a predicate, optionally with keyword arguments, for example
  ``untrusted_channel_in_agent_inputs`` or ``agent_has_tool_kind(kinds=exec|write)``;
* a mapping with exactly one key, ``all``, ``any`` or ``not``, whose value is a
  list of rules (``all``/``any``) or a single rule (``not``).

Rules are parsed into a tree once and evaluated by calling named Python
functions from a registry. There is no ``eval`` anywhere in the path from YAML
to a decision, so a catalogue file cannot execute code.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

CALL_RE = re.compile(r"^\s*([a-z][a-z0-9_]*)\s*(?:\((.*)\))?\s*$")
VALUE_SEPARATOR = "|"


class RuleSyntaxError(ValueError):
    """Raised when a rule cannot be parsed."""


@dataclass(frozen=True)
class Match:
    """Outcome of evaluating a rule: did it match, on which elements and why."""

    matched: bool
    elements: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    @staticmethod
    def no() -> Match:
        return Match(False)

    @staticmethod
    def of(elements: list[str] | set[str], reasons: list[str]) -> Match:
        """Build a positive match from element ids and reason strings."""
        return Match(True, tuple(_dedupe(sorted(elements))), tuple(_dedupe(reasons)))


@dataclass(frozen=True)
class PredicateCall:
    name: str
    args: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def kwargs(self) -> dict[str, tuple[str, ...]]:
        return dict(self.args)

    def text(self) -> str:
        if not self.args:
            return self.name
        inner = ", ".join(f"{k}={VALUE_SEPARATOR.join(v)}" for k, v in self.args)
        return f"{self.name}({inner})"


@dataclass(frozen=True)
class Rule:
    op: str  # "call", "all", "any" or "not"
    call: PredicateCall | None = None
    children: tuple[Rule, ...] = ()

    def text(self) -> str:
        """Render the rule back to a compact, human readable form."""
        if self.op == "call" and self.call is not None:
            return self.call.text()
        if self.op == "not":
            return f"not({self.children[0].text()})"
        return f"{self.op}({', '.join(c.text() for c in self.children)})"

    def predicate_names(self) -> set[str]:
        if self.op == "call" and self.call is not None:
            return {self.call.name}
        names: set[str] = set()
        for child in self.children:
            names |= child.predicate_names()
        return names


PredicateFn = Callable[..., Match]
Registry = Mapping[str, PredicateFn]


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _parse_call(text: str) -> PredicateCall:
    found = CALL_RE.match(text)
    if not found:
        raise RuleSyntaxError(f"cannot parse predicate call {text!r}")
    name, raw_args = found.group(1), found.group(2)
    args: list[tuple[str, tuple[str, ...]]] = []
    if raw_args is not None and raw_args.strip():
        for part in raw_args.split(","):
            if "=" not in part:
                raise RuleSyntaxError(f"argument {part.strip()!r} in {text!r} needs key=value")
            key, value = part.split("=", 1)
            key = key.strip()
            if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
                raise RuleSyntaxError(f"bad argument name {key!r} in {text!r}")
            values = tuple(v.strip() for v in value.split(VALUE_SEPARATOR) if v.strip())
            if not values:
                raise RuleSyntaxError(f"argument {key!r} in {text!r} has no value")
            args.append((key, values))
    return PredicateCall(name, tuple(args))


def parse_rule(obj: Any) -> Rule:
    """Parse a YAML value (string or mapping) into a :class:`Rule`."""
    if isinstance(obj, str):
        return Rule("call", call=_parse_call(obj))
    if isinstance(obj, Mapping):
        if len(obj) != 1:
            raise RuleSyntaxError(f"rule mapping must have exactly one key, got {sorted(obj)}")
        ((op, value),) = obj.items()
        if op in ("all", "any"):
            if not isinstance(value, list) or not value:
                raise RuleSyntaxError(f"'{op}' needs a non-empty list of rules")
            return Rule(op, children=tuple(parse_rule(v) for v in value))
        if op == "not":
            return Rule("not", children=(parse_rule(value),))
        raise RuleSyntaxError(f"unknown rule operator {op!r}; use all, any or not")
    raise RuleSyntaxError(f"rule must be a string or mapping, got {type(obj).__name__}")


def evaluate(rule: Rule, context: Any, registry: Registry) -> Match:
    """Evaluate a parsed rule against a context using the predicate registry."""
    if rule.op == "call":
        assert rule.call is not None
        try:
            fn = registry[rule.call.name]
        except KeyError as exc:
            raise KeyError(f"unknown predicate {rule.call.name!r}") from exc
        return fn(context, **rule.call.kwargs())
    if rule.op == "not":
        inner = evaluate(rule.children[0], context, registry)
        if inner.matched:
            return Match.no()
        return Match(True, (), (f"not {rule.children[0].text()}",))
    results = [evaluate(child, context, registry) for child in rule.children]
    hits = [r for r in results if r.matched]
    if rule.op == "all" and len(hits) != len(results):
        return Match.no()
    if rule.op == "any" and not hits:
        return Match.no()
    elements: list[str] = []
    reasons: list[str] = []
    for hit in hits:
        elements.extend(hit.elements)
        reasons.extend(hit.reasons)
    return Match.of(elements, reasons)
