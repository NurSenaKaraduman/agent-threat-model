#!/usr/bin/env python3
"""Generate docs/catalogue.md from the YAML catalogue (``--check`` verifies only)."""

from __future__ import annotations

import sys
from pathlib import Path

from agent_threat_model.catalogue import EFFORT_ORDER, STRIDE_TITLES, load_catalogue
from agent_threat_model.catalogue.references import OWASP_AGENTIC_2026, OWASP_LLM_2025, atlas_url
from agent_threat_model.predicates import REGISTRY

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "catalogue.md"


def render() -> str:
    catalogue = load_catalogue()
    threats = list(catalogue.threats.values())
    controls = sorted(catalogue.controls.values(), key=lambda c: (EFFORT_ORDER[c.effort], c.id))
    lines: list[str] = []
    lines.append("# Catalogue reference")
    lines.append("")
    lines.append(
        "Generated from `agent_threat_model/catalogue/threats.yaml` and `controls.yaml` by "
        "`scripts/gen_catalogue_doc.py`. Do not edit by hand."
    )
    lines.append("")
    lines.append(f"{len(threats)} threats, {len(controls)} controls, {len(REGISTRY)} predicates.")
    lines.append("")
    lines.append(
        "LLM ids refer to the OWASP Top 10 for LLM Applications 2025. ASI ids refer to the "
        "OWASP Top 10 for Agentic Applications 2026 as listed in the OWASP GenAI Security "
        "Project crosswalk repository "
        "(https://github.com/GenAI-Security-Project/crosswalk, CROSSREF.md); please check "
        "the mapping against the published PDF and open an issue if an id or title differs. "
        "MITRE ATLAS ids are validated against the ATLAS data distribution."
    )
    lines.append("")

    lines.append("## Threats")
    lines.append("")
    lines.append(
        "| Id | Title | STRIDE | OWASP LLM | OWASP Agentic | MITRE ATLAS | L x I | Applies when |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for t in threats:
        atlas = ", ".join(f"[{i}]({atlas_url(i)})" for i in t.mitre_atlas) or "-"
        lines.append(
            f"| [`{t.id}`](#{t.id}) | {t.title} | {STRIDE_TITLES[t.stride]} | "
            f"{', '.join(t.owasp_llm) or '-'} | {', '.join(t.owasp_agentic) or '-'} | "
            f"{atlas} | {t.likelihood} x {t.impact} | "
            f"`{t.rule.text()}` |"
        )
    lines.append("")
    for t in threats:
        lines.append(f"### {t.id}")
        lines.append("")
        lines.append(f"**{t.title}**")
        lines.append("")
        lines.append(t.description)
        lines.append("")
        lines.append(f"- STRIDE: {STRIDE_TITLES[t.stride]}")
        owasp = ", ".join(f"{i} {OWASP_LLM_2025[i]}" for i in t.owasp_llm) or "-"
        lines.append(f"- OWASP LLM Top 10 (2025): {owasp}")
        agentic = ", ".join(f"{i} {OWASP_AGENTIC_2026[i]}" for i in t.owasp_agentic)
        lines.append(f"- OWASP Agentic Top 10 (2026): {agentic or 'not mapped'}")
        atlas = ", ".join(f"[{i}]({atlas_url(i)})" for i in t.mitre_atlas) or "-"
        lines.append(f"- MITRE ATLAS: {atlas}")
        lines.append(
            f"- Inherent severity: likelihood {t.likelihood} x impact {t.impact} = "
            f"{t.inherent_score}"
        )
        lines.append(f"- Applies when: `{t.rule.text()}`")
        lines.append("- Mitigations: " + ", ".join(f"[`{m}`](#{m})" for m in t.mitigations))
        for ref in t.references:
            lines.append(f"- Reference: <{ref}>")
        lines.append("")

    lines.append("## Controls")
    lines.append("")
    lines.append("| Id | Title | Type | Effort | Mitigates |")
    lines.append("|---|---|---|---|---|")
    for c in controls:
        mitigates = ", ".join(f"`{t.id}`" for t in catalogue.threats_mitigated_by(c.id))
        lines.append(
            f"| [`{c.id}`](#{c.id}) | {c.title} | {c.type.value} | {c.effort.value} | {mitigates} |"
        )
    lines.append("")
    for c in controls:
        lines.append(f"### {c.id}")
        lines.append("")
        lines.append(f"**{c.title}** ({c.type.value}, {c.effort.value} effort)")
        lines.append("")
        lines.append(c.description)
        lines.append("")
        mitigates = ", ".join(f"[`{t.id}`](#{t.id})" for t in catalogue.threats_mitigated_by(c.id))
        lines.append(f"- Mitigates: {mitigates}")
        for ref in c.references:
            lines.append(f"- Reference: <{ref}>")
        lines.append("")

    lines.append("## Predicates")
    lines.append("")
    lines.append(
        "Rules in `applies_when` are built from these named predicates with `all`, `any` "
        "and `not`. Arguments are written `name(key=value)`; several values are separated "
        "with `|`."
    )
    lines.append("")
    lines.append("| Predicate | Meaning |")
    lines.append("|---|---|")
    for name in sorted(REGISTRY):
        doc = (REGISTRY[name].__doc__ or "").strip().splitlines()
        lines.append(f"| `{name}` | {doc[0] if doc else ''} |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(
                f"{OUT} is out of date; run: python scripts/gen_catalogue_doc.py", file=sys.stderr
            )
            return 1
        print(f"{OUT} is up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
