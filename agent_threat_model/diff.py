"""Compare two analyses and describe what changed in the threat register."""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_threat_model.engine import Analysis, Finding


@dataclass
class FindingChange:
    threat_id: str
    title: str
    old_residual: float
    new_residual: float
    old_band: str
    new_band: str
    elements_added: list[str] = field(default_factory=list)
    elements_removed: list[str] = field(default_factory=list)
    mitigations_now_present: list[str] = field(default_factory=list)
    mitigations_now_missing: list[str] = field(default_factory=list)

    @property
    def delta(self) -> float:
        return round(self.new_residual - self.old_residual, 1)


@dataclass
class Diff:
    old_source: str
    new_source: str
    added: list[Finding]
    removed: list[Finding]
    changed: list[FindingChange]
    unchanged: int
    controls_added: list[str]
    controls_removed: list[str]
    old_score: int
    new_score: int
    old_rating: str
    new_rating: str
    old_residual_total: float
    new_residual_total: float

    @property
    def score_delta(self) -> int:
        return self.new_score - self.old_score

    @property
    def is_empty(self) -> bool:
        return (
            not (
                self.added
                or self.removed
                or self.changed
                or self.controls_added
                or self.controls_removed
            )
            and self.old_score == self.new_score
        )


def diff_analyses(old: Analysis, new: Analysis) -> Diff:
    old_map = {f.threat_id: f for f in old.findings}
    new_map = {f.threat_id: f for f in new.findings}
    added = [new_map[t] for t in new_map if t not in old_map]
    removed = [old_map[t] for t in old_map if t not in new_map]
    changed: list[FindingChange] = []
    unchanged = 0
    for threat_id in old_map.keys() & new_map.keys():
        before, after = old_map[threat_id], new_map[threat_id]
        same = (
            before.residual == after.residual
            and set(before.elements) == set(after.elements)
            and set(before.mitigations_present) == set(after.mitigations_present)
        )
        if same:
            unchanged += 1
            continue
        changed.append(
            FindingChange(
                threat_id=threat_id,
                title=after.title,
                old_residual=before.residual,
                new_residual=after.residual,
                old_band=before.residual_band,
                new_band=after.residual_band,
                elements_added=sorted(set(after.elements) - set(before.elements)),
                elements_removed=sorted(set(before.elements) - set(after.elements)),
                mitigations_now_present=sorted(
                    set(after.mitigations_present) - set(before.mitigations_present)
                ),
                mitigations_now_missing=sorted(
                    set(before.mitigations_present) - set(after.mitigations_present)
                ),
            )
        )
    added.sort(key=lambda f: f.sort_key)
    removed.sort(key=lambda f: f.sort_key)
    changed.sort(key=lambda c: (c.delta, c.threat_id))
    return Diff(
        old_source=old.source,
        new_source=new.source,
        added=added,
        removed=removed,
        changed=changed,
        unchanged=unchanged,
        controls_added=sorted(set(new.system.controls) - set(old.system.controls)),
        controls_removed=sorted(set(old.system.controls) - set(new.system.controls)),
        old_score=old.residual_risk_score,
        new_score=new.residual_risk_score,
        old_rating=old.rating,
        new_rating=new.rating,
        old_residual_total=old.residual_total,
        new_residual_total=new.residual_total,
    )
