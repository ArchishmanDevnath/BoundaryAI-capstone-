"""Assessor interface. An assessor judges risk. It never receives authority to allow on its own."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ...models.core import Assessment, CanonicalAction, Decision, Signal


@dataclass
class AssessmentContext:
    objective: str
    action: CanonicalAction
    relevant_to_task: bool
    signals: list[Signal] = field(default_factory=list)
    recent_actions: list[str] = field(default_factory=list)
    denied_actions: list[str] = field(default_factory=list)
    # Stateful view. Empty unless the configuration includes history, so ablations cannot see it.
    untrusted_text: str = ""
    history_stats: dict[str, int] = field(default_factory=dict)
    policy_verdict: Decision = Decision.ALLOW


class Assessor(Protocol):
    name: str

    def assess(self, ctx: AssessmentContext) -> Assessment: ...
