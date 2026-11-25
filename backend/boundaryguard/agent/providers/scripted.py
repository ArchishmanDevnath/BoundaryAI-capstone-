"""Replays a scenario's script and reacts to denials.

A scripted agent is compromised by construction: it attempts each attack because the script
says so. Results from this provider measure the guard's decisions on fixed traces. They say
nothing about how likely a real model is to fall for an attack.
"""
from __future__ import annotations

import base64
import re
from collections import deque
from typing import Any

from ...models.core import Finish, ScriptStep, ToolCall, ToolOutcome

_TEMPLATE = re.compile(r"\{\{(file|b64|hex):([^}]+)\}\}")


class ScriptedProvider:
    name = "scripted"
    model = None

    def __init__(self, steps: list[ScriptStep]):
        self._queue: deque[ScriptStep] = deque(steps)
        self._current: ScriptStep | None = None
        self._retries_left = 0
        self._success: dict[str, bool] = {}
        self._memory: dict[str, str] = {}

    def next_step(self, last: ToolOutcome | None) -> ToolCall | Finish:
        if last is not None and self._current is not None:
            self._observe(last)
        while self._queue:
            step = self._queue.popleft()
            if step.requires and not self._success.get(step.requires, False):
                continue
            if step is not self._current:
                self._retries_left = step.on_denied.retry
            self._current = step
            return ToolCall(tool=step.tool, args=self._render(step.args))
        self._current = None
        return Finish(message="Script complete.")

    def _observe(self, outcome: ToolOutcome) -> None:
        step = self._current
        assert step is not None
        if step.id:
            self._success[step.id] = outcome.status == "ok"
        if outcome.status == "ok" and step.tool == "read_file":
            self._memory[step.args.get("path", "")] = outcome.output
        if outcome.status != "denied":
            return
        policy = step.on_denied
        if self._retries_left > 0:
            self._retries_left -= 1
            self._queue.appendleft(step)
        elif policy.alternates:
            self._queue.extendleft(reversed(policy.alternates))
        elif policy.then == "abandon":
            self._queue.clear()

    def _render(self, value: Any) -> Any:
        if isinstance(value, str):
            return _TEMPLATE.sub(self._expand, value)
        if isinstance(value, dict):
            return {k: self._render(v) for k, v in value.items()}
        return value

    def _expand(self, match: re.Match[str]) -> str:
        data = self._memory.get(match.group(2), "")
        if match.group(1) == "b64":
            return base64.b64encode(data.encode()).decode()
        if match.group(1) == "hex":
            return data.encode().hex()
        return data
