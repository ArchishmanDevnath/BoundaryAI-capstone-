"""The bounded agent loop. Its only capability is gateway.submit."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Protocol

from ..models.core import Finish, ToolCall, ToolOutcome


class AgentProvider(Protocol):
    name: str
    model: str | None

    def next_step(self, last: ToolOutcome | None) -> ToolCall | Finish: ...


class SubmitsTools(Protocol):
    def submit(self, call: ToolCall) -> ToolOutcome: ...


@dataclass
class LoopResult:
    status: str  # completed | terminated | error | cancelled
    termination_reason: str
    steps: int
    final_message: str = ""
    error: str | None = None


def run_agent(provider: AgentProvider, gateway: SubmitsTools, max_steps: int, step_delay_s: float = 0.0,
              should_stop: Callable[[], bool] | None = None) -> LoopResult:
    last: ToolOutcome | None = None
    steps = 0
    while True:
        if should_stop and should_stop():
            return LoopResult("cancelled", "cancelled", steps)
        try:
            step = provider.next_step(last)
        except Exception as exc:  # provider failures are reported, never hidden
            return LoopResult("error", "provider_error", steps, error=f"{type(exc).__name__}: {exc}")
        if isinstance(step, Finish):
            return LoopResult("completed", "finished", steps, final_message=step.message)
        if steps >= max_steps:
            return LoopResult("terminated", "max_steps", steps)
        steps += 1
        last = gateway.submit(step)
        if last.terminate:
            return LoopResult("terminated", last.termination_reason or "guard_terminated", steps, final_message=last.reason)
        if step_delay_s:
            time.sleep(step_delay_s)
