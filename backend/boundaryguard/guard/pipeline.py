"""Combines policy, history and assessor according to the configuration flags."""
from __future__ import annotations

import time

from ..models.core import (
    CanonicalAction, Decision, GuardDecision, GuardFlags, Policy, RiskLevel, most_restrictive,
)
from .context.base import AssessmentContext, Assessor
from .context.heuristic import app_relevant, is_relevant, mentioned_host
from .history import HistoryTracker
from .policy_engine import PolicyEngine, RunState


class Guard:
    def __init__(self, flags: GuardFlags, policy: Policy, objective: str,
                 assessor: Assessor | None = None, history: HistoryTracker | None = None):
        if flags.use_context and assessor is None:
            raise ValueError("A configuration with context needs an assessor.")
        self.flags = flags
        self.objective = objective
        self.engine = PolicyEngine(policy)
        self.assessor = assessor
        self.history = history or HistoryTracker()

    def evaluate(self, action: CanonicalAction, state: RunState) -> GuardDecision:
        if not self.flags.use_policy:
            return GuardDecision(final=Decision.ALLOW, source="passthrough",
                                 reasoning="No guard in this configuration.")

        start = time.perf_counter_ns()
        policy_result = self.engine.evaluate(action, state)
        policy_us = (time.perf_counter_ns() - start) / 1000

        # A hard prohibition ends evaluation here. The assessor is never consulted, so it cannot override it.
        if policy_result.verdict is Decision.BLOCK or not self.flags.use_context:
            return GuardDecision(
                final=policy_result.verdict,
                source="policy",
                policy_verdict=policy_result.verdict,
                rule_id=policy_result.rule_id,
                reasoning=policy_result.reason,
                terminate=policy_result.terminate,
                policy_latency_us=policy_us,
            )

        start = time.perf_counter_ns()
        relevant = self._relevant(action)
        signals = self.history.signals_for(action, relevant) if self.flags.use_history else []
        ctx = AssessmentContext(
            objective=self.objective,
            action=action,
            relevant_to_task=relevant,
            signals=signals,
            recent_actions=self._recent(denied=False) if self.flags.use_history else [],
            denied_actions=self._recent(denied=True) if self.flags.use_history else [],
            untrusted_text=self.history.untrusted_text() if self.flags.use_history else "",
            history_stats=self.history.stats_for(action) if self.flags.use_history else {},
            policy_verdict=policy_result.verdict,
        )
        assessment = self.assessor.assess(ctx)
        context_us = (time.perf_counter_ns() - start) / 1000

        final = most_restrictive(policy_result.verdict, assessment.recommended_action)
        source = "context" if final is not policy_result.verdict else "policy+context"
        reasoning = assessment.reasoning
        if policy_result.verdict is Decision.APPROVAL_REQUIRED:
            reasoning = f"{policy_result.reason} {reasoning}"
        return GuardDecision(
            final=final,
            source=source,
            policy_verdict=policy_result.verdict,
            rule_id=policy_result.rule_id,
            risk_level=RiskLevel(assessment.risk_level),
            risk_score=assessment.risk_score,
            reasoning=reasoning,
            signals=assessment.signals,
            assessor=assessment.assessor,
            assessor_fallback=assessment.fallback,
            policy_latency_us=policy_us,
            context_latency_us=context_us,
        )

    def _relevant(self, action: CanonicalAction) -> bool:
        if action.access == "network":
            return mentioned_host(self.objective, action.url_host)
        if action.access == "app":
            return app_relevant(self.objective, action.app_tool)
        return is_relevant(self.objective, action.real_virtual_path or action.virtual_path)

    def _recent(self, denied: bool) -> list[str]:
        return [f"#{e.seq} {e.tool} {e.target or ''}".strip() for e in self.history.entries if e.denied == denied]
