"""Shared types for policies, tool calls, guard decisions and scenarios."""
from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    BLOCK = "BLOCK"


_RESTRICTIVENESS = {Decision.ALLOW: 0, Decision.APPROVAL_REQUIRED: 1, Decision.BLOCK: 2}


def most_restrictive(*decisions: Decision) -> Decision:
    """The single place decisions combine. A later stage can only tighten an earlier one."""
    return max(decisions, key=lambda d: _RESTRICTIVENESS[d])


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def risk_to_decision(level: RiskLevel) -> Decision:
    if level is RiskLevel.LOW:
        return Decision.ALLOW
    if level is RiskLevel.MEDIUM:
        return Decision.APPROVAL_REQUIRED
    return Decision.BLOCK


class GuardFlags(BaseModel):
    model_config = ConfigDict(frozen=True)
    use_policy: bool
    use_context: bool
    use_history: bool
    use_ml: bool = False


# Stored ids never change meaning, so older experiment records stay correct. The research configurations are
# A, B, C (stored as RC), D and E. Stored id "C" is the heuristic with history, kept as a control so that E can be
# compared with the best non-ML guard.
CONFIGURATIONS: dict[str, GuardFlags] = {
    "A": GuardFlags(use_policy=False, use_context=False, use_history=False),
    "B": GuardFlags(use_policy=True, use_context=False, use_history=False),
    "RC": GuardFlags(use_policy=True, use_context=True, use_history=False),
    "C": GuardFlags(use_policy=True, use_context=True, use_history=True),
    "D": GuardFlags(use_policy=True, use_context=True, use_history=False, use_ml=True),
    "E": GuardFlags(use_policy=True, use_context=True, use_history=True, use_ml=True),
}

CONFIGURATION_NAMES = {
    "A": "A: Unprotected",
    "B": "B: Rules only",
    "RC": "C: Rules + heuristic",
    "C": "Control: Rules + heuristic + history",
    "D": "D: Rules + ML",
    "E": "E: Rules + ML + history",
}


class NetworkPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET"])


class ExecutionLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_steps: int = Field(default=30, ge=1, le=500)
    max_calls_per_tool: int = Field(default=25, ge=1, le=500)
    max_write_bytes: int = Field(default=200_000, ge=1)


class RetryLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    same_action_denials: int = Field(default=2, ge=1, le=50)
    total_denials: int = Field(default=6, ge=1, le=200)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = "unnamed"
    allowed_tools: list[str] = Field(default_factory=list)
    prohibited_tools: list[str] = Field(default_factory=list)
    read_paths: list[str] = Field(default_factory=list)
    write_paths: list[str] = Field(default_factory=list)
    protected_paths: list[str] = Field(default_factory=list)
    prohibited_content: list[str] = Field(default_factory=list)
    approval_tools: list[str] = Field(default_factory=list)
    approval_paths: list[str] = Field(default_factory=list)
    # Simulated application tools reachable through app_call. "*" means any. Prohibited always wins.
    app_tools: list[str] = Field(default_factory=list)
    prohibited_app_tools: list[str] = Field(default_factory=list)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    limits: ExecutionLimits = Field(default_factory=ExecutionLimits)
    retry: RetryLimits = Field(default_factory=RetryLimits)

    def content_hash(self) -> str:
        body = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(body.encode()).hexdigest()


class ToolCall(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class Finish(BaseModel):
    message: str = ""


class CanonicalAction(BaseModel):
    """A tool call after canonicalization. Everything the guard reasons about lives here."""
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    access: Literal["read", "write", "network", "exec", "app", "none"] = "none"
    app_tool: str | None = None
    app_effect: Literal["read", "write", "outbound"] | None = None
    raw_path: str | None = None
    path_form_violation: str | None = None
    virtual_path: str | None = None
    real_virtual_path: str | None = None
    inside_sandbox: bool = True
    floor_error: str | None = None
    url_host: str | None = None
    url_path: str | None = None
    url_scheme: str | None = None
    url_violation: str | None = None
    method: str | None = None
    payload: str | None = None
    fingerprint: str = ""

    @property
    def target(self) -> str | None:
        if self.access in ("read", "write"):
            return self.real_virtual_path or self.virtual_path or self.raw_path
        if self.access == "network":
            return f"{self.url_host or '?'}{self.url_path or ''}"
        if self.access == "app":
            return self.app_tool
        return None


class PolicyResult(BaseModel):
    verdict: Decision
    rule_id: str | None = None
    reason: str = ""
    terminate: bool = False


class Signal(BaseModel):
    name: str
    weight: float
    detail: str = ""
    hard: bool = False


class Assessment(BaseModel):
    risk_level: RiskLevel
    risk_score: float
    reasoning: str
    recommended_action: Decision
    assessor: str
    fallback: bool = False
    signals: list[Signal] = Field(default_factory=list)


class GuardDecision(BaseModel):
    final: Decision
    source: str
    policy_verdict: Decision | None = None
    rule_id: str | None = None
    risk_level: RiskLevel | None = None
    risk_score: float | None = None
    reasoning: str = ""
    signals: list[Signal] = Field(default_factory=list)
    terminate: bool = False
    assessor: str | None = None
    assessor_fallback: bool = False
    policy_latency_us: float | None = None
    context_latency_us: float | None = None
    approval_outcome: str | None = None


class ToolResult(BaseModel):
    status: Literal["ok", "error", "refused"]
    output: str = ""
    bytes: int = 0


class ToolOutcome(BaseModel):
    """What the agent sees after submitting a call."""
    action_id: str
    status: Literal["ok", "error", "denied"]
    output: str = ""
    decision: Decision
    rule_id: str | None = None
    reason: str = ""
    terminate: bool = False
    termination_reason: str | None = None


# ---- Scenario definitions -------------------------------------------------

Category = Literal["benign", "prompt_injection", "permission_violation", "repeated_unnecessary",
                   "injecagent_direct_harm", "injecagent_data_stealing"]


class OnDenied(BaseModel):
    model_config = ConfigDict(extra="forbid")
    retry: int = 0
    alternates: list["ScriptStep"] = Field(default_factory=list)
    then: Literal["continue", "abandon"] = "continue"


class ScriptStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = None
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    requires: str | None = None
    on_denied: OnDenied = Field(default_factory=OnDenied)


class LabelRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: Literal["legitimate", "unauthorized"]
    tool: str | list[str] | None = None
    path: str | None = None
    host: str | None = None
    method: str | None = None
    contains: str | None = None
    app_tool: str | None = None


class LinkSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    target: str


class Expected(BaseModel):
    model_config = ConfigDict(extra="forbid")
    no_unauthorized_executed: bool = True
    terminates: bool | None = None
    task_completed: bool | None = None


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title: str
    category: Category
    split: Literal["dev", "holdout", "external"]
    fixture: str
    objective: str
    policy: str = "project_standard"
    policy_overrides: dict[str, Any] = Field(default_factory=dict)
    overlays: dict[str, str] = Field(default_factory=dict)
    links: list[LinkSpec] = Field(default_factory=list)
    network: dict[str, dict[str, Any]] = Field(default_factory=dict)
    app_responses: dict[str, str] = Field(default_factory=dict)
    oracle: list[dict[str, Any]] = Field(default_factory=list)
    script: list[ScriptStep] = Field(default_factory=list)
    labels: list[LabelRule] = Field(default_factory=list)
    completion: list[dict[str, Any]] = Field(default_factory=list)
    expected: Expected = Field(default_factory=Expected)
    notes: str = ""


OnDenied.model_rebuild()
