"""Deterministic policy enforcement. Depends on nothing but the policy and the canonical action."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from ..models.core import CanonicalAction, Decision, Policy, PolicyResult
from .paths import glob_match, matches_any


@dataclass
class RunState:
    """Counters the deterministic limits need. Maintained by the gateway."""
    tool_calls: Counter = field(default_factory=Counter)
    denials_by_fingerprint: Counter = field(default_factory=Counter)
    total_denials: int = 0

    def record_denial(self, fingerprint: str) -> None:
        self.denials_by_fingerprint[fingerprint] += 1
        self.total_denials += 1


def _deny(rule: str, reason: str, terminate: bool = False) -> PolicyResult:
    return PolicyResult(verdict=Decision.BLOCK, rule_id=rule, reason=reason, terminate=terminate)


PASS = PolicyResult(verdict=Decision.ALLOW, rule_id=None, reason="Passed all deterministic rules.")


class PolicyEngine:
    def __init__(self, policy: Policy):
        self.policy = policy
        self._content = [re.compile(p, re.IGNORECASE) for p in policy.prohibited_content]

    def evaluate(self, action: CanonicalAction, state: RunState) -> PolicyResult:
        tool_result = self._check_tool(action)
        if tool_result is not None:
            return tool_result
        limit_result = self._check_stateful(action, state)
        if limit_result is not None:
            return limit_result
        return self.evaluate_static(action)

    def evaluate_static(self, action: CanonicalAction) -> PolicyResult:
        """Every rule that does not depend on run history. Also used post hoc by the bypass check."""
        for check in (self._check_tool, self._check_path, self._check_network, self._check_app, self._check_content, self._check_approval):
            result = check(action)
            if result is not None:
                return result
        return PASS

    def denial_budget_exhausted(self, state: RunState) -> bool:
        return state.total_denials >= self.policy.retry.total_denials

    # -- individual rule groups --------------------------------------------
    def _check_tool(self, action: CanonicalAction) -> PolicyResult | None:
        if action.tool in self.policy.prohibited_tools:
            return _deny("TOOL_PROHIBITED", f"Tool '{action.tool}' is prohibited by policy.")
        if action.tool not in self.policy.allowed_tools:
            return _deny("TOOL_NOT_ALLOWED", f"Tool '{action.tool}' is not in the allowed tool list.")
        return None

    def _check_stateful(self, action: CanonicalAction, state: RunState) -> PolicyResult | None:
        retry = self.policy.retry
        if state.denials_by_fingerprint[action.fingerprint] >= retry.same_action_denials:
            return _deny(
                "RETRY_LOCKOUT",
                f"This action was already denied {state.denials_by_fingerprint[action.fingerprint]} times. Ending the run.",
                terminate=True,
            )
        if state.tool_calls[action.tool] >= self.policy.limits.max_calls_per_tool:
            return _deny("LIMIT_TOOL_CALLS", f"Call limit of {self.policy.limits.max_calls_per_tool} reached for '{action.tool}'.")
        return None

    def _check_path(self, action: CanonicalAction) -> PolicyResult | None:
        if action.access not in ("read", "write"):
            return None
        if action.path_form_violation:
            return _deny("PATH_SUSPICIOUS_FORM", f"Path uses a disallowed form ({action.path_form_violation}).")
        if action.floor_error:
            return _deny("PATH_SUSPICIOUS_FORM", f"Path refused by the sandbox ({action.floor_error}).")
        if not action.inside_sandbox or action.real_virtual_path is None:
            return _deny("PATH_ESCAPE", "Path resolves outside the sandbox.")
        for path in (action.virtual_path, action.real_virtual_path):
            pattern = matches_any(self.policy.protected_paths, path)
            if pattern:
                return _deny("PATH_PROTECTED", f"'{path}' is protected by '{pattern}'.")
        # Both the path as written and where it really lands must be permitted.
        allowed = self.policy.read_paths if action.access == "read" else self.policy.write_paths
        rule = "PATH_NOT_READABLE" if action.access == "read" else "PATH_NOT_WRITABLE"
        for path in (action.virtual_path, action.real_virtual_path):
            if not matches_any(allowed, path):
                return _deny(rule, f"'{path}' is outside the permitted {action.access} paths.")
        if action.tool == "write_file" and len((action.payload or "").encode()) > self.policy.limits.max_write_bytes:
            return _deny("LIMIT_WRITE_BYTES", f"Write exceeds {self.policy.limits.max_write_bytes} bytes.")
        return None

    def _check_network(self, action: CanonicalAction) -> PolicyResult | None:
        if action.access != "network":
            return None
        net = self.policy.network
        if not net.enabled:
            return _deny("NET_DISABLED", "Network access is disabled by policy.")
        if action.url_violation:
            return _deny("NET_BAD_URL", f"URL rejected ({action.url_violation}).")
        if action.url_host not in [h.lower() for h in net.allowed_hosts]:
            return _deny("NET_HOST_NOT_ALLOWED", f"Host '{action.url_host}' is not on the allowlist.")
        if action.method not in net.allowed_methods:
            return _deny("NET_METHOD_NOT_ALLOWED", f"Method {action.method} is not allowed.")
        return None

    def _check_app(self, action: CanonicalAction) -> PolicyResult | None:
        if action.access != "app":
            return None
        if action.app_tool in self.policy.prohibited_app_tools:
            return _deny("APP_PROHIBITED", f"Application tool '{action.app_tool}' is prohibited by policy.")
        if "*" not in self.policy.app_tools and action.app_tool not in self.policy.app_tools:
            return _deny("APP_NOT_ALLOWED", f"Application tool '{action.app_tool}' is not on the allowlist.")
        return None

    def _check_content(self, action: CanonicalAction) -> PolicyResult | None:
        if action.payload:
            for pattern in self._content:
                if pattern.search(action.payload):
                    return _deny("CONTENT_PROHIBITED", f"Content matches prohibited pattern '{pattern.pattern}'.")
        return None

    def _check_approval(self, action: CanonicalAction) -> PolicyResult | None:
        if action.tool in self.policy.approval_tools:
            return PolicyResult(verdict=Decision.APPROVAL_REQUIRED, rule_id="APPROVAL_TOOL",
                                reason=f"Policy requires approval for '{action.tool}'.")
        if action.real_virtual_path and any(glob_match(p, action.real_virtual_path) for p in self.policy.approval_paths):
            return PolicyResult(verdict=Decision.APPROVAL_REQUIRED, rule_id="APPROVAL_PATH",
                                reason=f"Policy requires approval for '{action.real_virtual_path}'.")
        return None
