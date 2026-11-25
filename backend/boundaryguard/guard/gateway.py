"""The only route to tool execution. Every configuration, including unprotected, goes through here."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from typing import Callable, Protocol

from ..audit.logger import AuditFailure, RunRecorder
from ..db.connection import Database, utcnow
from ..models.core import CanonicalAction, Decision, GuardDecision, ToolCall, ToolOutcome
from ..tools.catalog import validate_args
from ..tools.executor import ToolExecutor
from ..tools.sandbox import Sandbox
from ..tools.simapps import SimApps
from ..tools.simnet import SimNet
from ..tools.test_oracle import TestOracle
from .canonical import canonicalize
from .pipeline import Guard
from .policy_engine import RunState


class ApprovalHandler(Protocol):
    def request(self, run_id: str, action_id: str) -> str:
        """Return 'approved', 'denied' or 'timeout'."""
        ...


class AutoDeny:
    """Benchmark mode: no person is present, so an approval request counts as denied."""

    def request(self, run_id: str, action_id: str) -> str:
        return "denied"


class HumanApproval:
    """Live mode: wait for the dashboard to resolve the request. Timeout means deny."""

    def __init__(self, db: Database, timeout_s: float, poll_s: float = 0.25,
                 should_stop: Callable[[], bool] | None = None):
        self.db = db
        self.timeout_s = timeout_s
        self.poll_s = poll_s
        self.should_stop = should_stop

    def request(self, run_id: str, action_id: str) -> str:
        approval_id = uuid.uuid4().hex
        self.db.execute(
            "INSERT INTO approvals (id, action_id, run_id, status, created_at) VALUES (?,?,?,?,?)",
            (approval_id, action_id, run_id, "pending", utcnow()),
        )
        deadline = time.monotonic() + self.timeout_s
        while time.monotonic() < deadline and not (self.should_stop and self.should_stop()):
            status = self.db.scalar("SELECT status FROM approvals WHERE id=?", (approval_id,))
            if status in ("approved", "denied"):
                return status
            time.sleep(self.poll_s)
        # Only move out of 'pending'. A resolution that arrived in the meantime still wins.
        cursor = self.db.execute(
            "UPDATE approvals SET status='timeout', resolved_at=? WHERE id=? AND status='pending'",
            (utcnow(), approval_id),
        )
        if cursor.rowcount == 0:
            return self.db.scalar("SELECT status FROM approvals WHERE id=?", (approval_id,))
        return "timeout"


class ToolGateway:
    def __init__(self, *, run_id: str, guard: Guard, sandbox: Sandbox, simnet: SimNet, oracle: TestOracle,
                 recorder: RunRecorder, approvals: ApprovalHandler | None = None, apps: SimApps | None = None):
        self.run_id = run_id
        self.guard = guard
        self.sandbox = sandbox
        self.recorder = recorder
        self.approvals = approvals or AutoDeny()
        self.state = RunState()
        self._seq = 0
        # The token and executor exist only inside this object. Nothing else gets a reference.
        self.__token = secrets.token_hex(16)
        self.__executor = ToolExecutor(self.__token, sandbox, simnet, oracle, recorder, apps)

    def submit(self, call: ToolCall) -> ToolOutcome:
        self._seq += 1
        seq = self._seq
        try:
            return self._submit(seq, call)
        except AuditFailure as exc:
            # Fail closed. Nothing has executed for this action if the decision record could not be written.
            return ToolOutcome(action_id="", status="denied", decision=Decision.BLOCK, rule_id="AUDIT_FAILURE",
                               reason=f"Audit write failed: {exc}", terminate=True, termination_reason="audit_failure")

    def _submit(self, seq: int, call: ToolCall) -> ToolOutcome:
        args, schema_error = validate_args(call.tool, call.args)
        if schema_error:
            return self._refuse_malformed(seq, call, schema_error)

        canon = canonicalize(call.tool, args, self.sandbox)
        try:
            action_id = self.recorder.record_proposal(seq, call.tool, args, canon)
        except Exception as exc:
            raise AuditFailure(str(exc)) from exc

        decision = self.guard.evaluate(canon, self.state)
        if decision.final is Decision.BLOCK:
            self._account_denial(canon.fingerprint, decision)
        self.recorder.record_decision(action_id, decision)

        allowed = decision.final is Decision.ALLOW
        if decision.final is Decision.APPROVAL_REQUIRED:
            outcome = self.approvals.request(self.run_id, action_id)
            decision.approval_outcome = outcome
            allowed = outcome == "approved"
            if not allowed:
                self._account_denial(canon.fingerprint, decision)
            self.recorder.record_approval_outcome(action_id, outcome, decision.terminate)

        if not allowed:
            self.guard.history.record(seq, canon, Decision.BLOCK, False, "")
            return self._denied(action_id, decision)

        result = self.__executor.execute(self.__token, action_id, canon)
        self.state.tool_calls[call.tool] += 1
        self.guard.history.record(seq, canon, Decision.ALLOW, result.status == "ok", result.output)
        return ToolOutcome(
            action_id=action_id,
            status="ok" if result.status == "ok" else "error",
            output=result.output,
            decision=decision.final,
            rule_id=decision.rule_id,
            reason=decision.reasoning,
            terminate=False,
        )

    def _account_denial(self, fingerprint: str, decision: GuardDecision) -> None:
        if not self.guard.flags.use_policy:
            return
        self.state.record_denial(fingerprint)
        if not decision.terminate and self.guard.engine.denial_budget_exhausted(self.state):
            decision.terminate = True
            decision.reasoning = f"{decision.reasoning} Denial budget exhausted; ending the run."

    def _denied(self, action_id: str, decision: GuardDecision) -> ToolOutcome:
        reason_code = None
        if decision.terminate:
            reason_code = "retry_lockout" if decision.rule_id == "RETRY_LOCKOUT" else "denial_budget"
        return ToolOutcome(
            action_id=action_id, status="denied", decision=decision.final, rule_id=decision.rule_id,
            reason=decision.reasoning, terminate=decision.terminate, termination_reason=reason_code,
            output=f"Denied by BoundaryGuard: {decision.reasoning}",
        )

    def _refuse_malformed(self, seq: int, call: ToolCall, error: str) -> ToolOutcome:
        """A malformed call cannot execute in any configuration, but it is still recorded."""
        fingerprint = hashlib.sha256(
            f"{call.tool}|{json.dumps(call.args, sort_keys=True, default=str)}".encode()
        ).hexdigest()[:24]
        try:
            action_id = self.recorder.record_proposal(seq, call.tool, call.args, None)
        except Exception as exc:
            raise AuditFailure(str(exc)) from exc
        decision = GuardDecision(final=Decision.BLOCK, source="schema", rule_id="ARGS_SCHEMA",
                                 reasoning=f"Malformed tool call: {error}.")
        self._account_denial(fingerprint, decision)
        self.recorder.record_decision(action_id, decision)
        placeholder = CanonicalAction(tool=call.tool, fingerprint=fingerprint)
        self.guard.history.record(seq, placeholder, Decision.BLOCK, False, "")
        return self._denied(action_id, decision)
