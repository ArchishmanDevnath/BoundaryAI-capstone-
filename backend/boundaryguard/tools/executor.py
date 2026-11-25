"""Runs simulated tools. Only the gateway holds this object and its token.

No configuration of this executor can start a process, open a socket or touch a path
outside run_root. The ledger is written here, independently of the guard's own records.
"""
from __future__ import annotations

import os
from typing import Protocol

from ..models.core import CanonicalAction, ToolResult
from .sandbox import FloorRefused, Sandbox
from .simapps import SimApps
from .simnet import SimNet
from .test_oracle import TestOracle

MAX_READ_BYTES = 64_000


class UnauthorizedExecution(Exception):
    """Raised when the executor is called without the gateway's token."""


class Ledger(Protocol):
    def record(self, action_id: str, tool: str, target: str | None, status: str, n_bytes: int,
               summary: str, scanned_text: str, sink: bool) -> None: ...


class ToolExecutor:
    def __init__(self, token: str, sandbox: Sandbox, simnet: SimNet, oracle: TestOracle, ledger: Ledger,
                 apps: SimApps | None = None):
        self._apps = apps or SimApps()
        self._token = token
        self._sandbox = sandbox
        self._simnet = simnet
        self._oracle = oracle
        self._ledger = ledger

    def execute(self, token: str, action_id: str, action: CanonicalAction) -> ToolResult:
        if token != self._token:
            raise UnauthorizedExecution("Executor called without the gateway token.")
        sink = False
        scanned = ""
        try:
            if action.tool == "http_request":
                result, sink, scanned = self._http(action)
            elif action.tool == "app_call":
                # Canned data only. No application, account or network is ever contacted.
                output = self._apps.call(action.app_tool or "")
                result = ToolResult(status="ok", output=output)
                sink = action.app_effect == "outbound"
                scanned = (action.payload or "") + output
            elif action.tool == "shell_exec":
                # A decoy. The attempt is recorded, and nothing runs.
                result = ToolResult(status="ok", output="[simulated shell] command accepted; nothing was executed.")
                scanned = action.args["command"]
            else:
                result = self._file_tool(action)
                scanned = (action.payload or "") + result.output
        except OSError as exc:
            # exc.strerror leaves out the real path, which the agent must never see.
            result = ToolResult(status="error", output=f"Tool error: {exc.strerror or type(exc).__name__}")
        self._ledger.record(action_id, action.tool, action.target, result.status, result.bytes,
                            result.output[:400], scanned, sink)
        return result

    # -- files -----------------------------------------------------------------
    def _file_tool(self, action: CanonicalAction) -> ToolResult:
        try:
            resolved = self._sandbox.resolve(action.raw_path or "")
        except FloorRefused as exc:
            return ToolResult(status="refused", output=f"Sandbox refused the path ({exc.code}).")
        if not resolved.inside or resolved.real_path is None:
            return ToolResult(status="refused", output="Sandbox refused the path: it resolves outside the sandbox.")
        # Check at time of use: the target must still be the one the guard evaluated.
        if resolved.real_virtual != action.real_virtual_path:
            return ToolResult(status="refused", output="TOCTOU_MISMATCH: the path changed after it was authorized.")
        real = resolved.real_path
        if action.tool == "read_file":
            if not os.path.isfile(real):
                return ToolResult(status="error", output="File not found.")
            with open(real, encoding="utf-8", errors="replace") as fh:
                text = fh.read(MAX_READ_BYTES)
            return ToolResult(status="ok", output=text, bytes=len(text.encode()))
        if action.tool == "list_dir":
            if not os.path.isdir(real):
                return ToolResult(status="error", output="Directory not found.")
            names = sorted(e + ("/" if os.path.isdir(os.path.join(real, e)) else "") for e in os.listdir(real))
            return ToolResult(status="ok", output="\n".join(names))
        if action.tool == "write_file":
            if os.path.isdir(real):
                return ToolResult(status="error", output="Target is a directory.")
            os.makedirs(os.path.dirname(real), exist_ok=True)
            data = action.args["content"]
            with open(real, "w", encoding="utf-8", newline="") as fh:
                fh.write(data)
            return ToolResult(status="ok", output=f"Wrote {resolved.real_virtual}.", bytes=len(data.encode()))
        if action.tool == "delete_file":
            if not os.path.isfile(real):
                return ToolResult(status="error", output="File not found.")
            os.unlink(real)
            return ToolResult(status="ok", output=f"Deleted {resolved.real_virtual}.")
        if action.tool == "run_tests":
            if not resolved.exists:
                return ToolResult(status="error", output="Test target not found.")
            return ToolResult(status="ok", output=self._oracle.run(self._sandbox, resolved.real_virtual or "tests"))
        return ToolResult(status="error", output=f"Unsupported tool {action.tool}.")

    # -- network ----------------------------------------------------------------
    def _http(self, action: CanonicalAction) -> tuple[ToolResult, bool, str]:
        url = action.args["url"]
        body = action.args.get("body", "")
        if action.url_host is None:
            return ToolResult(status="error", output="Simulated network: could not parse the URL."), False, ""
        resp = self._simnet.request(url, action.url_host, action.url_path, action.method or "GET", body)
        output = f"HTTP {resp.status}\n{resp.body}"
        request_text = f"{url}\n{body}"
        result = ToolResult(status="ok", output=output, bytes=len(body.encode()))
        return result, resp.sink, request_text
