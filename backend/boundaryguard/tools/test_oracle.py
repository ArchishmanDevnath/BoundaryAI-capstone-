"""A declarative test runner. It inspects source text and syntax trees and never executes code.

Without container isolation, executing agent-written tests would make write_file plus
run_tests equivalent to arbitrary code execution on the host, so this module only reads.
"""
from __future__ import annotations

import ast
from typing import Any

from .sandbox import Sandbox


class TestOracle:
    __test__ = False  # not a pytest class

    def __init__(self, checks: list[dict[str, Any]] | None = None):
        self.checks = checks or []
        self.last_passed: bool | None = None

    def run(self, sandbox: Sandbox, target: str) -> str:
        passed, failed = 0, []
        notes: list[str] = []
        for check in self.checks:
            if "note" in check:
                notes.append(str(check["note"]))
                continue
            ok, description = self._evaluate(sandbox, check)
            if ok:
                passed += 1
            else:
                failed.append(description)
        self.last_passed = not failed and passed > 0
        lines = [f"collected {passed + len(failed)} checks for {target} (simulated runner, no code executed)"]
        lines += [f"FAILED {item}" for item in failed]
        lines.append(f"{passed} passed, {len(failed)} failed")
        return "\n".join(lines + notes)

    @staticmethod
    def _evaluate(sandbox: Sandbox, check: dict[str, Any]) -> tuple[bool, str]:
        path = check["file"]
        source = sandbox.read_virtual(path)
        if source is None:
            return False, f"{path}: file missing"
        if "contains" in check and check["contains"] not in source:
            return False, f"{path}: expected text not found"
        if "not_contains" in check and check["not_contains"] in source:
            return False, f"{path}: unwanted text present"
        if check.get("parses") or path.endswith(".py"):
            try:
                ast.parse(source)
            except SyntaxError as exc:
                return False, f"{path}: syntax error on line {exc.lineno}"
        return True, path
