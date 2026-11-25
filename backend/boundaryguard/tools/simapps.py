"""Simulated application tools for the external benchmark. Returns canned text and never contacts anything."""
from __future__ import annotations

import re

_CAMEL = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
READ_VERBS = {"get", "read", "view", "search", "list", "find", "check", "retrieve", "fetch", "query", "navigate", "lookup", "download"}
OUTBOUND_VERBS = {"send", "share", "post", "transfer", "pay", "withdraw", "deposit", "forward", "publish", "invite", "tweet", "reply", "autofill", "fill"}


def classify_effect(app_tool: str) -> str:
    """Read, write or outbound, from the verbs in the tool's name. A name with no known verb counts as a write,
    the more cautious reading. The rule is mechanical so it can be audited and applied to tools it has not seen."""
    words = [w.lower() for w in _CAMEL.findall(app_tool)]
    if any(w in OUTBOUND_VERBS for w in words):
        return "outbound"
    if any(w in READ_VERBS for w in words):
        return "read"
    return "write"


class SimApps:
    def __init__(self, responses: dict[str, str] | None = None):
        self.responses = responses or {}
        self.called: set[str] = set()

    def call(self, app_tool: str) -> str:
        self.called.add(app_tool)
        return self.responses.get(app_tool, '{"success": true}')
