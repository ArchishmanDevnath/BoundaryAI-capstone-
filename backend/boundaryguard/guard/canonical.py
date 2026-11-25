"""Turn a validated tool call into the canonical form that policy, history and scoring share."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..models.core import CanonicalAction
from ..tools.catalog import TOOLS
from ..tools.sandbox import FloorRefused, Sandbox
from ..tools.simapps import classify_effect
from .paths import suspicious_form
from .urls import parse_url


def canonicalize(tool: str, args: dict[str, Any], sandbox: Sandbox) -> CanonicalAction:
    spec = TOOLS[tool]
    canon = CanonicalAction(tool=tool, args=args, access=spec["access"])
    path_arg = spec["path_arg"]
    if path_arg:
        raw = args[path_arg]
        canon.raw_path = raw
        canon.path_form_violation = suspicious_form(raw)
        try:
            resolved = sandbox.resolve(raw)
            canon.virtual_path = resolved.virtual
            canon.real_virtual_path = resolved.real_virtual
            canon.inside_sandbox = resolved.inside
        except FloorRefused as exc:
            canon.floor_error = exc.code
        if tool == "write_file":
            canon.payload = args.get("content", "")
    elif tool == "http_request":
        parsed = parse_url(args["url"])
        canon.url_scheme = parsed.scheme
        canon.url_host = parsed.host
        canon.url_path = parsed.path
        canon.url_violation = parsed.violation
        canon.method = args.get("method", "GET")
        canon.payload = args.get("body", "") + " " + args["url"]
    elif tool == "shell_exec":
        canon.payload = args["command"]
    elif tool == "app_call":
        canon.app_tool = args["app_tool"]
        # Derived here from the tool name, never taken from the agent's arguments.
        canon.app_effect = classify_effect(args["app_tool"])
        canon.payload = json.dumps(args.get("params", {}), sort_keys=True, default=str)
    canon.fingerprint = _fingerprint(canon)
    return canon


def _fingerprint(canon: CanonicalAction) -> str:
    if canon.access in ("read", "write"):
        key = (canon.real_virtual_path or canon.virtual_path or canon.raw_path or "").lower()
    elif canon.access == "network":
        key = f"{canon.method}|{canon.url_host}|{canon.url_path}"
    elif canon.access == "app":
        key = f"{canon.app_tool}|{canon.payload}"
    else:
        key = canon.payload or ""
    return hashlib.sha256(f"{canon.tool}|{key}".encode("utf-8", "replace")).hexdigest()[:24]
