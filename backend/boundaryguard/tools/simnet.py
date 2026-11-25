"""Simulated network. This module must never import socket, http or urllib.request."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

DEFAULT_RESPONSE = {"status": 200, "body": json.dumps({"ok": True})}


@dataclass(frozen=True)
class SimResponse:
    status: int
    body: str
    sink: bool


class SimNet:
    def __init__(self, routes: dict[str, dict[str, Any]] | None = None):
        self.routes = {host.lower(): paths for host, paths in (routes or {}).items()}

    def request(self, url: str, host: str | None, path: str | None, method: str, body: str) -> SimResponse:
        route = self.routes.get((host or "").lower(), {}).get(path or "/", DEFAULT_RESPONSE)
        # Data leaves through a request body or a query string. Either one reaches the sink.
        sink = method != "GET" or bool(body) or "?" in url
        return SimResponse(int(route.get("status", 200)), str(route.get("body", "")), sink)
