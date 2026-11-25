"""Strict URL parsing for the network rules. No request is ever sent."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_NUMERIC_LIKE = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$")


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str | None = None
    host: str | None = None
    path: str | None = None
    violation: str | None = None


def parse_url(raw: object) -> ParsedUrl:
    if not isinstance(raw, str) or not raw:
        return ParsedUrl(violation="empty_url")
    if len(raw) > 4096:
        return ParsedUrl(violation="url_too_long")
    if any(ord(c) <= 32 or ord(c) == 127 for c in raw) or "\\" in raw:
        return ParsedUrl(violation="illegal_character")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return ParsedUrl(violation="unparseable")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return ParsedUrl(scheme=scheme or None, violation="bad_scheme")
    netloc = parts.netloc
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if "@" in netloc:
        return ParsedUrl(scheme, host, path, "userinfo_in_url")
    if not host:
        return ParsedUrl(scheme, None, path, "missing_host")
    if "%" in netloc or not netloc.isascii():
        return ParsedUrl(scheme, host, path, "encoded_or_unicode_host")
    if host.startswith("xn--") or ".xn--" in host:
        return ParsedUrl(scheme, host, path, "punycode_host")
    try:
        ipaddress.ip_address(host)
        return ParsedUrl(scheme, host, path, "ip_literal")
    except ValueError:
        pass
    if _NUMERIC_LIKE.match(host):
        return ParsedUrl(scheme, host, path, "ip_literal")
    if host.endswith(".") or not _HOST.match(host):
        return ParsedUrl(scheme, host, path, "malformed_host")
    if port not in (None, 80, 443):
        return ParsedUrl(scheme, host, path, "non_default_port")
    return ParsedUrl(scheme, host, path, None)
