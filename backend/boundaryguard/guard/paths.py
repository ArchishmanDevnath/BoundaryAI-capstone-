"""Strict path-form checks and glob matching used by the policy engine.

The sandbox floor maps alias forms to files because a real filesystem would. The policy
refuses those same forms outright, since legitimate agents have no reason to use them.
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

from ..tools.sandbox import RESERVED_DEVICE_NAMES

_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
_DRIVE = re.compile(r"^/?[A-Za-z]:")
_SHORT_NAME = re.compile(r"~\d+(\.[^./]*)?$")


def suspicious_form(raw: str) -> str | None:
    """Return a violation code if the raw path uses an alias or encoding form, else None."""
    if not isinstance(raw, str) or not raw:
        return "empty_path"
    if len(raw) > 1024:
        return "path_too_long"
    if any(ord(c) < 32 or ord(c) == 127 for c in raw):
        return "control_character"
    if _PERCENT.search(raw):
        return "percent_encoding"
    if unicodedata.normalize("NFKC", raw) != raw:
        return "unicode_variant"
    normalized = raw.replace("\\", "/")
    if normalized.startswith("//"):
        return "unc_or_device_prefix"
    if _DRIVE.match(normalized):
        return "drive_path"
    for comp in normalized.split("/"):
        if comp in ("", ".", ".."):
            continue
        if ":" in comp:
            return "ntfs_stream"
        if comp != comp.rstrip(". "):
            return "trailing_dot_or_space"
        if _SHORT_NAME.search(comp):
            return "short_name"
        if comp.split(".", 1)[0].upper() in RESERVED_DEVICE_NAMES:
            return "device_name"
    return None


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        rest = pattern[i:]
        if rest.startswith("/**") and (len(rest) == 3 or rest[3] == "/"):
            if len(rest) == 3:
                out.append("(?:/.*)?")
                i += 3
            else:
                out.append("(?:/.*)?/")
                i += 4
        elif rest.startswith("**/"):
            out.append("(?:.*/)?")
            i += 3
        elif rest.startswith("**"):
            out.append(".*")
            i += 2
        elif rest[0] == "*":
            out.append("[^/]*")
            i += 1
        elif rest[0] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(rest[0]))
            i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def glob_match(pattern: str, path: str) -> bool:
    """Case-insensitive glob on virtual paths. `*` stays in one segment, `**` crosses segments."""
    return _compile(pattern).match(path) is not None


def matches_any(patterns: list[str], path: str | None) -> str | None:
    if path is None:
        return None
    for pattern in patterns:
        if glob_match(pattern, path):
            return pattern
    return None
