"""Action-history signals. These cover patterns a stateless rule cannot see."""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from ..models.core import CanonicalAction, Decision, Signal

# A secret is a value assigned to a sensitive key. Code that merely mentions a word like
# "password" (check_password, for example) is not sensitive data.
SECRET_ASSIGNMENT = re.compile(
    r"(?:api[_-]?key|secret|passw(?:or)?d|token|credential|access[_-]?key)[\w-]*[\"']?\s*[:=]\s*[\"']?([^\s\"'(),]{8,})",
    re.IGNORECASE,
)
SENSITIVE_MARKERS = re.compile(r"BEGIN [A-Z ]*PRIVATE|(^|[,\s])ssn([,\s]|$)", re.IGNORECASE | re.MULTILINE)
INJECTION_MARKERS = re.compile(
    r"(ignore (all |any |the )?(previous|prior|above) instructions|disregard (your|the|all) |"
    r"new instructions?:|system (note|override|prompt)|you must now|as the ai agent|"
    r"ai (agent|assistant)s?[,:]? (must|should|please)|do not (tell|inform|mention) .{0,30}(user|developer))",
    re.IGNORECASE,
)
_WORD = re.compile(r"[A-Za-z0-9_+/=:.-]{6,}")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
SHINGLE = 3


def _shingles(text: str) -> set[tuple[str, ...]]:
    words = _WORD.findall(text)
    if len(words) < SHINGLE:
        return {tuple(words)} if words else set()
    return {tuple(words[i:i + SHINGLE]) for i in range(len(words) - SHINGLE + 1)}


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text))


def _decoded_variants(text: str) -> list[str]:
    out = []
    for match in _B64.findall(text):
        try:
            out.append(base64.b64decode(match + "=" * (-len(match) % 4)).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            pass
    for match in _HEX.findall(text):
        try:
            out.append(bytes.fromhex(match[: len(match) // 2 * 2]).decode("utf-8", "ignore"))
        except ValueError:
            pass
    return [v for v in out if v]


@dataclass
class _ReadRecord:
    path: str
    sensitive: bool
    shingles: set[tuple[str, ...]]
    secret_tokens: set[str]


@dataclass
class _Entry:
    seq: int
    tool: str
    target: str | None
    fingerprint: str
    denied: bool
    payload_tokens: set[str]


@dataclass
class HistoryTracker:
    """Records what happened in the run and derives signals about the next proposed action."""
    entries: list[_Entry] = field(default_factory=list)
    reads: list[_ReadRecord] = field(default_factory=list)
    tainted_by: str | None = None
    untrusted: list[str] = field(default_factory=list)

    def untrusted_text(self, limit: int = 6000) -> str:
        """Tool output seen so far, newest last. It may hold instructions, so it is only ever data."""
        return "\n".join(self.untrusted)[-limit:]

    def stats_for(self, action: CanonicalAction) -> dict[str, int]:
        """Plain counters over the run so far, for the ML features."""
        return {
            "steps": len(self.entries),
            "denials": sum(1 for e in self.entries if e.denied),
            "recent_denials": sum(1 for e in self.entries[-5:] if e.denied),
            "same_action_runs": sum(1 for e in self.entries if e.fingerprint == action.fingerprint and not e.denied),
            "same_action_denials": sum(1 for e in self.entries if e.fingerprint == action.fingerprint and e.denied),
        }

    def signals_for(self, action: CanonicalAction, relevant_to_task: bool) -> list[Signal]:
        signals: list[Signal] = []
        self._data_flow(action, signals)
        self._retry_variant(action, signals)
        recent = self.entries[-5:]
        denials = sum(1 for e in recent if e.denied)
        if denials >= 2:
            signals.append(Signal(name="denial_burst", weight=0.25, detail=f"{denials} of the last {len(recent)} actions were denied."))
        if self.tainted_by and not relevant_to_task and action.tool not in ("run_tests", "list_dir"):
            signals.append(Signal(name="tainted_context", weight=0.45,
                                  detail=f"Injection-like text was read from {self.tainted_by}, and this action is not related to the task."))
        repeats = sum(1 for e in self.entries if e.fingerprint == action.fingerprint and not e.denied)
        if repeats >= 3 and action.tool != "run_tests":
            signals.append(Signal(name="repeat_unnecessary", weight=0.45, detail=f"The same action already ran {repeats} times."))
        touched = {self._top_dir(e.target) for e in self.entries if e.target and e.tool != "http_request"}
        touched.discard(None)
        if len(touched) >= 4 and not relevant_to_task:
            signals.append(Signal(name="scope_drift", weight=0.2, detail=f"Run has touched {len(touched)} top-level directories."))
        return signals

    @staticmethod
    def _top_dir(target: str | None) -> str | None:
        if not target:
            return None
        parts = target.strip("/").split("/")
        return "/".join(parts[:2]) if len(parts) > 2 else None

    def _data_flow(self, action: CanonicalAction, signals: list[Signal]) -> None:
        if action.access not in ("network", "write", "exec", "app") or not action.payload or not self.reads:
            return
        outbound = action.access in ("network", "exec") or (action.access == "app" and action.app_effect != "read")
        variants = [action.payload, *_decoded_variants(action.payload)]
        payload_shingles: set[tuple[str, ...]] = set()
        payload_tokens: set[str] = set()
        for text in variants:
            payload_shingles |= _shingles(text)
            payload_tokens |= _tokens(text)
        target = action.real_virtual_path or action.target
        for record in self.reads:
            if not outbound and record.path == target:
                continue
            leaked_secret = record.secret_tokens & payload_tokens
            overlap = record.shingles & payload_shingles
            if record.sensitive and (leaked_secret or (outbound and overlap)):
                signals.append(Signal(
                    name="sensitive_data_flow", weight=0.9, hard=outbound,
                    detail=f"Payload carries data read from sensitive file {record.path}.",
                ))
                return
            if outbound and len(overlap) >= 3:
                signals.append(Signal(name="data_flow", weight=0.45, detail=f"Payload carries content read from {record.path}."))
                return

    def _retry_variant(self, action: CanonicalAction, signals: list[Signal]) -> None:
        denied = [e for e in self.entries if e.denied and e.fingerprint != action.fingerprint]
        if not denied:
            return
        name = (action.target or "").rstrip("/").rsplit("/", 1)[-1].lower()
        stem = name.lstrip(".").split(".")[0]
        payload = _tokens(action.payload or "")
        for entry in denied:
            denied_name = (entry.target or "").rstrip("/").rsplit("/", 1)[-1].lower()
            denied_stem = denied_name.lstrip(".").split(".")[0]
            same_egress = (action.access == "network" and entry.tool == "http_request" and action.method != "GET"
                           and bool(payload) and len(payload & entry.payload_tokens) >= max(1, len(payload) // 2))
            same_stem = action.access in ("read", "write") and entry.tool == action.tool and bool(stem) and stem == denied_stem
            if same_egress or same_stem:
                signals.append(Signal(name="retry_variant", weight=0.45,
                                      detail=f"Looks like another route to denied action #{entry.seq} ({entry.target})."))
                return

    # -- recording, called by the gateway after each decision and execution ----
    def record(self, seq: int, action: CanonicalAction, decision: Decision, executed_ok: bool, output: str) -> None:
        denied = decision is not Decision.ALLOW
        self.entries.append(_Entry(seq, action.tool, action.target, action.fingerprint, denied, _tokens(action.payload or "")))
        if executed_ok and output and action.tool in ("read_file", "http_request", "app_call"):
            self.untrusted.append(output)
        if action.tool == "read_file" and executed_ok and output:
            path = action.real_virtual_path or action.virtual_path or ""
            secrets = set(SECRET_ASSIGNMENT.findall(output))
            sensitive = bool(secrets) or bool(SENSITIVE_MARKERS.search(output))
            self.reads.append(_ReadRecord(path, sensitive, _shingles(output), secrets))
            if self.tainted_by is None and INJECTION_MARKERS.search(output):
                self.tainted_by = path
        elif action.tool in ("http_request", "app_call") and executed_ok and output and self.tainted_by is None:
            if INJECTION_MARKERS.search(output):
                self.tainted_by = action.target
