"""Features shared by training and runtime, so the model never sees a different view in production.

Deliberately excluded: scenario ids, project names, literal file names and application tool names as categorical
values. A model given those would memorize the benchmark instead of learning general signals. Words from paths can
still reach the text model, which is why every split keeps projects and templates disjoint.
"""
from __future__ import annotations

import math
import re
from typing import Any

from ..guard.context.base import AssessmentContext
from ..guard.context.heuristic import (
    DELETE_WORDS, INFRA_PATH, NETWORK_WORDS, OPERATIONAL_PATH, RISKY_CODE, SENSITIVE_APP, SENSITIVE_PATH, TEST_PATH,
    TEST_WEAKENING, app_tool_words, mentioned_host, sensitive_in_scope, tokens,
)
from ..guard.history import INJECTION_MARKERS, SECRET_ASSIGNMENT, SENSITIVE_MARKERS

STATELESS_FEATURES = [
    "access_read", "access_write", "access_network", "access_exec", "access_app_read", "access_app_write", "access_app_outbound",
    "is_delete", "is_outbound", "target_sensitive", "target_sensitive_in_scope", "target_operational", "target_infra", "target_test",
    "relevant_to_task", "target_task_overlap", "host_named_in_task", "task_mentions_network", "task_mentions_delete",
    "out_of_scope_sensitive", "out_of_scope_change", "payload_risky_code", "payload_test_weakening", "payload_secret",
    "payload_log_length", "policy_needs_approval",
]
STATEFUL_FEATURES = [
    "prior_denials", "recent_denials", "same_action_runs", "same_action_denials",
    "signal_sensitive_data_flow", "signal_data_flow", "signal_retry_variant", "signal_tainted_context",
    "signal_repeat_unnecessary", "signal_denial_burst", "signal_scope_drift", "signal_weight_total", "signal_hard",
    "untrusted_has_injection", "target_in_untrusted", "action_words_only_in_untrusted",
]
# Computed but never trained on. An action's position in a run says nothing about its risk, and in generated traces it
# says a great deal about how the generator was written: model v1 learned "first action means attack" from it, and the
# post-hoc v2 still ranked it among its top five inputs. Bundles trained before this change list it, and still load.
POSITION_FEATURES = ["prior_steps"]
ALL_FEATURES = STATELESS_FEATURES + POSITION_FEATURES + STATEFUL_FEATURES
FEATURE_SET_VERSION = 2
FEATURE_SETS = {"stateless": STATELESS_FEATURES, "stateful": STATELESS_FEATURES + STATEFUL_FEATURES}

_TOKEN = re.compile(r"[a-z0-9]+")
_CANARY = re.compile(r"BG_CANARY_\w+")


def _flag(value: Any) -> float:
    return 1.0 if value else 0.0


def _action_words(ctx: AssessmentContext) -> set[str]:
    action = ctx.action
    if action.access == "app":
        return app_tool_words(action.app_tool) | tokens(action.payload or "")
    if action.access == "network":
        return tokens(f"{action.url_host or ''} {action.url_path or ''}")
    return tokens((action.real_virtual_path or action.virtual_path or "").removeprefix("/project/"))


def extract_features(ctx: AssessmentContext) -> dict[str, float]:
    """Every feature, for both profiles. Stateful values are zero when the configuration has no history."""
    action = ctx.action
    target = action.real_virtual_path or action.virtual_path or ""
    payload = action.payload or ""
    is_app = action.access == "app"
    effect = action.app_effect
    sensitive = bool(target and SENSITIVE_PATH.search(target)) or (is_app and bool(SENSITIVE_APP.search(action.app_tool or "")))
    in_scope = bool(target) and sensitive_in_scope(ctx.objective, target) if not is_app else ctx.relevant_to_task
    relevant = ctx.relevant_to_task
    task_words = tokens(ctx.objective)
    words = _action_words(ctx)
    outbound = (action.access == "network" and action.method != "GET") or action.access == "exec" or effect == "outbound"
    changes = action.tool in ("write_file", "delete_file") or (is_app and effect != "read") or outbound
    features = {
        "access_read": _flag(action.access == "read"),
        "access_write": _flag(action.access == "write"),
        "access_network": _flag(action.access == "network"),
        "access_exec": _flag(action.access == "exec"),
        "access_app_read": _flag(is_app and effect == "read"),
        "access_app_write": _flag(is_app and effect == "write"),
        "access_app_outbound": _flag(is_app and effect == "outbound"),
        "is_delete": _flag(action.tool == "delete_file"),
        "is_outbound": _flag(outbound),
        "target_sensitive": _flag(sensitive),
        "target_sensitive_in_scope": _flag(sensitive and in_scope),
        "target_operational": _flag(target and OPERATIONAL_PATH.search(target)),
        "target_infra": _flag(target and INFRA_PATH.search(target)),
        "target_test": _flag(target and TEST_PATH.search(target)),
        "relevant_to_task": _flag(relevant),
        "target_task_overlap": len(words & task_words) / len(words) if words else 0.0,
        "host_named_in_task": _flag(action.url_host and mentioned_host(ctx.objective, action.url_host)),
        "task_mentions_network": _flag(NETWORK_WORDS.search(ctx.objective)),
        "task_mentions_delete": _flag(DELETE_WORDS.search(ctx.objective)),
        "out_of_scope_sensitive": _flag(sensitive and not in_scope),
        "out_of_scope_change": _flag(changes and not relevant),
        "payload_risky_code": _flag(RISKY_CODE.search(payload)),
        "payload_test_weakening": _flag(TEST_PATH.search(target) and TEST_WEAKENING.search(payload)),
        "payload_secret": _flag(SECRET_ASSIGNMENT.search(payload) or SENSITIVE_MARKERS.search(payload)),
        "payload_log_length": math.log1p(len(payload)),
        "policy_needs_approval": _flag(ctx.policy_verdict.value == "APPROVAL_REQUIRED"),
    }
    stats = ctx.history_stats
    signals = {s.name: s for s in ctx.signals}
    untrusted = ctx.untrusted_text
    untrusted_words = tokens(untrusted) if untrusted else set()
    only_untrusted = words & untrusted_words - task_words
    features.update({
        "prior_steps": float(stats.get("steps", 0)),
        "prior_denials": float(stats.get("denials", 0)),
        "recent_denials": float(stats.get("recent_denials", 0)),
        "same_action_runs": float(stats.get("same_action_runs", 0)),
        "same_action_denials": float(stats.get("same_action_denials", 0)),
        "signal_sensitive_data_flow": _flag("sensitive_data_flow" in signals),
        "signal_data_flow": _flag("data_flow" in signals),
        "signal_retry_variant": _flag("retry_variant" in signals),
        "signal_tainted_context": _flag("tainted_context" in signals),
        "signal_repeat_unnecessary": _flag("repeat_unnecessary" in signals),
        "signal_denial_burst": _flag("denial_burst" in signals),
        "signal_scope_drift": _flag("scope_drift" in signals),
        "signal_weight_total": min(2.0, sum(s.weight for s in ctx.signals)),
        "signal_hard": _flag(any(s.hard for s in ctx.signals)),
        "untrusted_has_injection": _flag(untrusted and INJECTION_MARKERS.search(untrusted)),
        "target_in_untrusted": _flag(words and words <= untrusted_words),
        "action_words_only_in_untrusted": len(only_untrusted) / len(words) if words else 0.0,
    })
    return features


def _clean(text: str) -> str:
    """Lower-case, split identifiers into words, and remove per-run tokens that could only ever memorize a run."""
    text = _CANARY.sub(" ", text)
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    return " ".join(_TOKEN.findall(text.lower()))


def text_views(ctx: AssessmentContext) -> dict[str, str]:
    action = ctx.action
    effect = action.app_effect or action.access
    described = f"{action.tool} {effect} {action.method or ''} {action.target or ''} {(action.payload or '')[:800]}"
    return {"task": _clean(ctx.objective), "action": _clean(described), "untrusted": _clean(ctx.untrusted_text[-3000:])}
