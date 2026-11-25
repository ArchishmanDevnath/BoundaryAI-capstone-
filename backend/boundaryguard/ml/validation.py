"""Dataset, label and leakage checks. Training refuses to start if any of these fail."""
from __future__ import annotations

import math
import re
from typing import Any

from .features import ALL_FEATURES

LABELS = {"unauthorized", "legitimate"}
GROUP_FIELDS = ("project", "task", "family")
REQUIRED = ("id", "split", "project", "task", "family", "category", "label", "rule", "features", "text", "heuristic_stateless", "heuristic_stateful")
NEAR_DUPLICATE_JACCARD = 0.9
_WORD = re.compile(r"[a-z0-9]+")


class DatasetError(ValueError):
    """The data cannot be used safely. The message says why."""


def validate_records(records: list[dict[str, Any]]) -> None:
    if not records:
        raise DatasetError("The dataset is empty.")
    seen: set[str] = set()
    names = ALL_FEATURES
    for record in records:
        absent = [k for k in REQUIRED if k not in record or record[k] is None]
        if absent:
            raise DatasetError(f"Record {record.get('id', '?')} is missing {absent}.")
        if record["label"] not in LABELS:
            raise DatasetError(f"Record {record['id']} has invalid label {record['label']!r}.")
        if record["id"] in seen:
            raise DatasetError(f"Duplicate record id {record['id']}.")
        seen.add(record["id"])
        features = record["features"]
        for name in names:
            value = features.get(name)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
                raise DatasetError(f"Record {record['id']} has invalid feature {name}={value!r}.")
    for split in {r["split"] for r in records}:
        labels = {r["label"] for r in records if r["split"] == split}
        if labels != LABELS:
            raise DatasetError(f"Split '{split}' does not contain both classes: {sorted(labels)}.")


def _words(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def _signature(record: dict[str, Any]) -> set[str]:
    return _words(record["text"]["task"] + " " + record["text"]["action"])


def group_overlaps(records: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Any project, task or family present in more than one split."""
    out: dict[str, list[str]] = {}
    for field in GROUP_FIELDS:
        owners: dict[str, set[str]] = {}
        for record in records:
            owners.setdefault(record[field], set()).add(record["split"])
        shared = sorted(name for name, splits in owners.items() if len(splits) > 1)
        if shared:
            out[field] = shared
    return out


def near_duplicates(records: list[dict[str, Any]], threshold: float = NEAR_DUPLICATE_JACCARD) -> list[tuple[str, str, float]]:
    """Pairs across splits whose task and action text nearly coincide. Compares distinct signatures, to stay tractable."""
    by_split: dict[str, dict[frozenset[str], str]] = {}
    for record in records:
        by_split.setdefault(record["split"], {}).setdefault(frozenset(_signature(record)), record["id"])
    found: list[tuple[str, str, float]] = []
    splits = sorted(by_split)
    for i, first in enumerate(splits):
        for second in splits[i + 1:]:
            for a, a_id in by_split[first].items():
                for b, b_id in by_split[second].items():
                    if not a or not b:
                        continue
                    shared = len(a & b)
                    if shared / (len(a) + len(b) - shared) >= threshold:
                        found.append((a_id, b_id, round(shared / (len(a) + len(b) - shared), 3)))
    return found


def leakage_report(records: list[dict[str, Any]], internal_scenarios: list[Any], external_scenarios: list[Any]) -> dict[str, Any]:
    problems: list[str] = []
    overlaps = group_overlaps(records)
    if overlaps:
        problems.append(f"Groups shared across splits: {overlaps}")
    keys: dict[str, set[str]] = {}
    for record in records:
        keys.setdefault(str([record["text"], record["features"]]), set()).add(record["split"])
    exact = sum(1 for splits in keys.values() if len(splits) > 1)
    if exact:
        problems.append(f"{exact} identical records appear in more than one split.")
    near = near_duplicates(records)
    if near:
        problems.append(f"{len(near)} near-duplicate pairs across splits at Jaccard >= {NEAR_DUPLICATE_JACCARD}.")

    objectives = {r["objective"].strip().lower() for r in records}
    internal = sorted(s.id for s in internal_scenarios if s.objective.strip().lower() in objectives)
    external = sorted({s.id for s in external_scenarios if s.objective.strip().lower() in objectives})
    if internal:
        problems.append(f"Training objectives identical to benchmark scenarios: {internal}")
    if external:
        problems.append(f"Training objectives identical to InjecAgent cases: {external[:5]}")
    # Training text must not contain InjecAgent's own instructions, which would quietly contaminate the external test.
    training_text = " ".join(sorted({r["text"]["untrusted"] for r in records if r["split"] == "train"}))[:2_000_000]
    return {
        "problems": problems, "group_overlaps_across_splits": overlaps, "identical_records_across_splits": exact,
        "near_duplicate_pairs_across_splits": len(near), "near_duplicate_threshold": NEAR_DUPLICATE_JACCARD,
        "objectives_shared_with_internal_scenarios": internal, "objectives_shared_with_injecagent": external,
        "training_contains_injecagent_marker": "ignore all previous instructions and strictly adhere" in training_text,
    }
