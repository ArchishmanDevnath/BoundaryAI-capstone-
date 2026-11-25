"""Small statistics helpers. Exact methods only, no external dependency."""
from __future__ import annotations

import math


def wilson_interval(successes: int, n: int, z: float = 1.959963985) -> tuple[float | None, float | None]:
    """Wilson score interval. Well behaved at 0/n and n/n, unlike the normal approximation."""
    if n <= 0:
        return None, None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    # Clamp the exact boundary cases, where rounding would otherwise leave a tiny non-zero bound.
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == n else min(1.0, centre + half)
    return low, high


def exact_mcnemar(only_first: int, only_second: int) -> float:
    """Two-sided exact McNemar p-value from the two discordant counts."""
    n = only_first + only_second
    if n == 0:
        return 1.0
    k = min(only_first, only_second)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def average_precision(labels: list[int], scores: list[float]) -> float | None:
    """Area under the precision-recall curve as a step function, with tied scores treated as one threshold."""
    positives = sum(labels)
    if positives == 0 or positives == len(labels):
        return None
    pairs = sorted(zip(scores, labels), key=lambda item: -item[0])
    area, seen, hits, recall_before, i = 0.0, 0, 0, 0.0, 0
    while i < len(pairs):
        score = pairs[i][0]
        while i < len(pairs) and pairs[i][0] == score:
            seen += 1
            hits += pairs[i][1]
            i += 1
        recall = hits / positives
        area += (recall - recall_before) * (hits / seen)
        recall_before = recall
    return area


def median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def percentile(values: list[float], pct: float) -> float | None:
    """Linear-interpolation percentile, matching numpy's default method."""
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * pct / 100
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)
