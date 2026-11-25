"""The ML contextual assessor. It can raise risk and recommend a denial. It never sees an action the policy denied.

Failure is fail-closed. A missing, corrupt or tampered model, an exception, a timeout or an invalid prediction all
produce a BLOCK with assessor_fallback set. Nothing is allowed because the model could not give an opinion.
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..guard.context.base import AssessmentContext
from ..guard.context.heuristic import HeuristicAssessor
from ..models.core import Assessment, Decision, RiskLevel, Signal, risk_to_decision
from .features import ALL_FEATURES, extract_features, text_views

CURRENT_FILE = "CURRENT"
METADATA_FILE = "metadata.json"
PROFILES = ("stateless", "stateful")


class ModelUnavailable(Exception):
    """The model bundle is missing, incomplete, corrupt or fails its integrity check."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_digest(hashes: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


def resolve_bundle(model_dir: str | Path) -> Path:
    root = Path(model_dir)
    pointer = root / CURRENT_FILE
    if not pointer.is_file():
        raise ModelUnavailable("No trained model is installed.")
    name = pointer.read_text(encoding="utf-8").strip()
    # The pointer names a direct child of the model directory, nothing else.
    if not name or Path(name).name != name or name in (".", ".."):
        raise ModelUnavailable("The model pointer is invalid.")
    bundle = root / name
    if not bundle.is_dir():
        raise ModelUnavailable(f"Model bundle '{name}' is missing.")
    return bundle


def read_metadata(bundle: Path) -> dict[str, Any]:
    try:
        return json.loads((bundle / METADATA_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ModelUnavailable(f"Model metadata is unreadable: {exc}") from exc


def verify_bundle(bundle: Path, metadata: dict[str, Any]) -> None:
    """Joblib files can run code when loaded, so their hashes are checked first and a mismatch is never unpickled."""
    hashes = metadata.get("artifacts")
    if not isinstance(hashes, dict) or not hashes:
        raise ModelUnavailable("Model metadata lists no artifacts.")
    for name, expected in hashes.items():
        path = bundle / name
        if Path(name).name != name or not path.is_file():
            raise ModelUnavailable(f"Model artifact '{name}' is missing.")
        if _sha256(path) != expected:
            raise ModelUnavailable(f"Model artifact '{name}' failed its integrity check.")


@dataclass
class LoadedProfile:
    text: Any
    structured: Any
    hybrid: Any
    feature_names: list[str]
    review_threshold: float
    block_threshold: float
    importances: dict[str, float]
    version: str

    def predict(self, ctx: AssessmentContext, heuristic_score: float) -> dict[str, Any]:
        import numpy as np
        import pandas as pd

        features = extract_features(ctx)
        views = text_views(ctx)
        frame = pd.DataFrame([views])
        matrix = np.array([[features[name] for name in self.feature_names]])
        p_text = float(self.text.predict_proba(frame)[0, 1])
        p_structured = float(self.structured.predict_proba(matrix)[0, 1])
        meta = hybrid_inputs(p_text, p_structured, heuristic_score, features)
        p_hybrid = float(self.hybrid.predict_proba(np.array([meta]))[0, 1])
        return {"text": p_text, "structured": p_structured, "hybrid": p_hybrid, "features": features, "views": frame}


def _logit(p: float) -> float:
    p = min(1 - 1e-4, max(1e-4, p))
    return math.log(p / (1 - p))


def hybrid_inputs(p_text: float, p_structured: float, heuristic_score: float, features: dict[str, float]) -> list[float]:
    """Inputs to the stacked model. The history terms are zero in the stateless profile."""
    return [_logit(p_text), _logit(p_structured), heuristic_score, features["signal_weight_total"], features["signal_hard"]]


_cache: dict[tuple[str, str], dict[str, LoadedProfile]] = {}
_cache_lock = threading.Lock()
# predict_proba is not interruptible, so the wait is bounded here and a stuck call is abandoned rather than awaited.
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="bg-ml")


def load_profiles(model_dir: str | Path) -> dict[str, LoadedProfile]:
    bundle = resolve_bundle(model_dir)
    metadata = read_metadata(bundle)
    key = (str(bundle), json.dumps(metadata.get("artifacts", {}), sort_keys=True) + str((bundle / METADATA_FILE).stat().st_mtime_ns))
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    verify_bundle(bundle, metadata)
    try:
        import joblib

        profiles = {}
        for name in PROFILES:
            info = metadata["profiles"][name]
            trained_on = info.get("feature_names")
            # A bundle may use any subset of what this code computes, in its own order. Anything else is a mismatch.
            if not isinstance(trained_on, list) or not trained_on or not set(trained_on) <= set(ALL_FEATURES):
                raise ModelUnavailable("The model was trained with different features than this code computes.")
            profiles[name] = LoadedProfile(
                text=joblib.load(bundle / f"{name}_text.joblib"),
                structured=joblib.load(bundle / f"{name}_structured.joblib"),
                hybrid=joblib.load(bundle / f"{name}_hybrid.joblib"),
                feature_names=list(trained_on),
                review_threshold=float(info["thresholds"]["review"]),
                block_threshold=float(info["thresholds"]["block"]),
                importances=info.get("structured_importances", {}),
                version=metadata["version"],
            )
    except ModelUnavailable:
        raise
    except Exception as exc:  # any load problem means no usable model
        raise ModelUnavailable(f"Model could not be loaded: {type(exc).__name__}") from exc
    with _cache_lock:
        _cache.clear()
        _cache[key] = profiles
    return profiles


def active_model_info(model_dir: str | Path) -> dict[str, Any]:
    """What the dashboard and experiment manifests show. Verifies integrity, and never raises."""
    try:
        bundle = resolve_bundle(model_dir)
        metadata = read_metadata(bundle)
        verify_bundle(bundle, metadata)
        return {"available": True, "problem": None, "version": metadata["version"], "trained_at": metadata.get("trained_at"),
                "bundle_sha256": bundle_digest(metadata["artifacts"]), "metadata": metadata}
    except ModelUnavailable as exc:
        return {"available": False, "problem": str(exc), "version": None, "trained_at": None, "bundle_sha256": None, "metadata": None}


def _explain(profile: LoadedProfile, result: dict[str, Any], limit: int = 3) -> tuple[list[Signal], list[str]]:
    """Reason codes: the risk-raising structured features that are active, ordered by the model's own importances,
    plus the text terms that pushed the logistic regression towards risk the most."""
    features = result["features"]
    active = sorted(((profile.importances.get(n, 0.0), n) for n in profile.feature_names
                     if features.get(n) and n not in ("relevant_to_task", "payload_log_length", "prior_steps", "access_read")), reverse=True)
    reasons = [name.replace("_", " ") for weight, name in active[:limit] if weight > 0]
    terms: list[str] = []
    try:
        vectors = profile.text.named_steps["tfidf"]
        classifier = profile.text.named_steps["clf"]
        # A calibrated classifier wraps several fitted folds, so explanations use their average weights.
        fitted = [c.estimator for c in classifier.calibrated_classifiers_] if hasattr(classifier, "calibrated_classifiers_") else [classifier]
        coefficients = sum(f.coef_[0] for f in fitted) / len(fitted)
        row = vectors.transform(result["views"])
        names = vectors.get_feature_names_out()
        scored = sorted(((coefficients[i] * row[0, i], names[i]) for i in row.nonzero()[1]), reverse=True)
        from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

        def informative(term: str) -> bool:
            words = term.split()
            return any(len(w) > 2 and w not in ENGLISH_STOP_WORDS for w in words)

        # Function words can carry weight in a bag-of-words model, but they explain nothing to a reader.
        terms = [name.split("__", 1)[-1] for score, name in scored if score > 0 and informative(name.split("__", 1)[-1])][:limit]
    except (AttributeError, KeyError, IndexError):  # an explanation is optional, and the decision stands without it
        pass
    signals = [Signal(name="ml_hybrid", weight=round(result["hybrid"], 3),
                      detail=f"Text model {result['text']:.2f}, structured model {result['structured']:.2f}.")]
    return signals, reasons + ([f"terms: {', '.join(terms)}"] if terms else [])


class MLAssessor:
    def __init__(self, profile: str, model_dir: str | Path, timeout_s: float = 2.0):
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile '{profile}'.")
        self.profile_name = profile
        self.model_dir = model_dir
        self.timeout_s = timeout_s
        self.name = f"ml-{profile}"
        self.heuristic = HeuristicAssessor()

    def assess(self, ctx: AssessmentContext) -> Assessment:
        try:
            profile = load_profiles(self.model_dir)[self.profile_name]
            heuristic = self.heuristic.assess(ctx)
            future = _pool.submit(profile.predict, ctx, heuristic.risk_score)
            result = future.result(timeout=self.timeout_s)
            hybrid = result["hybrid"]
            if not isinstance(hybrid, float) or math.isnan(hybrid) or not 0.0 <= hybrid <= 1.0:
                raise ValueError("invalid prediction")
        except ModelUnavailable as exc:
            return self._fail_closed(ctx, str(exc))
        except FutureTimeout:
            return self._fail_closed(ctx, f"prediction exceeded {self.timeout_s} s")
        except Exception as exc:  # whatever went wrong, the action does not proceed on a missing opinion
            return self._fail_closed(ctx, type(exc).__name__)
        return self._decide(ctx, profile, result, heuristic)

    def _decide(self, ctx: AssessmentContext, profile: LoadedProfile, result: dict[str, Any], heuristic: Assessment) -> Assessment:
        hybrid = result["hybrid"]
        if hybrid >= profile.block_threshold:
            level = RiskLevel.HIGH
        elif hybrid >= profile.review_threshold:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW
        decision = risk_to_decision(level)
        # Deterministic history evidence cannot be talked away by a model.
        hard = [s for s in ctx.signals if s.hard]
        if hard:
            level, decision = RiskLevel.HIGH, Decision.BLOCK
        signals, reasons = _explain(profile, result)
        because = f" Main factors: {'; '.join(reasons)}." if reasons and decision is not Decision.ALLOW else ""
        comparison = f" The heuristic scored this {heuristic.risk_score:.2f} ({heuristic.recommended_action.value})."
        reasoning = (f"ML risk {hybrid:.2f} (review at {profile.review_threshold:.2f}, block at {profile.block_threshold:.2f}).{because}{comparison}")
        return Assessment(risk_level=level, risk_score=round(hybrid, 4), reasoning=reasoning, recommended_action=decision,
                          assessor=f"{self.name}:{profile.version}", signals=signals + list(ctx.signals))

    def _fail_closed(self, ctx: AssessmentContext, why: str) -> Assessment:
        return Assessment(
            risk_level=RiskLevel.HIGH, risk_score=1.0, recommended_action=Decision.BLOCK, fallback=True, assessor=self.name,
            reasoning=f"The ML assessor is unavailable ({why}), so this action was blocked. Deterministic rules still applied.",
            signals=list(ctx.signals),
        )
