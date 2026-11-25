"""The reproducible training pipeline: validate, tune on train, select on validation, then test once.

Selection and thresholds use train and validation data only. The native test split is read only when the caller asks
for the final evaluation, and every such read is recorded in an access log, so that repeated test-set use is visible.
"""
from __future__ import annotations

import hashlib
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GridSearchCV, GroupKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.utils.class_weight import compute_sample_weight

from .assessor import CURRENT_FILE, METADATA_FILE, PROFILES, _sha256, bundle_digest, hybrid_inputs
from .features import FEATURE_SET_VERSION, FEATURE_SETS
from .validation import DatasetError, group_overlaps, validate_records

SEED = 42
CV_FOLDS = 5
REVIEW_MAX_FPR = 0.05  # the proposal's false-block ceiling
BLOCK_MAX_FPR = 0.01
BOOTSTRAP = 1000
TEXT_COLUMNS = {"stateless": ["task", "action"], "stateful": ["task", "action", "untrusted"]}
HEURISTIC_MEDIUM = 0.40  # the heuristic's frozen review threshold, used as the baseline
CONFIG = {
    "seed": SEED, "cv_folds": CV_FOLDS, "cv_groups": "family", "selection_metric": "average_precision",
    "text_grid": {"clf__C": [0.1, 1.0, 10.0], "clf__class_weight": [None, "balanced"]},
    "tfidf": {"lowercase": True, "ngram_range": [1, 2], "min_df": 2, "max_features": 20000, "sublinear_tf": True},
    "random_forest_grid": {"n_estimators": [200], "max_depth": [8, None], "min_samples_leaf": [1, 5], "class_weight": ["balanced"]},
    "gradient_boosting_grid": {"n_estimators": [100, 200], "learning_rate": [0.05, 0.1], "max_depth": [2, 3]},
    "review_max_fpr": REVIEW_MAX_FPR, "block_max_fpr": BLOCK_MAX_FPR, "bootstrap_resamples": BOOTSTRAP,
    "threshold_rule": "lowest threshold with validation false-positive rate within the ceiling",
    # Part of the configuration hash, so a model trained on different inputs can never share a version name.
    "feature_set_version": FEATURE_SET_VERSION, "features": FEATURE_SETS,
}


def load_split(data_dir: Path, split: str) -> list[dict[str, Any]]:
    path = data_dir / "splits" / f"native_{split}.jsonl"
    if not path.is_file():
        raise DatasetError(f"{path} is missing. Run scripts/prepare_data.py.")
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def text_frame(records: list[dict[str, Any]], profile: str) -> pd.DataFrame:
    return pd.DataFrame([{c: r["text"][c] for c in TEXT_COLUMNS[profile]} for r in records], columns=TEXT_COLUMNS[profile])


def feature_matrix(records: list[dict[str, Any]], profile: str) -> np.ndarray:
    names = FEATURE_SETS[profile]
    return np.array([[r["features"][n] for n in names] for r in records], dtype=float)


def labels(records: list[dict[str, Any]]) -> np.ndarray:
    return np.array([1 if r["label"] == "unauthorized" else 0 for r in records])


def groups_of(records: list[dict[str, Any]]) -> np.ndarray:
    return np.array([r["family"] for r in records])


def heuristic_scores(records: list[dict[str, Any]], profile: str) -> np.ndarray:
    return np.array([r[f"heuristic_{profile}"] for r in records], dtype=float)


def build_text_pipeline(profile: str) -> Pipeline:
    params = CONFIG["tfidf"]
    vector = dict(lowercase=params["lowercase"], ngram_range=tuple(params["ngram_range"]), min_df=params["min_df"],
                  max_features=params["max_features"], sublinear_tf=params["sublinear_tf"])
    columns = ColumnTransformer([(c, TfidfVectorizer(**vector), c) for c in TEXT_COLUMNS[profile]])
    return Pipeline([("tfidf", columns), ("clf", LogisticRegression(max_iter=3000, random_state=SEED))])


def _cv(groups: np.ndarray) -> GroupKFold:
    if len(set(groups)) < CV_FOLDS:
        raise DatasetError(f"Need at least {CV_FOLDS} groups for group-aware cross-validation, found {len(set(groups))}.")
    return GroupKFold(n_splits=CV_FOLDS)


def tune(estimator: Any, grid: dict[str, list[Any]], X: Any, y: np.ndarray, groups: np.ndarray, **fit_params: Any) -> GridSearchCV:
    search = GridSearchCV(estimator, grid, scoring="average_precision", cv=_cv(groups), n_jobs=-1, refit=True)
    search.fit(X, y, groups=groups, **fit_params)
    return search


def expected_calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 10) -> tuple[float, list[dict[str, float]]]:
    edges = np.linspace(0, 1, bins + 1)
    error, rows = 0.0, []
    for low, high in zip(edges[:-1], edges[1:]):
        mask = (p >= low) & (p <= high if high == 1 else p < high)
        if mask.any():
            error += mask.mean() * abs(y[mask].mean() - p[mask].mean())
            rows.append({"low": float(low), "high": float(high), "n": int(mask.sum()), "mean_predicted": float(p[mask].mean()), "observed": float(y[mask].mean())})
    return float(error), rows


def select_thresholds(y: np.ndarray, p: np.ndarray) -> dict[str, float]:
    """The lowest threshold whose false-positive rate stays within the ceiling. That spends the legitimate-task budget
    on catching more attacks, and leaves a security margin for data less clean than validation."""
    negatives = max(1, int((y == 0).sum()))

    def best(max_fpr: float) -> tuple[float, float, float]:
        choice = (1.01, 0.0, 0.0)
        for threshold in sorted(set(np.round(p, 6)), reverse=True):
            predicted = p >= threshold
            fpr = (predicted & (y == 0)).sum() / negatives
            if fpr > max_fpr:
                break  # lowering the threshold further can only flag more legitimate actions
            choice = (float(threshold), float((predicted & (y == 1)).sum() / max(1, int((y == 1).sum()))), float(fpr))
        return choice

    review, review_recall, review_fpr = best(REVIEW_MAX_FPR)
    block, block_recall, block_fpr = best(BLOCK_MAX_FPR)
    block = max(block, review)
    return {"review": review, "block": block, "validation_recall_at_review": review_recall, "validation_fpr_at_review": review_fpr,
            "validation_recall_at_block": block_recall, "validation_fpr_at_block": block_fpr}


def _point(y: np.ndarray, p: np.ndarray, threshold: float) -> dict[str, Any]:
    predicted = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    two_classes = len(set(y)) == 2
    ece, curve = expected_calibration_error(y, p)
    return {
        "n": int(len(y)), "threshold": float(threshold), "precision": float(precision_score(y, predicted, zero_division=0)),
        "recall": float(recall_score(y, predicted, zero_division=0)), "f1": float(f1_score(y, predicted, zero_division=0)),
        "pr_auc": float(average_precision_score(y, p)) if two_classes else None, "roc_auc": float(roc_auc_score(y, p)) if two_classes else None,
        "false_positive_rate": float(fp / max(1, fp + tn)), "false_negative_rate": float(fn / max(1, fn + tp)),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "brier": float(brier_score_loss(y, p)) if two_classes else None, "ece": ece, "calibration_curve": curve,
    }


def bootstrap_by_group(y: np.ndarray, p: np.ndarray, threshold: float, groups: np.ndarray, resamples: int = BOOTSTRAP) -> dict[str, list[float] | None]:
    """Percentile intervals resampling whole behaviour families, because actions from one family are not independent."""
    rng = np.random.default_rng(SEED)
    names = sorted(set(groups))
    index = {g: np.flatnonzero(groups == g) for g in names}
    recalls, fprs, aucs = [], [], []
    for _ in range(resamples):
        chosen = np.concatenate([index[names[i]] for i in rng.integers(0, len(names), len(names))])
        ys, ps = y[chosen], p[chosen]
        predicted = ps >= threshold
        if (ys == 1).any():
            recalls.append((predicted & (ys == 1)).sum() / (ys == 1).sum())
        if (ys == 0).any():
            fprs.append((predicted & (ys == 0)).sum() / (ys == 0).sum())
        if len(set(ys)) == 2:
            aucs.append(average_precision_score(ys, ps))

    def interval(values: list[float]) -> list[float] | None:
        return [float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))] if values else None

    return {"recall_ci95": interval(recalls), "false_positive_rate_ci95": interval(fprs), "pr_auc_ci95": interval(aucs), "groups": len(names)}


def evaluate(records: list[dict[str, Any]], p: np.ndarray, threshold: float) -> dict[str, Any]:
    y = labels(records)
    out = _point(y, p, threshold)
    out["bootstrap_by_family"] = bootstrap_by_group(y, p, threshold, groups_of(records))
    out["by_category"] = {}
    for category in sorted({r["category"] for r in records}):
        mask = np.array([r["category"] == category for r in records])
        positives = y[mask] == 1
        predicted = p[mask] >= threshold
        out["by_category"][category] = {"actions": int(mask.sum()), "unauthorized": int(positives.sum()),
                                        "caught": int((predicted & positives).sum()), "legitimate": int((~positives).sum()),
                                        "legitimate_flagged": int((predicted & ~positives).sum())}
    return out


def hybrid_matrix(p_text: np.ndarray, p_structured: np.ndarray, records: list[dict[str, Any]], profile: str) -> np.ndarray:
    """Built with the same function the runtime uses. History inputs are zeroed in the stateless profile."""
    rows = []
    for a, b, heuristic, record in zip(p_text, p_structured, heuristic_scores(records, profile), records):
        features = record["features"] if profile == "stateful" else {"signal_weight_total": 0.0, "signal_hard": 0.0}
        rows.append(hybrid_inputs(float(a), float(b), float(heuristic), features))
    return np.array(rows)


def calibration_comparison(best: Any, X: Any, y: np.ndarray, groups: np.ndarray, X_val: Any, y_val: np.ndarray) -> dict[str, float]:
    """Does Platt scaling improve a component on validation? Reported for both components, fitted with group folds."""
    folds = list(_cv(groups).split(X, y, groups))
    calibrated = CalibratedClassifierCV(clone(best), method="sigmoid", cv=folds).fit(X, y)
    raw, scaled = best.predict_proba(X_val)[:, 1], calibrated.predict_proba(X_val)[:, 1]
    return {"brier_uncalibrated": float(brier_score_loss(y_val, raw)), "brier_sigmoid": float(brier_score_loss(y_val, scaled)),
            "ece_uncalibrated": expected_calibration_error(y_val, raw)[0], "ece_sigmoid": expected_calibration_error(y_val, scaled)[0]}


def _plain(params: dict[str, Any]) -> dict[str, Any]:
    return {k: v if isinstance(v, (int, float, str, type(None))) else str(v) for k, v in params.items()}


def train_profile(profile: str, train: list[dict[str, Any]], val: list[dict[str, Any]]) -> dict[str, Any]:
    y, y_val, groups = labels(train), labels(val), groups_of(train)
    T, T_val = text_frame(train, profile), text_frame(val, profile)
    X, X_val = feature_matrix(train, profile), feature_matrix(val, profile)

    text_search = tune(build_text_pipeline(profile), CONFIG["text_grid"], T, y, groups)
    text = text_search.best_estimator_

    forest = tune(RandomForestClassifier(random_state=SEED, n_jobs=1), CONFIG["random_forest_grid"], X, y, groups)
    boosting = tune(GradientBoostingClassifier(random_state=SEED), CONFIG["gradient_boosting_grid"], X, y, groups,
                    sample_weight=compute_sample_weight("balanced", y))
    candidates = {"random_forest": forest, "gradient_boosting": boosting}
    validation_ap = {name: float(average_precision_score(y_val, s.best_estimator_.predict_proba(X_val)[:, 1])) for name, s in candidates.items()}
    selected = max(validation_ap, key=lambda name: validation_ap[name])
    structured_search = candidates[selected]
    structured = structured_search.best_estimator_

    # Out-of-fold component scores train the stack, so it never learns from a component's memory of its own training data.
    cv = _cv(groups)
    oof_text = cross_val_predict(clone(text), T, y, groups=groups, cv=cv, method="predict_proba", n_jobs=-1)[:, 1]
    fit_params = {"sample_weight": compute_sample_weight("balanced", y)} if selected == "gradient_boosting" else {}
    oof_structured = cross_val_predict(clone(structured), X, y, groups=groups, cv=cv, method="predict_proba", n_jobs=-1, params=fit_params)[:, 1]
    hybrid = LogisticRegression(max_iter=2000, random_state=SEED).fit(hybrid_matrix(oof_text, oof_structured, train, profile), y)

    def scores(records: list[dict[str, Any]], T_: pd.DataFrame, X_: np.ndarray) -> dict[str, np.ndarray]:
        a, b = text.predict_proba(T_)[:, 1], structured.predict_proba(X_)[:, 1]
        return {"text": a, "structured": b, "hybrid": hybrid.predict_proba(hybrid_matrix(a, b, records, profile))[:, 1],
                "heuristic": heuristic_scores(records, profile)}

    val_scores = scores(val, T_val, X_val)
    thresholds = select_thresholds(y_val, val_scores["hybrid"])
    # Each component's own threshold comes from validation too, so the comparison is fair.
    component_thresholds = {name: select_thresholds(y_val, val_scores[name])["review"] for name in ("text", "structured")}
    component_thresholds.update(hybrid=thresholds["review"], heuristic=HEURISTIC_MEDIUM)
    return {
        "models": {"text": text, "structured": structured, "hybrid": hybrid},
        "score_fn": scores,
        "component_thresholds": component_thresholds,
        "thresholds": thresholds,
        "info": {
            "feature_names": FEATURE_SETS[profile], "text_columns": TEXT_COLUMNS[profile],
            "text_best_params": _plain(text_search.best_params_), "text_cv_pr_auc": float(text_search.best_score_),
            "structured_candidates": {
                name: {"best_params": _plain(s.best_params_), "cv_pr_auc": float(s.best_score_), "validation_pr_auc": validation_ap[name]}
                for name, s in candidates.items()},
            "structured_selected": selected,
            "structured_importances": {n: float(v) for n, v in zip(FEATURE_SETS[profile], structured.feature_importances_)},
            "hybrid_coefficients": dict(zip(["logit_text", "logit_structured", "heuristic_score", "history_signal_weight", "hard_signal"],
                                            (float(c) for c in hybrid.coef_[0]))),
            "hybrid_intercept": float(hybrid.intercept_[0]),
            "calibration_comparison": {
                "text": calibration_comparison(text, T, y, groups, T_val, y_val),
                "structured": calibration_comparison(structured, X, y, groups, X_val, y_val),
                "hybrid_validation_ece": expected_calibration_error(y_val, val_scores["hybrid"])[0],
                "decision": "The stacked logistic regression is the calibration layer, and fits on out-of-fold scores. Components are not separately rescaled.",
            },
            "thresholds": thresholds,
            "component_thresholds": component_thresholds,
            "validation": {name: evaluate(val, val_scores[name], component_thresholds[name]) for name in val_scores},
        },
    }


def _dataset_hash(data_dir: Path) -> str:
    digest = hashlib.sha256()
    for split in ("train", "val", "test"):
        digest.update((data_dir / "splits" / f"native_{split}.jsonl").read_bytes())
    return digest.hexdigest()


def test_groups_fingerprint(records: list[dict[str, Any]]) -> str:
    """Identifies a test set by the projects, tasks and families in it, not by its bytes. A regenerated dataset with the
    same test groups is the same test set as far as model selection is concerned. Reads no labels."""
    keys = sorted({f"{r['project']}|{r['task']}|{r['family']}" for r in records})
    return hashlib.sha256("\n".join(keys).encode()).hexdigest()


def _read_log(log: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()] if log.is_file() else []


def _record_test_access(data_dir: Path, version: str, dataset: str, config_hash: str, allow_retest: bool,
                        test_groups: str | None = None, shared_log: Path | None = None) -> dict[str, Any]:
    """Log one use of a test split. Uses are matched by dataset hash or by test-group fingerprint, across this data
    folder's log and the shared log, so a second data folder with the same test groups cannot hide an earlier use."""
    logs = [data_dir / "manifests" / "test_access_log.jsonl"]
    if shared_log is not None and shared_log.resolve() != logs[0].resolve():
        logs.append(shared_log)
    entries = [e for log in logs for e in _read_log(log)]
    same_set = [e for e in entries if e["dataset"] == dataset or (test_groups and e.get("test_groups") == test_groups)]
    earlier = sorted({e["model_version"] for e in same_set if e["model_version"] != version})
    if earlier and not allow_retest:
        raise DatasetError(f"The test split was already used for {earlier[-1]}. A different model on the same test data needs "
                           "--allow-retest, and the result is marked as a repeated use of the test set.")
    entry = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "model_version": version, "dataset": dataset, "config": config_hash,
             "test_groups": test_groups, "earlier_uses_by_other_models": len(earlier), "earlier_models": earlier}
    for log in logs:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def run_training(data_dir: Path, model_dir: Path, final_test: bool = False, allow_retest: bool = False, activate: bool = True,
                 profiles: tuple[str, ...] = PROFILES, shared_log: Path | None = None) -> dict[str, Any]:
    train, val = load_split(data_dir, "train"), load_split(data_dir, "val")
    validate_records(train + val)
    overlaps = group_overlaps(train + val)
    if overlaps:
        raise DatasetError(f"Groups are shared across splits: {overlaps}")

    dataset = _dataset_hash(data_dir)
    config_hash = hashlib.sha256(json.dumps(CONFIG, sort_keys=True).encode()).hexdigest()
    version = f"ml-{dataset[:8]}-{config_hash[:8]}"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=FutureWarning)
        trained = {profile: train_profile(profile, train, val) for profile in profiles}

    test_entry = None
    if final_test:
        test = load_split(data_dir, "test")
        validate_records(test)
        if group_overlaps(train + val + test):
            raise DatasetError("Test groups overlap with training or validation groups.")
        test_entry = _record_test_access(data_dir, version, dataset, config_hash, allow_retest, test_groups_fingerprint(test), shared_log)
        for profile, result in trained.items():
            scores = result["score_fn"](test, text_frame(test, profile), feature_matrix(test, profile))
            result["info"]["test"] = {name: evaluate(test, scores[name], result["component_thresholds"][name]) for name in scores}
            result["info"]["test_at_block_threshold"] = evaluate(test, scores["hybrid"], result["thresholds"]["block"])

    bundle = model_dir / version
    bundle.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, str] = {}
    for profile, result in trained.items():
        for name, model in result["models"].items():
            filename = f"{profile}_{name}.joblib"
            joblib.dump(model, bundle / filename)
            artifacts[filename] = _sha256(bundle / filename)
    metadata = {
        "version": version, "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "artifacts": artifacts,
        "bundle_sha256": bundle_digest(artifacts), "dataset_sha256": dataset, "config": CONFIG, "config_sha256": config_hash,
        "library_versions": {"scikit-learn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__},
        "data": {split: {"records": len(rows), "unauthorized": int(labels(rows).sum()), "legitimate": int((labels(rows) == 0).sum()),
                         "projects": sorted({r["project"] for r in rows}), "families": len({r["family"] for r in rows})}
                 for split, rows in (("train", train), ("validation", val))},
        "test_evaluated": test_entry is not None, "test_access": test_entry,
        "profiles": {profile: result["info"] for profile, result in trained.items()},
        "interpretation": ("Labels come from explicit rules over generated templates, so native test scores show how well the rules were learned on "
                           "unseen projects, tasks and behaviours. End-to-end benchmark results are the evidence about runtime security."),
    }
    if final_test:
        rows = load_split(data_dir, "test")
        metadata["data"]["test"] = {"records": len(rows), "unauthorized": int(labels(rows).sum()), "legitimate": int((labels(rows) == 0).sum()),
                                    "projects": sorted({r["project"] for r in rows}), "families": len({r["family"] for r in rows})}
    (bundle / METADATA_FILE).write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
    if activate:
        (model_dir / CURRENT_FILE).write_text(version, encoding="utf-8", newline="\n")
    return metadata
