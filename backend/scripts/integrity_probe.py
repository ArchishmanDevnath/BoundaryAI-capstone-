"""ML integrity probes for docs/ML_INTEGRITY_AUDIT.md. Reads train and validation splits only, never a test split.

Usage: python scripts/integrity_probe.py   (prints JSON)
"""
import json, sys, warnings
from collections import Counter
from pathlib import Path
import joblib, numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import average_precision_score

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
warnings.simplefilter("ignore")
from boundaryguard.ml.training import load_split, labels, feature_matrix, text_frame, hybrid_matrix, groups_of, heuristic_scores
from boundaryguard.ml.features import STATELESS_FEATURES, FEATURE_SETS

DATA = {name: path for name, path in {"v1_first": ROOT / "data", "v2_after": ROOT / "data" / "posthoc_v2", "v3_after": ROOT / "data" / "posthoc_v3"}.items() if (path / "splits").is_dir()}
MODELS = {name: path for name, path in {"v1": ROOT / "backend/models/ml-756975a1-114f9854", "v2": ROOT / "backend/models_posthoc/ml-957735c6-114f9854", "v3": ROOT / "backend/models/ml-df842b52-a2bd43dd"}.items() if path.is_dir()}
out = {}

def rate(mask, y):
    return {"n": int(mask.sum()), "unauth_rate": float(y[mask].mean()) if mask.any() else None}

for name, d in DATA.items():
    tr, va = load_split(d, "train"), load_split(d, "val")
    y, yv = labels(tr), labels(va)
    r = {"train": {"n": len(tr), "unauth": int(y.sum()), "legit": int((y == 0).sum())},
         "val": {"n": len(va), "unauth": int(yv.sum()), "legit": int((yv == 0).sum())},
         "train_rules": dict(Counter(x["rule"] for x in tr)), "val_rules": dict(Counter(x["rule"] for x in va)),
         "train_categories": dict(Counter(x["category"] for x in tr)),
         "unique": {k: len({x[k] for x in tr + va}) for k in ("project", "task", "family", "tool")}}
    # Position shortcut: unauthorized rate by step position, and a model that sees only position.
    ps = np.array([x["features"]["prior_steps"] for x in tr]); psv = np.array([x["features"]["prior_steps"] for x in va])
    r["train_rate_by_prior_steps"] = {int(k): rate(ps == k, y) for k in sorted(set(ps))[:6]}
    pos = LogisticRegression().fit(np.c_[ps, ps == 0], y)
    r["position_only_val_pr_auc"] = float(average_precision_score(yv, pos.predict_proba(np.c_[psv, psv == 0])[:, 1]))
    r["val_base_rate"] = float(yv.mean())
    # Circularity: how much of the label does a hand-written rule over heuristic-derived features reproduce?
    def rule(rec):
        f = rec["features"]
        return int(any(f[k] for k in ("out_of_scope_sensitive", "out_of_scope_change", "payload_risky_code", "payload_test_weakening", "payload_secret", "signal_hard")))
    for split, recs, ys in (("train", tr, y), ("val", va, yv)):
        pred = np.array([rule(x) for x in recs])
        r[f"{split}_simple_rule_agreement"] = float((pred == ys).mean())
        r[f"{split}_simple_rule_recall"] = float(pred[ys == 1].mean()); r[f"{split}_simple_rule_fpr"] = float(pred[ys == 0].mean())
        h = heuristic_scores(recs, "stateful") >= 0.40
        r[f"{split}_heuristic_flag_agreement"] = float((h == ys).mean())
    X, Xv = feature_matrix(tr, "stateless"), feature_matrix(va, "stateless")
    for depth in (2, 3):
        t = DecisionTreeClassifier(max_depth=depth, random_state=42, class_weight="balanced").fit(X, y)
        r[f"tree_depth{depth}_stateless_val_pr_auc"] = float(average_precision_score(yv, t.predict_proba(Xv)[:, 1]))
    r["heuristic_val_pr_auc"] = {p: float(average_precision_score(yv, heuristic_scores(va, p))) for p in ("stateless", "stateful")}
    out[name] = r

# Ordering invariance: score each model's validation behaviour on validation data generated with each ordering.
for m, bundle in MODELS.items():
    meta = json.loads((bundle / "metadata.json").read_text())
    for prof in ("stateless", "stateful"):
        text, struct, hyb = (joblib.load(bundle / f"{prof}_{k}.joblib") for k in ("text", "structured", "hybrid"))
        th = meta["profiles"][prof]["thresholds"]["review"]
        for dname, d in DATA.items():
            va = load_split(d, "val"); yv = labels(va)
            # Each bundle is scored with the feature list it was trained on, which differs between feature-set versions.
            names = meta["profiles"][prof]["feature_names"]
            X = np.array([[x["features"][n] for n in names] for x in va], dtype=float)
            a = text.predict_proba(text_frame(va, prof))[:, 1]; b = struct.predict_proba(X)[:, 1]
            p = hyb.predict_proba(hybrid_matrix(a, b, va, prof))[:, 1]
            first = np.array([x["features"]["prior_steps"] == 0 for x in va])
            out[f"{m}_{prof}_on_{dname}_val"] = {
                "pr_auc": float(average_precision_score(yv, p)), "threshold": th,
                "fpr": float((p[yv == 0] >= th).mean()), "recall": float((p[yv == 1] >= th).mean()),
                "fpr_first_step_legit": float((p[(yv == 0) & first] >= th).mean()) if ((yv == 0) & first).any() else None,
                "n_first_step_legit": int(((yv == 0) & first).sum())}
        imp = meta["profiles"][prof]["structured_importances"]
        out[f"{m}_{prof}_top_importances"] = sorted(imp.items(), key=lambda kv: -kv[1])[:6]
print(json.dumps(out, indent=1))
