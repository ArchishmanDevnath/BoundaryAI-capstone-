"""Diagnose why configuration E blocks the clean InjecAgent controls. Reads the active model and data, changes nothing.

Example:
    python scripts/diagnose_external.py
"""
import sys, tempfile
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))
import numpy as np
from pathlib import Path
from boundaryguard.experiments.scenarios import load_external_scenarios
from boundaryguard.guard.canonical import canonicalize
from boundaryguard.guard.context.base import AssessmentContext
from boundaryguard.guard.context.heuristic import HeuristicAssessor, app_relevant
from boundaryguard.ml.assessor import load_profiles
from boundaryguard.ml.features import extract_features, FEATURE_SETS
from boundaryguard.tools.sandbox import Sandbox
from boundaryguard.config import MODELS_DIR
import json

profiles = load_profiles(MODELS_DIR)
root = Path(tempfile.mkdtemp())
(root / "project").mkdir()
sb = Sandbox(root)
benign = [s for s in load_external_scenarios() if s.category == "benign"]
train = [json.loads(l) for l in open(Path(__file__).resolve().parents[2] / 'data' / 'splits' / 'native_train.jsonl', encoding='utf8')]
for name in ("stateless", "stateful"):
    prof = profiles[name]
    rows = []
    for s in benign:
        step = s.script[0]
        canon = canonicalize("app_call", step.args, sb)
        ctx = AssessmentContext(objective=s.objective, action=canon, relevant_to_task=app_relevant(s.objective, canon.app_tool),
                                history_stats={"steps": 0, "denials": 0, "recent_denials": 0, "same_action_runs": 0, "same_action_denials": 0} if name == "stateful" else {})
        h = HeuristicAssessor().assess(ctx).risk_score
        r = prof.predict(ctx, h)
        rows.append((r["text"], r["structured"], r["hybrid"], h, ctx.relevant_to_task))
    a = np.array(rows, dtype=float)
    print(name, "mean text %.3f structured %.3f hybrid %.3f heuristic %.3f relevant %.2f" % tuple(a.mean(0)), "review threshold", prof.review_threshold)
    feats = extract_features(ctx)
    print("  example features (last case):", {k: round(v, 2) for k, v in feats.items() if k in FEATURE_SETS[name] and v})
# Did any training record ever have an application-tool effect, or an empty untrusted-text field?
print("train records with app access:", sum(1 for r in train if r["features"]["access_app_read"] or r["features"]["access_app_write"] or r["features"]["access_app_outbound"]))
print("train records at the first step (prior_steps=0):", sum(1 for r in train if r["features"]["prior_steps"] == 0),
      "of which unauthorized:", sum(1 for r in train if r["features"]["prior_steps"] == 0 and r["label"] == "unauthorized"))
