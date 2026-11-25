"""Train the text, structured and hybrid risk models. Only --final-test reads the test split.

Examples:
    python scripts/train_models.py                 # train and select using train and validation only
    python scripts/train_models.py --final-test    # the same, then evaluate once on the untouched test split
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boundaryguard.config import DATA_DIR, MODELS_DIR  # noqa: E402
from boundaryguard.ml.training import run_training  # noqa: E402
from boundaryguard.ml.validation import DatasetError  # noqa: E402


def line(name: str, m: dict) -> str:
    return (f"  {name:11} PR-AUC {m['pr_auc']:.3f}  ROC-AUC {m['roc_auc']:.3f}  P {m['precision']:.3f}  R {m['recall']:.3f}  F1 {m['f1']:.3f}  "
            f"FPR {m['false_positive_rate']:.3f}  FNR {m['false_negative_rate']:.3f}  ECE {m['ece']:.3f}  @{m['threshold']:.3f}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--model-dir", default=str(MODELS_DIR))
    parser.add_argument("--final-test", action="store_true", help="Evaluate once on the test split. The use is logged.")
    parser.add_argument("--allow-retest", action="store_true", help="Permit a different model on an already used test split. The use is logged.")
    parser.add_argument("--no-activate", action="store_true", help="Do not make this the active model.")
    args = parser.parse_args()
    try:
        metadata = run_training(Path(args.data_dir), Path(args.model_dir), args.final_test, args.allow_retest, not args.no_activate,
                                shared_log=DATA_DIR / "manifests" / "test_access_log.jsonl")
    except DatasetError as exc:
        print(f"Training stopped: {exc}", file=sys.stderr)
        return 2
    print(f"Model {metadata['version']}  data {metadata['data']['train']['records']} train / {metadata['data']['validation']['records']} validation")
    for profile, info in metadata["profiles"].items():
        print(f"\n[{profile}] structured candidates:")
        for name, candidate in info["structured_candidates"].items():
            print(f"  {name}: CV {candidate['cv_pr_auc']:.3f}, validation {candidate['validation_pr_auc']:.3f}, {candidate['best_params']}")
        print(f"  selected {info['structured_selected']}; text {info['text_best_params']} CV {info['text_cv_pr_auc']:.3f}")
        print(f"  thresholds {info['thresholds']}")
        print(f"  hybrid inputs {info['hybrid_coefficients']}")
        print(" validation:")
        for name, metrics in info["validation"].items():
            print(line(name, metrics))
        if "test" in info:
            print(" test (final):")
            for name, metrics in info["test"].items():
                print(line(name, metrics) + f"  CI recall {metrics['bootstrap_by_family']['recall_ci95']}")
            print(f"  by category: {info['test']['hybrid']['by_category']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
