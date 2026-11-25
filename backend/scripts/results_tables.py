"""Print the result tables used in docs/EXPERIMENT_RESULTS.md, read from stored experiments.

Example:
    python scripts/results_tables.py --internal <experiment id> --external <experiment id>
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boundaryguard.config import load_settings  # noqa: E402
from boundaryguard.db.connection import Database  # noqa: E402
from boundaryguard.experiments.analytics import compare  # noqa: E402

ORDER = ["A", "B", "RC", "C", "D", "E"]
LABEL = {"A": "A", "B": "B", "RC": "C", "C": "Control", "D": "D", "E": "E"}
RATES = [("unauthorized_execution_rate", "Unauthorized executed"), ("attack_prevention_rate", "Prevention (recall)"),
         ("false_block_rate", "False blocks"), ("legitimate_task_success", "Benign task success"), ("precision", "Precision"),
         ("false_negative_rate", "False-negative rate")]
SCORES = [("f1", "F1"), ("pr_auc", "PR-AUC")]


def cell(row: dict | None, with_ci: bool = True) -> str:
    if not row or row["value"] is None:
        return "n/a"
    text = f"{row['value'] * 100:.1f}% ({row['numerator']:.0f}/{row['denominator']:.0f})"
    if with_ci and row.get("ci_low") is not None:
        text += f" [{row['ci_low'] * 100:.0f}-{row['ci_high'] * 100:.0f}]"
    return text


def table(data: dict, ci: bool) -> list[str]:
    configs = [c for c in ORDER if any(x["id"] == c for x in data["configurations"])]
    lines = ["| Metric | " + " | ".join(LABEL[c] for c in configs) + " |", "|---|" + "---|" * len(configs)]
    overall = data["overall"]
    for metric, label in RATES:
        lines.append(f"| {label} | " + " | ".join(cell(overall.get(metric, {}).get(c), ci) for c in configs) + " |")
    for metric, label in SCORES:
        values = []
        for c in configs:
            row = overall.get(metric, {}).get(c)
            values.append("n/a" if not row or row["value"] is None else f"{row['value']:.3f}")
        lines.append(f"| {label} | " + " | ".join(values) + " |")
    lat = []
    for c in configs:
        row = overall.get("decision_latency_mean_us", {}).get(c)
        lat.append("n/a" if not row or row["value"] is None else f"{row['value'] / 1000:.3f} ms")
    lines.append("| Mean authorization latency | " + " | ".join(lat) + " |")
    for metric, label in (("policy_bypass_rate", "Policy bypass"), ("audit_coverage", "Audit coverage"), ("repeated_violation_handling", "Retry handling")):
        lines.append(f"| {label} | " + " | ".join(cell(overall.get(metric, {}).get(c), False) for c in configs) + " |")
    fallbacks = " | ".join(str(int((overall.get("assessor_fallbacks", {}).get(c) or {}).get("value") or 0)) for c in configs)
    errors = " | ".join(str(int((overall.get("errored_runs", {}).get(c) or {}).get("value") or 0)) for c in configs)
    unlabeled = " | ".join(str(int((overall.get("unlabeled_actions", {}).get(c) or {}).get("value") or 0)) for c in configs)
    lines += [f"| Assessor failures (fail-closed) | {fallbacks} |", f"| Errored runs | {errors} |", f"| Unlabeled actions | {unlabeled} |"]
    return lines


def categories(data: dict) -> list[str]:
    configs = [c for c in ORDER if any(x["id"] == c for x in data["configurations"])]
    lines = ["| Category | " + " | ".join(LABEL[c] for c in configs) + " |", "|---|" + "---|" * len(configs)]
    for name, metrics in data["categories"].items():
        metric = "false_block_rate" if name == "benign" else "attack_prevention_rate"
        prefix = "false blocks" if name == "benign" else "prevention"
        lines.append(f"| {name} ({prefix}) | " + " | ".join(cell(metrics.get(metric, {}).get(c), False) for c in configs) + " |")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--internal")
    parser.add_argument("--external")
    args = parser.parse_args()
    db = Database(load_settings().db_path)
    if args.internal:
        for split in ("holdout", "dev", "all"):
            data = compare(db, args.internal, split)
            print(f"\n## internal {split}\n" + "\n".join(table(data, ci=True)))
            if split == "holdout":
                print("\n" + "\n".join(categories(data)))
                print("\n| Comparison | Outcome | Only first | Only second | p |\n|---|---|---|---|---|")
                for s in data["significance"]:
                    print(f"| {LABEL[s['first']]} vs {LABEL[s['second']]} | {s['outcome']} | {s['only_first']} | {s['only_second']} | {s['p_value']:.3f} |")
    if args.external:
        data = compare(db, args.external, "external")
        print("\n## external\n" + "\n".join(table(data, ci=False)))
        print("\n" + "\n".join(categories(data)))
        print("\n| Comparison | Prevention change [95% CI] | False-block change [95% CI] |\n|---|---|---|")
        for s in data["cluster_comparisons"]:
            def fmt(v, r):
                return "n/a" if v is None else f"{v * 100:+.1f} pts [{r[0] * 100:+.1f}, {r[1] * 100:+.1f}]" if r else f"{v * 100:+.1f} pts"
            print(f"| {LABEL[s['second']]} vs {LABEL[s['first']]} ({s['clusters']} attacker clusters) | {fmt(s['prevention_difference'], s['prevention_ci95'])} | {fmt(s['false_block_difference'], s['false_block_ci95'])} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
