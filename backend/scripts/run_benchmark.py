"""Run the benchmark from the command line and print a results table.

Example:
    python scripts/run_benchmark.py --name dev-run --split dev
    python scripts/run_benchmark.py --agent ollama --assessor ollama --repeats 3
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boundaryguard.config import load_settings  # noqa: E402
from boundaryguard.db.connection import Database  # noqa: E402
from boundaryguard.experiments.runner import create_experiment, run_experiment  # noqa: E402

MAIN_METRICS = [
    "unauthorized_execution_rate", "attack_prevention_rate", "legitimate_task_success", "false_block_rate",
    "audit_coverage", "policy_bypass_rate", "repeated_violation_handling", "false_negative_rate", "precision", "recall", "f1", "pr_auc",
]


def fmt(row: dict | None) -> str:
    if row is None or row["value"] is None:
        return "n/a"
    if row["numerator"] is None or row["denominator"] is None:
        return f"{row['value']:.3f}"
    return f"{row['value'] * 100:.1f}% ({row['numerator']:.0f}/{row['denominator']:.0f})"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="CLI benchmark")
    parser.add_argument("--configurations", nargs="*", default=["A", "B", "RC", "C"])
    parser.add_argument("--split", choices=["dev", "holdout", "external"], default=None)
    parser.add_argument("--suite", choices=["internal", "injecagent"], default="internal")
    parser.add_argument("--agent", default="scripted", choices=["scripted", "ollama", "openai_compatible"])
    parser.add_argument("--assessor", default="heuristic", choices=["heuristic", "ollama", "openai_compatible"])
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    settings = load_settings()
    db = Database(settings.db_path)
    experiment_id = create_experiment(db, {
        "name": args.name, "configurations": args.configurations, "split": args.split, "suite": args.suite,
        "agent_provider": args.agent, "assessor": args.assessor, "repeats": args.repeats, "seed": args.seed,
    }, settings.model_dir)
    run_experiment(db, settings, experiment_id)
    experiment = db.query_one("SELECT * FROM experiments WHERE id=?", (experiment_id,))
    print(f"Experiment {experiment_id}: {experiment['status']} ({experiment['completed_runs']}/{experiment['total_runs']} runs)")
    print(f"Provenance: {experiment['manifest']['provenance']}\n")

    for split in ["all", "dev", "holdout", "external"]:
        rows = db.query("SELECT * FROM experiment_metrics WHERE experiment_id=? AND split=? AND category='all'", (experiment_id, split))
        lookup = {(r["configuration"], r["metric"]): r for r in rows}
        configs = [c for c in args.configurations if any(key[0] == c for key in lookup)]
        if not configs:
            continue
        print(f"--- split: {split} ---")
        print(f"{'metric':32}" + "".join(f"{c:>20}" for c in configs))
        for metric in MAIN_METRICS:
            print(f"{metric:32}" + "".join(f"{fmt(lookup.get((c, metric))):>20}" for c in configs))
        def latency_text(config: str) -> str:
            row = lookup.get((config, "decision_latency_policy_us"))
            return f"{row['value'] / 1000:.3f}ms" if row and row["value"] is not None else "n/a"

        latency = "".join(f"{latency_text(c):>20}" for c in configs)
        print(f"{'policy latency (median)':32}{latency}")
        print(f"{'errored / unlabeled':32}" + "".join(
            f"{int(lookup[(c, 'errored_runs')]['value'])} / {int(lookup[(c, 'unlabeled_actions')]['value'])}".rjust(20) for c in configs))
        print()
    return 0 if experiment["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
