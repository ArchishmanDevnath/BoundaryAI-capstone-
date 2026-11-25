"""Validate the source data, build every dataset and split, and write the provenance manifests.

The files in data/external are read and hashed, and never written. Re-running gives identical data files.

Example:
    python scripts/prepare_data.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boundaryguard.config import DATA_DIR  # noqa: E402
from boundaryguard.experiments.scenarios import load_scenarios  # noqa: E402
from boundaryguard.ml import injecagent, native_dataset  # noqa: E402
from boundaryguard.ml.validation import DatasetError, leakage_report, validate_records  # noqa: E402


def write_jsonl(path: Path, rows: list[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows)
    path.write_text(body, encoding="utf-8", newline="\n")
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def composition(rows: list[dict]) -> dict:
    return {
        "records": len(rows), "labels": dict(Counter(r["label"] for r in rows)), "categories": dict(Counter(r["category"] for r in rows)),
        "rules": dict(Counter(r["rule"] for r in rows)), "projects": sorted({r["project"] for r in rows}),
        "tasks": sorted({r["task"] for r in rows}), "families": sorted({r["family"] for r in rows}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--out-dir", default=None, help="Write processed data, splits and manifests here instead of --data-dir.")
    parser.add_argument("--attack-position", choices=native_dataset.ATTACK_POSITIONS, default="first",
                        help="'first' reproduces the reported model's data. See docs/EXPERIMENT_RESULTS.md for the post-hoc variant.")
    args = parser.parse_args()
    source = Path(args.data_dir) / "external" / "injecagent"
    data = Path(args.out_dir or args.data_dir)
    missing = [f for f in injecagent.SOURCE_FILES if not (source / f).is_file()]
    if missing:
        print(f"Missing source files in {source}: {missing}", file=sys.stderr)
        return 2

    before = {f: injecagent.sha256_file(source / f) for f in injecagent.SOURCE_FILES}
    report = injecagent.profile_source(source)
    scenarios, review, adapted_stats = injecagent.adapt(source)
    print("InjecAgent:", json.dumps(adapted_stats))
    external_hash = write_jsonl(data / "splits" / "injecagent_external_test.jsonl", [s.model_dump(mode="json") for s in scenarios])
    write_jsonl(data / "processed" / "injecagent_manual_review.jsonl", review)
    if {f: injecagent.sha256_file(source / f) for f in injecagent.SOURCE_FILES} != before:
        print("A source file changed during processing.", file=sys.stderr)
        return 3
    write_json(data / "manifests" / "injecagent_manifest.json", {
        **injecagent.SOURCE,
        "local_path": "data/external/injecagent",
        "local_file_dates": "2026-11-05 (when the copy was placed in this project; the actual download date was not recorded)",
        "verification": "All nine data files were byte-compared with raw.githubusercontent.com at the commit above on 2026-11-05 and match.",
        "licence_note": "The licence file was not in the local folder. Upstream names it LICENCE. A copy is at data/manifests/INJECAGENT_LICENCE.txt.",
        "sha256": before, "adaptation": adapted_stats,
        "use": "Independent evaluation only. Not used for training, hyperparameter tuning, calibration or threshold selection.",
    })
    write_json(data / "manifests" / "injecagent_schema_report.json", report)

    records, ambiguous, stats = native_dataset.generate(args.attack_position)
    records, dedupe = native_dataset.deduplicate(records)
    validate_records(records)
    leakage = leakage_report(records, load_scenarios(), scenarios)
    if leakage["problems"]:
        raise DatasetError(f"Leakage checks failed: {leakage['problems']}")
    hashes = {}
    write_jsonl(data / "processed" / "native_labeled.jsonl", records)
    write_jsonl(data / "processed" / "native_ambiguous.jsonl", ambiguous)
    splits = {}
    for split in native_dataset.SPLITS:
        rows = [r for r in records if r["split"] == split]
        hashes[split] = write_jsonl(data / "splits" / f"native_{split}.jsonl", rows)
        splits[split] = composition(rows)
        print(split, splits[split]["records"], splits[split]["labels"])
    write_json(data / "manifests" / "native_split_manifest.json", {
        "generator_version": native_dataset.GENERATOR_VERSION, "generation": stats, "deduplication": dedupe,
        "ambiguous_excluded": {"records": len(ambiguous), "rules": dict(Counter(r["rule"] for r in ambiguous))},
        "grouping": "Projects, tasks and behaviour families each belong to exactly one split. A trace is kept only if all three agree.",
        "files": {f"data/splits/native_{s}.jsonl": hashes[s] for s in native_dataset.SPLITS},
        "composition": splits, "leakage_report": leakage,
        "external_test": {"file": "data/splits/injecagent_external_test.jsonl", "sha256": external_hash},
        "internal_scenarios": "The 53 benchmark scenarios are never used for training, tuning, calibration or threshold selection.",
    })
    print("Leakage report:", json.dumps({k: v for k, v in leakage.items() if k != "examples"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
