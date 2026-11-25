"""ML pipeline, datasets, leakage controls and fail-closed behaviour. Models here are trained on a small sample."""
from __future__ import annotations

import json
import math
import shutil
from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import average_precision_score

from boundaryguard.config import load_settings
from boundaryguard.experiments.runner import create_experiment, run_experiment
from boundaryguard.experiments.scenarios import load_external_scenarios, load_scenarios
from boundaryguard.experiments.stats import average_precision
from boundaryguard.guard.canonical import canonicalize
from boundaryguard.guard.context.base import AssessmentContext
from boundaryguard.ml import assessor as assessor_module
from boundaryguard.ml import injecagent, native_dataset, training
from boundaryguard.ml.assessor import MLAssessor, ModelUnavailable, active_model_info, hybrid_inputs, load_profiles, resolve_bundle, verify_bundle
from boundaryguard.ml.features import ALL_FEATURES, FEATURE_SETS, POSITION_FEATURES, STATELESS_FEATURES, extract_features, text_views
from boundaryguard.ml.validation import DatasetError, group_overlaps, leakage_report, near_duplicates, validate_records
from boundaryguard.models.core import CONFIGURATIONS, Decision, RiskLevel, ToolCall
from boundaryguard.tools.sandbox import Sandbox
from boundaryguard.tools.simapps import classify_effect

from conftest import build_gateway, standard_policy

REPO_DATA = Path(__file__).resolve().parents[2] / "data"
SOURCE = REPO_DATA / "external" / "injecagent"
needs_source = pytest.mark.skipif(not SOURCE.is_dir(), reason="The InjecAgent source files are not present.")


# -- a small real dataset and model, shared across tests -----------------------------------------
@pytest.fixture(scope="module")
def small_records() -> list[dict]:
    """Real replayed records from the generator, limited to a few traces per split so the tests stay fast."""
    records = []
    with __import__("tempfile").TemporaryDirectory() as tmp:
        work = Path(tmp)
        for split, count in (("train", 2), ("val", 1), ("test", 1)):
            for project in [p for p in native_dataset.PROJECTS if p["split"] == split][:count + 1]:
                for task in [t for t in native_dataset.TASKS if t["split"] == split][:2]:
                    for family in [f for f in native_dataset.FAMILIES if f["split"] == split]:
                        for shadow, block in (("permissive", False), ("enforcing", True)):
                            for index, row in enumerate(native_dataset.replay(project, task, family, block, work)):
                                if row["label"] in ("unauthorized", "legitimate"):
                                    records.append({
                                        "id": f"{project['slug']}|{task['id']}|{family['id']}|{shadow}|{index}", "split": split, "project": project["slug"],
                                        "task": task["id"], "family": family["id"], "category": family["category"], "shadow": shadow, "step": index,
                                        "tool": row["tool"], "target": row["target"], "objective": task["text"].format(**project),
                                        "label": row["label"], "rule": row["rule"], **row["ctx"]})
    records, _ = native_dataset.deduplicate(records)
    return records


@pytest.fixture(scope="module")
def trained(small_records, tmp_path_factory) -> tuple[Path, dict]:
    """A real bundle produced by the real pipeline, with smaller grids."""
    root = tmp_path_factory.mktemp("ml")
    data, models = root / "data", root / "models"
    (data / "splits").mkdir(parents=True)
    for split in native_dataset.SPLITS:
        with (data / "splits" / f"native_{split}.jsonl").open("w", encoding="utf-8") as fh:
            for record in small_records:
                if record["split"] == split:
                    fh.write(json.dumps(record) + "\n")
    saved = {k: training.CONFIG[k] for k in ("text_grid", "random_forest_grid", "gradient_boosting_grid")}
    training.CONFIG.update(text_grid={"clf__C": [1.0], "clf__class_weight": [None]},
                           random_forest_grid={"n_estimators": [20], "max_depth": [6], "min_samples_leaf": [1], "class_weight": ["balanced"]},
                           gradient_boosting_grid={"n_estimators": [20], "learning_rate": [0.1], "max_depth": [2]})
    try:
        metadata = training.run_training(data, models, final_test=True)
    finally:
        training.CONFIG.update(saved)
    return models, {"metadata": metadata, "data": data}


def copy_models(models: Path, target: Path) -> Path:
    shutil.copytree(models, target)
    return target


def context(world, tool="read_file", args=None, objective="Fix the add function in src/app.py."):
    action = canonicalize(tool, args or {"path": "src/app.py"}, Sandbox(world))
    return AssessmentContext(objective=objective, action=action, relevant_to_task=True)


# -- dataset validation --------------------------------------------------------------------------
def test_empty_dataset_is_rejected():
    with pytest.raises(DatasetError, match="empty"):
        validate_records([])


def test_records_missing_labels_are_rejected(small_records):
    broken = [dict(small_records[0])]
    del broken[0]["label"]
    with pytest.raises(DatasetError, match="missing"):
        validate_records(broken)


def test_invalid_label_is_rejected(small_records):
    with pytest.raises(DatasetError, match="invalid label"):
        validate_records([{**small_records[0], "label": "maybe"}])


def test_ambiguous_records_never_enter_a_training_split(small_records):
    assert {r["label"] for r in small_records} == {"unauthorized", "legitimate"}


def test_non_finite_feature_is_rejected(small_records):
    record = {**small_records[0], "features": {**small_records[0]["features"], "prior_steps": math.nan}}
    with pytest.raises(DatasetError, match="invalid feature"):
        validate_records([record])


def test_split_with_only_one_class_is_rejected(small_records):
    with pytest.raises(DatasetError, match="both classes"):
        validate_records([r for r in small_records if r["label"] == "legitimate"])


def test_training_stops_cleanly_when_data_is_missing(tmp_path):
    with pytest.raises(DatasetError, match="prepare_data"):
        training.run_training(tmp_path, tmp_path / "models")


def test_training_refuses_data_with_too_few_groups(small_records, tmp_path):
    (tmp_path / "splits").mkdir()
    for split in ("train", "val"):
        rows = [r for r in small_records if r["split"] == split]
        if split == "train":
            rows = [r for r in rows if r["family"] in {rows[0]["family"], next(x["family"] for x in rows if x["label"] != rows[0]["label"])}]
        (tmp_path / "splits" / f"native_{split}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (tmp_path / "splits" / "native_test.jsonl").write_text("", encoding="utf-8")
    with pytest.raises(DatasetError, match="groups"):
        training.run_training(tmp_path, tmp_path / "models")


# -- labels --------------------------------------------------------------------------------------
@pytest.mark.parametrize("step,scope,expected", [
    (native_dataset.R("config/prod.yaml"), {"src/a.py"}, ("unauthorized", "U7")),
    (native_dataset.R("config/prod.yaml"), {"config/prod.yaml"}, ("legitimate", "L1")),
    (native_dataset.R("README.md"), set(), ("legitimate", "L2")),
    (native_dataset.R("notes/x.txt"), set(), ("ambiguous", "A1")),
    (native_dataset.R("notes/x.txt", injected=True), set(), ("unauthorized", "U4")),
    (native_dataset.R("src/a.py", injected=True), {"src/a.py"}, ("ambiguous", "A3")),
    (native_dataset.W("scripts/r.py", "x"), {"src/a.py"}, ("unauthorized", "U6")),
    (native_dataset.W("src/a.py", "x", bad_content=True), {"src/a.py"}, ("unauthorized", "U1")),
])
def test_label_rules(step, scope, expected):
    decision = native_dataset.label_step(step, scope, set(), {"config/prod.yaml"}, {})
    assert decision.label == expected[0] and decision.rule.startswith(expected[1])


def test_the_same_action_can_flip_label_with_the_task():
    step = native_dataset.R("deploy/x.yaml")
    sensitive = {"deploy/x.yaml"}
    assert native_dataset.label_step(step, {"deploy/x.yaml"}, set(), sensitive, {}).label == "legitimate"
    assert native_dataset.label_step(step, {"src/a.py"}, set(), sensitive, {}).label == "unauthorized"


def test_labels_do_not_use_guard_decisions():
    import inspect
    source = inspect.getsource(native_dataset.label_step)
    body = source.split('"""')[2]
    assert "features" not in body and "guard" not in body and "assess" not in body


# -- leakage -------------------------------------------------------------------------------------
def test_generator_assigns_every_group_to_one_split():
    for table in (native_dataset.PROJECTS, native_dataset.TASKS, native_dataset.FAMILIES):
        names = [item.get("id") or item["slug"] for item in table]
        assert len(names) == len(set(names))
        assert all(item["split"] in native_dataset.SPLITS for item in table)
    for split in native_dataset.SPLITS:
        assert any(f["split"] == split and f["category"] == "benign" for f in native_dataset.FAMILIES)
        assert any(f["split"] == split and f["category"] != "benign" for f in native_dataset.FAMILIES)


def test_real_splits_have_no_shared_groups_or_near_duplicates(small_records):
    assert group_overlaps(small_records) == {}
    assert near_duplicates(small_records) == []


def test_group_overlap_is_detected(small_records):
    tampered = [dict(r) for r in small_records]
    tampered[0]["split"] = "test" if tampered[0]["split"] != "test" else "train"
    assert group_overlaps(tampered)


def test_near_duplicate_is_detected(small_records):
    train = next(r for r in small_records if r["split"] == "train")
    copy = {**train, "id": "copy", "split": "test", "text": {**train["text"], "task": train["text"]["task"] + " please"}}
    assert near_duplicates([train, copy])


def test_leakage_report_flags_training_on_a_benchmark_objective(small_records):
    internal = load_scenarios()
    tampered = [{**small_records[0], "objective": internal[0].objective}, *small_records[1:]]
    assert any("benchmark scenarios" in p for p in leakage_report(tampered, internal, [])["problems"])


def test_features_exclude_identifiers():
    banned = ("scenario", "project", "family", "file_name", "filename", "run_id", "task_id")
    assert not [n for names in FEATURE_SETS.values() for n in names if any(b in n for b in banned)]


def test_no_profile_trains_on_action_position():
    """Position in a run is a property of how traces were generated, not of risk. v1 learned "first action = attack" from it."""
    for names in FEATURE_SETS.values():
        assert not set(names) & set(POSITION_FEATURES)
    assert set(POSITION_FEATURES) <= set(ALL_FEATURES)
    assert all(name in ALL_FEATURES for names in FEATURE_SETS.values() for name in names)


def test_position_is_still_computed_so_older_bundles_load(world):
    assert set(extract_features(context(world))) == set(ALL_FEATURES)


REPO_MODELS = [p for p in (REPO_DATA.parent / "backend" / "models", REPO_DATA.parent / "backend" / "models_posthoc") if (p / "CURRENT").is_file()]


@pytest.mark.parametrize("model_dir", REPO_MODELS, ids=[p.name for p in REPO_MODELS])
def test_preserved_bundles_still_load_and_score(world, model_dir):
    """The reported models were trained with the position feature. They stay usable for audit and recomputation."""
    for profile in ("stateless", "stateful"):
        result = MLAssessor(profile, model_dir).assess(context(world))
        assert not result.fallback and 0.0 <= result.risk_score <= 1.0


def test_test_use_is_detected_across_data_folders_with_the_same_test_groups(small_records, tmp_path):
    """Regenerating the data in another folder changes its bytes but not its test groups. The earlier use must still count."""
    shared = tmp_path / "shared.jsonl"
    test = [r for r in small_records if r["split"] == "test"]
    groups = training.test_groups_fingerprint(test)
    training._record_test_access(tmp_path / "first", "model-1", "a" * 64, "cfg", False, groups, shared)
    with pytest.raises(DatasetError, match="already used"):
        training._record_test_access(tmp_path / "second", "model-2", "b" * 64, "cfg", False, groups, shared)
    entry = training._record_test_access(tmp_path / "second", "model-2", "b" * 64, "cfg", True, groups, shared)
    assert entry["earlier_models"] == ["model-1"]
    assert training.test_groups_fingerprint(list(reversed(test))) == groups


def test_stateless_profile_cannot_see_history():
    assert not set(STATELESS_FEATURES) & {"prior_denials", "same_action_runs", "signal_weight_total", "untrusted_has_injection"}
    assert "untrusted" not in training.TEXT_COLUMNS["stateless"]


def test_a_stateless_configuration_receives_no_history(db, world):
    captured = {}

    class Spy:
        name = "spy"

        def assess(self, ctx):
            captured["ctx"] = ctx
            from boundaryguard.guard.context.heuristic import HeuristicAssessor
            return HeuristicAssessor().assess(ctx)

    gateway = build_gateway(db, world, "D", assessor=Spy())
    gateway.submit(ToolCall(tool="read_file", args={"path": "README.md"}))
    gateway.submit(ToolCall(tool="read_file", args={"path": "src/app.py"}))
    assert captured["ctx"].untrusted_text == "" and captured["ctx"].history_stats == {} and captured["ctx"].signals == []


def test_test_split_is_only_read_on_request(trained, tmp_path):
    models, info = trained
    data = info["data"]
    target = tmp_path / "data"
    shutil.copytree(data, target)
    (target / "splits" / "native_test.jsonl").unlink()
    saved = {k: training.CONFIG[k] for k in ("text_grid", "random_forest_grid", "gradient_boosting_grid")}
    training.CONFIG.update(text_grid={"clf__C": [1.0], "clf__class_weight": [None]}, random_forest_grid={"n_estimators": [5], "max_depth": [3], "class_weight": ["balanced"]},
                           gradient_boosting_grid={"n_estimators": [5], "max_depth": [2]})
    try:
        original = training._dataset_hash
        training._dataset_hash = lambda d: "x" * 64  # hashing is the only other reader of the file
        metadata = training.run_training(target, tmp_path / "m", final_test=False)
    finally:
        training._dataset_hash = original
        training.CONFIG.update(saved)
    assert metadata["test_evaluated"] is False and "test" not in metadata["profiles"]["stateful"]


def test_test_set_use_is_logged_and_a_second_model_is_refused(trained):
    _, info = trained
    data = info["data"]
    log = data / "manifests" / "test_access_log.jsonl"
    assert len(log.read_text(encoding="utf-8").splitlines()) == 1
    with pytest.raises(DatasetError, match="already used"):
        training._record_test_access(data, "another-model", info["metadata"]["dataset_sha256"], "cfg", allow_retest=False)
    entry = training._record_test_access(data, "another-model", info["metadata"]["dataset_sha256"], "cfg", allow_retest=True)
    assert entry["earlier_uses_by_other_models"] == 1


# -- pipeline ------------------------------------------------------------------------------------
def test_thresholds_respect_the_false_positive_ceiling():
    y = np.array([0] * 100 + [1] * 20)
    p = np.array([i / 200 for i in range(100)] + [0.4 + i / 50 for i in range(20)])
    chosen = training.select_thresholds(y, p)
    flagged = ((p >= chosen["review"]) & (y == 0)).sum() / 100
    assert flagged <= training.REVIEW_MAX_FPR and chosen["block"] >= chosen["review"]
    assert ((p >= chosen["block"]) & (y == 0)).sum() / 100 <= training.BLOCK_MAX_FPR


def test_threshold_uses_the_budget_for_security():
    """With perfect separation, the threshold still drops as far as the ceiling allows, leaving a margin."""
    y = np.array([0] * 100 + [1] * 10)
    p = np.array([i / 1000 for i in range(100)] + [0.9] * 10)
    assert training.select_thresholds(y, p)["review"] < 0.1


def test_bundle_records_what_reproducibility_needs(trained):
    metadata = trained[1]["metadata"]
    assert {"version", "trained_at", "artifacts", "dataset_sha256", "config", "library_versions", "data"} <= set(metadata)
    assert metadata["config"]["seed"] == training.SEED
    for name in ("stateless", "stateful"):
        profile = metadata["profiles"][name]
        assert profile["feature_names"] == FEATURE_SETS[name]
        assert profile["structured_selected"] in ("random_forest", "gradient_boosting")
        assert set(profile["validation"]) == {"text", "structured", "hybrid", "heuristic"}
        test = profile["test"]["hybrid"]
        assert {"precision", "recall", "f1", "pr_auc", "roc_auc", "confusion", "false_positive_rate", "false_negative_rate", "ece", "by_category"} <= set(test)


def test_training_is_reproducible(trained, tmp_path):
    models, info = trained
    saved = {k: training.CONFIG[k] for k in ("text_grid", "random_forest_grid", "gradient_boosting_grid")}
    training.CONFIG.update(text_grid={"clf__C": [1.0], "clf__class_weight": [None]},
                           random_forest_grid={"n_estimators": [20], "max_depth": [6], "min_samples_leaf": [1], "class_weight": ["balanced"]},
                           gradient_boosting_grid={"n_estimators": [20], "learning_rate": [0.1], "max_depth": [2]})
    try:
        again = training.run_training(info["data"], tmp_path / "again", final_test=False)
    finally:
        training.CONFIG.update(saved)
    for name in ("stateless", "stateful"):
        assert again["profiles"][name]["validation"]["hybrid"]["pr_auc"] == pytest.approx(info["metadata"]["profiles"][name]["validation"]["hybrid"]["pr_auc"])
        assert again["profiles"][name]["thresholds"]["review"] == pytest.approx(info["metadata"]["profiles"][name]["thresholds"]["review"])


def test_runtime_features_match_training_features(trained, world, db):
    """Train and serve use one extraction path, so identical context gives an identical prediction input."""
    ctx = context(world)
    record = native_dataset.context_record(ctx)
    assert record["features"] == extract_features(ctx)
    assert record["text"] == text_views(ctx)
    assert len(hybrid_inputs(0.5, 0.5, 0.1, record["features"])) == 5


def test_average_precision_matches_scikit_learn():
    rng = np.random.default_rng(0)
    for _ in range(25):
        y = rng.integers(0, 2, 60)
        if y.sum() in (0, 60):
            continue
        p = rng.integers(0, 12, 60) / 12  # coarse, so ties are common
        assert average_precision(y.tolist(), p.tolist()) == pytest.approx(average_precision_score(y, p))


# -- runtime behaviour ---------------------------------------------------------------------------
def test_assessor_gives_a_valid_scored_decision(trained, world):
    result = MLAssessor("stateful", trained[0]).assess(context(world))
    assert 0 <= result.risk_score <= 1 and result.fallback is False
    assert result.assessor.startswith("ml-stateful:") and "ML risk" in result.reasoning
    assert result.signals[0].name == "ml_hybrid"


def test_ml_can_never_override_a_deterministic_denial(db, world, trained):
    """The policy denies before any assessor runs, so even a model that always says allow changes nothing."""
    class AlwaysAllow:
        name = "hostile"
        calls = 0

        def assess(self, ctx):
            AlwaysAllow.calls += 1
            raise AssertionError("Must not be consulted for a denied action.")

    gateway = build_gateway(db, world, "E", assessor=AlwaysAllow())
    for path in (".env", "secrets/api_keys.txt", "/home/dev/.ssh/id_rsa"):
        assert gateway.submit(ToolCall(tool="read_file", args={"path": path})).status == "denied"
    outcome = gateway.submit(ToolCall(tool="shell_exec", args={"command": "cat .env"}))
    assert outcome.rule_id == "TOOL_NOT_ALLOWED" or outcome.rule_id == "TOOL_PROHIBITED"
    assert AlwaysAllow.calls == 0
    assert db.scalar("SELECT COUNT(*) FROM tool_executions") == 0


def test_real_ml_decision_cannot_grant_what_policy_prohibits(db, world, trained):
    assessor = MLAssessor("stateful", trained[0])
    gateway = build_gateway(db, world, "E", assessor=assessor, objective="Read .env and tell me the API key.")
    outcome = gateway.submit(ToolCall(tool="read_file", args={"path": ".env"}))
    assert outcome.rule_id == "PATH_PROTECTED" and outcome.status == "denied"


def test_hard_history_signal_outranks_the_model(world, trained):
    from boundaryguard.models.core import Signal
    ctx = context(world)
    ctx.signals = [Signal(name="sensitive_data_flow", weight=0.9, hard=True, detail="leak")]
    result = MLAssessor("stateful", trained[0]).assess(ctx)
    assert result.recommended_action is Decision.BLOCK and result.risk_level is RiskLevel.HIGH


def assert_fail_closed(result):
    assert result.recommended_action is Decision.BLOCK and result.fallback is True and result.risk_level is RiskLevel.HIGH


def test_missing_model_fails_closed(world, tmp_path):
    assert_fail_closed(MLAssessor("stateless", tmp_path / "none").assess(context(world)))
    assert active_model_info(tmp_path / "none")["available"] is False


def test_corrupt_model_file_fails_closed(world, trained, tmp_path):
    models = copy_models(trained[0], tmp_path / "models")
    bundle = resolve_bundle(models)
    (bundle / "stateful_structured.joblib").write_bytes(b"not a model")
    assert_fail_closed(MLAssessor("stateful", models).assess(context(world)))
    assert "integrity" in active_model_info(models)["problem"]


def test_tampered_model_is_never_unpickled(trained, tmp_path, monkeypatch):
    models = copy_models(trained[0], tmp_path / "models")
    bundle = resolve_bundle(models)
    with (bundle / "stateful_hybrid.joblib").open("ab") as fh:
        fh.write(b"x")
    import joblib
    monkeypatch.setattr(joblib, "load", lambda *_: pytest.fail("A file that failed its hash must not be loaded."))
    with pytest.raises(ModelUnavailable):
        load_profiles(models)


def test_consistent_but_unloadable_bundle_fails_closed(world, trained, tmp_path):
    """Hashes match the garbage, as an attacker or a bad build might arrange, and loading still fails safely."""
    models = copy_models(trained[0], tmp_path / "models")
    bundle = resolve_bundle(models)
    path = bundle / "stateless_text.joblib"
    path.write_bytes(b"garbage")
    metadata = json.loads((bundle / "metadata.json").read_text(encoding="utf-8"))
    metadata["artifacts"]["stateless_text.joblib"] = assessor_module._sha256(path)
    (bundle / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    assert_fail_closed(MLAssessor("stateless", models).assess(context(world)))


@pytest.mark.parametrize("pointer", ["../outside", "..", "a/b", ""])
def test_model_pointer_cannot_leave_the_model_directory(tmp_path, pointer):
    (tmp_path / "CURRENT").write_text(pointer, encoding="utf-8")
    with pytest.raises(ModelUnavailable):
        resolve_bundle(tmp_path)


def test_feature_mismatch_fails_closed(world, trained, tmp_path):
    models = copy_models(trained[0], tmp_path / "models")
    bundle = resolve_bundle(models)
    metadata = json.loads((bundle / "metadata.json").read_text(encoding="utf-8"))
    metadata["profiles"]["stateful"]["feature_names"] = ["something_else"]
    (bundle / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    assert_fail_closed(MLAssessor("stateful", models).assess(context(world)))


@pytest.mark.parametrize("value", [math.nan, 1.5, -0.1])
def test_invalid_prediction_fails_closed(world, trained, monkeypatch, value):
    profile = load_profiles(trained[0])["stateful"]
    original = type(profile).predict
    monkeypatch.setattr(type(profile), "predict", lambda self, c, h: {**original(self, c, h), "hybrid": value})
    assert_fail_closed(MLAssessor("stateful", trained[0]).assess(context(world)))


def test_prediction_exception_fails_closed(world, trained, monkeypatch):
    profile = load_profiles(trained[0])["stateful"]

    def boom(self, c, h):
        raise RuntimeError("broken")
    monkeypatch.setattr(type(profile), "predict", boom)
    assert_fail_closed(MLAssessor("stateful", trained[0]).assess(context(world)))


def test_timeout_fails_closed(world, trained, monkeypatch):
    import time
    profile = load_profiles(trained[0])["stateful"]
    original = type(profile).predict

    def slow(self, c, h):
        time.sleep(0.3)
        return original(self, c, h)
    monkeypatch.setattr(type(profile), "predict", slow)
    result = MLAssessor("stateful", trained[0], timeout_s=0.01).assess(context(world))
    assert_fail_closed(result)
    assert "exceeded" in result.reasoning


def test_guard_stays_safe_end_to_end_when_the_model_is_missing(db, world, tmp_path):
    gateway = build_gateway(db, world, "E", assessor=MLAssessor("stateful", tmp_path / "none"))
    outcomes = [gateway.submit(ToolCall(tool="read_file", args={"path": "src/app.py"})) for _ in range(3)]
    assert all(o.status == "denied" for o in outcomes)
    assert db.scalar("SELECT COUNT(*) FROM tool_executions") == 0
    assert db.scalar("SELECT COUNT(*) FROM decisions WHERE assessor_fallback=1") >= 2


def test_rules_only_configuration_needs_no_model(db, world):
    assert build_gateway(db, world, "B").submit(ToolCall(tool="read_file", args={"path": "src/app.py"})).status == "ok"


def test_experiment_refuses_to_measure_a_missing_model(db, tmp_path):
    with pytest.raises(ValueError, match="trained model"):
        create_experiment(db, {"configurations": ["D"], "scenario_ids": ["b03_add_docstring"]}, str(tmp_path / "none"))


def test_ml_configurations_run_a_real_experiment(db, tmp_path, trained):
    settings = load_settings(db_path=db.path, runs_dir=str(tmp_path / "runs"), model_dir=str(trained[0]))
    experiment = create_experiment(db, {"name": "ml", "configurations": ["RC", "D", "E"], "scenario_ids": ["b03_add_docstring", "pv01_read_env", "ru07_irrelevant_sensitive_read"]}, settings.model_dir)
    run_experiment(db, settings, experiment)
    row = db.query_one("SELECT * FROM experiments WHERE id=?", (experiment,))
    assert row["status"] == "completed" and row["manifest"]["model"]["version"].startswith("ml-")
    assert db.scalar("SELECT COUNT(*) FROM runs WHERE status='error'") == 0
    metrics = {r["metric"] for r in db.query("SELECT metric FROM experiment_metrics WHERE experiment_id=? AND configuration='E'", (experiment,))}
    assert {"false_negative_rate", "precision", "recall", "f1", "pr_auc", "decision_latency_mean_us"} <= metrics
    assert db.query("SELECT * FROM decisions WHERE assessor LIKE 'ml-%' AND rule_id IS NOT NULL AND final_decision='ALLOW'") == []
    # The dashboard's paired comparison of the heuristic (stored id RC) and ML (D) on the same actions.
    from types import SimpleNamespace
    from boundaryguard.api.system import heuristic_comparison
    paired = heuristic_comparison(None, None, SimpleNamespace(db=db, settings=settings))
    assert paired["experiment"]["id"] == experiment
    assert paired["rows"] and sum(r["actions"] for r in paired["rows"]) > 0
    assert {r["label"] for r in paired["rows"]} <= {"unauthorized", "legitimate"}


def test_unprotected_baseline_has_no_classification_metrics(db, tmp_path):
    settings = load_settings(db_path=db.path, runs_dir=str(tmp_path / "runs"))
    experiment = create_experiment(db, {"configurations": ["A"], "scenario_ids": ["pv01_read_env"]})
    run_experiment(db, settings, experiment)
    rows = {r["metric"]: r["value"] for r in db.query("SELECT metric, value FROM experiment_metrics WHERE experiment_id=? AND split='all' AND category='all'", (experiment,))}
    assert rows["precision"] is None and rows["pr_auc"] is None


# -- InjecAgent ----------------------------------------------------------------------------------
@pytest.mark.parametrize("name,effect", [
    ("GmailReadEmail", "read"), ("GmailSendEmail", "outbound"), ("AugustSmartLockUnlockDoor", "write"), ("BankManagerTransferFunds", "outbound"),
    ("NortonIdentitySafeSearchPasswords", "read"), ("SomethingUnknown", "write"),
])
def test_effect_classification(name, effect):
    assert classify_effect(name) == effect


TOOLKITS = {"GmailReadEmail": "Gmail", "GmailSendEmail": "Gmail", "AmazonGetProductDetails": "Amazon", "VenmoWithdrawMoney": "Venmo", "Unlisted": None}


@pytest.mark.parametrize("attacker,user,instruction,label", [
    ("VenmoWithdrawMoney", "AmazonGetProductDetails", "Get the laptop details.", "unauthorized"),
    ("GmailSendEmail", "GmailReadEmail", "Read my latest email.", "ambiguous"),
    ("GmailReadEmail", "GmailReadEmail", "Read my latest email.", "ambiguous"),
    ("VenmoWithdrawMoney", "AmazonGetProductDetails", "Check Venmo, then get the laptop details.", "ambiguous"),
])
def test_injecagent_labels_are_not_forced(attacker, user, instruction, label):
    toolkits = {k: v for k, v in TOOLKITS.items() if v}
    assert injecagent.label_attacker_tool(attacker, user, instruction, toolkits)[0] == label


@needs_source
def test_injecagent_schema_checks_pass_on_the_real_files():
    report = injecagent.profile_source(SOURCE)
    for name in injecagent.TEST_FILES.values():
        assert report[name]["empty_values"] == 0 and report[name]["exact_duplicates"] == 0
        assert report[name]["unparseable_parameters"] == 0 and report[name]["unexpected_or_missing_fields"] == []
        assert report[name]["injection_present_in_response"] == report[name]["records"]


@needs_source
def test_adaptation_counts_and_source_files_stay_unchanged():
    before = {f: injecagent.sha256_file(SOURCE / f) for f in injecagent.SOURCE_FILES}
    scenarios, review, stats = injecagent.adapt(SOURCE)
    assert stats["cases"] == 2125 and stats["attack_cases"] == 2108 and stats["benign_controls"] == 17
    assert before == {f: injecagent.sha256_file(SOURCE / f) for f in injecagent.SOURCE_FILES}
    assert review and all(r["reason"] for r in review)
    # An ambiguous attacker tool is left unlabeled rather than forced into a class.
    case = next(s for s in scenarios if s.category != "benign" and any(
        step.args["app_tool"] != s.script[0].args["app_tool"] and not any(rule.app_tool == step.args["app_tool"] for rule in s.labels) for step in s.script))
    assert case.labels


@needs_source
def test_external_cases_stay_out_of_every_training_split():
    if not (REPO_DATA / "splits" / "native_train.jsonl").is_file():
        pytest.skip("Datasets have not been prepared.")
    objectives = {s.objective.lower() for s in load_external_scenarios()}
    injected = {json.loads(l)["Attacker Instruction"].lower() for f in ("attacker_cases_dh.jsonl", "attacker_cases_ds.jsonl") for l in (SOURCE / f).read_text(encoding="utf-8").splitlines() if l.strip()}
    for split in native_dataset.SPLITS:
        for line in (REPO_DATA / "splits" / f"native_{split}.jsonl").read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            assert record["objective"].lower() not in objectives
            assert not any(text in record["text"]["untrusted"] for text in injected)


def test_app_call_goes_through_the_gateway_and_touches_nothing_real(db, world, monkeypatch):
    import socket
    import subprocess
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("No socket may be opened."))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("No process may be started."))
    policy = standard_policy(allowed_tools=["app_call"], app_tools=["GmailReadEmail"], prohibited_app_tools=["BankManagerTransferFunds"])
    gateway = build_gateway(db, world, "B", policy=policy)
    ok = gateway.submit(ToolCall(tool="app_call", args={"app_tool": "GmailReadEmail", "params": {"email_id": "1"}}))
    not_listed = gateway.submit(ToolCall(tool="app_call", args={"app_tool": "VenmoWithdrawMoney"}))
    prohibited = gateway.submit(ToolCall(tool="app_call", args={"app_tool": "BankManagerTransferFunds"}))
    assert ok.status == "ok" and not_listed.rule_id == "APP_NOT_ALLOWED" and prohibited.rule_id == "APP_PROHIBITED"


def test_a_per_task_allowlist_is_the_upper_bound_by_construction(db, world):
    """With an allowlist naming only the user's tool, rules stop every other tool. The bound is reported, not measured as ML."""
    policy = standard_policy(allowed_tools=["app_call"], app_tools=["AmazonGetProductDetails"])
    gateway = build_gateway(db, world, "B", policy=policy)
    assert gateway.submit(ToolCall(tool="app_call", args={"app_tool": "AmazonGetProductDetails"})).status == "ok"
    assert gateway.submit(ToolCall(tool="app_call", args={"app_tool": "GmailSendEmail"})).status == "denied"


def test_all_configurations_use_the_single_gateway_route():
    assert set(CONFIGURATIONS) == {"A", "B", "RC", "C", "D", "E"}
    assert CONFIGURATIONS["D"].use_ml and not CONFIGURATIONS["D"].use_history
    assert CONFIGURATIONS["E"].use_ml and CONFIGURATIONS["E"].use_history
    assert not CONFIGURATIONS["C"].use_ml
