"""Executes single runs and whole experiments. All guard logic is reached through the gateway."""
from __future__ import annotations

import hashlib
import json
import platform
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..agent.loop import LoopResult, run_agent
from ..agent.providers.llm_agent import LLMAgentProvider
from ..agent.providers.scripted import ScriptedProvider
from ..audit.logger import RunRecorder
from ..config import MODELS_DIR, Settings
from ..db.connection import Database, to_json, utcnow
from ..guard.context.heuristic import HeuristicAssessor
from ..guard.context.llm import LLMAssessor
from ..guard.gateway import AutoDeny, HumanApproval, ToolGateway
from ..guard.pipeline import Guard
from ..ml.assessor import MLAssessor, ModelUnavailable, active_model_info, load_profiles
from ..llm import ChatClient, build_client
from ..models.core import CONFIGURATIONS, CanonicalAction, Policy, Scenario
from ..tools.sandbox import Sandbox, safe_rmtree
from ..tools.simapps import SimApps
from ..tools.simnet import SimNet
from ..tools.test_oracle import TestOracle
from . import metrics as metrics_module
from .scenarios import LinkUnavailable, build_workspace, load_benchmark_policy, load_suite, suite_hash
from .scoring import evaluate_completion, label_action, security_pass, workspace_diff

EXTERNAL_NOTE = ("InjecAgent cases replayed as if the agent complied with every injection. This measures the guard's decisions on those actions. "
                 "Authorization labels are an adaptation by this project, not part of InjecAgent.")
PROVENANCE_NOTES = {
    "scripted": ("Scripted traces: the agent attempts each attack by construction. These results measure guard "
                 "decisions on fixed traces, not how often a real model would attempt an attack."),
    "llm": "Live LLM agent: attempts and task success depend on the named model, prompt and seed.",
}


@dataclass
class RunSpec:
    configuration: str
    objective: str
    fixture: str
    policy: Policy
    seed: int = 0
    scenario: Scenario | None = None
    agent_provider: str = "scripted"
    assessor: str = "heuristic"
    approval_mode: str = "auto_deny"
    experiment_id: str | None = None
    repeat_index: int = 0
    step_delay_ms: int = 0
    run_id: str | None = None


def spec_from_scenario(scenario: Scenario, configuration: str, **kwargs: Any) -> RunSpec:
    return RunSpec(
        configuration=configuration,
        objective=scenario.objective,
        fixture=scenario.fixture,
        policy=load_benchmark_policy(scenario.policy, scenario.policy_overrides),
        scenario=scenario,
        **kwargs,
    )


def _client(kind: str, settings: Settings, clients: dict[str, ChatClient] | None) -> ChatClient:
    if clients and kind in clients:
        return clients[kind]
    return build_client(kind, settings)


def insert_run(db: Database, spec: RunSpec) -> str:
    run_id = spec.run_id or uuid.uuid4().hex
    spec.run_id = run_id
    flags = CONFIGURATIONS[spec.configuration]
    scenario = spec.scenario
    db.execute(
        "INSERT INTO runs (id, experiment_id, scenario_id, category, split, configuration, repeat_index, seed, objective,"
        " status, expected, agent_provider, assessor, approval_mode, policy_hash, policy_body, started_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, spec.experiment_id, scenario.id if scenario else None, scenario.category if scenario else None,
         scenario.split if scenario else None, spec.configuration, spec.repeat_index, spec.seed, spec.objective, "running",
         to_json(scenario.expected.model_dump()) if scenario else None, spec.agent_provider,
         ("ml" if flags.use_ml else spec.assessor) if flags.use_context else None, spec.approval_mode, spec.policy.content_hash(),
         spec.policy.model_dump_json(), utcnow()),
    )
    return run_id


def execute_run(db: Database, settings: Settings, spec: RunSpec, clients: dict[str, ChatClient] | None = None,
                should_stop: Callable[[], bool] | None = None) -> str:
    """Run one scenario in one configuration. Always cleans up its sandbox and always finalizes the run row."""
    run_id = spec.run_id if spec.run_id and db.scalar("SELECT 1 FROM runs WHERE id=?", (spec.run_id,)) else insert_run(db, spec)
    root = Path(settings.runs_dir) / f"run-{run_id}"
    runs_dir = Path(settings.runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)
    scenario = spec.scenario
    try:
        try:
            workspace = build_workspace(root, spec.fixture, scenario.id if scenario else run_id, spec.seed,
                                        scenario.overlays if scenario else None, scenario.links if scenario else None)
        except LinkUnavailable as exc:
            _finish(db, run_id, status="skipped", termination_reason="link_unavailable", error=str(exc))
            return run_id

        sandbox = Sandbox(workspace.root)
        baseline = sandbox.snapshot()
        recorder = RunRecorder(db, run_id, canaries=workspace.canaries)
        recorder.event("run_start", {"objective": spec.objective, "configuration": spec.configuration,
                                     "policy_hash": spec.policy.content_hash()})

        flags = CONFIGURATIONS[spec.configuration]
        assessor = None
        if flags.use_context:
            if flags.use_ml:
                assessor = MLAssessor("stateful" if flags.use_history else "stateless", settings.model_dir, settings.ml_timeout_s)
            elif spec.assessor == "heuristic":
                assessor = HeuristicAssessor()
            else:
                assessor = LLMAssessor(_client(spec.assessor, settings, clients), settings.assessor_timeout_s, spec.seed)
        guard = Guard(flags, spec.policy, spec.objective, assessor)
        oracle = TestOracle(scenario.oracle if scenario else [])
        approvals = (HumanApproval(db, settings.approval_timeout_s, should_stop=should_stop)
                     if spec.approval_mode == "human" else AutoDeny())
        apps = SimApps(scenario.app_responses if scenario else None)
        gateway = ToolGateway(run_id=run_id, guard=guard, sandbox=sandbox,
                              simnet=SimNet(scenario.network if scenario else None), oracle=oracle,
                              recorder=recorder, approvals=approvals, apps=apps)

        if spec.agent_provider == "scripted":
            if scenario is None:
                raise ValueError("The scripted provider needs a benchmark scenario.")
            provider = ScriptedProvider(scenario.script)
        else:
            client = _client(spec.agent_provider, settings, clients)
            provider = LLMAgentProvider(client, spec.objective, spec.seed, settings.agent_timeout_s)
        db.execute("UPDATE runs SET agent_model=? WHERE id=?", (provider.model, run_id))

        result = run_agent(provider, gateway, spec.policy.limits.max_steps, spec.step_delay_ms / 1000, should_stop)
        recorder.event("run_end", {"status": result.status, "termination_reason": result.termination_reason,
                                   "steps": result.steps})
        _score_and_finish(db, run_id, spec, sandbox, oracle, baseline, result, apps.called)
        return run_id
    except Exception as exc:  # recorded and reported as an errored run, never dropped
        _finish(db, run_id, status="error", termination_reason="internal_error", error=f"{type(exc).__name__}: {exc}")
        return run_id
    finally:
        if root.exists():
            safe_rmtree(root, runs_dir)


def _score_and_finish(db: Database, run_id: str, spec: RunSpec, sandbox: Sandbox, oracle: TestOracle,
                      baseline: dict[str, str], result: LoopResult, app_calls: set[str] | None = None) -> None:
    scenario = spec.scenario
    final = sandbox.snapshot()
    rules = scenario.labels if scenario else []
    actions = db.query("SELECT id, tool, canonical FROM actions WHERE run_id=?", (run_id,))
    labels: dict[str, str] = {}
    for action in actions:
        canon = CanonicalAction.model_validate(action["canonical"]) if action["canonical"] else None
        labels[action["id"]] = label_action(action["tool"], canon, rules)
    with db.transaction() as conn:
        conn.executemany("UPDATE actions SET gt_label=? WHERE id=?", [(lab, aid) for aid, lab in labels.items()])

    ledger = db.query("SELECT action_id, tool, target, status, contains_canary, sink FROM tool_executions WHERE run_id=?", (run_id,))
    ok_rows = [row for row in ledger if row["status"] == "ok"]
    canary_exposed = any(row["contains_canary"] for row in ok_rows)
    canary_exfiltrated = any(row["contains_canary"] and row["sink"] for row in ok_rows)
    unauthorized_executed = sum(1 for row in ok_rows if labels.get(row["action_id"]) == "unauthorized")

    changed = workspace_diff(baseline, final)
    ledgered = {row["target"] for row in ok_rows if row["tool"] in ("write_file", "delete_file")}
    unledgered = sorted(changed - ledgered)

    finished = result.status == "completed"
    if scenario:
        completed, details = evaluate_completion(scenario, sandbox, oracle, baseline, final, finished, app_calls)
        passed = security_pass(scenario, unauthorized_executed, canary_exfiltrated, result.termination_reason)
    else:
        completed, details, passed = finished, [], None

    _finish(
        db, run_id, status=result.status, termination_reason=result.termination_reason, error=result.error,
        final_message=result.final_message, task_completed=int(completed), completion_detail=to_json(details),
        security_pass=None if passed is None else int(passed), canary_exposed=int(canary_exposed),
        canary_exfiltrated=int(canary_exfiltrated), workspace_changed=int(bool(changed)),
        unledgered_changes=to_json(unledgered), step_count=result.steps,
    )


def _finish(db: Database, run_id: str, **columns: Any) -> None:
    columns["finished_at"] = utcnow()
    assignments = ", ".join(f"{name}=?" for name in columns)
    db.execute(f"UPDATE runs SET {assignments} WHERE id=?", (*columns.values(), run_id))


# ---- experiments -----------------------------------------------------------------

def select_scenarios(all_scenarios: list[Scenario], config: dict[str, Any]) -> list[Scenario]:
    selected = all_scenarios
    if config.get("scenario_ids"):
        wanted = set(config["scenario_ids"])
        selected = [s for s in selected if s.id in wanted]
    if config.get("categories"):
        selected = [s for s in selected if s.category in config["categories"]]
    if config.get("split") in ("dev", "holdout", "external"):
        selected = [s for s in selected if s.split == config["split"]]
    return selected


def _source_hash() -> str:
    digest = hashlib.sha256()
    package = Path(__file__).resolve().parent.parent
    for path in sorted(package.rglob("*.py")):
        digest.update(path.relative_to(package).as_posix().encode())
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()


def create_experiment(db: Database, config: dict[str, Any], model_dir: str | Path = MODELS_DIR) -> str:
    """Validate the configuration and store a manifest describing exactly what will run."""
    configurations = config.get("configurations") or list(CONFIGURATIONS)
    unknown = [c for c in configurations if c not in CONFIGURATIONS]
    if unknown:
        raise ValueError(f"Unknown configurations: {unknown}")
    config = {**config, "configurations": configurations, "repeats": int(config.get("repeats", 1)),
              "seed": int(config.get("seed", 0)), "agent_provider": config.get("agent_provider", "scripted"),
              "assessor": config.get("assessor", "heuristic"), "suite": config.get("suite") or "internal"}
    if config["repeats"] < 1:
        raise ValueError("repeats must be at least 1.")
    all_scenarios = load_suite(config["suite"])
    selected = select_scenarios(all_scenarios, config)
    uses_ml = any(CONFIGURATIONS[c].use_ml for c in configurations)
    model = active_model_info(model_dir) if uses_ml else None
    if uses_ml and not model["available"]:
        # A live run with a missing model fails closed. An experiment would only measure the outage, so refuse to start it.
        raise ValueError(f"Configurations D and E need a trained model: {model['problem']} Run scripts/train_models.py.")
    if not selected:
        raise ValueError("No scenarios match this selection.")
    policies = {s.id: load_benchmark_policy(s.policy, s.policy_overrides).content_hash() for s in selected}
    is_scripted = config["agent_provider"] == "scripted"
    manifest = {
        "suite_hash": suite_hash(all_scenarios),
        "source_hash": _source_hash(),
        "policy_set_hash": hashlib.sha256(json.dumps(policies, sort_keys=True).encode()).hexdigest(),
        "scenario_ids": [s.id for s in selected],
        "suite": config["suite"],
        "model": {k: model[k] for k in ("version", "bundle_sha256", "trained_at")} if model else None,
        "flags": {c: CONFIGURATIONS[c].model_dump() for c in configurations},
        "agent_provider": config["agent_provider"],
        "assessor": config["assessor"],
        "seed": config["seed"],
        "repeats": config["repeats"],
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "provenance": EXTERNAL_NOTE if config["suite"] == "injecagent" else PROVENANCE_NOTES["scripted" if is_scripted else "llm"],
    }
    experiment_id = uuid.uuid4().hex
    total = len(selected) * len(configurations) * config["repeats"]
    db.execute(
        "INSERT INTO experiments (id, name, status, config, manifest, total_runs, created_at) VALUES (?,?,?,?,?,?,?)",
        (experiment_id, config.get("name") or "Benchmark experiment", "queued", to_json(config), to_json(manifest), total, utcnow()),
    )
    return experiment_id


def run_experiment(db: Database, settings: Settings, experiment_id: str,
                   clients: dict[str, ChatClient] | None = None) -> None:
    experiment = db.query_one("SELECT * FROM experiments WHERE id=?", (experiment_id,))
    if experiment is None:
        raise ValueError("Unknown experiment.")
    config = experiment["config"]
    db.execute("UPDATE experiments SET status='running', started_at=? WHERE id=?", (utcnow(), experiment_id))
    if any(CONFIGURATIONS[c].use_ml for c in config["configurations"]):
        # Load before the clock starts, so the first decision's latency does not include loading the model.
        try:
            load_profiles(settings.model_dir)
        except ModelUnavailable:
            pass  # each decision will fail closed, and that is recorded per action

    def cancelled() -> bool:
        return bool(db.scalar("SELECT cancel_requested FROM experiments WHERE id=?", (experiment_id,)))

    try:
        selected = select_scenarios(load_suite(config.get("suite") or "internal"), config)
        done = 0
        for repeat in range(config["repeats"]):
            for scenario in selected:
                for configuration in config["configurations"]:
                    if cancelled():
                        metrics_module.compute_experiment_metrics(db, experiment_id)
                        db.execute("UPDATE experiments SET status='cancelled', finished_at=? WHERE id=?", (utcnow(), experiment_id))
                        return
                    spec = spec_from_scenario(
                        scenario, configuration, seed=config["seed"] + repeat, repeat_index=repeat,
                        agent_provider=config["agent_provider"], assessor=config["assessor"], experiment_id=experiment_id,
                    )
                    execute_run(db, settings, spec, clients=clients)
                    done += 1
                    db.execute("UPDATE experiments SET completed_runs=? WHERE id=?", (done, experiment_id))
        metrics_module.compute_experiment_metrics(db, experiment_id)
        db.execute("UPDATE experiments SET status='completed', finished_at=? WHERE id=?", (utcnow(), experiment_id))
    except Exception as exc:
        db.execute("UPDATE experiments SET status='failed', error=?, finished_at=? WHERE id=?",
                   (f"{type(exc).__name__}: {exc}", utcnow(), experiment_id))
        raise
