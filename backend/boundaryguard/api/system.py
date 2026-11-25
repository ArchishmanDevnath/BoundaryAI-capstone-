"""Health, overview and catalog endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from ..audit.logger import verify_chain
from ..experiments.analytics import KPI_DEFINITIONS
from ..experiments.scenarios import list_fixtures
from ..ml.assessor import active_model_info
from ..models.core import CONFIGURATION_NAMES, CONFIGURATIONS
from ..tools.catalog import catalog_summary
from .state import AppState, get_state

router = APIRouter()

BLOCKED_SQL = "(d.final_decision='BLOCK' OR (d.final_decision='APPROVAL_REQUIRED' AND COALESCE(d.approval_outcome,'')!='approved'))"


@router.get("/health")
def health(state: AppState = Depends(get_state)) -> dict[str, Any]:
    db_ok = state.db.scalar("SELECT 1") == 1
    running = state.db.scalar("SELECT COUNT(*) FROM experiments WHERE status IN ('queued','running')")
    live = state.db.scalar("SELECT COUNT(*) FROM runs WHERE status='running' AND experiment_id IS NULL")
    model = active_model_info(state.settings.model_dir)
    return {
        "status": "ok" if db_ok else "degraded",
        "database": db_ok,
        "llm": {"ollama": state.llm_available("ollama"), "openai_compatible": state.llm_available("openai_compatible")},
        "deterministic_guard": True,
        "ml_model": {k: model[k] for k in ("available", "version", "problem")},
        "experiments_active": running,
        "live_runs_active": live,
    }


@router.get("/providers")
def providers(state: AppState = Depends(get_state)) -> dict[str, Any]:
    settings = state.settings
    return {
        "agents": [
            {"id": "scripted", "label": "Scripted traces", "available": True, "model": None,
             "note": "Replays each scenario's fixed trace. Measures guard decisions, not model behaviour."},
            {"id": "ollama", "label": "Ollama (local)", "available": state.llm_available("ollama"), "model": settings.ollama_model,
             "note": f"Needs a running Ollama server with {settings.ollama_model} pulled."},
            {"id": "openai_compatible", "label": "OpenAI-compatible (optional)", "available": state.llm_available("openai_compatible"),
             "model": settings.openai_model or None, "note": "Needs BG_OPENAI_BASE_URL and BG_OPENAI_MODEL."},
        ],
        "assessors": [
            {"id": "heuristic", "label": "Heuristic", "available": True, "model": None, "note": "Deterministic, no LLM."},
            {"id": "ollama", "label": "Ollama (local)", "available": state.llm_available("ollama"), "model": settings.ollama_model,
             "note": "Falls back to the fail-safe heuristic if unavailable."},
            {"id": "openai_compatible", "label": "OpenAI-compatible (optional)", "available": state.llm_available("openai_compatible"),
             "model": settings.openai_model or None, "note": "Falls back to the fail-safe heuristic if unavailable."},
        ],
        "fixtures": list_fixtures(),
    }


@router.get("/ml/model")
def ml_model(state: AppState = Depends(get_state)) -> dict[str, Any]:
    """The active model and its recorded evaluation. Everything shown comes from the bundle's own metadata."""
    return active_model_info(state.settings.model_dir)


@router.get("/ml/heuristic-comparison")
def heuristic_comparison(experiment_id: str | None = None, split: str | None = None, state: AppState = Depends(get_state)) -> dict[str, Any]:
    """Paired decisions on the same scenario and action step, for the latest experiment containing both C and D."""
    db = state.db
    if experiment_id is None:
        experiment_id = db.scalar(
            """SELECT e.id FROM experiments e WHERE e.status='completed' AND EXISTS (SELECT 1 FROM runs r WHERE r.experiment_id=e.id AND r.configuration='D')
               AND EXISTS (SELECT 1 FROM runs r WHERE r.experiment_id=e.id AND r.configuration='RC')
               AND json_extract(e.manifest, '$.model.version') IS ?
               ORDER BY e.finished_at DESC LIMIT 1""", (active_model_info(state.settings.model_dir)["version"],))
    if experiment_id is None:
        return {"experiment": None, "rows": []}
    # Two indexed reads matched in memory. A SQL self-join on scenario was quadratic in the number of runs.
    def decisions(configuration: str) -> dict[tuple[Any, ...], dict[str, Any]]:
        rows = db.query(
            f"""SELECT r.scenario_id, r.repeat_index, a.seq, a.fingerprint, a.gt_label, d.final_decision, d.source
                FROM runs r JOIN actions a ON a.run_id=r.id JOIN decisions d ON d.action_id=a.id
                WHERE r.experiment_id=? AND r.configuration=? {"AND r.split=?" if split else ""}""",
            (experiment_id, configuration, *([split] if split else [])))
        return {(x["scenario_id"], x["repeat_index"], x["seq"], x["fingerprint"]): x for x in rows}

    heuristic, ml = decisions("RC"), decisions("D")
    counts: dict[tuple[str, str, str], int] = {}
    for key, h in heuristic.items():
        m = ml.get(key)
        if m is None or h["gt_label"] not in ("unauthorized", "legitimate") or h["source"] == "policy":
            continue
        cell = (h["gt_label"], "allow" if h["final_decision"] == "ALLOW" else "stop", "allow" if m["final_decision"] == "ALLOW" else "stop")
        counts[cell] = counts.get(cell, 0) + 1
    rows = [{"label": k[0], "heuristic": k[1], "ml": k[2], "actions": v} for k, v in sorted(counts.items())]
    name = db.scalar("SELECT name FROM experiments WHERE id=?", (experiment_id,))
    return {"experiment": {"id": experiment_id, "name": name}, "rows": rows}


@router.get("/configurations")
def configurations() -> list[dict[str, Any]]:
    return [{"id": c, "name": CONFIGURATION_NAMES[c], **flags.model_dump()} for c, flags in CONFIGURATIONS.items()]


@router.get("/tools")
def tools() -> list[dict[str, Any]]:
    return catalog_summary()


@router.get("/overview")
def overview(state: AppState = Depends(get_state)) -> dict[str, Any]:
    """Status plus results of the latest experiment. Totals across experiments are only used for run accounting,
    because adding benchmark repeats and the deliberately unprotected baseline together means nothing."""
    db = state.db
    by_experiment = db.query(
        """SELECT e.id, e.name, e.status, e.total_runs, e.created_at, COUNT(r.id) AS recorded_runs
           FROM experiments e LEFT JOIN runs r ON r.experiment_id=e.id GROUP BY e.id ORDER BY e.created_at DESC""")
    experiment_runs = sum(e["recorded_runs"] for e in by_experiment)
    live_runs = db.scalar("SELECT COUNT(*) FROM runs WHERE experiment_id IS NULL")
    recent_runs = db.query("SELECT id FROM runs WHERE status NOT IN ('running') ORDER BY started_at DESC LIMIT 25")
    chain_checks = [verify_chain(db, r["id"]) for r in recent_runs]
    # Only configurations with a guard. The baseline never stops anything, by design.
    events = db.query(
        f"""SELECT a.id AS action_id, a.run_id, a.seq, a.tool, a.args, d.final_decision, d.approval_outcome, d.source, d.rule_id,
                   d.risk_level, d.reasoning, d.decided_at, r.configuration, r.scenario_id, r.agent_provider, a.gt_label
            FROM decisions d JOIN actions a ON a.id=d.action_id JOIN runs r ON r.id=a.run_id
            WHERE {BLOCKED_SQL} AND r.configuration!='A' ORDER BY d.decided_at DESC LIMIT 8"""
    )
    # The headline describes the system as configured now, so experiments run with a different model (for example a
    # post-hoc retrain) are left out of it. They stay listed under Experiments.
    active_version = active_model_info(state.settings.model_dir)["version"]
    latest = next((e for e in db.query("SELECT id, name, status, total_runs, finished_at, manifest FROM experiments WHERE status='completed'"
                                       " ORDER BY finished_at DESC LIMIT 50")
                   if not (e["manifest"] or {}).get("model") or e["manifest"]["model"]["version"] == active_version), None)
    latest_metrics: list[dict[str, Any]] = []
    if latest:
        names = [k["metric"] for k in KPI_DEFINITIONS]
        marks = ",".join("?" * len(names))
        latest_metrics = db.query(
            f"SELECT configuration, split, metric, numerator, denominator, value FROM experiment_metrics"
            f" WHERE experiment_id=? AND category='all' AND metric IN ({marks})", (latest["id"], *names))
    # Approved actions a scenario labels unauthorized: the guard flagged them and a person let them through.
    human_overrides = db.scalar(
        "SELECT COUNT(*) FROM decisions d JOIN actions a ON a.id=d.action_id WHERE d.approval_outcome='approved' AND a.gt_label='unauthorized'")
    return {
        "runs": {
            "total": db.scalar("SELECT COUNT(*) FROM runs"),
            "experiment_runs": experiment_runs,
            "live_runs": live_runs,
            "by_experiment": by_experiment,
        },
        "approvals_pending": db.scalar("SELECT COUNT(*) FROM approvals WHERE status='pending'"),
        "human_overrides": human_overrides,
        "scenarios": db.scalar("SELECT COUNT(*) FROM scenarios"),
        "recent_events": events,
        "audit_integrity": {"runs_checked": len(chain_checks), "runs_valid": sum(1 for c in chain_checks if c["valid"])},
        "latest_experiment": latest,
        "latest_metrics": latest_metrics,
        "health": health(state),
    }
