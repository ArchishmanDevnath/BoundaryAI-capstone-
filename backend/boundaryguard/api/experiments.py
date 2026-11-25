"""Experiment management and comparative analytics."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field, field_validator

from ..db.connection import to_json, utcnow
from ..experiments.analytics import compare
from ..experiments.runner import create_experiment, run_experiment
from .state import AppState, get_state, to_csv

router = APIRouter()


class ExperimentCreate(BaseModel):
    name: str = Field(default="Benchmark experiment", max_length=200)
    configurations: list[Literal["A", "B", "RC", "C", "D", "E"]] = Field(default=["A", "B", "RC", "C"], min_length=1)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Give the experiment a name.")
        return value

    @field_validator("configurations")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))  # a configuration listed twice would only duplicate identical runs
    suite: Literal["internal", "injecagent"] = "internal"
    # None means "no filter". An empty list would select nothing, so it is rejected rather than read as "everything".
    scenario_ids: list[str] | None = Field(default=None, min_length=1)
    categories: list[str] | None = Field(default=None, min_length=1)
    split: Literal["dev", "holdout", "external"] | None = None
    agent_provider: Literal["scripted", "ollama", "openai_compatible"] = "scripted"
    assessor: Literal["heuristic", "ollama", "openai_compatible"] = "heuristic"
    repeats: int = Field(default=1, ge=1, le=20)
    seed: int = 0


def _background(state: AppState, experiment_id: str) -> None:
    try:
        run_experiment(state.db, state.settings, experiment_id, clients=state.clients)
    except Exception:  # run_experiment has already stored the failure on the experiment row
        pass


@router.post("/experiments", status_code=202)
def start_experiment(payload: ExperimentCreate, state: AppState = Depends(get_state)) -> dict[str, Any]:
    try:
        experiment_id = create_experiment(state.db, payload.model_dump(), state.settings.model_dir)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    state.experiment_pool.submit(_background, state, experiment_id)
    return {"experiment_id": experiment_id, "status": "queued"}


@router.get("/experiments")
def list_experiments(state: AppState = Depends(get_state)) -> list[dict[str, Any]]:
    return state.db.query("SELECT * FROM experiments ORDER BY created_at DESC LIMIT 200")


def _experiment(state: AppState, experiment_id: str) -> dict[str, Any]:
    row = state.db.query_one("SELECT * FROM experiments WHERE id=?", (experiment_id,))
    if row is None:
        raise HTTPException(404, "Experiment not found.")
    return row


@router.get("/experiments/{experiment_id}")
def get_experiment(experiment_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    return _experiment(state, experiment_id)


@router.post("/experiments/{experiment_id}/cancel")
def cancel_experiment(experiment_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    row = _experiment(state, experiment_id)
    if row["status"] not in ("queued", "running"):
        raise HTTPException(409, f"Experiment is already {row['status']}.")
    state.db.execute("UPDATE experiments SET cancel_requested=1 WHERE id=?", (experiment_id,))
    return {"id": experiment_id, "cancel_requested": True}


RESULT_COLUMNS = ["scenario_id", "category", "split", "configuration", "repeat_index", "seed", "status", "termination_reason",
                  "task_completed", "security_pass", "canary_exposed", "canary_exfiltrated", "step_count",
                  "unauthorized_attempted", "unauthorized_executed", "legitimate_blocked", "actions_total",
                  "agent_provider", "agent_model", "assessor", "error"]


def _experiment_results(state: AppState, experiment_id: str, category: str | None = None, limit: int = 100000, offset: int = 0) -> list[dict[str, Any]]:
    filter_sql = " AND r.category=?" if category else ""
    params: list[Any] = [experiment_id, *([category] if category else []), limit, offset]
    return state.db.query(
        """SELECT r.id AS run_id, r.scenario_id, r.category, r.split, r.configuration, r.repeat_index, r.seed, r.status,
                  r.termination_reason, r.task_completed, r.security_pass, r.canary_exposed, r.canary_exfiltrated, r.step_count,
                  r.agent_provider, r.agent_model, r.assessor, r.error, s.title,
                  (SELECT COUNT(*) FROM actions a WHERE a.run_id=r.id) AS actions_total,
                  (SELECT COUNT(*) FROM actions a WHERE a.run_id=r.id AND a.gt_label='unauthorized') AS unauthorized_attempted,
                  (SELECT COUNT(*) FROM actions a JOIN tool_executions e ON e.action_id=a.id
                     WHERE a.run_id=r.id AND a.gt_label='unauthorized' AND e.status='ok') AS unauthorized_executed,
                  (SELECT COUNT(*) FROM actions a JOIN decisions d ON d.action_id=a.id
                     WHERE a.run_id=r.id AND a.gt_label='legitimate' AND d.final_decision!='ALLOW'
                     AND COALESCE(d.approval_outcome,'')!='approved') AS legitimate_blocked
           FROM runs r LEFT JOIN scenarios s ON s.id=r.scenario_id
           WHERE r.experiment_id=?""" + filter_sql + """ ORDER BY r.scenario_id, r.configuration, r.repeat_index LIMIT ? OFFSET ?""",
        params,
    )


@router.get("/experiments/{experiment_id}/runs")
def experiment_runs(experiment_id: str, category: str | None = None, limit: int = Query(default=600, ge=1, le=20000), offset: int = Query(default=0, ge=0),
                    state: AppState = Depends(get_state)) -> list[dict[str, Any]]:
    _experiment(state, experiment_id)
    return _experiment_results(state, experiment_id, category, limit, offset)


@router.get("/experiments/{experiment_id}/metrics")
def experiment_metrics(experiment_id: str, configuration: str | None = None, category: str | None = None, split: str | None = None,
                       state: AppState = Depends(get_state)) -> list[dict[str, Any]]:
    _experiment(state, experiment_id)
    sql = "SELECT * FROM experiment_metrics WHERE experiment_id=?"
    params: list[Any] = [experiment_id]
    for column, value in (("configuration", configuration), ("category", category), ("split", split)):
        if value:
            sql += f" AND {column}=?"
            params.append(value)
    return state.db.query(sql, params)


@router.get("/experiments/{experiment_id}/export")
def export_experiment(experiment_id: str, format: Literal["csv", "json"] = "csv", state: AppState = Depends(get_state)) -> Response:
    experiment = _experiment(state, experiment_id)
    results = _experiment_results(state, experiment_id)
    disposition = {"Content-Disposition": f'attachment; filename="boundaryguard-{experiment_id[:8]}.{format}"'}
    if format == "json":
        metrics = state.db.query("SELECT * FROM experiment_metrics WHERE experiment_id=?", (experiment_id,))
        body = to_json({"exported_at": utcnow(), "experiment": experiment, "results": results, "metrics": metrics})
        return Response(body, media_type="application/json", headers=disposition)
    return PlainTextResponse(to_csv(results, RESULT_COLUMNS), media_type="text/csv", headers=disposition)


@router.get("/analytics/compare")
def analytics_compare(experiment_id: str | None = None, split: Literal["all", "dev", "holdout", "external"] = Query(default="all"),
                      state: AppState = Depends(get_state)) -> dict[str, Any]:
    if experiment_id is None:
        experiment_id = state.db.scalar("SELECT id FROM experiments WHERE status='completed' ORDER BY finished_at DESC LIMIT 1")
        if experiment_id is None:
            raise HTTPException(404, "No completed experiment yet.")
    result = compare(state.db, experiment_id, split)
    if result is None:
        raise HTTPException(404, "Experiment not found.")
    return result
