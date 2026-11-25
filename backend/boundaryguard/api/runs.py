"""Scenarios, live runs, traces and approvals."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..db.connection import utcnow
from ..experiments.runner import RunSpec, execute_run, insert_run, spec_from_scenario
from ..experiments.scenarios import list_benchmark_policies, list_fixtures, load_scenarios
from ..models.core import Policy
from .state import AppState, get_state

router = APIRouter()


@router.get("/scenarios")
def list_scenarios(category: str | None = None, split: str | None = None, state: AppState = Depends(get_state)) -> list[dict[str, Any]]:
    sql = "SELECT id, category, split, title, definition FROM scenarios WHERE 1=1"
    params: list[Any] = []
    if category:
        sql += " AND category=?"
        params.append(category)
    if split:
        sql += " AND split=?"
        params.append(split)
    rows = state.db.query(sql + " ORDER BY id", params)
    return [{"id": r["id"], "category": r["category"], "split": r["split"], "title": r["title"],
             "objective": r["definition"]["objective"], "fixture": r["definition"]["fixture"],
             "policy": r["definition"]["policy"]} for r in rows]


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    row = state.db.query_one("SELECT definition FROM scenarios WHERE id=?", (scenario_id,))
    if row is None:
        raise HTTPException(404, "Scenario not found.")
    return row["definition"]


class RunCreate(BaseModel):
    scenario_id: str | None = None
    objective: str | None = Field(default=None, max_length=4000)
    fixture: str | None = None
    policy_id: str | None = None
    configuration: Literal["A", "B", "RC", "C", "D", "E"] = "C"
    agent_provider: Literal["scripted", "ollama", "openai_compatible"] = "scripted"
    assessor: Literal["heuristic", "ollama", "openai_compatible"] = "heuristic"
    approval_mode: Literal["auto_deny", "human"] = "auto_deny"
    step_delay_ms: int = Field(default=0, ge=0, le=5000)
    seed: int = 0


def _resolve_policy(policy_id: str | None, state: AppState) -> Policy:
    if not policy_id:
        raise HTTPException(422, "A custom run needs a policy_id.")
    if policy_id.startswith("benchmark:"):
        for policy in list_benchmark_policies():
            if policy.name == policy_id.split(":", 1)[1]:
                return policy
        raise HTTPException(404, "Policy not found.")
    row = state.db.query_one("SELECT body FROM policies WHERE id=? AND active=1", (policy_id,))
    if row is None:
        raise HTTPException(404, "Policy not found.")
    return Policy.model_validate(row["body"])


@router.post("/runs", status_code=202)
def create_run(payload: RunCreate, state: AppState = Depends(get_state)) -> dict[str, Any]:
    if payload.scenario_id:
        scenario = next((s for s in load_scenarios() if s.id == payload.scenario_id), None)
        if scenario is None:
            raise HTTPException(404, "Scenario not found.")
        spec = spec_from_scenario(scenario, payload.configuration, seed=payload.seed, agent_provider=payload.agent_provider,
                                  assessor=payload.assessor, approval_mode=payload.approval_mode, step_delay_ms=payload.step_delay_ms)
    else:
        if payload.agent_provider == "scripted":
            raise HTTPException(422, "Scripted runs replay a scenario, so they need a scenario_id.")
        if not (payload.objective or "").strip() or not payload.fixture:
            raise HTTPException(422, "A custom run needs an objective and a fixture.")
        if payload.fixture not in list_fixtures():
            raise HTTPException(422, "Unknown fixture.")
        spec = RunSpec(configuration=payload.configuration, objective=payload.objective, fixture=payload.fixture,
                       policy=_resolve_policy(payload.policy_id, state), seed=payload.seed,
                       agent_provider=payload.agent_provider, assessor=payload.assessor,
                       approval_mode=payload.approval_mode, step_delay_ms=payload.step_delay_ms)
    run_id = insert_run(state.db, spec)
    state.live_pool.submit(execute_run, state.db, state.settings, spec, state.clients)
    return {"run_id": run_id, "status": "running"}


RUN_COLUMNS = ("r.id, r.experiment_id, r.scenario_id, r.category, r.split, r.configuration, r.repeat_index, r.seed, r.objective,"
               " r.status, r.termination_reason, r.error, r.final_message, r.task_completed, r.completion_detail, r.security_pass,"
               " r.expected, r.agent_provider, r.agent_model, r.assessor, r.approval_mode, r.canary_exposed, r.canary_exfiltrated,"
               " r.workspace_changed, r.unledgered_changes, r.step_count, r.policy_hash, r.started_at, r.finished_at")


@router.get("/runs")
def list_runs(experiment_id: str | None = None, configuration: str | None = None, scenario_id: str | None = None,
              status: str | None = None, live_only: bool = False, limit: int = Query(default=50, ge=1, le=1000), offset: int = Query(default=0, ge=0),
              state: AppState = Depends(get_state)) -> dict[str, Any]:
    where = " WHERE 1=1"
    params: list[Any] = []
    for column, value in (("experiment_id", experiment_id), ("configuration", configuration), ("scenario_id", scenario_id), ("status", status)):
        if value:
            where += f" AND r.{column}=?"
            params.append(value)
    if live_only:
        where += " AND r.experiment_id IS NULL"
    total = state.db.scalar(f"SELECT COUNT(*) FROM runs r{where}", params)
    items = state.db.query(
        f"SELECT {RUN_COLUMNS}, (SELECT COUNT(*) FROM decisions d WHERE d.run_id=r.id AND d.final_decision!='ALLOW'"
        f" AND COALESCE(d.approval_outcome,'')!='approved') AS blocked_actions FROM runs r{where}"
        " ORDER BY r.started_at DESC, r.id LIMIT ? OFFSET ?", [*params, limit, offset])
    return {"total": total, "items": items}


@router.get("/runs/{run_id}")
def get_run(run_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    run = state.db.query_one(f"SELECT {RUN_COLUMNS} FROM runs r WHERE r.id=?", (run_id,))
    if run is None:
        raise HTTPException(404, "Run not found.")
    return run


@router.get("/runs/{run_id}/trace")
def get_trace(run_id: str, after_seq: int = Query(default=0, ge=0), state: AppState = Depends(get_state)) -> dict[str, Any]:
    if not state.db.scalar("SELECT 1 FROM runs WHERE id=?", (run_id,)):
        raise HTTPException(404, "Run not found.")
    rows = state.db.query(
        """SELECT a.id AS action_id, a.seq, a.tool, a.args, a.canonical, a.gt_label, a.proposed_at,
                  d.policy_verdict, d.final_decision, d.source, d.rule_id, d.risk_level, d.risk_score, d.reasoning, d.signals,
                  d.terminate, d.approval_outcome, d.assessor, d.assessor_fallback, d.policy_latency_us, d.context_latency_us, d.decided_at,
                  e.status AS exec_status, e.target AS exec_target, e.result_summary, e.bytes, e.contains_canary, e.sink, e.executed_at,
                  p.id AS approval_id, p.status AS approval_status
           FROM actions a LEFT JOIN decisions d ON d.action_id=a.id LEFT JOIN tool_executions e ON e.action_id=a.id
           LEFT JOIN approvals p ON p.action_id=a.id
           WHERE a.run_id=? AND a.seq>? ORDER BY a.seq""",
        (run_id, after_seq),
    )
    return {"run": get_run(run_id, state), "actions": rows}


@router.get("/approvals")
def list_approvals(status: str = "pending", state: AppState = Depends(get_state)) -> list[dict[str, Any]]:
    return state.db.query(
        """SELECT p.id, p.run_id, p.action_id, p.status, p.created_at, p.resolved_at, p.note, a.tool, a.args, d.reasoning, d.risk_level, r.objective
           FROM approvals p JOIN actions a ON a.id=p.action_id LEFT JOIN decisions d ON d.action_id=p.action_id
           JOIN runs r ON r.id=p.run_id WHERE p.status=? ORDER BY p.created_at DESC LIMIT 100""", (status,))


class ApprovalResolve(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=1000)


@router.post("/approvals/{approval_id}/resolve")
def resolve_approval(approval_id: str, payload: ApprovalResolve, state: AppState = Depends(get_state)) -> dict[str, Any]:
    status = "approved" if payload.approve else "denied"
    cursor = state.db.execute(
        "UPDATE approvals SET status=?, resolver='dashboard', note=?, resolved_at=? WHERE id=? AND status='pending'",
        (status, payload.note, utcnow(), approval_id),
    )
    if cursor.rowcount == 0:
        if not state.db.scalar("SELECT 1 FROM approvals WHERE id=?", (approval_id,)):
            raise HTTPException(404, "Approval not found.")
        raise HTTPException(409, "This approval was already decided or has timed out.")
    return {"id": approval_id, "status": status}

