"""Searchable audit history, exports and chain verification."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response

from ..audit.logger import verify_chain
from ..db.connection import to_json
from .state import AppState, get_state, to_csv

router = APIRouter(prefix="/audit")

BASE = """FROM decisions d JOIN actions a ON a.id=d.action_id JOIN runs r ON r.id=a.run_id
          LEFT JOIN tool_executions e ON e.action_id=a.id"""
COLUMNS = """a.id AS action_id, a.run_id, a.seq, a.tool, a.args, a.gt_label, a.fingerprint, a.proposed_at, d.final_decision, d.approval_outcome,
             d.source, d.rule_id, d.risk_level, d.risk_score, d.reasoning, d.assessor, d.assessor_fallback, d.decided_at, d.policy_latency_us,
             d.context_latency_us, e.status AS exec_status, e.target AS exec_target, r.configuration, r.scenario_id, r.experiment_id, r.agent_provider"""
EXPORT_COLUMNS = ["decided_at", "experiment_id", "run_id", "seq", "configuration", "scenario_id", "agent_provider", "tool", "args", "final_decision",
                  "approval_outcome", "source", "rule_id", "risk_level", "risk_score", "reasoning", "exec_status", "exec_target", "gt_label"]


def _where(q: str | None, decision: str | None, tool: str | None, rule_id: str | None, run_id: str | None,
           experiment_id: str | None, gt_label: str | None) -> tuple[str, list[Any]]:
    clause = " WHERE 1=1"
    params: list[Any] = []
    for column, value in (("d.final_decision", decision), ("a.tool", tool), ("d.rule_id", rule_id), ("a.run_id", run_id),
                          ("r.experiment_id", experiment_id), ("a.gt_label", gt_label)):
        if value:
            clause += f" AND {column}=?"
            params.append(value)
    if q:
        # Escape LIKE wildcards so a search for "%" or "_" means those literal characters.
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        clause += (" AND (a.args LIKE ? ESCAPE '\\' OR d.reasoning LIKE ? ESCAPE '\\' OR a.tool LIKE ? ESCAPE '\\'"
                   " OR r.scenario_id LIKE ? ESCAPE '\\' OR d.rule_id LIKE ? ESCAPE '\\')")
        params.extend([like] * 5)
    return clause, params


@router.get("")
def search(q: str | None = None, decision: str | None = None, tool: str | None = None, rule_id: str | None = None,
           run_id: str | None = None, experiment_id: str | None = None, gt_label: str | None = None,
           limit: int = Query(default=50, ge=1, le=500), offset: int = Query(default=0, ge=0),
           state: AppState = Depends(get_state)) -> dict[str, Any]:
    clause, params = _where(q, decision, tool, rule_id, run_id, experiment_id, gt_label)
    total = state.db.scalar(f"SELECT COUNT(*) {BASE}{clause}", params)
    items = state.db.query(f"SELECT {COLUMNS} {BASE}{clause} ORDER BY d.decided_at DESC, a.seq DESC LIMIT ? OFFSET ?", [*params, limit, offset])
    return {"total": total, "items": items}


@router.get("/export")
def export(format: Literal["csv", "json"] = "csv", q: str | None = None, decision: str | None = None, tool: str | None = None,
           rule_id: str | None = None, run_id: str | None = None, experiment_id: str | None = None, gt_label: str | None = None,
           state: AppState = Depends(get_state)) -> Response:
    clause, params = _where(q, decision, tool, rule_id, run_id, experiment_id, gt_label)
    rows = state.db.query(f"SELECT {COLUMNS} {BASE}{clause} ORDER BY d.decided_at DESC LIMIT 100000", params)
    headers = {"Content-Disposition": f'attachment; filename="boundaryguard-audit.{format}"'}
    if format == "json":
        return Response(to_json(rows), media_type="application/json", headers=headers)
    return PlainTextResponse(to_csv(rows, EXPORT_COLUMNS), media_type="text/csv", headers=headers)


@router.get("/repeated")
def repeated(experiment_id: str | None = None, limit: int = Query(default=50, ge=1, le=500), state: AppState = Depends(get_state)) -> list[dict[str, Any]]:
    clause = " AND r.experiment_id=?" if experiment_id else ""
    params: list[Any] = [experiment_id] if experiment_id else []
    return state.db.query(
        f"""SELECT a.run_id, a.fingerprint, a.tool, MIN(a.args) AS args, COUNT(*) AS denials, r.configuration, r.scenario_id, r.termination_reason
            FROM actions a JOIN decisions d ON d.action_id=a.id JOIN runs r ON r.id=a.run_id
            WHERE d.final_decision!='ALLOW' AND COALESCE(d.approval_outcome,'')!='approved' AND a.fingerprint IS NOT NULL{clause}
            GROUP BY a.run_id, a.fingerprint HAVING COUNT(*)>1 ORDER BY denials DESC, MAX(d.decided_at) DESC LIMIT ?""",
        [*params, limit],
    )


@router.get("/verify/{run_id}")
def verify(run_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    if not state.db.scalar("SELECT 1 FROM runs WHERE id=?", (run_id,)):
        raise HTTPException(404, "Run not found.")
    return verify_chain(state.db, run_id)
