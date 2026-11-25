"""Per-run records: actions, decisions, the executor ledger and the hash-chained audit log."""
from __future__ import annotations

import hashlib
import uuid
from typing import Any

from ..db.connection import Database, to_json, utcnow
from ..models.core import CanonicalAction, GuardDecision


class AuditFailure(Exception):
    """A required audit write failed. The gateway must not execute the action."""


def _chain_hash(prev_hash: str, run_id: str, seq: int, event_type: str, payload_json: str, created_at: str) -> str:
    material = "|".join([prev_hash, run_id, str(seq), event_type, payload_json, created_at])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def genesis_hash(run_id: str) -> str:
    return hashlib.sha256(f"boundaryguard-genesis|{run_id}".encode()).hexdigest()


class RunRecorder:
    def __init__(self, db: Database, run_id: str, canaries: set[str] | None = None):
        self.db = db
        self.run_id = run_id
        self._canaries = canaries or set()
        self._seq = 0
        self._prev = genesis_hash(run_id)

    def _append(self, conn: Any, event_type: str, payload: dict[str, Any]) -> None:
        self._seq += 1
        created = utcnow()
        payload_json = to_json(payload)
        digest = _chain_hash(self._prev, self.run_id, self._seq, event_type, payload_json, created)
        conn.execute(
            "INSERT INTO audit_events (run_id, seq, event_type, payload, prev_hash, hash, created_at) VALUES (?,?,?,?,?,?,?)",
            (self.run_id, self._seq, event_type, payload_json, self._prev, digest, created),
        )
        self._prev = digest

    def event(self, event_type: str, payload: dict[str, Any]) -> None:
        with self.db.transaction() as conn:
            self._append(conn, event_type, payload)

    def record_proposal(self, seq: int, tool: str, args: Any, canonical: CanonicalAction | None) -> str:
        action_id = uuid.uuid4().hex
        canon_json = canonical.model_dump_json() if canonical else None
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO actions (id, run_id, seq, tool, args, canonical, fingerprint, proposed_at) VALUES (?,?,?,?,?,?,?,?)",
                (action_id, self.run_id, seq, tool, to_json(args), canon_json,
                 canonical.fingerprint if canonical else None, utcnow()),
            )
            self._append(conn, "proposal", {"action_id": action_id, "seq": seq, "tool": tool, "args": args})
        return action_id

    def record_decision(self, action_id: str, d: GuardDecision) -> None:
        """Write-ahead: this commits before the action can execute."""
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO decisions (action_id, run_id, policy_verdict, final_decision, source, rule_id, risk_level,"
                    " risk_score, reasoning, signals, terminate, assessor, assessor_fallback, policy_latency_us,"
                    " context_latency_us, decided_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (action_id, self.run_id, d.policy_verdict.value if d.policy_verdict else None, d.final.value, d.source,
                     d.rule_id, d.risk_level.value if d.risk_level else None, d.risk_score, d.reasoning,
                     to_json([s.model_dump() for s in d.signals]), int(d.terminate), d.assessor, int(d.assessor_fallback),
                     d.policy_latency_us, d.context_latency_us, utcnow()),
                )
                self._append(conn, "decision", {
                    "action_id": action_id, "final": d.final.value, "source": d.source, "rule_id": d.rule_id,
                    "risk_level": d.risk_level.value if d.risk_level else None, "reasoning": d.reasoning,
                })
        except Exception as exc:
            raise AuditFailure(str(exc)) from exc

    def record_approval_outcome(self, action_id: str, outcome: str, terminate: bool) -> None:
        try:
            with self.db.transaction() as conn:
                conn.execute("UPDATE decisions SET approval_outcome=?, terminate=? WHERE action_id=?",
                             (outcome, int(terminate), action_id))
                self._append(conn, "approval", {"action_id": action_id, "outcome": outcome})
        except Exception as exc:
            raise AuditFailure(str(exc)) from exc

    # Ledger interface used by the executor.
    def record(self, action_id: str, tool: str, target: str | None, status: str, n_bytes: int,
               summary: str, scanned_text: str, sink: bool) -> None:
        has_canary = any(c in scanned_text for c in self._canaries)
        try:
            with self.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO tool_executions (id, run_id, action_id, tool, target, status, bytes, result_summary,"
                    " contains_canary, sink, executed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (uuid.uuid4().hex, self.run_id, action_id, tool, target, status, n_bytes, summary,
                     int(has_canary), int(sink), utcnow()),
                )
                self._append(conn, "execution", {"action_id": action_id, "status": status, "target": target, "sink": sink})
        except Exception as exc:
            raise AuditFailure(str(exc)) from exc


def verify_chain(db: Database, run_id: str) -> dict[str, Any]:
    """Recompute the run's chain from stored text."""
    rows = db.conn.execute(
        "SELECT seq, event_type, payload, prev_hash, hash, created_at FROM audit_events WHERE run_id=? ORDER BY seq",
        (run_id,),
    ).fetchall()
    prev = genesis_hash(run_id)
    for index, row in enumerate(rows, start=1):
        if row["seq"] != index:
            return {"run_id": run_id, "valid": False, "events": len(rows), "first_bad_seq": index, "problem": "missing event"}
        if row["prev_hash"] != prev:
            return {"run_id": run_id, "valid": False, "events": len(rows), "first_bad_seq": row["seq"], "problem": "broken link"}
        digest = _chain_hash(prev, run_id, row["seq"], row["event_type"], row["payload"], row["created_at"])
        if digest != row["hash"]:
            return {"run_id": run_id, "valid": False, "events": len(rows), "first_bad_seq": row["seq"], "problem": "hash mismatch"}
        prev = digest
    return {"run_id": run_id, "valid": True, "events": len(rows), "first_bad_seq": None, "problem": None}
