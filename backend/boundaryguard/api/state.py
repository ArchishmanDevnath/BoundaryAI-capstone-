"""Shared application state: the database, settings and background workers."""
from __future__ import annotations

import csv
import io
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import Request

from ..config import Settings
from ..db.connection import Database, to_json, utcnow
from ..experiments.scenarios import load_scenarios, suite_hash
from ..llm import ChatClient, LLMError, build_client


class AppState:
    def __init__(self, settings: Settings, clients: dict[str, ChatClient] | None = None):
        self.settings = settings
        self.clients = clients
        self.db = Database(settings.db_path)
        # One experiment at a time keeps latency measurements clean. Live runs have their own workers,
        # so a person taking time over an approval cannot stall an experiment.
        self.experiment_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="bg-experiment")
        self.live_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="bg-live")
        self._llm_cache: dict[str, tuple[float, bool]] = {}
        self.sync_scenarios()
        self.recover_interrupted()

    def sync_scenarios(self) -> None:
        scenarios = load_scenarios()
        digest = suite_hash(scenarios)
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM scenarios")
            conn.executemany(
                "INSERT INTO scenarios (id, suite_hash, category, split, title, definition) VALUES (?,?,?,?,?,?)",
                [(s.id, digest, s.category, s.split, s.title, to_json(s.model_dump(mode="json"))) for s in scenarios],
            )

    def recover_interrupted(self) -> None:
        """A restart cannot resume a run. Report what was cut off instead of leaving it 'running' forever."""
        now = utcnow()
        self.db.execute("UPDATE runs SET status='error', termination_reason='interrupted', error='Server restarted during the run.',"
                        " finished_at=? WHERE status='running'", (now,))
        self.db.execute("UPDATE experiments SET status='failed', error='Server restarted during the experiment.', finished_at=?"
                        " WHERE status IN ('queued','running')", (now,))
        self.db.execute("UPDATE approvals SET status='timeout', resolved_at=? WHERE status='pending'", (now,))

    def llm_available(self, kind: str) -> bool:
        cached = self._llm_cache.get(kind)
        if cached and time.monotonic() - cached[0] < 15:
            return cached[1]
        try:
            client = self.clients[kind] if self.clients and kind in self.clients else build_client(kind, self.settings)
            available = client.available()
        except LLMError:
            available = False
        self._llm_cache[kind] = (time.monotonic(), available)
        return available

    def shutdown(self) -> None:
        self.experiment_pool.shutdown(wait=False, cancel_futures=True)
        self.live_pool.shutdown(wait=False, cancel_futures=True)
        self.db.close()


def get_state(request: Request) -> AppState:
    return request.app.state.bg


def safe_cell(value: Any) -> str:
    """Neutralize spreadsheet formula injection. Agent-controlled text ends up in these exports."""
    text = "" if value is None else str(value)
    if text and text[0] in "=+-@\t\r":
        return "'" + text
    return text


def to_csv(rows: list[dict[str, Any]], columns: list[str]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(to_json(row.get(c)) if isinstance(row.get(c), (dict, list)) else row.get(c)) for c in columns])
    return buffer.getvalue()
