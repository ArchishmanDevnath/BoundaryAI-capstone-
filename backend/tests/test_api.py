"""API integration tests over a real app, database and worker threads."""
from __future__ import annotations

import csv
import io
import time

import pytest
from fastapi.testclient import TestClient

from boundaryguard.config import load_settings
from boundaryguard.db.connection import utcnow
from boundaryguard.main import create_app

JSON = {"Content-Type": "application/json"}


@pytest.fixture
def client(tmp_path):
    settings = load_settings(db_path=str(tmp_path / "api.sqlite3"), runs_dir=str(tmp_path / "runs"),
                             ollama_url="http://127.0.0.1:9", approval_timeout_s=10)
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def wait_for(fn, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("Timed out waiting.")


def run_experiment(client, **body):
    body = {"name": "t", "scenario_ids": ["pv01_read_env", "b03_add_docstring", "ru01_exact_retry"], **body}
    response = client.post("/api/v1/experiments", json=body)
    assert response.status_code == 202, response.text
    experiment_id = response.json()["experiment_id"]
    wait_for(lambda: client.get(f"/api/v1/experiments/{experiment_id}").json()["status"] in ("completed", "failed"))
    return experiment_id


def test_empty_database_gives_real_zeros_not_sample_data(client):
    data = client.get("/api/v1/overview").json()
    assert data["runs"] == {"total": 0, "experiment_runs": 0, "live_runs": 0, "by_experiment": []}
    assert data["recent_events"] == [] and data["latest_experiment"] is None and data["latest_metrics"] == []
    assert client.get("/api/v1/analytics/compare").status_code == 404
    assert client.get("/api/v1/audit").json() == {"total": 0, "items": []}


def test_health_reports_llm_down_with_guard_up(client):
    data = client.get("/api/v1/health").json()
    assert data["status"] == "ok" and data["deterministic_guard"] is True and data["llm"]["ollama"] is False


def test_catalog_endpoints(client):
    assert {t["name"] for t in client.get("/api/v1/tools").json()} >= {"read_file", "shell_exec"}
    assert [c["id"] for c in client.get("/api/v1/configurations").json()] == ["A", "B", "RC", "C", "D", "E"]
    providers = client.get("/api/v1/providers").json()
    assert {a["id"]: a["available"] for a in providers["agents"]}["scripted"] is True
    assert "calc_lib" in providers["fixtures"]
    assert len(client.get("/api/v1/scenarios").json()) >= 40
    assert all(s["category"] == "benign" for s in client.get("/api/v1/scenarios", params={"category": "benign"}).json())
    assert client.get("/api/v1/scenarios/pv01_read_env").json()["id"] == "pv01_read_env"
    assert client.get("/api/v1/scenarios/nope").status_code == 404


def test_writes_require_json(client):
    assert client.post("/api/v1/experiments", content="name=x", headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code == 415
    assert client.post("/api/v1/experiments/abc/cancel").status_code == 415
    assert client.post("/api/v1/approvals/abc/resolve", content="{}", headers={"Content-Type": "text/plain"}).status_code == 415


def test_untrusted_host_header_is_rejected(client):
    assert client.get("/api/v1/health", headers={"Host": "evil.test"}).status_code == 400


def test_cors_only_allows_the_frontend(client):
    good = client.options("/api/v1/experiments", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
    bad = client.options("/api/v1/experiments", headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "POST"})
    assert good.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "access-control-allow-origin" not in bad.headers


def test_experiment_flow_uses_real_records(client):
    experiment_id = run_experiment(client, configurations=["A", "B", "C"])
    experiment = client.get(f"/api/v1/experiments/{experiment_id}").json()
    assert experiment["status"] == "completed" and experiment["completed_runs"] == experiment["total_runs"] == 9

    results = client.get(f"/api/v1/experiments/{experiment_id}/runs").json()
    assert len(results) == 9
    pv_a = next(r for r in results if r["scenario_id"] == "pv01_read_env" and r["configuration"] == "A")
    pv_b = next(r for r in results if r["scenario_id"] == "pv01_read_env" and r["configuration"] == "B")
    assert pv_a["unauthorized_executed"] == 1 and pv_b["unauthorized_executed"] == 0

    compare = client.get("/api/v1/analytics/compare", params={"experiment_id": experiment_id}).json()
    assert [c["id"] for c in compare["configurations"]] == ["A", "B", "C"]
    assert compare["overall"]["unauthorized_execution_rate"]["B"]["value"] == 0
    assert compare["overall"]["false_block_rate"]["A"]["value"] is None
    assert {k["metric"] for k in compare["kpis"]} >= {"attack_prevention_rate", "policy_bypass_rate"}
    assert "by construction" in compare["manifest"]["provenance"]
    assert compare["significance"][0]["first"] == "B"

    overview = client.get("/api/v1/overview").json()
    assert overview["runs"]["total"] == overview["runs"]["experiment_runs"] + overview["runs"]["live_runs"]
    assert overview["audit_integrity"]["runs_checked"] == overview["audit_integrity"]["runs_valid"] > 0
    assert overview["latest_experiment"]["id"] == experiment_id and overview["latest_metrics"]
    assert overview["recent_events"]


def test_metrics_filter_and_export(client):
    experiment_id = run_experiment(client, configurations=["B"])
    rows = client.get(f"/api/v1/experiments/{experiment_id}/metrics", params={"category": "benign", "split": "dev"}).json()
    assert rows and all(r["category"] == "benign" and r["split"] == "dev" for r in rows)
    exported = client.get(f"/api/v1/experiments/{experiment_id}/export", params={"format": "csv"})
    assert "attachment" in exported.headers["content-disposition"]
    assert len(list(csv.DictReader(io.StringIO(exported.text)))) == 3
    as_json = client.get(f"/api/v1/experiments/{experiment_id}/export", params={"format": "json"}).json()
    assert as_json["experiment"]["id"] == experiment_id and as_json["metrics"]


def test_live_trace_with_incremental_polling(client):
    response = client.post("/api/v1/runs", json={"scenario_id": "pi01_readme_env_exfil", "configuration": "C"})
    assert response.status_code == 202
    run_id = response.json()["run_id"]
    wait_for(lambda: client.get(f"/api/v1/runs/{run_id}").json()["status"] != "running")
    trace = client.get(f"/api/v1/runs/{run_id}/trace").json()
    assert [a["seq"] for a in trace["actions"]] == sorted(a["seq"] for a in trace["actions"])
    denied = [a for a in trace["actions"] if a["final_decision"] == "BLOCK"]
    assert denied and denied[0]["rule_id"] == "PATH_PROTECTED" and denied[0]["exec_status"] is None
    later = client.get(f"/api/v1/runs/{run_id}/trace", params={"after_seq": 1}).json()
    assert [a["seq"] for a in later["actions"]] == [a["seq"] for a in trace["actions"]][1:]
    assert client.get(f"/api/v1/audit/verify/{run_id}").json()["valid"] is True


def test_run_validation(client):
    assert client.post("/api/v1/runs", json={"configuration": "C"}).status_code == 422
    assert client.post("/api/v1/runs", json={"scenario_id": "nope"}).status_code == 404
    assert client.post("/api/v1/runs", json={"scenario_id": "b01_fix_add", "configuration": "Z"}).status_code == 422
    assert client.post("/api/v1/runs", json={"objective": "x", "fixture": "../../etc", "agent_provider": "ollama", "policy_id": "benchmark:project_standard"}).status_code == 422
    assert client.get("/api/v1/runs/nope").status_code == 404
    assert client.get("/api/v1/runs/nope/trace").status_code == 404


def test_custom_run_with_unavailable_llm_is_reported_as_error(client):
    response = client.post("/api/v1/runs", json={"objective": "Fix src/calc.py", "fixture": "calc_lib", "agent_provider": "ollama",
                                                 "policy_id": "benchmark:project_standard", "configuration": "B"})
    run_id = response.json()["run_id"]
    run = wait_for(lambda: (r := client.get(f"/api/v1/runs/{run_id}").json())["status"] != "running" and r)
    assert run["status"] == "error" and "LLMError" in run["error"]


def test_human_approval_through_the_api(client):
    response = client.post("/api/v1/runs", json={"scenario_id": "ru06_irrelevant_write", "configuration": "C", "approval_mode": "human"})
    run_id = response.json()["run_id"]
    pending = wait_for(lambda: client.get("/api/v1/approvals").json())
    assert pending[0]["run_id"] == run_id and pending[0]["tool"] == "write_file"
    resolved = client.post(f"/api/v1/approvals/{pending[0]['id']}/resolve", json={"approve": True, "note": "ok"})
    assert resolved.json()["status"] == "approved"
    assert client.post(f"/api/v1/approvals/{pending[0]['id']}/resolve", json={"approve": False}).status_code == 409
    wait_for(lambda: client.get(f"/api/v1/runs/{run_id}").json()["status"] != "running")
    actions = client.get(f"/api/v1/runs/{run_id}/trace").json()["actions"]
    assert actions[0]["approval_outcome"] == "approved" and actions[0]["exec_status"] == "ok"


def test_denied_approval_does_not_execute(client):
    run_id = client.post("/api/v1/runs", json={"scenario_id": "ru06_irrelevant_write", "configuration": "C", "approval_mode": "human"}).json()["run_id"]
    pending = wait_for(lambda: client.get("/api/v1/approvals").json())
    client.post(f"/api/v1/approvals/{pending[0]['id']}/resolve", json={"approve": False})
    wait_for(lambda: client.get(f"/api/v1/runs/{run_id}").json()["status"] != "running")
    action = client.get(f"/api/v1/runs/{run_id}/trace").json()["actions"][0]
    assert action["approval_outcome"] == "denied" and action["exec_status"] is None


def test_policy_crud_and_versioning(client):
    body = {"allowed_tools": ["read_file"], "read_paths": ["/project/**"]}
    created = client.post("/api/v1/policies", json={"name": "mine", "body": body})
    assert created.status_code == 201
    policy = created.json()
    assert policy["version"] == 1
    assert client.post("/api/v1/policies", json={"name": "mine", "body": body}).status_code == 409
    updated = client.put(f"/api/v1/policies/{policy['id']}", json={"name": "mine", "body": {**body, "protected_paths": ["**/.env"]}}).json()
    assert updated["version"] == 2 and updated["id"] != policy["id"] and updated["hash"] != policy["hash"]
    names = [p["name"] for p in client.get("/api/v1/policies").json()]
    assert names.count("mine") == 1 and "project_standard" in names
    assert client.delete(f"/api/v1/policies/{updated['id']}").status_code == 204
    assert client.delete(f"/api/v1/policies/{updated['id']}").status_code == 404


def test_benchmark_policies_are_read_only(client):
    body = {"name": "project_standard", "body": {"allowed_tools": ["shell_exec"]}}
    assert client.put("/api/v1/policies/benchmark:project_standard", json=body).status_code == 403
    assert client.delete("/api/v1/policies/benchmark:project_standard").status_code == 403
    assert client.get("/api/v1/policies/benchmark:project_standard").json()["read_only"] is True


@pytest.mark.parametrize("body", [
    {"allowed_tools": ["teleport"]},
    {"prohibited_content": ["("]},
    {"unknown_field": 1},
    {"limits": {"max_steps": 0}},
])
def test_invalid_policies_are_rejected(client, body):
    assert client.post("/api/v1/policies", json={"name": "bad", "body": body}).status_code == 422


@pytest.mark.parametrize("name", ["", "   ", "-leading-dash", "semi;colon", "x" * 81])
def test_policy_names_are_validated(client, name):
    response = client.post("/api/v1/policies", json={"name": name, "body": {"allowed_tools": ["read_file"]}})
    assert response.status_code == 422


def test_policy_name_is_trimmed_and_unique_ignoring_case(client):
    created = client.post("/api/v1/policies", json={"name": "  Team Policy  ", "body": {}}).json()
    assert created["name"] == "Team Policy"
    assert client.post("/api/v1/policies", json={"name": "team policy", "body": {}}).status_code == 409


def test_policy_cannot_take_a_benchmark_name(client):
    response = client.post("/api/v1/policies", json={"name": "Project_Standard", "body": {}})
    assert response.status_code == 409 and "benchmark" in response.json()["detail"]


@pytest.mark.parametrize("body,fragment", [
    ({"read_paths": ["src/**"]}, "must start with '/'"),
    ({"protected_paths": ["  "]}, "empty entries"),
    ({"network": {"enabled": True, "allowed_hosts": ["https://api.example.com/x"]}}, "not a host name"),
    ({"network": {"enabled": True, "allowed_hosts": ["10.0.0.1"]}}, "IP address"),
    ({"network": {"enabled": True, "allowed_methods": ["get"]}}, "not supported"),
])
def test_policy_rules_that_could_never_match_are_rejected_with_a_reason(client, body, fragment):
    response = client.post("/api/v1/policies", json={"name": "never-matches", "body": body})
    assert response.status_code == 422 and fragment in response.json()["detail"]


def test_every_benchmark_policy_can_be_copied(client):
    """Copying is how users start a custom policy, so the benchmark policies must pass the same validation."""
    for row in client.get("/api/v1/policies").json():
        if row["read_only"]:
            copy = client.post("/api/v1/policies", json={"name": f"copy-of-{row['name']}", "body": row["body"]})
            assert copy.status_code == 201, copy.json()


def test_stale_and_unchanged_policy_updates_are_refused(client):
    body = {"allowed_tools": ["read_file"], "read_paths": ["/project/**"]}
    v1 = client.post("/api/v1/policies", json={"name": "stale", "body": body}).json()
    assert client.put(f"/api/v1/policies/{v1['id']}", json={"name": "stale", "body": body}).status_code == 409  # nothing changed
    v2 = client.put(f"/api/v1/policies/{v1['id']}", json={"name": "stale", "body": {**body, "write_paths": ["/project/docs/**"]}}).json()
    stale = client.put(f"/api/v1/policies/{v1['id']}", json={"name": "stale", "body": {**body, "write_paths": ["/project/x/**"]}})
    assert stale.status_code == 409 and "no longer active" in stale.json()["detail"]
    assert client.get(f"/api/v1/policies/{v2['id']}").json()["active"]


def test_policy_history_and_restore(client):
    body = {"allowed_tools": ["read_file"], "read_paths": ["/project/**"]}
    v1 = client.post("/api/v1/policies", json={"name": "hist", "body": body}).json()
    v2 = client.put(f"/api/v1/policies/{v1['id']}", json={"name": "hist", "body": {**body, "allowed_tools": ["read_file", "list_dir"]}}).json()
    history = [p for p in client.get("/api/v1/policies", params={"include_inactive": True}).json() if p["name"] == "hist"]
    assert [p["version"] for p in history] == [2, 1] and [bool(p["active"]) for p in history] == [True, False]
    assert [p["name"] for p in client.get("/api/v1/policies").json()].count("hist") == 1

    response = client.post(f"/api/v1/policies/{v1['id']}/restore", json={})
    assert response.status_code == 200, response.text
    restored = response.json()
    assert restored["version"] == 3 and restored["hash"] == v1["hash"] and restored["active"]
    assert not client.get(f"/api/v1/policies/{v2['id']}").json()["active"]
    assert client.post(f"/api/v1/policies/{restored['id']}/restore", json={}).status_code == 409  # already active

    # A deactivated policy can be brought back, and its old versions are never rewritten.
    assert client.delete(f"/api/v1/policies/{restored['id']}").status_code == 204
    assert "hist" not in [p["name"] for p in client.get("/api/v1/policies").json()]
    back = client.post(f"/api/v1/policies/{restored['id']}/restore", json={}).json()
    assert back["version"] == 4 and back["active"]
    assert client.get(f"/api/v1/policies/{v1['id']}").json()["hash"] == v1["hash"]
    assert client.post("/api/v1/policies/benchmark:project_standard/restore", json={}).status_code == 403
    assert client.post("/api/v1/policies/missing/restore", json={}).status_code == 404


def test_a_restored_name_cannot_collide_with_a_new_policy(client):
    old = client.post("/api/v1/policies", json={"name": "reuse", "body": {}}).json()
    client.delete(f"/api/v1/policies/{old['id']}")
    newer = client.post("/api/v1/policies", json={"name": "reuse", "body": {"allowed_tools": ["read_file"]}}).json()
    restored = client.post(f"/api/v1/policies/{old['id']}/restore", json={}).json()
    # Restoring replaces the current version of the same name rather than creating two active policies.
    assert restored["active"] and not client.get(f"/api/v1/policies/{newer['id']}").json()["active"]
    assert [p["name"] for p in client.get("/api/v1/policies").json()].count("reuse") == 1


@pytest.mark.parametrize("payload", [{"name": "   "}, {"configurations": []}, {"categories": []}, {"scenario_ids": ["does_not_exist"]}])
def test_experiment_input_is_validated(client, payload):
    assert client.post("/api/v1/experiments", json=payload).status_code == 422


def test_custom_run_needs_a_real_objective(client):
    response = client.post("/api/v1/runs", json={"objective": "   ", "fixture": "calc_lib", "policy_id": "benchmark:project_standard",
                                                  "agent_provider": "ollama"})
    assert response.status_code == 422


def test_audit_search_filters_and_export(client):
    experiment_id = run_experiment(client, configurations=["B"])
    everything = client.get("/api/v1/audit", params={"experiment_id": experiment_id}).json()
    assert everything["total"] > 0
    blocked = client.get("/api/v1/audit", params={"decision": "BLOCK", "experiment_id": experiment_id}).json()
    assert blocked["total"] > 0 and all(i["final_decision"] == "BLOCK" for i in blocked["items"])
    assert all(".env" in i["args"]["path"] for i in client.get("/api/v1/audit", params={"q": ".env", "tool": "read_file"}).json()["items"])
    assert client.get("/api/v1/audit", params={"q": "%"}).json()["total"] <= everything["total"]
    assert client.get("/api/v1/audit", params={"q": "zzz-not-present"}).json()["total"] == 0
    paged = client.get("/api/v1/audit", params={"limit": 1, "offset": 1}).json()
    assert len(paged["items"]) == 1
    exported = client.get("/api/v1/audit/export", params={"format": "csv", "experiment_id": experiment_id})
    assert len(list(csv.DictReader(io.StringIO(exported.text)))) == everything["total"]
    repeated = client.get("/api/v1/audit/repeated", params={"experiment_id": experiment_id}).json()
    assert repeated and repeated[0]["scenario_id"] == "ru01_exact_retry" and repeated[0]["denials"] >= 3


def test_csv_export_neutralizes_formula_injection():
    from boundaryguard.api.state import safe_cell, to_csv
    assert safe_cell("=HYPERLINK('http://evil.test')").startswith("'=")
    assert safe_cell("+1") == "'+1" and safe_cell("@x") == "'@x" and safe_cell("normal") == "normal"
    assert "'=cmd" in to_csv([{"a": "=cmd"}], ["a"])


def test_cancel(client):
    response = client.post("/api/v1/experiments", json={"name": "c"})
    experiment_id = response.json()["experiment_id"]
    client.post(f"/api/v1/experiments/{experiment_id}/cancel", json={})
    final = wait_for(lambda: (e := client.get(f"/api/v1/experiments/{experiment_id}").json())["status"] in ("cancelled", "completed", "failed") and e, timeout=120)
    assert final["status"] == "cancelled" and final["completed_runs"] < final["total_runs"]
    assert client.post(f"/api/v1/experiments/{experiment_id}/cancel", json={}).status_code == 409


def test_trace_never_reveals_host_paths(client):
    run_id = client.post("/api/v1/runs", json={"scenario_id": "pi01_readme_env_exfil", "configuration": "A"}).json()["run_id"]
    wait_for(lambda: client.get(f"/api/v1/runs/{run_id}").json()["status"] != "running")
    assert "boundaryAI" not in client.get(f"/api/v1/runs/{run_id}/trace").text


def test_restart_marks_interrupted_work(tmp_path):
    from boundaryguard.db.connection import Database
    settings = load_settings(db_path=str(tmp_path / "r.sqlite3"), runs_dir=str(tmp_path / "runs"))
    db = Database(settings.db_path)
    db.execute("INSERT INTO runs (id, configuration, objective, status, agent_provider, started_at) VALUES ('r1','C','x','running','scripted',?)", (utcnow(),))
    db.execute("INSERT INTO experiments (id, name, status, config, created_at) VALUES ('e1','x','running','{}',?)", (utcnow(),))
    db.close()
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/runs/r1").json()["termination_reason"] == "interrupted"
        assert client.get("/api/v1/experiments/e1").json()["status"] == "failed"


def test_overview_run_counts_reconcile_with_experiment_records(client):
    """Regression: the Overview total looked wrong next to an experiment's own count, because it silently added
    every experiment and live run together. The parts must now add up, and each experiment must match its own page."""
    first = run_experiment(client, configurations=["B"])
    second = run_experiment(client, configurations=["A", "B"])
    overview = client.get("/api/v1/overview").json()
    runs = overview["runs"]
    assert runs["total"] == runs["experiment_runs"] + runs["live_runs"]
    assert runs["total"] == client.get("/api/v1/runs", params={"limit": 1}).json()["total"]
    for row in runs["by_experiment"]:
        detail = client.get(f"/api/v1/experiments/{row['id']}").json()
        assert row["recorded_runs"] == detail["total_runs"] == detail["completed_runs"]
        assert row["recorded_runs"] == len(client.get(f"/api/v1/experiments/{row['id']}/runs").json())
    assert overview["latest_experiment"]["id"] == second and first != second
    # Headline numbers are scoped to one experiment and agree with the analytics page.
    compare = client.get("/api/v1/analytics/compare", params={"experiment_id": second, "split": "all"}).json()
    row = next(m for m in overview["latest_metrics"] if m["configuration"] == "B" and m["split"] == "all" and m["metric"] == "attack_prevention_rate")
    assert row["value"] == compare["overall"]["attack_prevention_rate"]["B"]["value"]


def test_overview_events_exclude_the_unprotected_baseline(client):
    run_experiment(client, configurations=["A", "B"])
    assert all(e["configuration"] != "A" for e in client.get("/api/v1/overview").json()["recent_events"])


def test_overview_headline_ignores_experiments_run_with_another_model(client):
    """A post-hoc model's experiment must not appear as the system's headline result."""
    first = run_experiment(client, configurations=["B"])
    state = client.app.state.bg
    row = state.db.query_one("SELECT * FROM experiments WHERE id=?", (first,))
    import json as _json
    manifest = {**row["manifest"], "model": {"version": "ml-posthoc", "bundle_sha256": "x", "trained_at": "x"}}
    state.db.execute("INSERT INTO experiments (id, name, status, config, manifest, total_runs, completed_runs, created_at, finished_at)"
                     " VALUES ('posthoc', 'POST HOC', 'completed', '{}', ?, 0, 0, '2999-01-01', '2999-01-01')", (_json.dumps(manifest),))
    assert client.get("/api/v1/overview").json()["latest_experiment"]["id"] == first
    assert client.get("/api/v1/ml/heuristic-comparison").json()["experiment"] is None


def test_resolving_an_unknown_approval_is_not_found(client):
    response = client.post("/api/v1/approvals/does-not-exist/resolve", json={"approve": True})
    assert response.status_code == 404
