PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    body TEXT NOT NULL,
    hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(name, version);

CREATE TABLE IF NOT EXISTS scenarios (
    id TEXT PRIMARY KEY,
    suite_hash TEXT NOT NULL,
    category TEXT NOT NULL,
    split TEXT NOT NULL,
    title TEXT NOT NULL,
    definition TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    config TEXT NOT NULL,
    manifest TEXT NOT NULL DEFAULT '{}',
    total_runs INTEGER NOT NULL DEFAULT 0,
    completed_runs INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    experiment_id TEXT REFERENCES experiments(id) ON DELETE CASCADE,
    scenario_id TEXT,
    category TEXT,
    split TEXT,
    configuration TEXT NOT NULL,
    repeat_index INTEGER NOT NULL DEFAULT 0,
    seed INTEGER NOT NULL DEFAULT 0,
    objective TEXT NOT NULL,
    status TEXT NOT NULL,
    termination_reason TEXT,
    error TEXT,
    final_message TEXT,
    task_completed INTEGER,
    completion_detail TEXT,
    security_pass INTEGER,
    expected TEXT,
    agent_provider TEXT NOT NULL,
    agent_model TEXT,
    assessor TEXT,
    approval_mode TEXT NOT NULL DEFAULT 'auto_deny',
    canary_exposed INTEGER NOT NULL DEFAULT 0,
    canary_exfiltrated INTEGER NOT NULL DEFAULT 0,
    workspace_changed INTEGER NOT NULL DEFAULT 0,
    unledgered_changes TEXT,
    step_count INTEGER NOT NULL DEFAULT 0,
    policy_hash TEXT,
    policy_body TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_experiment ON runs(experiment_id, configuration);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    canonical TEXT,
    fingerprint TEXT,
    gt_label TEXT,
    proposed_at TEXT NOT NULL,
    UNIQUE (run_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_actions_tool ON actions(tool);

CREATE TABLE IF NOT EXISTS decisions (
    action_id TEXT PRIMARY KEY REFERENCES actions(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    policy_verdict TEXT,
    final_decision TEXT NOT NULL,
    source TEXT NOT NULL,
    rule_id TEXT,
    risk_level TEXT,
    risk_score REAL,
    reasoning TEXT NOT NULL,
    signals TEXT NOT NULL DEFAULT '[]',
    terminate INTEGER NOT NULL DEFAULT 0,
    approval_outcome TEXT,
    assessor TEXT,
    assessor_fallback INTEGER NOT NULL DEFAULT 0,
    policy_latency_us REAL,
    context_latency_us REAL,
    decided_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_final ON decisions(final_decision);
CREATE INDEX IF NOT EXISTS idx_decisions_run ON decisions(run_id);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    resolver TEXT,
    note TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

CREATE TABLE IF NOT EXISTS tool_executions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    target TEXT,
    status TEXT NOT NULL,
    bytes INTEGER NOT NULL DEFAULT 0,
    result_summary TEXT,
    contains_canary INTEGER NOT NULL DEFAULT 0,
    sink INTEGER NOT NULL DEFAULT 0,
    executed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exec_run ON tool_executions(run_id);
CREATE INDEX IF NOT EXISTS idx_exec_action ON tool_executions(action_id);

CREATE TABLE IF NOT EXISTS audit_events (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);

CREATE TABLE IF NOT EXISTS experiment_metrics (
    experiment_id TEXT NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    configuration TEXT NOT NULL,
    category TEXT NOT NULL,
    split TEXT NOT NULL,
    metric TEXT NOT NULL,
    numerator REAL,
    denominator REAL,
    value REAL,
    scenario_numerator INTEGER,
    scenario_denominator INTEGER,
    ci_low REAL,
    ci_high REAL,
    extra TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (experiment_id, configuration, category, split, metric)
);
