"use client";

import { useCallback, useEffect, useState } from "react";

export const API = "/api/v1";

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

/** Long enough for the slowest legitimate request (analytics over 12,750 runs), short enough that a hung backend is reported. */
const TIMEOUT_MS = 30_000;

/** FastAPI validation errors arrive as a list of {loc, msg}. Turn them into one readable sentence per field. */
function describe(detail: unknown, status: number): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => {
      const loc = Array.isArray(item?.loc) ? item.loc.filter((p: unknown) => p !== "body" && typeof p !== "number").join(" › ") : "";
      const msg = String(item?.msg ?? "is invalid").replace(/^Value error, /, "");
      return loc ? `${loc.replaceAll("_", " ")}: ${msg}` : msg;
    }).join(" ");
  }
  return `Request failed (${status}).`;
}

export async function api<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const method = init?.method ?? "GET";
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(`${API}${path}`, {
      method,
      headers: method === "GET" ? undefined : { "Content-Type": "application/json" },
      body: method === "GET" || method === "DELETE" ? undefined : JSON.stringify(init?.body ?? {}),
      cache: "no-store",
      signal: controller.signal,
    });
  } catch (err) {
    window.clearTimeout(timer);
    if ((err as Error).name === "AbortError") throw new ApiError("The backend did not answer in time. Try again in a moment.", 408);
    throw new ApiError("Cannot reach the BoundaryGuard backend.", 0);
  }
  window.clearTimeout(timer);
  if (!response.ok) {
    let detail = `Request failed (${response.status}).`;
    try {
      detail = describe((await response.json()).detail, response.status);
    } catch {
      // The Next.js proxy answers 500 with an HTML page when the backend is down.
      if (response.status >= 500) detail = "Cannot reach the BoundaryGuard backend.";
    }
    throw new ApiError(detail, response.status);
  }
  if (response.status === 204) return undefined as T;
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError("The backend sent a response that could not be read.", response.status);
  }
}

export interface Polled<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  refresh: () => void;
}

/** Fetch a path and optionally keep polling it. A null path pauses fetching. */
export function usePoll<T>(path: string | null, intervalMs = 0): Polled<T> {
  const [state, setState] = useState<{ path: string | null; data: T | null; error: ApiError | null }>({ path: null, data: null, error: null });
  const [generation, setGeneration] = useState(0);
  const refresh = useCallback(() => setGeneration((g) => g + 1), []);

  useEffect(() => {
    if (path === null) return;
    let cancelled = false;
    const load = () => {
      api<T>(path).then(
        (data) => { if (!cancelled) setState({ path, data, error: null }); },
        (error: ApiError) => {
          // Keep the last good data on screen when a later poll fails.
          if (!cancelled) setState((prev) => ({ path, data: prev.path === path ? prev.data : null, error }));
        },
      );
    };
    load();
    const timer = intervalMs > 0
      ? window.setInterval(() => { if (!document.hidden) load(); }, intervalMs)
      : undefined;
    return () => {
      cancelled = true;
      if (timer) window.clearInterval(timer);
    };
  }, [path, intervalMs, generation]);

  // State from a previous path is never shown under the new one.
  const current = state.path === path;
  return { data: current ? state.data : null, error: current ? state.error : null, loading: path !== null && !current, refresh };
}

// ---- response types ---------------------------------------------------------

export interface MetricRow {
  configuration: string;
  category: string;
  split: string;
  metric: string;
  numerator: number | null;
  denominator: number | null;
  value: number | null;
  scenario_numerator: number | null;
  scenario_denominator: number | null;
  ci_low: number | null;
  ci_high: number | null;
  extra: Record<string, unknown>;
}

export interface KpiDefinition {
  metric: string;
  label: string;
  kind: "rate" | "latency_us";
  better: "higher" | "lower";
  target: number;
  target_label: string;
  definition: string;
}

export interface Manifest {
  suite_hash: string;
  source_hash: string;
  policy_set_hash: string;
  scenario_ids: string[];
  agent_provider: string;
  assessor: string;
  seed: number;
  repeats: number;
  python: string;
  platform: string;
  provenance: string;
  suite?: string;
  model?: { version: string; bundle_sha256: string; trained_at: string } | null;
}

export interface Experiment {
  id: string;
  name: string;
  status: string;
  config: Record<string, unknown>;
  manifest: Manifest;
  total_runs: number;
  completed_runs: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Compare {
  experiment: Pick<Experiment, "id" | "name" | "status" | "total_runs" | "completed_runs" | "created_at" | "finished_at">;
  manifest: Manifest;
  split: string;
  configurations: { id: string; name: string; use_policy: boolean; use_context: boolean; use_history: boolean }[];
  kpis: KpiDefinition[];
  research_metrics: Omit<KpiDefinition, "target" | "target_label">[];
  splits: string[];
  cluster_comparisons: { first: string; second: string; clusters: number; prevention_difference: number | null; prevention_ci95: [number, number] | null;
    false_block_difference: number | null; false_block_ci95: [number, number] | null }[];
  overall: Record<string, Record<string, MetricRow>>;
  categories: Record<string, Record<string, Record<string, MetricRow>>>;
  ablation: { configuration: string; label: string; metrics: Record<string, MetricRow | null> }[];
  significance: { first: string; second: string; outcome: string; scenarios: number; only_first: number; only_second: number; p_value: number }[];
}

export interface Run {
  id: string;
  experiment_id: string | null;
  scenario_id: string | null;
  category: string | null;
  split: string | null;
  configuration: string;
  objective: string;
  status: string;
  termination_reason: string | null;
  error: string | null;
  final_message: string | null;
  task_completed: boolean | null;
  security_pass: boolean | null;
  agent_provider: string;
  agent_model: string | null;
  assessor: string | null;
  approval_mode: string;
  canary_exposed: boolean;
  canary_exfiltrated: boolean;
  step_count: number;
  started_at: string;
  finished_at: string | null;
  blocked_actions?: number;
}

export interface Signal {
  name: string;
  weight: number;
  detail: string;
  hard: boolean;
}

export interface TraceAction {
  action_id: string;
  seq: number;
  tool: string;
  args: Record<string, unknown>;
  canonical: { target?: string; real_virtual_path?: string | null; virtual_path?: string | null; url_host?: string | null; url_path?: string | null } | null;
  gt_label: string | null;
  proposed_at: string;
  policy_verdict: string | null;
  final_decision: string | null;
  source: string | null;
  rule_id: string | null;
  risk_level: string | null;
  risk_score: number | null;
  reasoning: string | null;
  signals: Signal[] | null;
  terminate: boolean | null;
  approval_outcome: string | null;
  assessor: string | null;
  assessor_fallback: boolean | null;
  policy_latency_us: number | null;
  context_latency_us: number | null;
  exec_status: string | null;
  exec_target: string | null;
  result_summary: string | null;
  contains_canary: boolean | null;
  sink: boolean | null;
  approval_id: string | null;
  approval_status: string | null;
}

export interface Health {
  status: string;
  database: boolean;
  llm: { ollama: boolean; openai_compatible: boolean };
  deterministic_guard: boolean;
  experiments_active: number;
  live_runs_active: number;
  ml_model?: { available: boolean; version: string | null; problem: string | null };
}

export interface SecurityEvent {
  action_id: string;
  run_id: string;
  seq: number;
  tool: string;
  args: Record<string, unknown>;
  final_decision: string;
  approval_outcome: string | null;
  source: string;
  rule_id: string | null;
  risk_level: string | null;
  reasoning: string;
  decided_at: string;
  configuration: string;
  scenario_id: string | null;
  agent_provider: string;
  gt_label: string | null;
}

export interface Overview {
  runs: {
    total: number;
    experiment_runs: number;
    live_runs: number;
    by_experiment: { id: string; name: string; status: string; total_runs: number; recorded_runs: number; created_at: string }[];
  };
  approvals_pending: number;
  human_overrides: number;
  scenarios: number;
  recent_events: SecurityEvent[];
  audit_integrity: { runs_checked: number; runs_valid: number };
  latest_experiment: { id: string; name: string; status: string; total_runs: number; finished_at: string; manifest: Manifest } | null;
  latest_metrics: Pick<MetricRow, "configuration" | "split" | "metric" | "numerator" | "denominator" | "value">[];
  health: Health;
}

export interface EvalMetrics {
  n: number;
  threshold: number;
  precision: number;
  recall: number;
  f1: number;
  pr_auc: number | null;
  roc_auc: number | null;
  false_positive_rate: number;
  false_negative_rate: number;
  confusion: { tn: number; fp: number; fn: number; tp: number };
  brier: number | null;
  ece: number;
  bootstrap_by_family?: { recall_ci95: [number, number] | null; false_positive_rate_ci95: [number, number] | null; pr_auc_ci95: [number, number] | null; groups: number };
  by_category?: Record<string, { actions: number; unauthorized: number; caught: number; legitimate: number; legitimate_flagged: number }>;
}

export interface ModelProfile {
  feature_names: string[];
  text_best_params: Record<string, unknown>;
  text_cv_pr_auc: number;
  structured_candidates: Record<string, { best_params: Record<string, unknown>; cv_pr_auc: number; validation_pr_auc: number }>;
  structured_selected: string;
  structured_importances: Record<string, number>;
  thresholds: { review: number; block: number };
  validation: Record<string, EvalMetrics>;
  test?: Record<string, EvalMetrics>;
}

export interface ModelInfo {
  available: boolean;
  problem: string | null;
  version: string | null;
  trained_at: string | null;
  bundle_sha256: string | null;
  metadata: {
    version: string;
    trained_at: string;
    dataset_sha256: string;
    test_evaluated: boolean;
    library_versions: Record<string, string>;
    data: Record<string, { records: number; unauthorized: number; legitimate: number; projects: string[]; families: number }>;
    profiles: Record<string, ModelProfile>;
    interpretation: string;
    config: { seed: number; cv_folds: number; review_max_fpr: number; block_max_fpr: number; threshold_rule: string };
  } | null;
}

export interface HeuristicComparison {
  experiment: { id: string; name: string } | null;
  rows: { label: string; heuristic: string; ml: string; actions: number }[];
}

export interface Policy {
  name: string;
  allowed_tools: string[];
  prohibited_tools: string[];
  read_paths: string[];
  write_paths: string[];
  protected_paths: string[];
  prohibited_content: string[];
  approval_tools: string[];
  approval_paths: string[];
  network: { enabled: boolean; allowed_hosts: string[]; allowed_methods: string[] };
  limits: { max_steps: number; max_calls_per_tool: number; max_write_bytes: number };
  retry: { same_action_denials: number; total_denials: number };
}

export interface PolicyRow {
  id: string;
  name: string;
  version: number;
  body: Policy;
  hash: string;
  read_only: boolean;
  /** SQLite stores 1 or 0; benchmark rows send true. Only one version per name is active. */
  active: boolean | number;
  created_at: string | null;
}

/** A pending approval from GET /approvals. */
export interface Approval {
  id: string;
  run_id: string;
  action_id: string;
  status: string;
  created_at: string;
  tool: string;
  args: Record<string, unknown> | string | null;
  reasoning: string | null;
  risk_level: string | null;
  objective: string;
}

export interface Tool {
  name: string;
  description: string;
  access: string;
  simulated: boolean;
}

export interface ScenarioSummary {
  id: string;
  category: string;
  split: string;
  title: string;
  objective: string;
  fixture: string;
  policy: string;
}

export interface ProviderOption {
  id: string;
  label: string;
  available: boolean;
  model: string | null;
  note: string;
}

export interface Providers {
  agents: ProviderOption[];
  assessors: ProviderOption[];
  fixtures: string[];
}

export interface ExperimentResult {
  run_id: string;
  scenario_id: string;
  title: string | null;
  category: string;
  split: string;
  configuration: string;
  repeat_index: number;
  status: string;
  termination_reason: string | null;
  task_completed: boolean | null;
  security_pass: boolean | null;
  canary_exfiltrated: boolean;
  unauthorized_attempted: number;
  unauthorized_executed: number;
  legitimate_blocked: number;
  actions_total: number;
  error: string | null;
}

export interface AuditItem extends SecurityEvent {
  fingerprint: string | null;
  risk_score: number | null;
  assessor: string | null;
  assessor_fallback: boolean | null;
  policy_latency_us: number | null;
  context_latency_us: number | null;
  exec_status: string | null;
  exec_target: string | null;
  experiment_id: string | null;
}

export interface RepeatedViolation {
  run_id: string;
  fingerprint: string;
  tool: string;
  args: Record<string, unknown> | string;
  denials: number;
  configuration: string;
  scenario_id: string | null;
  termination_reason: string | null;
}
