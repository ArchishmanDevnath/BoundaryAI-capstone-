# Database Schema

SQLite in WAL mode with one connection per thread and foreign keys on. The authoritative definition is `backend/boundaryguard/db/schema.sql`.

```
policies                    experiments 1--* runs 1--* actions 1--1 decisions
                                                 |          |--0..1 approvals
                                                 |          |--0..1 tool_executions
experiment_metrics *--1 experiments              |--* audit_events
scenarios (loaded from YAML)                     |--* tool_executions (ledger)
```

| Table | Purpose | Key columns |
|---|---|---|
| `policies` | Custom policies, versioned by row | `id`, `name`, `version`, `body` (JSON), `hash`, `active`, `created_at` |
| `scenarios` | Snapshot of the benchmark suite | `id`, `suite_hash`, `category`, `split`, `title`, `definition` (JSON) |
| `experiments` | One benchmark execution | `id`, `name`, `status`, `config` (JSON), `manifest` (JSON), `total_runs`, `completed_runs`, `error`, timestamps |
| `runs` | One scenario in one configuration | `id`, `experiment_id` (nullable for live runs), `scenario_id`, `category`, `split`, `configuration`, `repeat_index`, `seed`, `objective`, `status`, `termination_reason`, `task_completed`, `completion_detail`, `security_pass`, `agent_provider`, `agent_model`, `assessor`, `canary_exposed`, `canary_exfiltrated`, `workspace_changed`, `unledgered_changes`, `step_count`, `policy_hash`, timestamps |
| `actions` | Every proposal | `id`, `run_id`, `seq`, `tool`, `args`, `canonical`, `fingerprint`, `gt_label`, `proposed_at` |
| `decisions` | One per action | `action_id`, `policy_verdict`, `final_decision`, `source`, `rule_id`, `risk_level`, `risk_score`, `reasoning`, `signals`, `terminate`, `approval_outcome`, `assessor`, `assessor_fallback`, `policy_latency_us`, `context_latency_us`, `decided_at` |
| `approvals` | Human review queue | `id`, `action_id`, `run_id`, `status`, `resolver`, `note`, `created_at`, `resolved_at` |
| `tool_executions` | Ledger written by tools | `id`, `run_id`, `action_id`, `tool`, `target`, `status`, `bytes`, `result_summary`, `contains_canary`, `sink`, `executed_at` |
| `audit_events` | Hash-chained log | `run_id`, `seq`, `event_type`, `payload`, `prev_hash`, `hash`, `created_at` |
| `experiment_metrics` | Computed KPIs | `experiment_id`, `configuration`, `category`, `split`, `metric`, `numerator`, `denominator`, `value`, `scenario_numerator`, `scenario_denominator`, `ci_low`, `ci_high`, `extra` |

`final_decision` is `ALLOW`, `BLOCK` or `APPROVAL_REQUIRED`. When approval is resolved, `approval_outcome` holds `approved`, `denied` or `timeout`. An action executes only if the decision is `ALLOW` or approval was granted.

The ML assessor and the external benchmark needed no schema change:

- **Configurations:** `runs.configuration` can also hold `D` and `E`.
- **Categories and splits:** `runs.category` can hold `injecagent_direct_harm` or `injecagent_data_stealing`, and `runs.split` can hold `external`.
- **ML decisions:** `decisions.assessor` holds `ml-stateless:<model version>` or `ml-stateful:<model version>`, and `assessor_fallback=1` marks a fail-closed block.
- **New metrics:** `experiment_metrics.metric` gains `false_negative_rate`, `precision`, `recall`, `f1`, `pr_auc` and `decision_latency_mean_us`. Experiments recorded before these existed simply have no such rows.
- **Experiment manifests:** these record the scenario suite and the model version and bundle hash.

Model bundles and datasets live in files, not in the database: `backend/models/` and `data/`.
