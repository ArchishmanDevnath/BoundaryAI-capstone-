# API Specification

Base path `/api/v1`. JSON only. Errors use FastAPI's `{"detail": ...}` form. Interactive docs are at `/docs` while the backend runs.

## System

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Database status, ML model availability, LLM reachability, worker state |
| GET | `/overview` | Run accounting (per experiment and live, adding up to the total), approvals pending, human overrides of unauthorized labels, latest experiment metrics by split, recent stops in guarded configurations |
| GET | `/tools` | Tool catalog |
| GET | `/providers` | Agent providers and assessors with availability |
| GET | `/configurations` | Guard configurations and flags (A, B, RC, C, D, E) |
| GET | `/ml/model` | Active model: version, integrity, training data, selected models, thresholds, validation and test metrics |
| GET | `/ml/heuristic-comparison` | Paired decisions of C (`RC`) and D on the same actions, for the latest experiment containing both. Filters: `experiment_id`, `split` |

## Policies

| Method | Path | Purpose |
|---|---|---|
| GET | `/policies?include_inactive=false` | Active custom policies and the read-only benchmark policies. With `include_inactive=true`, every stored version, newest first per name |
| GET | `/policies/{id}` | One policy version, active or not |
| POST | `/policies` | Create. Body: `{ "name": str, "body": Policy }`. 201, 409 if the name is taken (case-insensitive) or reserved by a benchmark policy, 422 if invalid |
| PUT | `/policies/{id}` | Save as a new version, deactivating this one. 409 if this version is no longer active (stale edit) or nothing changed |
| POST | `/policies/{id}/restore` | Make an earlier or deactivated version current again, saved as a new version. 409 if it is already active |
| DELETE | `/policies/{id}` | Deactivate. 404 if no active policy has this id |

Policies are never physically deleted. Runs record the hash of the policy they used, so the version history stays intact.

Benchmark policies (`benchmark:<name>`) return 403 for every write.

Validation, in addition to the schema:

- **Names:** 1–80 characters after trimming. Unaccented letters, digits, spaces, `.`, `-` and `_`, starting with a letter or digit.
- **Tools:** must be known tools.
- **Path globs:** must start with `/` or `**`, so that they can match the sandbox's virtual paths.
- **Hosts:** must be lower-case host names: no scheme, port, path or IP address.
- **Methods:** must be one of `GET HEAD POST PUT PATCH DELETE`.
- **Content patterns:** must be valid regular expressions.

Errors carry a `detail` that names the field and says how to fix it.

## Scenarios

| Method | Path | Purpose |
|---|---|---|
| GET | `/scenarios` | Filters: `category`, `split` |
| GET | `/scenarios/{id}` | Full definition |

## Runs and trace

| Method | Path | Purpose |
|---|---|---|
| POST | `/runs` | Start a live run. Body: `scenario_id`, or `objective` + `fixture` + `policy_id`; plus `configuration`, `agent_provider`, `assessor`, `approval_mode` (`auto_deny` or `human`), `step_delay_ms`. Returns 202. |
| GET | `/runs` | Filters: `experiment_id`, `configuration`, `scenario_id`, `status`, `live_only`, `limit`, `offset` |
| GET | `/runs/{id}` | Run summary |
| GET | `/runs/{id}/trace?after_seq=N` | Actions with decisions and execution results after `seq` N |

## Approvals

| Method | Path | Purpose |
|---|---|---|
| GET | `/approvals?status=pending` | Queue |
| POST | `/approvals/{id}/resolve` | Body: `{ "approve": bool, "note": str }`. 404 if the approval does not exist, 409 if it was already decided or timed out |

## Experiments

| Method | Path | Purpose |
|---|---|---|
| POST | `/experiments` | Body: `name`, `suite` (`internal` or `injecagent`), `configurations`, `scenario_ids` or `categories` or `split`, `agent_provider`, `assessor`, `repeats`, `seed`. Returns 202. Returns 422 if D or E is requested without a usable model, if the name is blank, if `configurations` is empty, or if `scenario_ids` or `categories` is an empty list (omit them to mean "no filter") |
| GET | `/experiments` | List |
| GET | `/experiments/{id}` | Status, progress, manifest |
| POST | `/experiments/{id}/cancel` | Cancel after the current run |
| GET | `/experiments/{id}/runs` | Per-run results. Filters: `category`, `limit` (default 600), `offset` |
| GET | `/experiments/{id}/metrics` | Metric rows. Filters: `configuration`, `category`, `split` |
| GET | `/experiments/{id}/export?format=csv\|json` | Download results |

## Analytics

| Method | Path | Purpose |
|---|---|---|
| GET | `/analytics/compare?experiment_id=&split=` | KPIs and research metrics (false-negative rate, precision, recall, F1, PR-AUC, mean latency) per configuration, category breakdown, ablation, exact McNemar tests for internal suites, cluster bootstrap comparisons for InjecAgent, proposal targets (labelled as targets), available splits. Cached once an experiment completes |

## Audit

| Method | Path | Purpose |
|---|---|---|
| GET | `/audit` | Search. Filters: `q`, `decision`, `tool`, `rule_id`, `run_id`, `experiment_id`, `gt_label`, `limit`, `offset` |
| GET | `/audit/export?format=csv\|json` | Same filters, as a download |
| GET | `/audit/verify/{run_id}` | Verify the run's hash chain |
| GET | `/audit/repeated` | Fingerprints denied more than once |
