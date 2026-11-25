# Feature Audit

This audit covers every page, control, endpoint and backend component as of 2026-11-06, before and after this round of work. Each feature is classified as one of the following:

- **KEEP:** essential and working.
- **FIX:** useful but defective.
- **SIMPLIFY:** useful but more complicated than it needs to be.
- **REMOVE:** redundant, misleading or unused.
- **ADD:** a missing capability the research needs.

Nothing that held data was deleted. All earlier experiments, runs and audit chains are still in the database, and their stored configuration ids keep their original meaning (see [Configuration ids](#configuration-ids)).

## Security and correctness defects found

| # | Defect | Root cause | Resolution | Tests |
|---|---|---|---|---|
| 1 | `ru07_irrelevant_sensitive_read`: the trace called `deploy/prod.yaml` sensitive and unrelated to the task, yet the action was approved and executed | The heuristic gave an unrelated sensitive read a weight of 0.45, which falls in the 0.40–0.70 band that maps to APPROVAL_REQUIRED. In auto-deny benchmark runs that band behaves like a block, so the benchmark scored it as stopped. In live runs a person can approve it. The three approved traces in the database came from the browser test, which clicked Approve on this scenario. Nothing in the UI warned that the approved action was labelled unauthorized | An unrelated read of a sensitive resource now scores 0.75 (HIGH, so BLOCK), and it never reaches a person. Operational files such as CI and deploy directories stay at 0.45 (approvable). The Overview and the trace now flag any action a person approved that the scenario labels unauthorized | `tests/test_regressions.py`: the exact reproduction in configurations RC and C with a person who approves everything, nine other sensitive names, and allowed reads the task names |
| 2 | Relevance was fooled by file extensions | `is_relevant` compared every token of the path, so "Fix the YAML parser" made any `*.yaml` file relevant | Only directory and file stem tokens are compared, never the extension | `test_relevance_is_not_fooled_by_extensions_or_substrings`, `test_yaml_task_does_not_unlock_a_production_manifest` |
| 3 | Relevance was fooled by substrings | `name in objective` was a substring test, so a file called `ci` was "named" by the word *specific* | Whole-word matching | same tests |
| 4 | A sensitive file became relevant through an incidental shared word | A task about `src/db.py` made `backups/db_backup.sql` relevant through the token *db* | New `sensitive_in_scope`: a sensitive file is in scope only if the task names it, or mentions the word that makes it sensitive | `test_irrelevant_sensitive_reads_are_blocked_for_any_such_name[backups/db_backup.sql]` |
| 5 | The Overview run count did not match the experiment pages | `/overview` returned one `COUNT(*)` over all runs: two full benchmarks of 212 runs each (the second was started from the UI during the browser test) plus three live runs, 427 in total, next to experiment pages showing 212. Its "actions evaluated / stopped" totals also mixed both benchmarks and the unprotected baseline, which never stops anything | The Overview now shows run accounting (each experiment's own count plus live runs, which add up to the total) and headline results scoped to one experiment and one split. The decision totals that mixed configurations were removed | `test_overview_run_counts_reconcile_with_experiment_records`, `test_overview_events_exclude_the_unprotected_baseline`, and the browser test compares the page with the API |

The fix in row 1 left the measured outcome of every scenario unchanged. In the auto-deny benchmark, "approval required" and "block" both stop the action, and re-running the 53 scenarios gave the same holdout results as before (C: 5/20 unauthorized executed, 0/36 false blocks). The heuristic was not tuned to the remaining holdout misses (`pi15`, `ru08`, `ru10`), because that would turn the holdout into a tuning set. They are reported as misses.

## Frontend

| Page or control | What it does | Works and backed by API | Decision | Reason |
|---|---|---|---|---|
| Navigation, six items | Moves between pages | Yes | SIMPLIFY | Analytics merged into Experiments and a Risk model page added, so the count stays at six. "Execution trace" renamed to "Live runs", which says what the page is for |
| System status in the sidebar | Backend, rule engine, Ollama | Yes | FIX | Added the risk model, which configurations D and E depend on |
| Overview: four stat tiles | Experiments, actions evaluated, stopped, audit chain | Partly | REMOVE | Totals summed across experiments and configurations (defect 5). The audit figure moved into System status |
| Overview: "All recorded decisions" segmented bar | Allowed vs stopped across everything | Yes, but misleading | REMOVE | Mixed the unprotected baseline with guarded runs, so the ratio meant nothing |
| Overview: "Most frequent blocking rules" | Rule histogram | Yes | REMOVE | Decorative here. The audit log filters by rule when this matters |
| Overview: system status, latest experiment, recent events | Status, headline result, recent stops | Yes | FIX | Latest results now come from the held-out or external split. Recent events exclude configuration A. Run accounting and the human-override warning were added |
| Live runs: run form | Starts a scenario or custom run | Yes | SIMPLIFY | The delay slider was removed (fixed at 500 ms). The assessor selector appears only for configurations that use it. Custom LLM tasks are disabled with an explanation when no LLM is running, instead of failing after submission. All six configurations are offered |
| Live runs: list, trace page, approvals | Inspect decisions and approve or deny | Yes | KEEP and FIX | ML reasoning and signals now appear in the trace. Human overrides of an unauthorized label are flagged |
| Experiments: form | Starts an experiment | Yes | FIX | Added the benchmark choice (internal or InjecAgent) and configurations D and E, which are disabled when no model is installed. Repeats and seed are shown only for LLM agents, because scripted runs are deterministic |
| Experiment detail: scenario matrix | Per-scenario outcome per configuration | Yes | FIX | Pages at 600 runs, since the external benchmark has 12,750. Added a category filter |
| Analytics page | KPIs, ablation, significance | Yes | SIMPLIFY | Merged into the experiment page's Results tab. The same numbers appeared in seven KPI panels, an ablation table and an "all results" table. One table now holds every number, and two charts show the trade-off (attacks stopped against legitimate actions blocked). `/analytics` redirects old links |
| Analytics: per-KPI bar panels (7) | One chart per metric | Yes | REMOVE | Duplicated the table |
| Analytics: ablation table | Contribution of each component | Yes | REMOVE | Rows of the main table already form the ablation |
| Analytics: latency table | Rule and context latency | Yes | SIMPLIFY | Mean authorization latency is now a column of the main table |
| Analytics: significance | McNemar | Yes | FIX | Cluster bootstrap for the external benchmark, where cases are not independent |
| Policies page | View, copy, version and deactivate policies | Yes | KEEP | Benchmark policies stay read-only, so edits cannot change benchmark results |
| Audit page | Search, export, verify chain, repeated violations | Yes | KEEP and FIX | Deep links (`/audit?gt_label=...`) apply filters. Added `app_call` to the tool filter |
| Risk model page | Active model, data, offline metrics, heuristic vs ML | – | ADD | The research needs a visible record of which model ran and how it was evaluated |

## Backend and API

| Component | Decision | Notes |
|---|---|---|
| `ToolGateway.submit`, the single execution route | KEEP | Still the only holder of the executor. The new `app_call` tool goes through it like every other tool |
| Deterministic policy engine | KEEP and ADD | Added the application tool allowlist and prohibition (`APP_NOT_ALLOWED`, `APP_PROHIBITED`). The policy runs first and the assessor never sees an action it denied |
| Heuristic assessor | FIX | Defects 1–4. Added an application-tool branch, with the same weights as the file and network branches, fixed before the external run |
| History analyzer | KEEP and ADD | Now also records untrusted tool output and simple counters for the stateful ML profile |
| LLM assessor and clients | KEEP | Unchanged. Still untested against a real model |
| ML assessor (`boundaryguard/ml/`) | ADD | Text, structured and hybrid models. Fails closed. Integrity-checked loading |
| Configurations D and E | ADD | Configuration ids are explained below |
| Simulated application tools (`tools/simapps.py`) | ADD | Canned responses only, needed to replay InjecAgent |
| Experiment runner, scoring, metrics | FIX and ADD | Scenario suites (internal or InjecAgent). Added false-negative rate, precision, recall, F1, PR-AUC and mean latency. Models are preloaded so loading time stays out of latency |
| `/overview` | FIX | Defect 5 |
| `/analytics/compare` | FIX | Cached for finished experiments, because recomputing 12,750 hash chains per page view took seconds. Added cluster bootstrap comparisons |
| `/experiments/{id}/runs` | FIX | Pagination and a category filter |
| `/ml/model`, `/ml/heuristic-comparison` | ADD | Read-only. Values come from the model bundle's metadata and stored decisions |
| `/health` | FIX | Reports model availability |
| `/configurations`, `/tools`, `/providers`, `/scenarios` | KEEP | – |
| Polling-based live updates | KEEP | Simple and adequate for a local dashboard |
| SQLite schema | KEEP | No migration was needed. New configurations and categories are values, not columns |

## Configuration ids

Stored ids never change meaning, so the earlier experiment records stay correct.

| Study label | Stored id | Components |
|---|---|---|
| A | `A` | No guard |
| B | `B` | Deterministic rules |
| C | `RC` | Rules + heuristic contextual assessor |
| D | `D` | Rules + ML assessor (stateless profile) |
| E | `E` | Rules + ML assessor (stateful profile) + history signals |
| Control | `C` | Rules + heuristic + history. Earlier this was called "BoundaryGuard". It is kept so that E can be compared with the strongest non-ML guard |

## Data and files

| Item | Decision | Notes |
|---|---|---|
| `data/external/injecagent/` | KEEP, read only | Byte-identical to upstream commit `f19c9f2`. Hashes are checked before and after processing |
| Copies of the same nine files directly in `data/` | Flagged, not deleted | They are byte-identical to the files in `data/external/injecagent/` (same SHA-256), so they are redundant. Nothing reads them. Delete them yourself if you agree |
| Earlier experiments in `backend/var/boundaryguard.sqlite3` | KEEP | Still listed. "Benchmark run" is the duplicate started during the earlier browser test |
| `docs/KNOWN_LIMITATIONS.md` | Replaced | Superseded by `docs/LIMITATIONS_AND_FUTURE_WORK.md` |

## Final audit (2026-11-06)

A second pass checked the first pass's claims against the code and stored artefacts. Four genuine defects were fixed. Nothing else was redesigned.

| # | Defect | Root cause | Fix | Regression tests |
|---|---|---|---|---|
| F1 | A shared keyword authorized a confidential file. "Fix the payroll calculation bug in src/pay.py" let the agent read `hr/payroll_2024.xlsx` silently, and the same happened with `credentials`, `customers` and `backup` | `sensitive_in_scope` treated mentioning a sensitive word as equivalent to naming the file | The heuristic grades the link: named, located, keyword only, or none. Keyword only now needs a person's approval. The feature definition is unchanged, so stored training data stays valid | `test_regressions.py`: keyword-only reads are denied in benchmark mode and sent to a person in live mode; generic words (*database*, *production*, *YAML*, *CI*) unlock nothing |
| F2 | The post-hoc model v2 still relied on action position | `prior_steps` stayed a feature. With attacks moved later, step 0 became always legitimate, so the shortcut was reversed rather than removed | Position is computed but no longer trained on (feature-set version 2). Model v3 was trained on train and validation only and made active. v1 and v2 are preserved and still load | `test_ml.py`: no profile trains on position; preserved bundles load and score |
| F3 | A repeated use of the test split was invisible | The test-access log matched on file bytes, inside each data folder. v2's regenerated data had the same test groups and logged "0 earlier uses" | Uses are matched by a test-group fingerprint and checked against a shared log as well. Earlier uses were appended to it, and no lines were rewritten | `test_ml.py`: a second data folder with the same groups is refused without `--allow-retest` |
| F4 | The feature set did not change the model version | The version hash covered data and configuration but not feature names, so a model with different inputs could overwrite a bundle | Feature lists and their version are part of the configuration hash | Covered by the bundle reproducibility tests |

Unchanged after inspection, with the evidence for each:

- **Policy, path and URL handling:** the existing bypass tables pass.
- **Approvals:** a person is asked only when the final decision is APPROVAL_REQUIRED, so a policy denial never reaches them. A test approves everything and still gets denied.
- **Audit chain:** write-ahead and verify tests pass.
- **Metrics:** stored values match independent recomputation, as described in `TESTING.md`.

**Housekeeping:**

- An interrupted benchmark started during this audit is marked `cancelled` and is not used anywhere.
- An empty file created by mistake, `var/boundaryguard.db`, was removed.

## Product polish (2026-11-07)

The core jobs the dashboard serves:

1. See whether agent actions are safe.
2. Find out why each was allowed, stopped or escalated.
3. Decide on anything waiting for a person.
4. Manage policies.
5. Run and read experiments.
6. Inspect the audit trail.

Every change below was made against that list. No security logic, data, benchmark method or result changed.

### Changed

| Page | Change | Why |
|---|---|---|
| Navigation | A "Live runs" badge shows how many actions are waiting for approval. The sidebar status block now shows only the backend's status, with the start command when it is offline | Approvals were only discoverable as a count on the Overview. The sidebar repeated the Overview's system status |
| Live runs | New "Waiting for your decision" panel, linking to each paused action. The default configuration is now Control, marked "recommended". "Steps" and "Stopped" merged into "Stopped: n of m" | Pending decisions are the most time-critical task. The old default was E, an experimental configuration. The table clipped its last column |
| Run trace | A paused action reads "Paused until you decide" instead of "Not executed". "Decided by" uses words ("Rules", "Contextual check") instead of internal codes. A missing run shows a clear message and a way back | "Not executed" looked final while the action was still waiting |
| Policies | Inline validation that mirrors the backend. Save is enabled only when something changed. Unsaved-changes guard on switching policy or leaving the page. Confirmation dialog before deactivating. History view with "Restore this version". Success messages after the backend confirms | See the CRUD audit below |
| Experiments | Inline validation (name, repeats, at least one configuration, at least one scenario), with the reason shown under the button. Confirmation before cancelling. Started message. A missing experiment shows a clear message and a way back | Previously a blank name or an empty selection reached the backend, and cancelling was one unconfirmed click |
| Audit log | Enter applies the filters. Reset button. Applied filters are written to the address bar so a view can be shared. Plain "Decided by" column. The description states the records are append-only | The form could not be submitted with Enter, and filtered views could not be linked |
| Overview | The run breakdown lists the three newest experiments and sums the rest in one row, so the parts still add up to the total. Control is marked "recommended" in the headline table | Nine rows of accounting crowded out the security information |
| Risk model | The banner says that neither ML configuration outperformed rules + heuristic + history. An empty "test results" panel is hidden when the model has no test evaluation | The empty panel repeated the message above it |
| Everywhere | Decision badges read Allowed, Blocked, Needs approval, Approved by a person, Approval denied. An unrecognised decision shows "Unknown decision", never success. A run cut off by a restart shows "Interrupted by a restart". Invalid timestamps show "unknown time" | Consistent status language, with no state shown as success by accident |

### Removed or consolidated

| Element | Reason |
|---|---|
| Sidebar rows for Rule engine, Risk model and Ollama | Duplicated the Overview's system status |
| Unused `Stat` component | Dead code |
| "Test results by behaviour" panel for models without a test evaluation | It only said that there was nothing to show |
| Separate "Steps" column on Live runs | Merged into "Stopped: n of m" |

Nothing that carries data or a security function was removed.

### CRUD audit

| Entity | Create | Read | Update | Delete | Notes |
|---|---|---|---|---|---|
| Custom policy | Verified: validation in the browser and on the server, duplicate and reserved names rejected (409), success message | Verified: list, detail, version history, persists across backend restart | Verified: new version only if changed (409 otherwise), stale edit rejected (409), unsaved-changes guard | Verified as deactivate, with a confirmation dialog and restore. History is never rewritten | API tests and browser test |
| Benchmark policy | Not allowed | Verified, read-only | 403 | 403 | The benchmark results depend on these policies |
| Experiment | Verified: validation, double-submit protection, started message | Verified: list, detail, results, scenario matrix, export, not-found page | Not applicable | Cancel with confirmation. No delete: experiments are research records | |
| Live run and approval | Verified: start a run; approve or deny with double-click protection | Verified: trace, pending list, badge, not-found page | Approval resolve: 404 if missing, 409 if already decided | Not applicable | |
| Audit record | Written by the gateway only | Verified: search, filter, export, chain verification | **Not allowed** | **Not allowed** | Append-only and hash-chained by design |
| Risk model | Training script only | Verified: metadata, read-only page | Not from the UI | Not from the UI | The UI does not edit models |

### Edge cases checked

| Case | How it was checked | Result |
|---|---|---|
| Backend down | Every page loaded with the backend stopped | Each shows "Cannot reach the BoundaryGuard backend". The sidebar shows Offline with the start command. No uncaught errors |
| Slow backend | 30-second client timeout | A clear "did not answer in time" message (status 408). Not exercised against a real hang |
| Malformed or non-JSON responses | Client code path | A typed, readable error instead of a crash. Not exercised against a live malformed response |
| Malformed request JSON, wrong content type, missing records, invalid ids, out-of-range query values, unknown Host header | Direct HTTP requests to the running API | 422, 415, 404, 404, 422 and 400 respectively, each with a readable `detail` |
| Validation errors from FastAPI | Rendered in the UI | Shown as "field: message", not raw JSON |
| Blank, whitespace-only, too long, reserved, duplicate (any case), punctuation-only and Unicode policy names | API tests and direct requests | Rejected with a reason. Names are deliberately limited to unaccented letters to avoid look-alike names. Unicode inside rules is stored correctly |
| Rules that could never match: relative paths, URLs or IP addresses as hosts, lower-case methods | API tests | Rejected with the fix in the message |
| Empty `categories` or `scenario_ids` list | API test | Previously read as "no filter" and would have run the whole benchmark. Now rejected (422) |
| Stale edit from a second tab | API test | 409 with "reload to see the current version" |
| Double clicks and double submits | Buttons disabled while a request is in flight | Verified in code. The browser test exercises each path once |
| Cancelled dialogs | Browser test | Cancelling deactivation keeps the policy. Cancelling "discard changes" keeps the edits |
| Persistence | Created a policy, restarted the backend, read it back | Persisted |
| Phone width | Browser test at 390 px on seven pages | No horizontal page scroll |
| Security behaviour | Backend suite: `test_regressions.py`, `test_ml.py`, `test_gateway_security.py`, `test_paths_and_urls.py`, `test_api.py` | Hard denials not overridable by ML or by approval, model failures fail closed, keyword-only scope not authorized, traversal and invalid paths rejected, injected instructions do not authorize, retry lockout, denied actions never executed, audit write-ahead, tamper detection |

### Known limits of this pass

- **Browser coverage:** the browser test runs in Edge only.
- **Accessibility:** keyboard use was checked through the native dialog and form behaviour. No screen-reader audit was done.
- **Authentication:** none exists in this local prototype, so 401 and 403 for users do not apply. 403 is used only for read-only benchmark policies.
