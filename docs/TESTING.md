# Testing

All results on this page were measured on 2026-11-06 on Windows 11, with Python 3.14.3, scikit-learn 1.9.1 and Node 24. Experimental results are in `EXPERIMENT_RESULTS.md`.

## How to run

| What | Command, from the folder shown | Needs |
|---|---|---|
| Backend tests | `backend`: `.\.venv\Scripts\python.exe -m pytest` | Nothing else. About 10–15 minutes, because ML tests train small real models and one test runs the full benchmark |
| ML integrity probes | `backend`: `.\.venv\Scripts\python.exe scripts\integrity_probe.py` | The prepared datasets. Reads train and validation only |
| Frontend lint | `frontend`: `npm run lint` | – |
| Frontend types | `frontend`: `npm run typecheck` | – |
| Production build | `frontend`: `npm run build` | – |
| Browser test | `frontend`: `npm run e2e` | Both servers running, the completed experiments, and Edge (or set `BG_E2E_CHANNEL=chrome`). `BG_E2E_BASE` selects another frontend URL |
| Independent recomputation | `backend`: `python scripts/analyze_results.py --experiment <id>` | A completed experiment |

The browser test creates two live runs and one temporary policy in whichever database the running backend uses.

## Results

Latest run, on 2026-11-07, after the product-polish changes:

| Check | Result |
|---|---|
| Backend pytest | **469 passed, 1 skipped**. Exit code 0 |
| ESLint | No errors |
| TypeScript `tsc --noEmit` | No errors |
| `next build` | Succeeded, 10 routes |
| Browser test, headless Edge, against the final code and model v3 | **45 of 45 checks passed**, no console errors and no 5xx responses |
| Backend-down check | All 8 page types show a readable error, and none throws |
| Persistence | A policy created before a backend restart was read back after it |
| Independent recomputation, final internal experiment `3350c3d6…` | All recomputed values match. Exit code 0 (2026-11-06) |
| Independent recomputation, final InjecAgent experiment `6f9f51d0…` | All recomputed values match. Exit code 0 (2026-11-06) |
| Reproduction | A, B, C and Control in the final experiments give results identical to the earlier experiments, to the action, on both benchmarks |

**Fresh-clone verification (2026-11-07):** a snapshot of exactly the files git would publish was committed to a separate git database, cloned into a new folder with this machine's Git for Windows settings (`core.autocrlf=true`), and set up from scratch, using Python 3.12.3 and a new virtual environment, and `npm ci` on Node 24:

| Step | Result |
|---|---|
| Byte comparison of all 240 tracked files against the original | Identical, after adding `.gitattributes`. Before that, data, model metadata and scenario files came out with CRLF line endings and different SHA-256 |
| `pip install -r requirements.txt` on Python 3.12 | Succeeded |
| Backend start with no `var/` folder | Database created, 53 scenarios and 3 benchmark policies loaded, model v3 loaded with its hashes verified |
| Live run in configuration E, and a holdout benchmark (B, C, Control, E) | Completed. Holdout prevention 7/21, 11/20, 15/20, 14/20, identical to the published results |
| `npm ci`, lint, type check (before any build), production build | All succeeded |
| All six pages in Edge against the clone's servers | Rendered, no console errors |
| Full backend test suite inside the clone | **469 passed, 1 skipped** |

This was the same Windows machine with a separate, clean checkout and environment, not a different computer.

**Change in counts:** the final audit on 2026-11-06 recorded 447 passed (448 collected). The product polish added 22 tests:

- policy name rules;
- rules that could never match;
- copying every benchmark policy;
- stale and no-op edits;
- history and restore;
- experiment and run input checks;
- the approval 404.

**The browser test grew from 35 to 45 checks.** The new checks cover:

- policy validation and reserved names;
- unsaved-changes protection;
- deactivating, with both cancel and confirm;
- restoring from history;
- the pending-approval panel and navigation badge;
- audit filters in the address bar, and reset.

The test triggers one 409 on purpose (a reserved policy name), and allows exactly that one in the console.

`pytest.ini` already passes `-q`. Adding a second `-q` suppresses the summary line, which is why the count above comes from `--collect-only` plus the progress output: one `s`, no `F` or `E`.

**The one skip:** a true symlink needs elevated privileges on Windows (`WinError 1314`). Link escapes are tested with junctions instead.

**Tests added in the final audit (20):**

- Keyword-only and generic-word scope cases.
- A CI-workflow write.
- The frozen feature definition.
- No training on position.
- Preserved bundles still loading.
- Cross-folder test-split reuse.

The browser test now also checks that a model without a test evaluation says so.

Earlier fixes that made the test runs reliable:

- **Browser test timing:** the first runs failed because the test waited for network silence on pages that poll the API, which does not happen while the backend is busy. It now waits for page content.
- **A slow endpoint:** the browser test exposed `/ml/heuristic-comparison` taking about 2 minutes on the external experiment. A self-join was quadratic in the number of runs. It was rewritten, now takes 0.45 s, and has a test.

## What the tests cover

| Area | File | Examples |
|---|---|---|
| Regressions from the audit | `test_regressions.py` | The exact `ru07` failure in RC and C with a person who approves everything. Nine other sensitive names. Sensitive files the task asks for stay allowed. File extension and substring relevance bugs. A shared incidental word is not scope. Protected resources stay denied even when the task names them. Retry lockout, including after context denials. Secret read then sent. Indirect injection. Unrequested writes |
| Run accounting | `test_api.py` | The Overview total equals experiment runs plus live runs, matches `/runs`, and each experiment's own count. Headline values match the analytics endpoint. The unprotected baseline is excluded from events. Experiments run with another model are excluded from the headline |
| Dataset validation | `test_ml.py` | Empty dataset, missing label, invalid label, non-finite feature, a split with one class, missing data files, too few groups for cross-validation. All stop training with a clear message |
| Labels | `test_ml.py` | Every rule family. The same action flips label with the task. Label code reads no features and no guard output |
| Leakage | `test_ml.py` | Every project, task and family in one split. No shared groups or near-duplicates across splits. Detection of injected overlaps and near-duplicates. A training objective equal to a benchmark scenario is flagged. Features exclude identifiers. The stateless profile receives no history. No InjecAgent objective or injection text in any training split |
| Test-set discipline | `test_ml.py` | The test split is not read without `--final-test`. Every use is logged, and a second model is refused without `--allow-retest` |
| Pipeline | `test_ml.py` | The threshold respects the false-positive ceiling and uses the budget. The bundle records seed, data hash, configuration, library versions and metrics. Training twice gives the same validation metrics and thresholds. Training and runtime features are identical. Average precision matches scikit-learn on tied scores |
| ML safety | `test_ml.py` | ML cannot override a deterministic denial: a hostile assessor is never consulted, and a real model cannot grant a protected read. Hard history signals outrank the model. Missing model, corrupt file, hash mismatch (never unpickled), consistent but unloadable bundle, pointer escape, feature mismatch, NaN or out-of-range prediction, an exception and a timeout all fail closed. The guard stays safe end to end without a model. Experiments with D or E refuse to start without one |
| ML end to end | `test_ml.py` | Real experiments with C, D and E record the new metrics with no errors. Paired heuristic and ML comparison |
| InjecAgent | `test_ml.py` | Effect classification. Labels are not forced for the same tool, same toolkit or a named service. Schema checks pass on the real files. Adaptation counts. Source files unchanged after processing. `app_call` goes through the gateway with no socket or process. A per-task allowlist blocks everything else |
| Earlier coverage | `test_paths_and_urls.py`, `test_gateway_security.py`, `test_context_and_llm.py`, `test_experiments.py`, `test_api.py` | Filesystem and URL bypass forms, policy rules, the single execution route, audit write-ahead and tamper detection, LLM fail-safe, full-benchmark integrity with sockets and processes rigged to fail, reproducibility, API hardening |

## Browser test checks

The browser test checks the following:

- All six pages render.
- The Overview total matches the API, its parts add up, and the headline uses the active model.
- Results pages for the internal and external experiments show the API's measured values, and label targets as goals.
- Both scenario matrices render.
- Old `/analytics` links redirect.
- The Risk model page shows the active version and test PR-AUC.
- Approval flow: a human denial means the action does not execute.
- An ML trace shows a risk explanation.
- Policy copy, version and deactivate.
- Audit deep link, filter and chain verification.
- No horizontal scroll at phone width on seven pages.

## Reproducibility

- `prepare_data.py` writes byte-identical data files on every run. Hashes are recorded in the manifests.
- Model versions are derived from the dataset hash and the configuration hash. Seeds are fixed at 42.
- Experiment manifests record the suite hash, source hash, policy hash and model bundle hash.
- The final experiments ran from a fixed backend source. Two later changes affect only how explanations and comparison queries are displayed, not any decision or metric. Recomputation with the current code reproduces every stored metric.
