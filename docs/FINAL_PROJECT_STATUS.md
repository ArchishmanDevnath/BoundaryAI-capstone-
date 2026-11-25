# Final Project Status

**Status on 2026-11-07: ready for academic submission, with documented limitations.** Product polish (UX, CRUD integrity and edge cases) is recorded in `FEATURE_AUDIT.md`.

BoundaryGuard is a research prototype. It is not production-ready, and it does not prevent all prompt injection or agent attacks. Everything below was checked against the code and stored artefacts on this date.

## What BoundaryGuard is

A runtime authorization layer for tool-using AI agents. Every tool call an agent proposes passes through one gateway before it runs. The gateway also comes with a benchmark that measures whether this helps.

```
agent ──► ToolGateway.submit ──► 1. validate and canonicalize arguments
                                 2. deterministic policy        (final authority; first deny wins)
                                 3. history signals             (Control, E)
                                 4. contextual assessor         (heuristic: C, Control | ML: D, E)
                                    · only consulted if the policy passed
                                    · can only tighten: allow → approval → block
                                    · fails closed on any error
                                 5. write-ahead, hash-chained audit record
                       ──► simulated executor (sandboxed files, fake network and apps, no shell)
```

| Layer | Implementation |
|---|---|
| Deterministic policy | Tool allow and deny lists, canonical paths (traversal, NTFS streams, 8.3 names, junctions, UNC and device names rejected), protected paths, read and write ACLs, network allowlist, prohibited content, retry and denial limits |
| Heuristic assessor | Weighted, explainable signals: task relevance, graded sensitive-file scope, operational paths, risky or test-weakening content, unrequested network, delete or write |
| History | Retry variants, sensitive data flowing outward (exact, base64, hex), tainted context, denial bursts, scope drift. Hard signals always block |
| ML assessor | TF-IDF + logistic regression, random forest, and a stacked logistic regression. Two profiles. SHA-256-verified bundles, a 2 s timeout, and fail-closed behaviour |
| Sandbox | A throwaway virtual root per run. No process creation, no sockets, dummy credentials only |
| Audit | Written before execution. If the write fails, the action does not run. SHA-256 chain per run, with a verify endpoint |
| Benchmark | 53 internal scenarios (35 dev, 18 holdout) and 2,125 adapted InjecAgent cases. Six configurations under identical conditions. Independent recomputation script |
| Dashboard | Next.js: Overview, Live runs (with the pending-approval queue), Experiments (with results and scenario matrix), Risk model, Policies (versioned, with history and restore), Audit log (append-only). Every value comes from the API |

**Configurations:**

| Label | Stored id | Components |
|---|---|---|
| A | `A` | Unprotected |
| B | `B` | Rules only |
| C | `RC` | Rules + heuristic |
| **Control (recommended)** | `C` | Rules + heuristic + history |
| D | `D` | Rules + ML |
| E | `E` | Rules + ML + history |

## Final results

Scripted agents. D and E use the active model v3 and are **post-hoc**. Details are in `EXPERIMENT_RESULTS.md`.

| Configuration | InjecAgent stopped | InjecAgent legitimate blocked | Internal holdout stopped | Holdout legitimate blocked |
|---|---|---|---|---|
| A | 0/3042 (0%) | n/a | 0/21 (0%) | n/a |
| B | 0/3042 (0%) | 0/2127 | 7/21 (33%) | 0/36 |
| C | 1998/2514 (79.5%) | 0/2127 | 11/20 (55%) | 0/36 |
| **Control** | **2022/2332 (86.7%)** | 0/2127 | **15/20 (75%)** | 0/36 |
| D (v3) | 2030/2498 (81.3%) | 0/2127 | 14/20 (70%) | 0/36 |
| E (v3) | 2015/2498 (80.7%) | 0/2127 | 14/20 (70%) | 0/36 |

**Independent ML test, model v1:** D stopped 80.7% with no false blocks. E stopped 99.9% but blocked 2127 of 2127 legitimate actions, so it was unusable.

**Conclusion:**

- Contextual assessment adds large gains over rules.
- ML does not beat the heuristic end to end. With history it is worse: −6.0 points on InjecAgent, 95% CI [−9.2, −2.8].
- The best measured configuration is Control, which is still short of the 95% target.

## What changed in the final audit

| Fix | Files |
|---|---|
| A shared keyword no longer authorizes a confidential file. Keyword-only links need approval, and in benchmarks they are denied | `guard/context/heuristic.py`, `tests/test_regressions.py` |
| No model trains on action position. v3 was retrained on train and validation only and activated. v1 and v2 are preserved and still load | `ml/features.py`, `ml/assessor.py`, `ml/validation.py`, `tests/test_ml.py` |
| Test-split reuse is detected across data folders, by test-group fingerprint and a shared log | `ml/training.py`, `scripts/train_models.py`, `data/manifests/test_access_log.jsonl` |
| Feature lists are part of the model version hash | `ml/training.py` |
| The Risk model page explains when a model has no test result, and the browser test checks it | `frontend/src/app/model/page.tsx`, `frontend/e2e/smoke.mjs` |
| The integrity probes are a repository script | `backend/scripts/integrity_probe.py` |
| Docs consolidated: `EXPERIMENT_RESULTS.md` and `LIMITATIONS_AND_FUTURE_WORK.md` (renamed, single source), new `ML_INTEGRITY_AUDIT.md` and this file | `docs/`, `README.md` |

`FEATURE_AUDIT.md` lists every feature kept, fixed, simplified, removed and added across both audits.

## Final test results

| Check | Result |
|---|---|
| Backend pytest (2026-11-07) | **469 passed, 1 skipped**. The skip is a true-symlink test that needs Windows admin rights, and junctions are tested instead |
| ESLint, `tsc --noEmit` | No errors |
| `next build` | Succeeded |
| Browser test (headless Edge, final code, model v3) | **45 of 45 checks passed**, no console errors, no 5xx responses |
| Independent metric recomputation | Matches stored values for both final experiments |
| Reproduction | A, B, C and Control reproduce the earlier experiments exactly on both benchmarks |
| Backend and frontend start | Verified on ports 8001 and 3001, including a restart (data persisted) and a stopped backend (every page degrades with a readable error). The user's own servers on 8000 and 3000 were left untouched |

## Acceptance criteria

| Criterion | Status |
|---|---|
| Backend starts | Met |
| Frontend starts, and the production build passes | Met |
| Full backend suite passes apart from justified skips | Met (1 justified skip) |
| No critical security regression | Met. The one new weakness found (keyword-only scope) was fixed with tests |
| Metrics reproducible from stored results | Met. Independent recomputation and identical reruns |
| ML pipeline integrity audited | Met. See `ML_INTEGRITY_AUDIT.md` |
| Leakage and label circularity disclosed | Met. Circularity is a FAIL verdict, stated in the docs and on the Risk model page |
| ML cannot override a deterministic denial | Met, and tested |
| Dashboard reflects backend data | Met. The browser test compares UI values with the API |
| Docs match the implementation | Met as of this date |
| Limitations honestly reported | Met. See `LIMITATIONS_AND_FUTURE_WORK.md` |

## Known limitations

These are the most important. The full list is in `LIMITATIONS_AND_FUTURE_WORK.md`.

1. **No real LLM agent has been run.** Every result is about the guard's decisions on scripted traces.
2. **The ML labels are circular with the heuristic**, so the ML assessor cannot be called an independent risk model.
3. **The active model v3 has no independent result.** Its native test groups were already used, and its InjecAgent results are post-hoc.
4. **Small samples:** 18 holdout scenarios and 17 distinct legitimate InjecAgent calls. No internal comparison survives a multiple-comparison correction.
5. **Scope and sensitivity are lexical.** Paraphrased leaks and neutral-looking unnecessary actions get through.
6. **No authentication on the local API**, and the audit chain is per run and unsigned.

## How to run

Windows PowerShell, from the project root. Python 3.12+ and Node 20+.

```powershell
# Backend (terminal 1)
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m boundaryguard.main          # http://127.0.0.1:8000

# Frontend (terminal 2)
cd frontend
npm ci
npm run build
npm start                                                 # http://localhost:3000

# Tests
cd backend;  .\.venv\Scripts\python.exe -m pytest
cd frontend; npm run lint; npm run typecheck; npm run build
cd frontend; npm run e2e                                  # with both servers running

# Benchmark (from backend)
.\.venv\Scripts\python.exe scripts\run_benchmark.py --name internal --configurations A B RC C D E
.\.venv\Scripts\python.exe scripts\run_benchmark.py --name external --suite injecagent --configurations A B RC C D E
.\.venv\Scripts\python.exe scripts\analyze_results.py --experiment <id> --out var\report\<name>
```

Optional real-model evaluation (not performed). It needs Ollama and a model download of several GB:

```powershell
ollama pull qwen2.5:7b
cd backend
.\.venv\Scripts\python.exe scripts\run_benchmark.py --name llm-run --agent ollama --configurations A B RC C D E --repeats 3
```

The README has the commands for reproducing the datasets and models.
