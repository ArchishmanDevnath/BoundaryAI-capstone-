# BoundaryGuard

BoundaryGuard is a runtime authorization layer for tool-using AI agents, plus a benchmark that measures whether it helps. Every tool call an agent proposes is authorized before it runs:

1. Deterministic policy rules decide first.
2. A contextual risk assessor can then only tighten that decision. The assessor is a rule-based heuristic, a supervised ML model, or optionally an LLM.

This is a final-year project prototype. All tools are simulated: nothing it runs can start a process, open a network socket or touch a file outside a throwaway sandbox, and every credential in it is a dummy value.

## Measured results

These were measured with scripted agents on 2026-11-06. Full tables, intervals and caveats are in [docs/EXPERIMENT_RESULTS.md](docs/EXPERIMENT_RESULTS.md).

| Configuration | InjecAgent (external): attacks stopped | InjecAgent: legitimate actions blocked | Internal holdout: attacks stopped | Median decision time |
|---|---|---|---|---|
| A. Unprotected | 0% (0/3042) | n/a | 0% (0/21) | – |
| B. Rules only (broad policy) | 0% (0/3042) | 0% (0/2127) | 33% (7/21) | – |
| C. Rules + heuristic | 79.5% (1998/2514) | 0% | 55% (11/20) | 0.13 ms |
| **Control. Rules + heuristic + history (recommended)** | **86.7% (2022/2332)** | 0% | **75% (15/20)** | 0.17 ms |
| D. Rules + ML (model v3, post-hoc) | 81.3% (2030/2498) | 0% | 70% (14/20) | 56 ms |
| E. Rules + ML + history (model v3, post-hoc) | 80.7% (2015/2498) | 0% | 70% (14/20) | 63 ms |

What these results show:

- **Contextual assessment works.** It adds large gains over rules alone, with no false blocks.
- **ML does not beat the heuristic end to end,** despite much better offline scores. With history, ML is worse than the heuristic on InjecAgent: −6.0 points, 95% CI −9.2 to −2.8.
- **The only independent ML test failed.** Model v1's E blocked *every* legitimate InjecAgent action, because of a shortcut in its generated training data. The corrected models (v2, then v3, now active) were built after seeing that failure, so their results are labelled post-hoc.
- **The ML labels are largely the heuristic's own rules** (see [docs/ML_INTEGRITY_AUDIT.md](docs/ML_INTEGRITY_AUDIT.md)).
- **No real LLM agent has been run.** The results measure the guard's decisions on fixed attack traces.

BoundaryGuard is a research prototype. It is not production-ready, and it does not prevent all prompt injection.

## Setup

You need Git, Python 3.12 or newer, and Node.js 20.9 or newer, which Next.js 16 requires. Docker, a GPU, an internet connection after installing, and paid services are not needed. Microsoft Edge is needed only for the browser test.

**What has been verified:** a fresh clone was set up with Python 3.12 and Node 24 on Windows 11. The checks:

- the backend tests all pass;
- the app starts on an empty database;
- the published holdout results reproduce exactly.

Other operating systems and Python versions have not been tested.

```powershell
git clone <repository-url> boundaryAI
cd boundaryAI

# Backend, first terminal
cd backend
py -3.12 -m venv .venv          # or: python -m venv .venv, with any Python 3.12+
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m boundaryguard.main
```

The API is at http://127.0.0.1:8000, with interactive docs at http://127.0.0.1:8000/docs. The commands call the virtual environment's Python directly, so `Activate.ps1` and PowerShell's execution policy are not involved.

```powershell
# Frontend, second terminal, from the repository root
cd frontend
npm ci                          # installs exactly the versions in package-lock.json
npm run build
npm start
```

Open http://localhost:3000.

**On first start:**

- **Database:** the backend creates its SQLite database in `backend/var/`, which git ignores, and loads the 53 scenarios and the three benchmark policies. Nothing needs to be initialized by hand.
- **Empty dashboard:** a fresh clone has no experiment results, so the dashboard starts empty. Run the benchmarks in the next section to produce them. Your experiment ids will differ from the ones quoted in `docs/`, but the results are the same.
- **Settings:** these are optional. To change one, copy [.env.example](.env.example) to `backend/.env`, which git ignores.

**What the repository includes:** the trained models (`backend/models/`, active model v3), the prepared datasets (`data/`), and the untouched InjecAgent source with its licence. You only need the next section to rebuild them.

**Line endings:** the repository pins its line endings in `.gitattributes`. Datasets, model bundles and scenario files are verified by SHA-256, and Git for Windows would otherwise convert them to CRLF on checkout and break those checks. No action is needed. Do not run line-ending converters over `data/` or `backend/models*/`.

## Reproduce the data, model and experiments

From `backend`, in Windows PowerShell. Each step writes new files and never overwrites `data/external/injecagent/`.

```powershell
$py = ".\.venv\Scripts\python.exe"

# Active model v3: data with attacks after the task's first step, no position feature. Train and validation only.
& $py scripts\prepare_data.py --out-dir ..\data\posthoc_v3 --attack-position after_first_task_step   # about 3 min
& $py scripts\train_models.py --data-dir ..\data\posthoc_v3                                         # about 2 min, becomes active

# Benchmarks with the active model
& $py scripts\run_benchmark.py --name internal --configurations A B RC C D E
& $py scripts\run_benchmark.py --name external --suite injecagent --configurations A B RC C D E      # 30-60 min
& $py scripts\analyze_results.py --experiment <id> --out var\report\<name>   # independent recomputation; non-zero exit on any mismatch
& $py scripts\results_tables.py --internal <id> --external <id>               # the tables in EXPERIMENT_RESULTS.md
& $py scripts\integrity_probe.py                                             # ML integrity probes (train and validation only)
& $py scripts\diagnose_external.py                                           # why v1's E failed on InjecAgent
```

**Earlier models are preserved:**

- **v1** (`backend/models/ml-756975a1-114f9854`) was trained on `data/` and evaluated once on its test split.
- **v2** is in `backend/models_posthoc/`.

To run D and E with v1 again, write `ml-756975a1-114f9854` into `backend/models/CURRENT`. To switch back, write `ml-df842b52-a2bd43dd`.

`train_models.py --final-test` evaluates on the native test split. It refuses a model whose test groups were already used unless you pass `--allow-retest`, and every use is logged in `data/manifests/test_access_log.jsonl`. Those groups have been used twice, so **do not** use `--final-test` for new models. A new test set is needed instead.

Running `train_models.py` without `--data-dir` trains on the v1 data with the current features, and makes that model active. Pass `--no-activate` to avoid this.

## Using the dashboard

| Page | What it is for |
|---|---|
| **Overview** | System status, run accounting, the latest experiment's held-out results, recent stops |
| **Live runs** | Run one scenario in any configuration, watch each decision, approve or deny. Open a run to see why each action was allowed or stopped, including the ML risk score and its main factors |
| **Experiments** | Start a benchmark (internal or InjecAgent). Open one for results: one table of every metric, the trade-off charts, significance, and a scenario matrix linking to every trace |
| **Risk model** | The active model, its training data and splits, its test results, what it relies on, and its decisions compared with the heuristic's |
| **Policies** | Copy, edit and version policies. Benchmark policies are read-only |
| **Audit log** | Search every decision, export it, and verify a run's hash chain |

A short demonstration:

1. **Experiments:** open "InjecAgent external benchmark", then **Results**.
2. **Live runs:** pick `pi01_readme_env_exfil`.
   - Run it with A, and a dummy credential is stolen.
   - Run it with Control, the recommended configuration, then with E, and compare the heuristic and ML explanations on each action.
3. **Risk model:** look at the test results and the heuristic-against-ML table.
4. **Audit log:** search `id_rsa`, expand a row and verify its chain.

## Configurations

| Label | Stored id | Rules | Contextual assessor | History |
|---|---|---|---|---|
| A | `A` | no | none | no |
| B | `B` | yes | none | no |
| C | `RC` | yes | heuristic | no |
| Control | `C` | yes | heuristic | yes |
| D | `D` | yes | ML (stateless) | no |
| E | `E` | yes | ML (stateful) | yes |

Stored ids keep their original meaning, so experiments recorded earlier remain correct.

## Running with a real model

Ollama is supported, but it was not installed on the development machine, so this path has been tested only against a mock server.

```powershell
ollama pull qwen2.5:7b
.\.venv\Scripts\python.exe scripts\run_benchmark.py --name llm-run --agent ollama --configurations A B RC C D E --repeats 3
```

## Tests

```powershell
cd backend;  .\.venv\Scripts\python.exe -m pytest
cd frontend; npm run lint; npm run typecheck; npm run build
cd frontend; npm run e2e    # needs both servers running, and an internal and an InjecAgent benchmark (A B RC C D E) completed with the active model
```

Results are in [docs/TESTING.md](docs/TESTING.md).

## Repository layout

```
backend/
  boundaryguard/  guard/ (gateway, policy, history, heuristic and LLM assessors), ml/ (features, ML assessor,
                  datasets, InjecAgent adapter, validation, training), tools/, agent/, audit/, experiments/, api/, db/
  benchmark/      fixtures, policies, 53 internal scenarios
  models/         v1 and the active v3 bundle, and the CURRENT pointer (models_posthoc/: v2)
  scripts/        prepare_data, train_models, run_benchmark, analyze_results, results_tables, integrity_probe, diagnose_external
  tests/          pytest suite
data/             external/ (untouched InjecAgent), processed/, splits/, manifests/ (v1 data); posthoc_v2/, posthoc_v3/
frontend/         Next.js dashboard and the browser test
docs/             see below
```

## Documentation

| Document | Contents |
|---|---|
| [Feature audit](docs/FEATURE_AUDIT.md) | What was kept, fixed, simplified, removed and added, and why |
| [Final project status](docs/FINAL_PROJECT_STATUS.md) | Start here: architecture, features, final test results, readiness |
| [Experiment results](docs/EXPERIMENT_RESULTS.md) | All measured results and the answer to the research question |
| [ML integrity audit](docs/ML_INTEGRITY_AUDIT.md) | Label circularity, leakage, shortcuts, test-set use: verdicts per category |
| [ML methodology](docs/ML_METHODOLOGY.md) | Models, training procedure, thresholds and native test results |
| [Dataset documentation](docs/DATASET_DOCUMENTATION.md) | InjecAgent provenance and adaptation, the generated dataset and its splits |
| [Architecture](docs/ARCHITECTURE.md) | – |
| [Security design](docs/SECURITY_DESIGN.md) | – |
| [Testing](docs/TESTING.md) | – |
| [Limitations and future work](docs/LIMITATIONS_AND_FUTURE_WORK.md) | What the results cannot show, and what would close each gap |
| [Database schema](docs/DATABASE_SCHEMA.md) | – |
| [API specification](docs/API_SPECIFICATION.md) | – |
| [Project plan](docs/PROJECT_PLAN.md) | – |

InjecAgent is © 2023 Qiusi Zhan, MIT licence (see `data/manifests/INJECAGENT_LICENCE.txt`). Cite it as described in the dataset documentation.
