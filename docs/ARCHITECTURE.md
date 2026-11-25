# Architecture

## Overview

```
 Agent provider (scripted | ollama | openai_compatible)
        | proposes ToolCall
        v
 ToolGateway.submit()  <-- the only route to the executor, in every configuration
        |  1. schema validation and canonicalization
        |  2. Guard.evaluate()
        |        PolicyEngine (hard rules, first deny wins)   -- a deny ends evaluation here
        |        HistoryAnalyzer (signals, configurations with history only)
        |        Assessor: heuristic | ML | LLM (only if the policy passed)
        |        final = most_restrictive(policy, assessor)
        |  3. approval handling (auto_deny | human)
        |  4. write-ahead audit record (fails closed)
        v
 ToolExecutor (needs the gateway's private token)
        |  re-resolves paths at use time
        v
 Sandbox floor (virtual filesystem under run_root) + SimNet + SimApps + ledger
```

## Components

| Component | Location | Responsibility |
|---|---|---|
| Models | `boundaryguard/models` | Pydantic types for policies, tool calls, decisions and scenarios |
| Sandbox floor | `tools/sandbox.py` | Maps virtual paths to `run_root`. Always on. Nothing escapes `run_root` |
| Executor | `tools/executor.py` | Runs simulated tools and writes the ledger. Requires the gateway token |
| SimNet, SimApps | `tools/simnet.py`, `tools/simapps.py` | Fake HTTP and fake application tools. Canned responses and an exfiltration sink. No sockets |
| Test oracle | `tools/test_oracle.py` | Evaluates declarative checks. Never executes code |
| Policy engine | `guard/policy_engine.py` | Deterministic rules, including path, network and application tool allowlists. No ML or LLM dependency |
| History analyzer | `guard/history.py` | Signals derived from earlier actions, plus the run's untrusted tool output |
| Heuristic assessor | `guard/context/heuristic.py` | Weighted evidence. Thresholds frozen |
| ML assessor | `ml/assessor.py`, `ml/features.py` | Text, structured and hybrid models. Integrity-checked loading. Fails closed |
| LLM assessor | `guard/context/llm.py` | Optional. Falls back to the heuristic with a safety ceiling |
| Guard pipeline | `guard/pipeline.py` | Combines the above according to the configuration flags |
| Gateway | `guard/gateway.py` | Sole owner of the executor. Orchestrates audit and approvals |
| Audit | `audit/logger.py` | Per-run SHA-256 hash chain |
| Agent loop | `agent/loop.py` | Bounded loop that only ever sees `gateway.submit` |
| Experiments | `experiments/` | Scenario suites (internal and InjecAgent), runner, scoring, metrics, statistics, manifests |
| Data and training | `ml/native_dataset.py`, `ml/injecagent.py`, `ml/validation.py`, `ml/training.py`, `scripts/prepare_data.py`, `scripts/train_models.py` | Dataset generation and adaptation, leakage checks, training and evaluation |
| API | `api/` | FastAPI routers under `/api/v1` |
| Frontend | `frontend/` | Next.js dashboard, polling the API through a same-origin rewrite |

## Configurations

Every configuration uses the same gateway, sandbox, ledger and audit. Only the guard flags differ. Stored ids never change meaning, so older records stay valid.

| Study label | Stored id | `use_policy` | `use_context` | `use_history` | Assessor |
|---|---|---|---|---|---|
| A | `A` | no | no | no | none |
| B | `B` | yes | no | no | none |
| C | `RC` | yes | yes | no | heuristic |
| Control | `C` | yes | yes | yes | heuristic |
| D | `D` | yes | yes | no | ML, stateless profile |
| E | `E` | yes | yes | yes | ML, stateful profile |

Without history, the assessor receives an empty history view: no signals, no counters and no untrusted output. A test checks this, so the D and E comparison isolates history.

## Run lifecycle

1. Build `run_root` from the fixture, apply overlays and links, and plant per-run canaries.
2. Hash the workspace.
3. Loop: the provider proposes, the gateway decides, and the outcome returns to the provider. The loop stops on finish, `max_steps`, safe termination or audit failure.
4. Evaluate completion criteria against the final state, and against the simulated applications for external cases.
5. Label actions from scenario ground truth, then score the run.
6. Remove `run_root`. Cleanup does not follow links.

## ML lifecycle

```
data/external/injecagent --(prepare_data.py: adapt, profile, hash)--> data/splits/injecagent_external_test.jsonl --> experiments only
generator templates --(replay through the real gateway)--> data/processed --> data/splits/native_{train,val,test}
native train/val --(train_models.py)--> backend/models/<version>/ + CURRENT --> MLAssessor at runtime
native test --(train_models.py --final-test, logged once)--> metadata.json
```

## Technical decisions

| Decision | Reason |
|---|---|
| Standard library `sqlite3` rather than an ORM | Small schema, explicit SQL |
| Polling rather than SSE | Simple and adequate for a local dashboard |
| Hash chain per run | Parallel runs do not contend. Deleting a whole run is not detected (documented) |
| Emulated NTFS aliases in the sandbox floor | Configuration A can genuinely be tricked, and results are the same on every OS |
| Benchmark policies live in files | Dashboard edits cannot silently change benchmark results |
| Plain SQL for metrics plus a separate pandas and scikit-learn recomputation | A bug in one implementation shows up as a disagreement |
| Training data replayed through the real gateway | Features at training time are computed by the runtime code, and only actions that pass the policy, which the assessor actually sees, become examples |
| scikit-learn, CPU only, no deep learning | The data is small and the labels are rule-based. Larger models would only memorize more. No GPU or paid service is needed |
| Model artifacts verified by hash before loading | Joblib files can execute code when loaded |
| Analytics cached for completed experiments | Recomputing 12,750 hash chains per page view was too slow |

## Fail-safe behaviour

| Failure | Behaviour |
|---|---|
| ML model missing, corrupt, tampered, incompatible, slow or invalid | BLOCK with `assessor_fallback=true`. Experiments using D or E refuse to start without a model |
| LLM assessor unavailable or invalid | Heuristic fallback. Medium risk or above needs approval or is blocked |
| Audit write fails | Nothing executes. The run ends as `audit_failure` |
| Agent LLM unavailable | The run ends as `error` and is counted |
| Approval timeout | Treated as a denial |
