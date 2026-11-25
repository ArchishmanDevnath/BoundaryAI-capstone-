# Project Plan

BoundaryGuard is a runtime layer that authorizes every tool call an AI agent proposes before it runs, plus a benchmark that measures whether doing so helps. The source of truth for objectives is the project proposal (`pjt2_proposed_idea.pdf`).

## Environment constraints

| Constraint | Effect on the build |
|---|---|
| No Docker | All tools are simulated. `run_tests` is a declarative oracle and never executes agent-written code. |
| No Ollama, no GPU | LLM clients are built and tested against mock HTTP transports. Benchmarks run here use the scripted agent and heuristic assessor and are labelled accordingly. |
| Windows host | Path handling covers NTFS-specific aliases. Benchmark behaviour is emulated so results match across operating systems. |

## Milestones and acceptance criteria

| # | Milestone | Acceptance criteria |
|---|---|---|
| 1 | Planning docs | The five documents in `docs/` exist and agree with each other. |
| 2 | Foundation | Virtual environment, pinned dependencies, SQLite schema and repositories pass tests. |
| 3 | Security core | Paths, URLs, policy engine, sandbox floor, gateway and audit pass the bypass tests with no LLM present. |
| 4 | Agent and tools | Bounded loop, scripted provider and LLM clients work. A scripted scenario runs end to end. |
| 5 | Contextual assessment | History analyzer, heuristic and LLM assessors work. Hostile-assessor tests cannot override a deny. |
| 6 | Benchmark | About 52 scenarios, runner, scoring and statistics work. Two runs produce identical normalized results. Metrics are hand-checked on a small fixture. |
| 7 | API | All endpoints in `API_SPECIFICATION.md` exist with integration tests. |
| 8 | Frontend | Six pages use live backend data. Lint, type checks and production build pass. |
| 9 | Completion | The real benchmark has been run, KPIs are independently recomputed, and README, TESTING and KNOWN_LIMITATIONS report actual results. |

## Status

Milestones 1 to 9 are implemented, with results in `TESTING.md`. Two things remain outside this build: benchmark runs with a real model, which needs Ollama installed, and a container-based test runner, which needs Docker. See `LIMITATIONS_AND_FUTURE_WORK.md`.

## Second phase: audit, ML assessor and external benchmark (2026-11-06)

| # | Milestone | Acceptance criteria | Status |
|---|---|---|---|
| 10 | Feature audit and fixes | `FEATURE_AUDIT.md` classifies every feature. The `ru07` failure and the Overview count are reproduced, fixed and covered by regression tests | Done |
| 11 | Datasets | InjecAgent provenance verified, schema profiled, adapted under a written policy, kept out of training. Native dataset generated with group-disjoint splits and leakage checks | Done |
| 12 | ML assessor | Text, structured and hybrid models trained with group-aware tuning, validation-only selection and thresholds, one logged test evaluation, and fail-closed loading | Done |
| 13 | Experiments | Configurations A–E plus the heuristic-with-history control, run on the internal suite and on InjecAgent, and independently recomputed | Done |
| 14 | Dashboard | Analytics merged into Experiments, Risk model page added, all values from the API, verified in the browser | Done |

The research question cannot be fully answered without real LLM agents. See `EXPERIMENT_RESULTS.md` for what the scripted experiments do and do not show.

## Proposal timeline mapping

| Proposal weeks | Proposal milestone | Plan milestone |
|---|---|---|
| 1-2 | Threat model, requirements, benchmark design | 1 |
| 3-4 | Baseline agent, simulated tools, sandbox | 2, 4 |
| 5-6 | Policy engine, secure execution | 3 |
| 7-8 | Contextual assessment, history | 5 |
| 9-10 | Dashboard, traces, experiment runner | 6, 7, 8 |
| 11-12 | Benchmark, threshold tuning, ablations | 6, 9 |
| 13-14 | Analysis, dissertation, demo | Done by the student, using the output of 9 |

## Main risks

| Risk | Mitigation |
|---|---|
| The same author writes the heuristic and the scenarios, which inflates results | Dev and holdout split. Tune on dev only, freeze, then report holdout separately. |
| Scripted agents make attack rates true by construction | Every run stores its provider. The UI and docs state what scripted results can and cannot show. |
| The guard grades itself | Ground truth comes from scenario labels, the executor ledger, canaries and workspace hashes, not guard decisions. |
| A prompt injection reaches the LLM assessor | The assessor can only tighten. Its output is schema-validated, and it never runs on a policy deny. |
| Code execution through `write_file` then `run_tests` | `run_tests` does not execute code. |
