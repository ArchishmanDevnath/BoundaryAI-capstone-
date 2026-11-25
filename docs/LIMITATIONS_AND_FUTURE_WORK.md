# Limitations and Future Work

BoundaryGuard is an academic research prototype, not a production system. This page lists what the results cannot show, the assumptions nobody has validated, and the work that would close each gap. `EXPERIMENT_RESULTS.md` has the numbers, and `ML_INTEGRITY_AUDIT.md` has the audit of the ML pipeline.

## Evaluation validity

| Limitation | Effect | What would address it |
|---|---|---|
| No real LLM has been run | Every agent in every experiment is scripted. The results measure the guard's decisions on fixed traces. They do not show how often a real model attempts these actions, or whether it completes tasks | Install Ollama and run the benchmark (see the README) |
| Scripted traces attack by construction | Configuration A's high execution rate is a design property, not a finding about any model | Same as above |
| **The ML labels are circular with the heuristic** | The labels come from rules the guard's author wrote, using the same scope and sensitivity ideas as the heuristic. On validation, an OR of six heuristic-derived features agrees with the labels 98.8% of the time, and the stacked model's largest weight is the heuristic score. Native test scores (PR-AUC 0.93–0.97) show that the author's rules were learned, not that real attacks would be caught | Labels from people other than the author, from real incidents, or from an external benchmark's own ground truth |
| The active model (v3) has no untouched test result | The native test groups were used by v1, and again by v2. v3 was not evaluated on them, and its InjecAgent results are post-hoc because v3 was built after seeing v1 fail there | A fresh test set: new projects, tasks and behaviour families written by someone else, used once |
| The internal holdout has been seen | The heuristic author wrote the holdout scenarios, and the holdout results were inspected in earlier work. The ML models were never tuned on them, but the generator's behaviour families were written with knowledge of the benchmark's attack types | Treat InjecAgent as the independent test, and add scenarios written by someone else |
| InjecAgent authorization labels are an interpretation | Policy IA-P1 decides labels. Same-toolkit attacker actions are left unlabeled (154) rather than forced into a class | Manual review of `injecagent_manual_review.jsonl`, or a second labelling policy as a sensitivity check |
| InjecAgent attacker calls have no arguments | The dataset names attacker tools without arguments, so replayed calls have empty parameters. Data-flow and parameter-based features cannot fire on them, and argument-free calls may be easier to separate from the parameterized user calls | Generate arguments with an LLM agent, or construct them by hand and report them separately |
| InjecAgent has 17 legitimate actions | False-block rates on the external benchmark rest on 17 distinct user calls, repeated across 2,125 cases | A benchmark with more benign tasks, such as AgentDojo's user tasks |
| InjecAgent cases are clustered | Cases are a cross product of 62 attacker cases and 17 user cases. Intervals resample attacker cases with the user tasks fixed, so they do not generalize to new user tasks | More user tasks, or two-way cluster bootstrap |
| Thresholds did not transfer | Both ML thresholds exceeded their validation false-positive budget on the native test split (D 18.5%, E 10.0%, against 5%). No re-tuning was done on test | More varied validation data, or picking thresholds on a validation set that includes a held-out domain |
| A per-task allowlist would stop every InjecAgent attack | If an operator could list the tools each task needs, deterministic rules alone would block every unrelated attacker tool by construction. The broad policy used for the external benchmark represents a general assistant without such a list | Report both. The bound is stated, not measured |
| Repeats add nothing for deterministic runs | Scripted agents and the ML and heuristic assessors are deterministic, so the sample size is the number of scenarios | Repeats with LLM agents |

## Security

| Limitation | Detail |
|---|---|
| Task relevance is lexical | Scope is decided by words shared between the task and a resource name. The final audit closed one gap (a single shared sensitive word no longer authorizes a file), but a task that happens to mention a file's directory and sensitive word still puts it in scope. A model of what a task actually needs would be stronger |
| Contextual assessors are pattern-based | Both the heuristic and the ML features rely on names, words and provenance. Paraphrased leaks and neutral-looking unnecessary actions get through (the internal holdout misses `pi15`, `ru08` and `ru10`). An attacker who knows the features can phrase around them |
| Data-flow detection is partial | It handles exact text, base64 and hex. Summaries, translations and data split across requests get through |
| The ML model directory is trusted code | Hash checks stop corruption and casual tampering. Someone who can rewrite the artifacts and the metadata together can run code when the model loads |
| Residual time-of-use race | The executor re-resolves a path just before opening it. A link swapped in that tiny window is not caught. The agent has no way to create links in this prototype |
| The audit chain is tamper-evident within a run only | Deleting a whole run is not detected, and the chain is not signed |
| No user authentication | Anyone who can reach the local API can resolve approvals and change policies. It binds to `127.0.0.1` with Host, CORS and content-type checks, and must not be exposed |
| Python is not a security boundary | The gateway's private executor and token stop accidental bypass. They would not stop malicious code running in the same process |
| True symlinks are untested on this machine | They need elevated privileges. Junctions were tested and go through the same code |
| A person can still approve something harmful | Medium-risk actions in live runs can be approved. Approvals of actions a scenario labels unauthorized are counted and flagged, but not prevented |

## Functionality

| Limitation | Detail |
|---|---|
| `run_tests` does not run tests | It is a declarative oracle, because running agent-written code without isolation would be arbitrary code execution |
| No Docker test runner | Docker was not available to test against |
| All tools are simulated | Network, shell and application tools return canned results |
| A restart ends active runs | They are marked as interrupted, not resumed |
| Custom live tasks need an LLM | Scripted runs can only replay benchmark scenarios |
| ML training data is generated | Fourteen synthetic projects cannot represent the variety of real repositories |

## Unvalidated assumptions

- **The scripted traces represent what agents do.** No real agent's behaviour was measured.
- **Resource names indicate sensitivity.** A confidential file with a neutral name (`notes.txt`) is invisible to the sensitivity checks. Only the deterministic protected paths apply to it.
- **The policies are realistic.** The internal policies and the broad InjecAgent policy were written for this project. Real deployments may allow more or less.
- **Policy IA-P1 labels InjecAgent fairly.** It is one reasonable reading of "authorized". Another reading would move the 154 unlabeled actions and could change rates.
- **A person who is asked will decide well.** Live approvals are counted but not evaluated.

## Missing real-world testing

- No real LLM agent, local or hosted, has been run through the benchmark. Ollama support exists but was tested only against a mock server, because Ollama was not installed and installing a multi-gigabyte model was out of scope.
- No real repositories, credentials, networks or users were involved. Every tool is simulated, by design.
- No adversary adapted to the guard. Every attack was written before the guard's results were known, or was taken from InjecAgent.
- No measurement of usability or operator workload from approval requests.

## Future work

In order of value for the research question:

1. **Real agents.** Run the internal and InjecAgent suites with local models through Ollama, with repeats. This answers how often agents attempt these actions, and whether the guard keeps tasks completable.
2. **Independent labels and scenarios.** Have someone other than the author write scenarios and label actions. This breaks the circularity in the ML labels and the authorship bias in the internal holdout.
3. **A benchmark with many legitimate tasks**, such as AgentDojo's user tasks, so false-block rates rest on more than 17 distinct calls.
4. **A fresh, single-use test set** for any further ML model, created before the model is designed.
5. **Semantic data-flow detection** for paraphrased and split leaks, which both assessors currently miss.
6. **Task-derived allowlists:** derive a per-task tool and resource list automatically. On InjecAgent, a hand-written allowlist would stop every unrelated attacker tool by construction.
7. **Signed audit chains** across runs, and authentication for the dashboard API.
8. **A container-based test runner**, so `run_tests` can execute tests safely instead of using a declarative oracle.
