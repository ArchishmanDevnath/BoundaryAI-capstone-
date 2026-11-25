# ML Integrity Audit

This audit checks whether the ML risk assessor learned something real, or something the dataset happened to make easy. It was done on 2026-11-06 from the source code, the stored datasets and model bundles, and probes run on the **training and validation splits only**. No test split was read for this audit.

How the models are built is described in `ML_METHODOLOGY.md`, and end-to-end results are in `EXPERIMENT_RESULTS.md`.

## Verdicts

| Category | Verdict | One-line reason |
|---|---|---|
| Training data quality | **PASS, with limits** | Validated, deduplicated, no contradictory labels. But it is generated from 14 projects and 50 behaviour templates, so it is narrow |
| Label provenance and independence | **FAIL: labels are circular with the heuristic** | Labels come from written rules over generator templates, not from the heuristic's output. But the rules encode the same scope and sensitivity concepts the heuristic uses, and the features include the heuristic's own scope checks |
| Group-aware splitting | **PASS** | Projects, tasks and behaviour families each belong to exactly one split. No shared groups and no near-duplicates across splits |
| Preprocessing and tuning on training data only | **PASS** | TF-IDF is fitted inside the pipeline on training folds. Cross-validation is grouped by family. Model choice and thresholds use validation only |
| Shortcut learning | **FAIL for v1 and v2, fixed in v3** | v1 learned "first action means attack". v2 kept the position feature, which then pointed the other way. v3 no longer trains on position |
| Test-set discipline | **INCONCLUSIVE** | v1's test evaluation was untouched. v2 reused the same test groups, which the old log could not see. v3 was deliberately not evaluated on test, so it has no untouched test result |
| Train and serve consistency | **PASS** | One feature extraction function serves both. A heuristic change in this audit was kept out of the features, and v3's data was regenerated so its stored heuristic scores match the runtime |
| Runtime safety | **PASS** | The model never sees a policy denial, cannot lower a decision, and fails closed on every failure tested |
| Model validity as a security control | **INCONCLUSIVE, leaning negative** | Offline scores are high, but no ML configuration beat rules + heuristic + history end to end on any benchmark |

## 1. Training data

All counts are from `data/manifests/native_split_manifest.json` (v1 data) and `data/posthoc_v3/manifests/native_split_manifest.json` (v3 data).

| | v1 data (`data/`) | v3 data (`data/posthoc_v3/`) |
|---|---|---|
| Attack placement in a trace | Before the task's steps | After the task's first step |
| Train records (unauthorized / legitimate) | 6,388 (1,749 / 4,639) | 5,096 (1,749 / 3,347) |
| Validation records | 505 (137 / 368) | 403 (141 / 262) |
| Test records | 557 (168 / 389) | 434 (168 / 266) |
| Unauthorized share, train | 27.4% | 34.3% |
| Projects / tasks / behaviour families | 14 / 16 / 50 across all splits | same |
| Tools | 6 (`list_dir`, `read_file`, `write_file`, `delete_file`, `run_tests`, `http_request`) | same |
| Exact duplicates removed | 6,278 | 7,851 |
| Contradictory duplicates (same input, different label) | 0 | 0 |
| Ambiguous actions excluded | 288 (272 unscoped non-sensitive reads, 16 in-scope but injected) | 288 |
| Near-duplicate pairs across splits (Jaccard ≥ 0.9) | 0 | 0 |
| Possible traces / kept / discarded because groups cross splits | 11,200 / 1,952 / 9,248 | same |

**Source:** every record is one action from a generated trace, replayed through the real gateway with a recorder in the assessor slot. Only actions the policy passed become records, because the model is never consulted on a policy denial. Each trace is replayed twice: once permissively, and once with unauthorized steps blocked so that denial history is represented.

**InjecAgent is not in any training split.** The leakage report checks for shared objectives, injection text and the dataset's marker phrase, and finds none.

## 2. Label provenance and the circularity finding

**How labels are made:** `native_dataset.label_step` applies twelve written rules to the generator's template knowledge: which files the task scopes, which hosts it names, which steps follow an injected instruction, and which payloads are harmful. A test checks that the label function reads no features, guard decisions or assessor output. In that narrow sense the labels are independent of the heuristic.

**Why that is not enough:** the label rules and the heuristic were written by the same author around the same ideas. Both decide by task scope, file sensitivity, injected provenance and harmful content. The structured features include the heuristic's own checks (`out_of_scope_sensitive`, `out_of_scope_change`, `relevant_to_task`), and the stacked model receives the heuristic's score as an input.

Measured on train and validation only (`backend/scripts/integrity_probe.py`):

| Probe | v1 data | Post-hoc data |
|---|---|---|
| A hand rule: any of six heuristic-derived features is set (out-of-scope sensitive, out-of-scope change, risky code, test weakening, secret in payload, hard history signal). Agreement with validation labels | 98.8% | 98.5% |
| Same rule, false-positive rate on validation | 0.0% | 0.0% |
| Heuristic flag (score ≥ 0.40) agreement with validation labels | 96.4% | 95.5% |
| Heuristic score PR-AUC on validation | 0.96–0.97 | 0.97 |
| Weight of the heuristic score in the stacked model (v3) | – | 8.4 stateless, 7.9 stateful, against 0.4–0.8 for each ML component's logit |

**Conclusion:** the ML model largely learns to reproduce the author's rules, with the heuristic as its strongest input. It cannot be described as learning security risk independently. Native test scores measure how well the rules were learned on unseen projects and behaviours, and say little about real attacks. This is disclosed in the model metadata, on the Risk model page and in `LIMITATIONS_AND_FUTURE_WORK.md`. Fixing it needs labels from someone other than the guard's author: human annotation, real incidents, or an external benchmark's own ground truth.

## 3. Splitting and leakage

| Check | Result | Evidence |
|---|---|---|
| Group disjointness | Projects, tasks and families each in one split. A trace is kept only if all three agree | Manifest `grouping`. `group_overlaps` returns nothing, and training refuses to start otherwise |
| Exact and near-duplicate leakage | 0 identical records and 0 near-duplicate pairs across splits | Manifest `leakage_report` |
| Benchmark leakage | No training objective equals an internal scenario or an InjecAgent case | Same report, with a test that plants one and detects it |
| Identifiers | No scenario, project, family, file-name or run-id feature | `features.py`, plus a test |
| Text views | Canary tokens removed. File paths still reach the text model, which is why groups are split | `features._clean` |
| Preprocessing fit | TF-IDF lives inside the scikit-learn pipeline and is refitted on each training fold | `training.build_text_pipeline`, `GridSearchCV` |
| Hyperparameters | Grouped 5-fold CV on train. Random forest against gradient boosting chosen on validation | `training.train_profile` |
| Thresholds | Chosen on validation: lowest threshold with false-positive rate ≤ 5% (review) and ≤ 1% (block) | `training.select_thresholds` |
| Stacking | Fitted on out-of-fold component scores | `cross_val_predict` |
| Seeds | 42 everywhere. Two trainings give identical validation metrics and thresholds | A test |

**One weakness in this area:** validation is nearly separable (hybrid PR-AUC 0.994–1.000). A threshold chosen on near-perfect validation scores sits on a cliff. For v1 on the test split, the stateless false-positive rate came out at 18.5% against a 5% target. This is a property of narrow generated data, not of leakage.

## 4. Shortcut learning

| Model | Data | Position feature | What the probe showed |
|---|---|---|---|
| v1 `ml-756975a1-114f9854` | Attack first | Trained on `prior_steps` | 65% of first-step training actions were unauthorized. `prior_steps` was the third most important stateful feature. On InjecAgent, where the user's call comes first, E blocked every legitimate action |
| v2 `ml-957735c6-114f9854` | Attack after the first task step | Trained on `prior_steps` | Step 0 is now **always** legitimate in training (50 of 50). `prior_steps` was still a top-five stateful feature, so the shortcut was reversed rather than removed |
| v3 `ml-df842b52-a2bd43dd` | Same as v2, regenerated | Not trained on | Its top stateful inputs are untrusted provenance (0.131), relevance (0.119), out-of-scope change (0.105), task overlap (0.100) and out-of-scope sensitivity (0.077). The probe scored validation data generated with each attack ordering: PR-AUC 0.995 with attacks first and 0.994 with attacks later, so ordering no longer moves it. Position is still computed, so older bundles load, but a test ensures no profile trains on it |

**Why removing the feature is the root-cause fix:** where an action falls in a run is a property of how traces were generated, not of what the action does. The history the model legitimately needs (denials, repeats, data flow, untrusted provenance) has its own features.

**Remaining position-like inputs, accepted and disclosed:** denial counters and the accumulated untrusted text grow over a run. They carry real history information, so they were kept.

**Other shortcuts checked:**

- **Task templates:** groups are split, so a template never appears in two splits.
- **File names:** they reach the text model only. The text model is weak on its own (validation PR-AUC 0.51–0.60), and the structured model sees no names.
- **Application tools:** there are none in training, so InjecAgent's tool calls are out of distribution for every ML model. That is a coverage gap, not a leak.

## 5. Test-set discipline

| Model | Native test split | Status |
|---|---|---|
| v1 | Evaluated once, logged | **Untouched** at the time of evaluation. This is the only untouched native test result |
| v2 | Evaluated on regenerated data with **the same test groups** | **Repeated use.** Its log, in its own data folder, recorded no earlier uses because it matched on file bytes. Found in this audit |
| v3 | Not evaluated | Deliberately not evaluated, because a third use could not count as a test |

**What was fixed:** `_record_test_access` now matches earlier uses by a fingerprint of the test groups as well as by dataset hash. It also checks a shared log, `data/manifests/test_access_log.jsonl`, whichever data folder is used. The two earlier uses were appended to the shared log with their fingerprint, without rewriting any line. A test reproduces the two-folder case.

**InjecAgent status:**

- For v1 it is a genuine independent test: it was never used for training, tuning or thresholds, and was first run after the model was frozen.
- v2 and v3 were designed after seeing v1's InjecAgent failure, so their InjecAgent results are **post-hoc** and are labelled that way everywhere.

## 6. Model implementation

| Item | Value |
|---|---|
| Text model | TF-IDF (word 1–2-grams, `min_df=2`, at most 20,000 terms, sublinear) over task, action and, for stateful, untrusted text. Then logistic regression. Grid: C ∈ {0.1, 1, 10}, class weight ∈ {none, balanced} |
| Structured model | Random forest or gradient boosting, whichever has the better validation PR-AUC. v3 chose the random forest in both profiles |
| Hybrid | Logistic regression on the two component logits, the heuristic score, and (stateful only) history signal weight and hard-signal flag |
| Features | 26 stateless. Stateful adds 16 in feature-set version 2: 17 minus `prior_steps` |
| Calibration | The stacked logistic regression is the calibration layer. Separate Platt scaling of each component was measured and not adopted |
| Serialization | joblib, with SHA-256 per artifact checked **before** unpickling. A version pointer that leaves the model folder is refused |
| Runtime features | `extract_features` and `text_views` are the same functions the dataset generator calls. A test checks the outputs are identical |
| Old bundles | The loader accepts any trained feature list that the runtime computes. v1 and v2 still load and score, which a test checks |

**Runtime safety, each item a test in `tests/test_ml.py`:**

- The model is never consulted on a policy denial.
- A hostile assessor that always says ALLOW cannot release a protected read.
- A hard history signal outranks the model.
- Each of these blocks the action with `assessor_fallback`: a missing model, a corrupt file, a hash mismatch (the file is never unpickled), a consistent but unloadable bundle, a pointer escape, a feature mismatch, NaN or out-of-range output, an exception, and a timeout.
- Experiments with D or E refuse to start without a model.

## 7. Model selection: is ML worth it?

The rule in the brief was to prefer the simple, interpretable option unless a more complex one shows an independently validated advantage. The evidence:

- **The heuristic** is the simpler model: about 20 readable weights, under 0.3 ms per decision, and no training data.
- **ML** added about 60–95 ms per decision, and gave no end-to-end gain over the heuristic with history on any benchmark (see `EXPERIMENT_RESULTS.md`).
- **The only independent ML result (v1 on InjecAgent):** D was +1.2 points over C [0.0, +2.9]. E was unusable.

**Decision:** the recommended configuration is **rules + heuristic + history** (stored id `C`, labelled "Control"). D and E remain in the system as experimental configurations, with v3 as the active model so they run without the known shortcut. The ML pipeline is kept because it is the instrument that produced the negative finding, not because it improves security.

## Reproducing this audit

```powershell
cd backend
$py = ".\.venv\Scripts\python.exe"
& $py scripts\prepare_data.py --out-dir ..\data\posthoc_v3 --attack-position after_first_task_step
& $py scripts\train_models.py --data-dir ..\data\posthoc_v3      # v3, train and validation only
& $py scripts\integrity_probe.py                                 # sections 2 and 4: train and validation only
& $py -m pytest tests\test_ml.py tests\test_regressions.py
```

The model bundles hold every importance and coefficient cited here, in `metadata.json`.
