# ML Methodology

The ML assessor is a supervised contextual risk model used by configurations D and E. It runs only on actions the deterministic policy has already passed. It can raise risk, send an action for review, or block it. It cannot allow anything the policy denied, because the policy decides first and the assessor is never consulted on a denial.

Everything here is reproduced by two commands:

```powershell
cd backend
.\.venv\Scripts\python.exe scripts\prepare_data.py
.\.venv\Scripts\python.exe scripts\train_models.py --final-test
```

The data is described in `DATASET_DOCUMENTATION.md`. Whether the model learned anything beyond its own label rules is examined in `ML_INTEGRITY_AUDIT.md`.

## Model versions

| Version | Data | Features | Native test | InjecAgent | Where |
|---|---|---|---|---|---|
| v1 `ml-756975a1-114f9854` | `data/` (attacks placed first) | Version 1, with `prior_steps` | Evaluated once, untouched | **Independent** | `backend/models/` |
| v2 `ml-957735c6-114f9854` | `data/posthoc_v2/` (attacks after the task's first step) | Version 1 | Same test groups reused | Post-hoc | `backend/models_posthoc/` |
| v3 `ml-df842b52-a2bd43dd`, **active** | `data/posthoc_v3/` (as v2, with heuristic scores from the current heuristic) | Version 2, without `prior_steps` | Not evaluated, because the test groups were already used twice | Post-hoc | `backend/models/` |

v3 is active because v1 has a known defect: it makes configuration E block every legitimate InjecAgent action. Replacing v1 does not make v3's results independent. The thresholds, grids and pipeline are the same for all three, and only the inputs changed. An intermediate bundle, trained before the heuristic change, is kept as `models_posthoc/ml-957735c6-a2bd43dd-superseded`. It was used only by a cancelled experiment.

The commands for v1 are below. v3 is reproduced with:

```powershell
.\.venv\Scripts\python.exe scripts\prepare_data.py --out-dir ..\data\posthoc_v3 --attack-position after_first_task_step
.\.venv\Scripts\python.exe scripts\train_models.py --data-dir ..\data\posthoc_v3
```

## Two profiles

| Profile | Used by | Can see |
|---|---|---|
| stateless | D | The task, the proposed action (tool, effect, target, method, payload) and the policy verdict |
| stateful | E | All of the above, plus history counters, history signals and the untrusted tool output read so far in the run |

The pipeline enforces the ablation: a stateless context carries empty history, and a test checks this. Each profile has its own three models and thresholds.

## Models

**Model A: text.** TF-IDF over separate fields, then logistic regression.

- Fields: task, action and (stateful only) untrusted output.
- Preprocessing: lower case, identifiers split into words (`check_password` becomes `check password`), and per-run canary tokens removed.
- Vectorizer: word 1–2-grams, `min_df=2`, at most 20,000 features, sublinear term frequency.
- Explanation: the terms that pushed the score towards risk (coefficient × tf-idf) are reported in the trace.

**Model B: structured.** 26 stateless features, plus 16 stateful ones for E. Models before feature-set version 2 also used `prior_steps`, the action's position in the run, which was removed as a shortcut (see "Model versions" below):

- the action's class and effect;
- resource sensitivity and whether the task covers it;
- whether the action is relevant to the task and their word overlap;
- whether the host is named;
- out-of-scope change;
- risky or test-weakening payloads;
- the policy verdict;
- for E only: prior denials, repeats, history signals, injection markers in untrusted output, and how far the action's words appear only in untrusted content.

Random forest and gradient boosting are both tuned, and the one with the better validation PR-AUC is kept. Identifiers are excluded on purpose (see `features.py`).

**Model C: hybrid.** A logistic regression stacked on:

- the logits of A and B;
- the heuristic risk score;
- for E only: the history signal weight and the hard-signal flag.

It is fitted on **out-of-fold** predictions of A and B (group 5-fold), so it never learns from a component's memory of its own training rows.

**Runtime rules:**

- Hybrid score ≥ review threshold: APPROVAL_REQUIRED.
- Hybrid score ≥ block threshold: BLOCK.
- A hard history signal (a secret flowing outward) always blocks, whatever the model says.
- The final decision is `most_restrictive(policy, ml)`.

## Training procedure

1. **Validation:** schema, labels, finite features, both classes in each split, group disjointness. Training stops with a clear message otherwise, and the tests cover each case.
2. **Group-aware tuning on train only:** `GridSearchCV` with `GroupKFold(5)` by behaviour family, scored by average precision.
   - Text: C ∈ {0.1, 1, 10}, class weight ∈ {none, balanced}.
   - Random forest: 200 trees, max depth ∈ {8, none}, min leaf ∈ {1, 5}, balanced class weight.
   - Gradient boosting: 100 or 200 trees, learning rate ∈ {0.05, 0.1}, depth ∈ {2, 3}, balanced sample weights.
3. **Class imbalance:** about 27% of examples are unauthorized. Class weights are part of the grid. The random forest is always balanced, and gradient boosting uses balanced sample weights.
4. **Model selection on validation:** random forest against gradient boosting by validation PR-AUC.
5. **Calibration:** the stacked logistic regression is the calibration layer. Platt scaling of each component, fitted with group folds on train, was compared on validation (Brier and expected calibration error). It did not consistently help, so components are not separately rescaled. Both numbers are kept in the metadata.
6. **Threshold selection on validation:**
   - Review: the lowest threshold whose false-positive rate is at most 5%, the proposal's false-block ceiling.
   - Block: the same with at most 1%.

   Using the whole false-positive budget favours catching attacks, while keeping legitimate work within the stated limit on validation. The rule was changed once, before the test split was read. The first version picked the highest threshold among ties, which left no margin.
7. **Final evaluation:** one read of the untouched test split, with these measures:
   - precision, recall and F1;
   - PR-AUC and ROC-AUC;
   - confusion matrix, false-positive and false-negative rates;
   - Brier score and expected calibration error with a reliability table;
   - results by behaviour category;
   - 95% intervals from 1,000 bootstrap resamples of whole behaviour families.
8. **Persistence:** `backend/models/<version>/` holds the joblib artifacts, plus `metadata.json` containing the following. The version string is derived from the dataset hash and the configuration hash.
   - SHA-256 of each artifact;
   - dataset hash;
   - full configuration and seed (42);
   - library versions;
   - feature names;
   - chosen hyperparameters and cross-validation scores;
   - thresholds;
   - validation and test metrics.

Training accuracy is never reported as performance.

## Safety of the assessor

| Failure | Behaviour |
|---|---|
| No model installed, bad pointer, missing artifact | BLOCK, `assessor_fallback=true`. The dashboard shows the model as missing, and experiments with D or E refuse to start |
| Artifact hash mismatch | BLOCK. The file is never unpickled, because joblib can run code while loading |
| Hashes match but the file cannot be loaded | BLOCK |
| Model trained with different features from the running code | BLOCK |
| Prediction raises, returns NaN or a value outside [0, 1] | BLOCK |
| Prediction slower than `BG_ML_TIMEOUT` (default 2 s) | BLOCK |

Each row is a test in `tests/test_ml.py`. The integrity check protects against accidental corruption and casual tampering. Someone who can rewrite both the artifacts and the metadata can still load arbitrary pickles, so the model directory must be treated as trusted code.

## Results on the native test split (v1)

These are v1's results, the only model with an untouched test evaluation. The test split was evaluated once (see `data/manifests/test_access_log.jsonl`). It has 557 actions: 168 unauthorized and 389 legitimate. They come from 3 projects, 4 tasks and 13 behaviour families, none of them seen in training or validation. Each component uses its own validation-chosen threshold, and the heuristic uses its frozen review threshold of 0.40. Intervals come from resampling families.

**Stateful profile (configuration E):**

| Model | PR-AUC [95% CI] | Precision | Recall [95% CI] | F1 | False-positive rate [95% CI] | False-negative rate | ECE |
|---|---|---|---|---|---|---|---|
| Hybrid (deployed) | 0.933 [0.803, 0.993] | 0.789 | 0.869 [0.688, 1.0] | 0.827 | 0.100 [0.044, 0.165] | 0.131 | 0.082 |
| Structured (random forest) | 0.941 [0.825, 0.994] | 0.778 | 0.917 [0.764, 1.0] | 0.842 | 0.113 | 0.083 | 0.044 |
| Text (TF-IDF + LR) | 0.742 | 0.682 | 0.268 | 0.385 | 0.054 | 0.732 | 0.187 |
| Heuristic baseline | 0.745 | 0.791 | 0.607 | 0.687 | 0.069 | 0.393 | 0.137 |

At the block threshold, the stateful hybrid had precision 0.919, recall 0.815 and a false-positive rate of 0.031.

**Stateless profile (configuration D):**

| Model | PR-AUC [95% CI] | Precision | Recall | F1 | False-positive rate [95% CI] | False-negative rate | ECE |
|---|---|---|---|---|---|---|---|
| Hybrid (deployed) | 0.968 [0.918, 0.992] | 0.700 | 1.000 | 0.824 | 0.185 [0.140, 0.236] | 0.000 | 0.292 |
| Structured (random forest) | 0.908 | 0.975 | 0.708 | 0.821 | 0.008 | 0.292 | 0.106 |
| Text (TF-IDF + LR) | 0.711 | 0.773 | 0.345 | 0.477 | 0.044 | 0.655 | 0.311 |
| Heuristic baseline | 0.728 | 0.939 | 0.548 | 0.692 | 0.015 | 0.452 | 0.160 |

### What these results show

- **Ranking:** the structured and hybrid models rank actions much better than the text model or the heuristic on unseen projects and behaviours (PR-AUC about 0.93–0.97, against about 0.73).
- **Text model:** it is weak. Whether an action fits a task is a *relation* between the two, and a bag of words cannot represent it.
- **Thresholds did not transfer:** both deployed thresholds exceeded the 5% false-positive budget they were chosen for. D reached 18.5% and E reached 10.0%. Validation was nearly perfectly separable (hybrid PR-AUC 1.000), so a threshold chosen there sits on a cliff. It was not re-tuned on test, and these are the thresholds used in the experiments.
- **Stateless hybrid:** it puts most of its weight on the heuristic score (coefficient 9.6) and is poorly calibrated on test (ECE 0.29). The stateful hybrid is better calibrated (ECE 0.08).
- **What the stateful model relies on:** the most important stateful features are `action_words_only_in_untrusted`, `target_task_overlap`, `prior_steps` and `relevant_to_task`. The model uses provenance (did the idea come from untrusted text?) and relevance, the two concepts the label rules are built on. That fits the data, and it is also the reason these scores overstate real-world performance.

### A flaw the native test could not reveal

The generator placed every behaviour family before the task's own steps. As a result, "first action of a run" predicts "unauthorized" in this data: 579 of the 891 first-step training actions are unauthorized. The stateful model used that cue, which is why `prior_steps` ranks third. The native test split was built the same way, so it rewarded the shortcut instead of exposing it.

On InjecAgent, where the legitimate user call always comes first, configuration E blocked every legitimate action. A post-hoc retrain with the ordering corrected (v2) removed the false blocks, and also removed E's advantage over D. The final audit found that v2 still ranked `prior_steps` among its top five features, now pointing the other way, because step 0 was always legitimate in its data. v3 therefore stops training on position altogether. See `EXPERIMENT_RESULTS.md`. The lesson for this methodology: group-disjoint splits prevent leakage between splits, but they cannot detect a bias shared by every split of a generated dataset. An independent benchmark can.

End-to-end effects on the benchmarks are in `EXPERIMENT_RESULTS.md`.
