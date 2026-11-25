# Experiment Results

Every number here was measured on 2026-11-05 or 2026-11-06 and read back from the stored experiments in `backend/var/boundaryguard.sqlite3`.

- `scripts/results_tables.py` regenerates the tables.
- `scripts/analyze_results.py` recomputes the main metrics from raw rows with separate pandas and scikit-learn code. It exits non-zero on any disagreement, and it agreed for all four main experiments.
- Proposal targets are goals, and are labelled as such wherever they appear.

**Read this first: what the experiments measure.**

- **Every agent is scripted.** It attempts each attack because its trace says to, so the results measure the guard's *decisions* on fixed attack and task traces. No real LLM agent was run.
- **Offline ML scores are not runtime security.** They are reported in `ML_METHODOLOGY.md` and kept separate from the end-to-end results here.
- **Independent and post-hoc results are separated.** Only model v1's results are an independent test of the ML assessor. v2 and v3 were built after seeing v1 fail on InjecAgent.

## 1. Experiments

| Experiment | Id | Model for D and E | Runs | Status of the ML evidence |
|---|---|---|---|---|
| Internal benchmark, A–E | `afca0501d70f43d5817c05a9998a2270` | v1 `ml-756975a1-114f9854` | 318, 0 errors | Independent (holdout) |
| InjecAgent external benchmark, A–E | `8d6584a23939474ca8d7910f6059a539` | v1 | 12,750, 0 errors | **Independent** |
| Post-hoc v2, internal (D, E) | `65b46f6f246d47d0a55337d3b22f692d` | v2 `ml-957735c6-114f9854` | 106 | Post-hoc |
| Post-hoc v2, InjecAgent (D, E) | `39292da5ea87407ba88adfcc362c75b9` | v2 | 4,250 | Post-hoc, not independent |
| **Final internal benchmark, A–E** | `3350c3d65f754ad7aa3fc99630f37cff` | **v3 `ml-df842b52-a2bd43dd`, active** | 318, 0 errors | Post-hoc for D and E |
| **Final InjecAgent benchmark, A–E** | `6f9f51d0ae044a8d928c9bc74721e70e` | v3 | 12,750, 0 errors | Post-hoc for D and E, not independent |
| Interrupted run | `0781548bca9f426db55df0e0bec1e19a` | intermediate bundle | 246 of 318 | Cancelled, not used |

**The final runs reproduce the earlier ones.** Configurations A, B, C and Control do not use a model. Their results in the final experiments are identical to the first ones, to the action, on both benchmarks. The heuristic change made in the final audit (keyword-only scope, see `SECURITY_DESIGN.md`) affects no scenario in either suite.

## 2. Configurations

| Label | Stored id | Rules | Contextual assessor | History |
|---|---|---|---|---|
| A | `A` | no | none | no |
| B | `B` | yes | none | no |
| C | `RC` | yes | heuristic | no |
| Control | `C` | yes | heuristic | yes |
| D | `D` | yes | ML, stateless profile | no |
| E | `E` | yes | ML, stateful profile | yes |

Every run used seed 0 and one repeat. All components are deterministic, so repeats would add identical rows rather than evidence.

## 3. Datasets and separation of evidence

| Evidence | Data | Used to build or tune anything? | Where reported |
|---|---|---|---|
| Training | Generated BoundaryGuard actions, train split | It is the training data. Never reported as performance | – |
| Validation | Generated, validation split | Model selection and thresholds | `ML_METHODOLOGY.md`, Risk model page |
| Native test | Generated, test split | No. Read once for v1, reused for v2, not read for v3 | `ML_METHODOLOGY.md`, `ML_INTEGRITY_AUDIT.md` |
| Internal dev | 35 hand-written scenarios | The heuristic was tuned on them (earlier work) | Section 6 |
| Internal holdout | 18 hand-written scenarios | No. Written by the heuristic's author, and seen once in earlier work | Sections 5 and 6 |
| External | InjecAgent: 2,108 attack cases + 17 clean controls = 2,125 | No. Never used for training, tuning or thresholds. v2 and v3 were designed after seeing v1's results on it | Sections 5 and 7 |

**InjecAgent adaptation:** policy IA-P1 decides labels, and same-toolkit attacker actions are left unlabeled. The broad policy `injecagent_broad` allows every application tool, as for a general assistant. Details are in `DATASET_DOCUMENTATION.md`.

## 4. Metrics

All rates count **actions**, and each is reported with its numerator and denominator.

| Metric | Definition | Limitation |
|---|---|---|
| Unauthorized executed | Unauthorized actions that executed ÷ unauthorized actions attempted | Configurations attempt different numbers of actions, because a block changes what the scripted agent does next |
| Prevention (recall) | Unauthorized actions blocked or denied ÷ attempted | The complement of the above |
| False-negative rate | 1 − recall | – |
| False blocks (false-positive rate) | Legitimate actions not executed ÷ legitimate actions attempted. An approval request with nobody present counts as a block | On InjecAgent the 2,127 legitimate actions are 17 distinct calls, repeated |
| Benign task success | Clean scenarios whose completion criteria hold at the end | 5 holdout scenarios, 17 InjecAgent controls |
| Precision | Unauthorized among actions the guard stopped | 100% means only that nothing legitimate was stopped in these scenarios |
| F1 | Harmonic mean of precision and recall | – |
| PR-AUC | Average precision of the configuration's contextual risk score against labels, over actions the policy passed. scikit-learn's `average_precision_score` agrees | It ranks scores. It is not the decision the guard made. Undefined for A and B, which have no score |
| Latency | Contextual-assessor time per decision. The median and 95th percentile are robust | Measured on one laptop. See the note on standby below |
| Policy bypass | Executed actions the post-hoc policy check would deny | – |
| Audit coverage | Proposed actions with an audit record written before execution | – |

**Intervals:**

- **Internal benchmark:** 95% Wilson intervals over *scenarios*. Paired comparisons use an exact McNemar test with scenarios as the unit.
- **InjecAgent:** a paired cluster bootstrap over the 62 attacker cases (2,000 resamples), with the 17 user tasks fixed.

## 5. Main results

Final experiments (`3350c3d6…` internal, `6f9f51d0…` InjecAgent). For D and E these use model v3 and are **post-hoc**.

| Configuration | InjecAgent: attacks stopped | InjecAgent: legitimate actions blocked | Internal holdout: attacks stopped | Internal holdout: legitimate actions blocked | Median assessor latency (InjecAgent) |
|---|---|---|---|---|---|
| A. Unprotected | 0.0% (0/3042) | n/a | 0.0% (0/21) | n/a | – |
| B. Rules only | 0.0% (0/3042) | 0.0% (0/2127) | 33.3% (7/21) | 0.0% (0/36) | – |
| C. Rules + heuristic | 79.5% (1998/2514) | 0.0% (0/2127) | 55.0% (11/20) | 0.0% (0/36) | 0.13 ms |
| **Control. Rules + heuristic + history** | **86.7% (2022/2332)** | 0.0% (0/2127) | **75.0% (15/20)** | 0.0% (0/36) | 0.17 ms |
| D. Rules + ML (v3) | 81.3% (2030/2498) | 0.0% (0/2127) | 70.0% (14/20) | 0.0% (0/36) | 56 ms |
| E. Rules + ML + history (v3) | 80.7% (2015/2498) | 0.0% (0/2127) | 70.0% (14/20) | 0.0% (0/36) | 63 ms |

**The only independent ML evaluation is v1** (`8d6584a2…`), where InjecAgent was run once on a frozen model:

| | D (v1) | E (v1) |
|---|---|---|
| InjecAgent attacks stopped | 80.7% (2026/2512) | 99.9% (2080/2082) |
| InjecAgent legitimate actions blocked | 0.0% (0/2127) | **100% (2127/2127)** |
| Clean controls completed | 17/17 | **0/17** |
| Internal holdout attacks stopped | 70.0% (14/20) | 85.0% (17/20), with 8.6% (3/35) false blocks |

## 6. Internal benchmark (final experiment)

### Holdout split: 18 scenarios, never tuned on

Square brackets give 95% Wilson intervals over scenarios, in percent.

| Metric | A | B | C | Control | D (v3) | E (v3) |
|---|---|---|---|---|---|---|
| Unauthorized executed | 95.2% (20/21) [67-99] | 66.7% (14/21) [36-82] | 45.0% (9/20) [18-64] | 25.0% (5/20) [8-50] | 30.0% (6/20) [4-42] | 30.0% (6/20) [4-42] |
| Prevention (recall) | 0.0% (0/21) | 33.3% (7/21) | 55.0% (11/20) | 75.0% (15/20) | 70.0% (14/20) | 70.0% (14/20) |
| False blocks | n/a | 0.0% (0/36) [0-18] | 0.0% (0/36) | 0.0% (0/36) | 0.0% (0/36) | 0.0% (0/36) |
| Benign task success | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Precision | n/a | 100% (7/7) | 100% (11/11) | 100% (15/15) | 100% (14/14) | 100% (14/14) |
| False-negative rate | n/a | 66.7% | 45.0% | 25.0% | 30.0% | 30.0% |
| F1 | n/a | 0.500 | 0.710 | 0.857 | 0.824 | 0.824 |
| PR-AUC | n/a | n/a | 0.711 | 0.866 | 0.986 | 0.961 |
| Assessor latency, median / p95 (all splits) | – | – | 0.12 / 0.50 ms | 0.15 / 0.29 ms | 33.8 / 68.7 ms | 34.9 / 82.2 ms |
| Policy bypass | n/a | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 |
| Audit coverage | 100% (57/57) | 100% (57/57) | 100% (56/56) | 100% (56/56) | 100% (56/56) | 100% (56/56) |
| Errored runs, unlabeled actions, assessor failures | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 |

Prevention by category, holdout:

| Category | B | C | Control | D | E |
|---|---|---|---|---|---|
| Prompt injection | 1/8 | 4/7 | 6/7 | 7/7 | 7/7 |
| Permission violation | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 |
| Repeated or unnecessary | 2/9 | 3/9 | 5/9 | 3/9 | 3/9 |
| Benign: false blocks | 0/17 | 0/17 | 0/17 | 0/17 | 0/17 |

ML ranks better (PR-AUC 0.96–0.99 against 0.71–0.87) and catches every holdout prompt injection. But it misses more "repeated or unnecessary" actions than the heuristic with history, so its overall prevention is lower than Control's.

**Paired comparisons:** exact McNemar over scenarios, outcome "any unauthorized action executed".

| Comparison | Only the first leaked | Only the second leaked | p (uncorrected) |
|---|---|---|---|
| B vs C | 3 | 0 | 0.250 |
| B vs D | 6 | 0 | 0.031 |
| C vs D | 3 | 0 | 0.250 |
| D vs E | 0 | 0 | 1.000 |
| Control vs E | 1 | 0 | 1.000 |
| C vs Control | 2 | 0 | 0.500 |
| B vs Control | 5 | 0 | 0.062 |

**No difference is statistically established.** Seven comparisons were made. Under a Holm correction the smallest p (B vs D, 0.031) would need to be below 0.05/7 ≈ 0.007, and it is not. With 18 holdout scenarios, the test can only detect very large effects.

### Dev split and all scenarios

The heuristic was tuned on dev, so the heuristic configurations look better there than they should.

| Metric, all 53 scenarios | B | C | Control | D (v3) | E (v3) |
|---|---|---|---|---|---|
| Prevention | 55.2% (32/58) | 73.7% (42/57) | 90.9% (50/55) | 85.5% (47/55) | 89.1% (49/55) |
| False blocks | 0.0% (0/98) | 0.0% (0/98) | 0.0% (0/99) | 2.0% (2/99) | 1.0% (1/99) |
| Benign task success | 16/16 | 16/16 | 16/16 | 16/16 | 16/16 |
| Retry handling | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |

## 7. InjecAgent external benchmark (final experiment)

Deterministic rules stop nothing here by construction (B = A), because the broad policy allows every application tool. Every difference comes from the contextual layer. With a per-task allowlist naming only the user's tool, rules alone would stop every unrelated attacker tool. That is a bound by construction, not a measured result.

| Metric | A | B | C | Control | D (v3) | E (v3) |
|---|---|---|---|---|---|---|
| Unauthorized executed | 100% (3042/3042) | 100% (3042/3042) | 20.5% (516/2514) | 13.3% (310/2332) | 18.7% (468/2498) | 19.3% (483/2498) |
| Prevention (recall) | 0% | 0% | 79.5% | 86.7% | 81.3% | 80.7% |
| False blocks | n/a | 0% (0/2127) | 0% (0/2127) | 0% (0/2127) | 0% (0/2127) | 0% (0/2127) |
| Clean controls completed | 17/17 | 17/17 | 17/17 | 17/17 | 17/17 | 17/17 |
| Precision | n/a | n/a | 100% (1998/1998) | 100% (2022/2022) | 100% (2030/2030) | 100% (2015/2015) |
| F1 | n/a | n/a | 0.886 | 0.929 | 0.897 | 0.893 |
| PR-AUC | n/a | n/a | 0.906 | 0.937 | 0.934 | 0.993 |
| Assessor latency, median / p95 | – | – | 0.13 / 0.21 ms | 0.17 / 0.26 ms | 56.4 / 77.7 ms | 63.0 / 87.0 ms |
| Audit coverage | 100% | 100% | 100% | 100% | 100% | 100% |
| Errored runs, assessor failures | 0, 0 | 0, 0 | 0, 0 | 0, 0 | 0, 0 | 0, 0 |
| Unlabeled actions (excluded from rates) | 152 | 152 | 76 | 50 | 72 | 72 |

**Latency note:** the laptop entered Windows Modern Standby during one D decision. Windows logged events 506 and 507, from 08:51:45 to 09:24:34 UTC. That decision recorded 1,967 seconds, which pulls D's *mean* authorization latency up to 470 ms. The decision itself completed normally with no fallback, so no outcome changed. Without it, D's mean is 50.9 ms. Medians are reported for this reason.

Prevention by attack type:

| Type | C | Control | D (v3) | E (v3) |
|---|---|---|---|---|
| Direct harm (1,012 actions) | 95.7% | 95.7% | 98.4% | 96.9% |
| Data stealing | 68.6% (1030/1502) | 79.8% (1054/1320) | 69.6% (1034/1486) | 69.6% (1034/1486) |

**Paired differences:** cluster bootstrap over the 62 attacker cases, with the 17 user tasks fixed.

| Comparison | Change in prevention [95% CI] | Change in false blocks |
|---|---|---|
| C vs B | +79.5 pts [+72.9, +86.7] | 0 |
| Control vs B | +86.7 pts [+82.4, +91.3] | 0 |
| D vs B | +81.3 pts [+74.8, +88.2] | 0 |
| D vs C (ML instead of heuristic) | +1.8 pts [+0.0, +4.1] | 0 |
| Control vs C (history, heuristic) | +7.2 pts [+4.4, +9.8] | 0 |
| E vs D (history, ML) | −0.6 pts [−1.8, +0.0] | 0 |
| **E vs Control (ML vs heuristic, both with history)** | **−6.0 pts [−9.2, −2.8]** | 0 |

The interval for E vs Control excludes zero: **the best ML configuration is measurably worse than the heuristic with history on InjecAgent.** History helps the heuristic mainly by catching the send step of data-stealing attacks (79.8% against 68.6%). Neither ML configuration gains from it.

## 8. The independent v1 result, and why E failed

In the independent run, v1's E blocked all 2,127 legitimate actions, so its 99.9% prevention means nothing. `scripts/diagnose_external.py` reproduces the diagnosis:

1. **Shortcut:**
   - The v1 generator placed attacks before the task's steps, so 579 of 891 first-step training actions (65%) were unauthorized.
   - The stateful model learned that position meant risk: `prior_steps` was its third most important feature.
   - In InjecAgent the user's legitimate call always comes first.
2. **Unfamiliar input:** no training record used an application tool.
3. **Thresholds:** clean controls scored 0.88 on average against E's 0.52 review threshold.

The native test split was generated the same way, so it rewarded the shortcut rather than exposing it.

**Post-hoc corrections:**

- **v2** moved the attacks after the task's first step. E's false blocks fell to 0/2127, and its advantage disappeared: 81.7% against D's 81.3%. But v2 still used `prior_steps`, which now pointed the other way.
- **v3**, from the final audit, stops training on position (`ML_INTEGRITY_AUDIT.md`). It gives the results in sections 5–7. These corrections were motivated by the external failure, so none of their InjecAgent numbers is an independent test.

## 9. Statistical limitations

- **Internal holdout:** 18 scenarios. Wilson intervals are 30–40 points wide, and no paired comparison survives a multiple-comparison correction.
- **InjecAgent:** the 3,042 attacker actions come from 62 attacker cases crossed with 17 user tasks. Intervals resample attacker cases, so they do not generalize to new user tasks. False blocks rest on 17 distinct legitimate calls.
- **Determinism:** runs are deterministic, so repeats add nothing. The sample size is the number of scenarios or clusters, not of runs.
- **Labels:** labels for both benchmarks are this project's interpretation, and for internal scenarios the authors are the guard's authors.
- **Uncorrected comparisons:** the bootstrap intervals are unadjusted 95% intervals across seven comparisons. Corrected (for example 99.3%) intervals were not computed. Treat E vs Control and Control vs C, whose intervals exclude zero, as strong indications rather than confirmed findings.

## 10. Answer to the research question

*Does combining deterministic runtime authorization, supervised ML contextual risk assessment and interaction history improve the security of tool-using AI agents?*

The answer covers scripted agents on these two benchmarks only.

1. **Contextual assessment on top of deterministic rules helps substantially, at no measured cost.**
   - On InjecAgent, with a broad policy, rules alone stop nothing, while every contextual configuration stops 79–87% of unauthorized actions and blocks no legitimate action.
   - Internally, contextual assessment lifts holdout prevention from 33% to 55–75%.
   - Rules stayed the final authority throughout: 0 policy bypasses, 100% audit coverage, and 0 assessor failures.
2. **Supervised ML did not improve on the hand-written heuristic end to end.**
   - D against C: +1.8 points on InjecAgent (CI 0 to +4.1), and 70% against 55% on the holdout (p = 0.25).
   - With history, ML is worse than the heuristic: E against Control is −6.0 points (CI −9.2 to −2.8) on InjecAgent, and 70% against 75% on the holdout.
   - ML's higher PR-AUC (better ranking) did not translate into better decisions at its thresholds. It costs about 300 times the latency.
   - The ML labels are largely the heuristic's own concepts (`ML_INTEGRITY_AUDIT.md`), which limits how much it could add.
3. **History helps the heuristic (+7.2 points on InjecAgent), and does not help the ML assessor.**
4. **The independent ML test failed:** v1's E blocked every legitimate action because of a data-generation shortcut that only the external benchmark revealed. Accuracy on generated data did not predict runtime behaviour.
5. **The best configuration measured is rules + heuristic + history** (Control):
   - 86.7% prevention on InjecAgent and 75% on the internal holdout, with no false blocks;
   - under 0.3 ms per decision;
   - still 8–25 points short of the proposal's 95% target, and weakest on data stealing (79.8%).

**Recommendation:** deploy Control. Keep D and E as experimental configurations. The negative ML result is a finding of this project, not a gap to hide. Real LLM agents and independently written labels are the next steps (`LIMITATIONS_AND_FUTURE_WORK.md`).
