# RISKSTOP: design, implementation and results

> **Primary result: the alert-driven benchmark (section A).** The episode-based results that follow it (section B) were the first attempt;
> they motivated the redesign of the benchmark.

## A. Alert-driven benchmark with risk-controlled stopping (primary)

**Benchmark** (`src/alert_benchmark.py`).
* Every investigation starts from a **real Carbon Black vendor alert** on ATLASv2 and investigates the same host's Carbon Black EDR
  telemetry within ±15 minutes.
* Same sensor and same hosts for attack and benign cases.
* 528 alerts: 59 ATTACK (the alerted process is a REAPr attack process; exact `process_guid` join), 170 vendor false positives on
  attack days (hard negatives), and 299 alerts from the benign period.
* Splits by attack scenario and by benign day (train 277 / val 78 / test 173 alerts). Each alert runs under no noise, a heavy
  background flood and (ATTACK only) missing critical evidence, giving 371 test investigations per memory type.
* Side information: Sigma ATT&CK tactic tags per event (kill-chain progression) and alert metadata (severity, watchlist, tactic),
  both independent of the REAPr labels.

**Risk control** (`src/run_alert_riskstop.py`).
* Thresholds are calibrated with **fixed-sequence Learn-then-Test** on validation investigations, with exact binomial p-values and
  Bonferroni over 3 residual caps × 2 risks.
* Target: missed-attack rate ≤ 0.10 and false-alarm rate ≤ 0.10, each with probability ≥ 0.90.
* Cost model, fixed in advance: missed attack 10, false alarm 3, unnecessary defer 1, full budget 0.5.
* Regret is measured against a hindsight-optimal stopping oracle for the same classifier.

**TEST results** (`results/paper/table13_alert_riskstop.md`):

| Memory / policy | Missed attacks [95% CI] | False alarms [95% CI] | Defer | Budget | Expected cost |
|---|---|---|---|---|---|
| EVICTGuard / **RISKSTOP (LTT)** | **0.053** [0.015, 0.131] | 0.101 [0.069, 0.142] | 0.34 | **0.08** | **0.744** |
| EVICTGuard / BAGEN-style | 0.280 | 0.037 | 0 | 0.23 | 0.795 |
| EVICTGuard / confidence stop | 0.360 | 0.020 | 0 | 0.05 | 0.823 |
| EVICTGuard / conformal deferral (end) | 0.160 | 0.054 | 0.16 | 0.97 | 1.110 |
| EVICTGuard / fixed budget | 0.267 | 0.068 | 0 | 0.97 | 1.209 |
| FIFO / **RISKSTOP (LTT)** | **0.000** [0.000, 0.048] | **0.024** [0.010, 0.048] | 0.48 | 0.12 | **0.600** |
| FIFO / BAGEN-style | 0.320 | 0.030 | 0 | 0.24 | 0.861 |
| FIFO / fixed budget | 0.347 | 0.064 | 0 | 0.97 | 1.363 |

**Findings**
1. **Missed attacks fall from 16–36% (every baseline) to 0–5%**, using 8–12% of the investigation budget.
2. **RISKSTOP has the lowest expected cost of all policies.** Paired bootstrap on per-investigation cost
   (`table13_alert_riskstop_significance.md`): significantly cheaper than fixed budget and conformal deferral for both memories, and
   than BAGEN-style with FIFO memory. Not significantly different from BAGEN-style or confidence stop with EVICTGuard memory.
3. **The guarantee holds with FIFO memory** (both risks ≤ 0.10, CIs inside the target). **With EVICTGuard memory the false-alarm rate is
   0.101**, on the boundary (CI 0.069–0.142). Validation and test aren't fully exchangeable: the test set adds host h2's vendor false
   positives, which validation doesn't contain. That is a stated limitation of distribution-free guarantees under shift.
4. **The price is deferral.** 34–48% of alerts are escalated to an analyst. The guarantee buys safety by handing over uncertain cases.
5. **Ablations.** Calibration is essential: uncalibrated defaults miss 37% of attacks. The query-value rule helps: removing it
   significantly raises cost. The residual-risk cap was **not used** (LTT picked ρ = 1.0), so that component currently adds nothing.
6. **Memory.** In these short alert windows (about 4–5k events), FIFO memory plus RISKSTOP did best overall. EVICTGuard's advantage shows in
   large investigations (section B and the EVICTGuard results), not small ones.

### A2. Small budget (12 units), rule-based investigator: not certifiable (negative result)
* Same benchmark, budget cut from 20 to 12 units. Training data was extended with background-flood and missing-critical runs.
* **LTT certified no threshold setting** at α = δ = 0.10, nor at α = 0.15 / δ = 0.20. On validation, 7 of 45 attack investigations are
  confidently wrong, and the 18 summary features can't separate them at this budget.
* Best baseline on TEST (EVICTGuard memory, 173 alerts): confidence stop, missed 0.24 / false alarms 0.04 / budget 0.05 / cost 0.48.
  Fixed budget: 0.16 / 0.09 / 0.96 / 0.94.
* Interpretation: a guarantee needs a score that is reliable on validation. That is what the LLM investigator is meant to supply.

### A3. LLM investigator: local Qwen2.5-7B, budget 12 (all noise conditions)
**Setup.**
* `src/llm_investigator.py`: the LLM picks the next query from numbered candidate leads and outputs a hypothesis plus an attack likelihood.
  Every response is cached on disk.
* Backends: local Qwen2.5-7B via Ollama (free, reproducible; `--investigator llm`) or Claude via the Anthropic SDK (`--investigator llm_opus`).
* **RISKSTOP-LLM**: the same fixed-sequence LTT policy, with the LLM's attack likelihood as its attack score.
* 542 investigations: VAL + TEST alerts × {no noise, background flood, missing critical}, EVICTGuard memory.
* The risk models (residual risk, classifier fallback) are trained on the rule-based TRAIN runs (`--train-from heuristic_b12`).
  Calibration and test use Qwen's own trajectories, so the validity of the guarantee is unaffected.

**TEST results** (371 investigations; `data/alert_bench/test_metrics_llm.csv`):

| Policy | Missed attacks [95% CI] | False alarms [95% CI] | Defer | Budget | Expected cost |
|---|---|---|---|---|---|
| **RISKSTOP-LLM (LTT-certified)** | 0.160 [0.086, 0.263] | **0.014** [0.004, 0.034] | 0.26 | **0.09** | **0.678** |
| Confidence stop | 0.280 [0.182, 0.396] | 0.057 [0.034, 0.090] | 0 | 0.12 | 0.788 |
| BAGEN-style (gain stall) | 0.240 [0.149, 0.353] | 0.101 [0.069, 0.142] | 0 | 0.37 | 0.938 |
| RISKSTOP, uncalibrated defaults | 0.360 [0.252, 0.479] | 0.034 | 0.01 | 0.21 | 0.940 |
| Conformal deferral (end) | 0.147 [0.076, 0.247] | 0.064 | 0.15 | 0.99 | 1.098 |
| Fixed budget | 0.227 [0.138, 0.338] | 0.105 | 0 | 0.99 | 1.227 |
| LLM confidence stop (no RISKSTOP) | 0.013 | 0.767 | 0 | 0.49 | 2.142 |
| LLM verdict at end (no RISKSTOP) | 0.013 | 0.858 | 0 | 0.99 | 2.606 |

Paired bootstrap on per-investigation cost, RISKSTOP-LLM minus baseline [95% CI]:
* fixed budget −0.55 [−0.73, −0.39]; conformal −0.42 [−0.59, −0.24]; BAGEN −0.26 [−0.47, −0.04]; uncalibrated −0.26 [−0.47, −0.07];
* LLM-only −1.46 to −1.93;
* confidence stop −0.11 [−0.27, +0.04] (not significant).

**Findings**
1. **The LLM alone is a poor triager.** It flags 77–86% of benign alerts as attacks, so it misses almost nothing but is useless in practice.
2. **RISKSTOP turns it into the cheapest policy.** False alarms drop to 1.4% (inside the 10% target), using 9% of the budget. Cost is
   significantly lower than every baseline except confidence stop.
3. **The LLM makes certification possible at a small budget.** Rule-based RISKSTOP at budget 12 certified nothing (A2). RISKSTOP-LLM was
   certified for all three residual caps (validation: miss 0.00, false alarms 0.016).
4. **The missed-attack guarantee did not transfer to TEST** (0.16 vs target 0.10). The validation attacks (h1-s4, h1-m4) and the test attacks
   (h1-m5, h1-m6) come from different scenarios, so they aren't exchangeable. As in A, this is the main limitation; the fix is validation
   attacks drawn from the same scenario mix as test.
5. **Noise had no effect, for a trivial reason.** The median decision is made at step 0 (on the alert and its seed process), before the
   injected events matter. Decisions under no noise and under a background flood are identical. This is a result about alert triage, not
   about robustness of long investigations.
6. **Cost:** $0 (local model, about 12 h on a laptop). A paid Claude run was started and stopped after 695 calls ($6.86). Those
   responses are cached and can be resumed.

Reproduce: `./scripts/resume_qwen.sh` (collect plus evaluate; cached answers make reruns fast).

## B. Episode-based benchmark (first attempt)


## What was built (proposal slides 12–17)
| Component | File | Status |
|---|---|---|
| Telemetry & query layer: budgeted queries (process, children, parent, target, network, time window) with costs | `src/investigation.py` (`QueryEngine`) | ✅ |
| Investigator: rule-based stand-in for the LLM that follows the most suspicious open lead; same interface the LLM will use | `src/investigation.py` (`HeuristicInvestigator`) | ✅ (LLM version pending API key) |
| Bounded memory: EVICTGuard (v3 scoring) or FIFO, fixed capacity | `src/investigation.py` (`Memory`) | ✅ |
| RISKSTOP state evaluation: 18 label-free features (evidence strength, suspicious processes, lineage depth, sensitive targets, unresolved leads, host coverage, missing telemetry, budget, information gain, novelty) | `src/riskstop.py` (`state_features`) | ✅ |
| Evidence risk: P(attack) classifier and residual-risk regressor (share of attack evidence still unseen), trained on TRAIN only | `src/riskstop.py` (`RiskModels`) | ✅ |
| Query value: residual risk × recent information gain | `src/riskstop.py` | ✅ |
| Decision policy: CONTINUE / ATTACK / BENIGN / DEFER, with thresholds calibrated on VALIDATION under error budgets (false ATTACK ≤ 5%, missed attack ≤ 5%) | `src/riskstop.py`, `src/run_riskstop.py` | ✅ |
| Decision certificate: verdict, rationale, cited evidence IDs, open questions, resources used | `src/riskstop.py` (`Certificate`); example in `results/paper/example_decision_certificate.json` | ✅ |
| Baselines: fixed budget; confidence stop; BAGEN-style (stop when information gain stalls); dual-threshold conformal deferral at the end only (Şahin & Mert, 2026) | `src/riskstop.py` | ✅ |

**Protocol.**
* Each investigation is run once to its full budget (20 units, about 13 queries), recording RISKSTOP's state at every step.
  The investigator's plan doesn't depend on the stopping decision, so every policy is replayed on the identical trajectory.
* 1,120 investigations in total: every episode × {no noise, heavy background flood, missing critical evidence} × {EVICTGuard memory, FIFO memory}.
* Gold verdicts: ATTACK, BENIGN, or DEFER (attack with < 50% of its core evidence left), fixed in advance.
* Splits: OTRF train/val/test by technique family; ATLASv2 h1 attacks for training and h2 for testing; ATLASv2 benign days split by day; CDB windows for testing only.

## Results on TEST (`results/paper/table11_riskstop_test.md`)

**ATLASv2: genuine benign days and expert attack labels (26 test investigations)**

| Memory / policy | Accuracy | Missed attacks | False alarms | Budget used | ATTACK verdicts citing real attack evidence |
|---|---|---|---|---|---|
| EVICTGuard / RISKSTOP | 0.73 | 0.06 | **0.00** | **0.15** | **1.00** |
| EVICTGuard / BAGEN-style | 0.77 | 0.00 | 0.00 | 0.22 | 1.00 |
| EVICTGuard / fixed budget | 0.69 | 0.00 | 0.25 | 0.99 | 1.00 |
| FIFO / RISKSTOP | **0.81** | 0.00 | 0.00 | **0.08** | 1.00 |
| FIFO / fixed budget | 0.58 | 0.00 | **0.62** | 0.99 | **0.11** |

* **RISKSTOP** removes false alarms and uses 8–15% of the budget instead of 99%. A simple "stop when new evidence stalls" rule
  (BAGEN-style) does about as well here. With 26 investigations, the differences between the good policies are not statistically meaningful.
* **Memory matters for verdicts.** Under a fixed budget, FIFO memory produces 62% false alarms, and only 11% of its ATTACK
  verdicts cite real attack evidence. EVICTGuard memory gives 25% and 100%. This is the first end-to-end evidence (without an LLM)
  that better memory produces better-grounded verdicts.

**OTRF "benign twins" and CDB windows: unreliable benign labels**
* RISKSTOP defers 80–97% of these investigations. False alarms stay at about 6% (baselines: 50–100%), but most cases are handed
  to an analyst, which is safe but not useful.
* Cause, diagnosed: the attack-confidence model separates OTRF attack vs twin poorly on held-out data (AUC 0.58 validation,
  0.73 test, against 0.97 on training data); no model family does better (0.52–0.59). A twin is the attack recording minus *our labelled*
  attack events. Our labeller misses attack steps (κ = 0.08–0.19 against CDB's), so many "benign twins" probably still contain
  attacker activity, and their BENIGN gold answer is wrong. CDB has only 4 benign windows.

## Honest assessment
* RISKSTOP is **built end to end and works** where the labels are reliable: zero false alarms, a small budget, grounded certificates.
* It is **not yet shown to beat simple stopping rules**. On ATLASv2 the BAGEN-style baseline is as good; elsewhere the label noise dominates.
* What would most improve it:
  1. **Reliable benign data from the same environment as the attacks**, e.g. ATLASv2 Carbon Black or Security streams from the benign days, or more native benign telemetry.
  2. **The LLM investigator.** It reads the evidence semantically (what the attacker did) rather than through 18 summary numbers.
     That's the API-key step.
  3. **More test investigations** (ATLASv2 only has 6 held-out attacks), to separate the good policies statistically.

## Reproduce
```bash
.venv_mac/bin/python -m src.run_riskstop collect --workers 3     # ~45 min, 1,326 investigations
.venv_mac/bin/python -m src.run_riskstop evaluate                # trains on TRAIN, calibrates on VAL, reports TEST
```
