# RISKSTOP: design, implementation and first (no-LLM) results

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
