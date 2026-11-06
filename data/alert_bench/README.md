# Alert benchmark results (RISKSTOP)

| File pattern | Content |
|---|---|
| `alerts.csv` | 528 alerts, gold verdict, `split` (scenario split) and `split_alert` (alert-level split) |
| `test_metrics*.csv` | per-policy summary on TEST (rates, 95% Clopper-Pearson CIs, defer, budget, expected cost, regret) |
| `test_decisions*.csv` | **per-investigation decisions** for every policy (action, step, budget used, p_attack, residual, cost, oracle cost) |
| `significance*.csv` | paired bootstrap of per-investigation cost, RISKSTOP vs each baseline |
| `report*.json` | Learn-then-Test calibration (certified thresholds, validation risks, p-values) |
| `trajectories*.pkl` | full investigation trajectories (state features per step, queries, LLM log with hypotheses/scores) |

Suffixes: none = rule-based, budget 20, scenario split (section A of docs/RISKSTOP.md) · `_heuristic_b12` = rule-based, budget 12 (A2) ·
`_llm` = Qwen2.5-7B investigator, scenario split (A3) · `_alertsplit` = alert-level split (A4) ·
`trajectories_llm_opus.pkl` = partial Claude Opus 5.5 run (stopped after 695 calls; not evaluated).

`data/llm_cache/` holds every LLM response (keyed by a hash of model and prompt), so re-running the LLM experiments is free and
gives identical results. `data/logs/` holds the run logs.
