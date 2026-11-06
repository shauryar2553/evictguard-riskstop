# Handoff: where the EVICTGuard work stands (2026-11-03)

## Status
* **Dataset + pipeline: done.** OTRF attacks labelled event by event (Sigma `r2026-04-01` + process tree),
  ATLASv2 benign background and 16 native attack scenarios streamed (`data/atlasv2`, ~233 MB),
  300 spliced episodes + 16 OOD episodes. Details: `docs/DATASET.md`.
* **EVICTGuard v2: done and evaluated.** `src/evictguard_v2.py` (frozen; SHA-256 in `results/evictguard_v2.sha256`).
  Held-out h2 (6 real attacks): core action recall 0.973 at 1,024 events (0.5% of log) vs v1 0.000,
  Random 0.015, FIFO 0.000. Write-up and caveats: `docs/RESULTS_EVICTGUARD_V2.md`.
  Paper tables and figures: `results/paper/`.
* **Viva guide:** `~/Desktop/EVICTGuard_Viva_Guide.docx`. Regenerate with `.venv_mac/bin/python scripts/make_viva_doc.py`.
* Tests: `.venv_mac/bin/python -m pytest -q` (38+ passing). Full rerun: `./run_pipeline.sh atlasv2`.
* Python env on the Mac: `.venv_mac` (the `.venv` folder is the original Windows one).

## EVICTGuard: COMPLETE (2026-11-04)
* Second dataset: 84 native OTRF episodes (`--split otrf_native_{train,val,test}`, cold start `--no-history`).
* Literature baselines in `src/baselines.py`: NoDoze-style, Sigma prioritisation, rare-action, recency + dedup (random tie-break).
* Streaming version `src/evictguard_online.py` with the slide-15 reservoirs (frozen, SHA-256 in `results/evictguard_online.sha256`).
* Weight sensitivity (`scripts/weight_sensitivity.py`): 0.817 ± 0.013 under ±50% perturbations.
* Ledger integration: `python -m src.evaluate --method v2`. Context assembly: `python -m src.context <episode.parquet>`.
* Final write-up: `docs/RESULTS_EVICTGUARD_V2.md`. Tables and figures: `results/paper/`.

## Caveat fixes (2026-11-04): see docs/RESULTS_EVICTGUARD_V2.md sections 10-12
* New frozen: EVICTGuard v3 (`results/evictguard_v3.json`) and Online v2 (`src/evictguard_online_v2.py`, SHA-256 in `results/`).
* Third dataset: CDB public sample (`--split cdb` raw labels, `--split cdb_filtered` sensitivity analysis). Data in `data/cdb_sample/`.
* Labeller-vs-CDB agreement: `results/paper/labeller_vs_cdb_agreement.json` (kappa 0.08 / 0.19).
* Human review sheet: `~/Desktop/EVICTGuard_label_review.csv`. Fill `reviewer_is_attack`, then run `python -m scripts.label_review_kit score`.

## GitHub (shared, private)
https://github.com/shauryar2553/evictguard-riskstop (collaborators: Ankitaashok20, thanmayasrii).
gh CLI at ~/.local/bin/gh (logged in as shauryar2553). Large files are uploaded in 15 MB parts:
run ./scripts/reassemble_large_files.sh after cloning.

## Done 2026-11-05 (no-LLM round)
* Online v2 fast implementation (identical decisions, ~2x faster): `src/evictguard_online_v2_fast.py`.
* EVICTGuard v4 (supporting-evidence quota, frozen `results/evictguard_v4.json`): no gain on fresh data (negative result).
* Fresh test set: ATLASv2 Carbon Black EDR (`--split cbc`, data in `data/atlasv2/standardized/cbc_edr/`): EVICTGuard v3 leads.
* RISKSTOP built end to end: `src/investigation.py` (query layer, heuristic investigator, memory), `src/riskstop.py`
  (state features, risk models, policy, certificate, baselines), `src/run_riskstop.py` (collect/evaluate). Results and
  honest assessment: `docs/RISKSTOP.md`. Trajectories: `data/riskstop/`.

* RISKSTOP upgraded: alert-driven benchmark on real Carbon Black alerts (`src/alert_benchmark.py`, data in `data/alert_bench/`)
  + fixed-sequence Learn-then-Test risk control, cost model, oracle regret, ablations (`src/run_alert_riskstop.py`).
  Test: missed attacks 0-5% vs 16-36% for baselines, ~10% budget, lowest cost; defers 34-48%. Details in docs/RISKSTOP.md section A.

## Next (needs the API key)
1. LLM investigator implementing `Investigator.next_query` (and reading the context semantically), then re-run
   `python -m src.run_riskstop collect` + `evaluate` with it; compare to the heuristic investigator.
2. End-to-end: LLM verdicts with EVICTGuard memory vs FIFO memory; hypothesis relevance in EVICTGuard scoring.
3. Still open without the LLM: human label check; reliable benign data for the OTRF environment.

## Headline results (for quick reference)
ATLASv2 held-out: EVICTGuard 0.96-0.97 vs best baseline 0.014-0.048 (~20-70x). OTRF: 0.53-0.90 vs 0.07-0.34 (~2.6-8x).
CDB: not better than rare-action (limitation). Details: docs/RESULTS_EVICTGUARD_V2.md.

## Rules we follow
* Never tune on held-out data (h2 OOD, OTRF test split). Develop on ATLASv2 h1 + OTRF train split; OTRF val/test and ATLASv2 h2 are held-out.
* The scorer must never read gt_* / is_synthetic / noise_type / dup_of (a test enforces this).
* Don't use SigmaHQ releases newer than r2026-04-01 (they use renumbered ATT&CK IDs).

## Free LLM run (done 2026-11-06; results in docs/RISKSTOP.md A3)
* Paid Claude run stopped after 695 calls ($6.86; responses cached in data/llm_cache, reusable).
* Running instead: local Qwen2.5-7B, VAL+TEST alerts, all noise conditions, EVICTGuard memory, budget 12 (~9-10 h).
  Risk models trained on the rule-based TRAIN runs (`evaluate --train-from heuristic_b12`); calibration and test use Qwen's own runs.
* Resume/restart any time: `./scripts/resume_qwen.sh` (cached answers make finished work free). Results: data/logs/qwen_eval.log.
* Budget-12 rule-based RISKSTOP could not be certified (negative result; document it).
* Result: RISKSTOP-LLM is certified on VAL; on TEST, false alarms 1.4% and lowest cost, but misses 16% (target 10%) because the VAL and TEST
  attack scenarios differ. Next: re-split the h1 attack scenarios so VAL contains every attack type (or use cross-validated LTT), then re-evaluate.
  No new LLM calls are needed for alerts already cached.
* Re-split done (docs/RISKSTOP.md A4, `--scheme alert`): with val matching test, both RISKSTOP variants hold the guarantee
  (0% misses; false alarms 0.7% LLM / 6.1% classifier). Confidence stop is cheaper (no deferrals, no guarantee).
* Remaining: rule-based TEST noise runs for the alert split (`collect --investigator heuristic_b12 --splits test --scheme alert --only-missing`, fast);
  human label check; push.
