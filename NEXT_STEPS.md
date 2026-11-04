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

## Next
1. Human label check (above), about 30 minutes for one person.
2. End-to-end LLM verdict test (needs an API key or a local model; user's decision), then RISKSTOP.
3. Performance: Online v2 re-scoring is slow on ~900k-event streams (vectorise or scale rescore_every with memory; that would be a new version).
4. Future work: EVICTGuard under broad evidence definitions (CDB), where it only matches rare-action ranking.
5. Any new version must be judged on data it was not designed on.

## Rules we follow
* Never tune on held-out data (h2 OOD, OTRF test split). Develop on ATLASv2 h1 + OTRF train split; OTRF val/test and ATLASv2 h2 are held-out.
* The scorer must never read gt_* / is_synthetic / noise_type / dup_of (a test enforces this).
* Don't use SigmaHQ releases newer than r2026-04-01 (they use renumbered ATT&CK IDs).
