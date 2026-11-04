#!/usr/bin/env bash
# Anomaly baselines under 5 random tie-break seeds (clean data, main capacities).
cd "$(dirname "$0")/.."
for s in 1 2 3 4 5; do
  .venv_mac/bin/python -u -W ignore -m src.run_benchmark --split ood --seed $s --noise none:0 --capacity 256 1024 4096 --methods nodoze rare_action --tag tieseed$s
  for sp in otrf_native_test otrf_native_val; do
    .venv_mac/bin/python -u -W ignore -m src.run_benchmark --split $sp --seed $s --no-history --noise none:0 --capacity 0.01 0.05 --methods nodoze rare_action --tag tieseed$s
  done
done
