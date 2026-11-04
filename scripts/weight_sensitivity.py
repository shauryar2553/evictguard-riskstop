"""Weight sensitivity of frozen EVICTGuard v2 on DEVELOPMENT data only (ATLASv2 h1-*).

Each of the 9 weights (5 evidence weights + 4 process weights) is multiplied by an independent
U(0.5, 1.5) factor; 30 random draws plus the default. Reports core action recall at capacity 1,024.
"""
import glob
import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.evictguard_v2 import DEFAULT_PROCESS_WEIGHTS, DEFAULT_WEIGHTS, PrevalenceProfile, action_keys, select_evictguard_v2

prof = PrevalenceProfile.load(Path("data/benchmark/prevalence_train.json"))
episodes = []
for path in sorted(glob.glob("data/benchmark/episodes/ood-attack-h1-*.parquet")):
    e = pd.read_parquet(path)
    keys = action_keys(e)
    episodes.append((e, keys, set(keys[e.gt_tier.eq("core").to_numpy()])))

rng = np.random.default_rng(2026)
draws = [({}, {})] + [({k: v * rng.uniform(0.5, 1.5) for k, v in DEFAULT_WEIGHTS.items()},
                       {k: v * rng.uniform(0.5, 1.5) for k, v in DEFAULT_PROCESS_WEIGHTS.items()}) for _ in range(30)]
rows = []
for i, (w, pw) in enumerate(draws):
    recalls = []
    for e, keys, core in episodes:
        sel = select_evictguard_v2(e, 1024, profile=prof, weights=w or None, process_weights=pw or None)
        kept = set(keys[e.record_id.isin(set(sel.selected.record_id)).to_numpy()])
        recalls.append(len(core & kept) / len(core))
    rows.append({"draw": i, "default": i == 0, "recall": float(np.mean(recalls)), "weights": json.dumps({**w, **pw})})
    print(i, round(rows[-1]["recall"], 3), flush=True)
out = pd.DataFrame(rows)
Path("results/paper").mkdir(parents=True, exist_ok=True)
out.to_csv("results/paper/weight_sensitivity_dev.csv", index=False)
pert = out[~out.default].recall
print(f"default {out.recall.iloc[0]:.3f}; perturbed mean {pert.mean():.3f}, min {pert.min():.3f}, max {pert.max():.3f}, std {pert.std():.3f}")
