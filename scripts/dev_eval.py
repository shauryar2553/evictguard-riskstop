"""Quick development evaluation of EVICTGuard v2 on the h1 OOD scenarios (dev only)."""
import sys, glob, time, json
import numpy as np, pandas as pd
from pathlib import Path
from src.evictguard_v2 import select_evictguard_v2, score_events, PrevalenceProfile, action_keys

def ap(score, y):
    o = np.argsort(-score, kind="stable"); y = y[o]; hits = np.cumsum(y)
    return float(((hits / np.arange(1, len(y) + 1)) * y).sum() / max(y.sum(), 1))

def run(profile, caps=(1024, 4096), pattern="h1-", **kw):
    rows = []
    for path in sorted(glob.glob(f"data/benchmark/episodes/ood-attack-{pattern}*.parquet")):
        e = pd.read_parquet(path); core = e.gt_tier.eq("core").to_numpy()
        sc = score_events(e, profile, kw.get("weights"), kw.get("process_weights"), kw.get("decay", 0.85), kw.get("disable"))
        row = {"ep": Path(path).stem.replace("ood-attack-", ""), "AP": ap(sc.eg_value.to_numpy(), core)}
        for c in caps:
            sel = select_evictguard_v2(e, c, profile=profile, **{k: v for k, v in kw.items() if k in ("weights", "process_weights", "decay", "disable")})
            ids = set(sel.selected.record_id); row[f"rec@{c}"] = float(np.isin(e.record_id[core], list(ids)).mean())
            keys = action_keys(e); kept = set(keys[e.record_id.isin(ids).to_numpy()]); ck = set(keys[core])
            row[f"act@{c}"] = len(ck & kept) / len(ck)
        rows.append(row)
    return pd.DataFrame(rows)

if __name__ == "__main__":
    prof = PrevalenceProfile.load(Path("data/benchmark/prevalence_train.json"))
    df = run(prof); print(df.round(3).to_string(index=False)); print(df.mean(numeric_only=True).round(3).to_string())
