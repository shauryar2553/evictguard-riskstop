"""Development sweep for EVICTGuard v4 (sigma, theta) on DEV data only: ATLASv2 h1 + OTRF native train."""
import glob, itertools, json
import numpy as np, pandas as pd
from pathlib import Path
from src.evictguard_v2 import PrevalenceProfile, action_keys, select_evictguard_v2
from src.evictguard_v4 import select_evictguard_v4
prof = PrevalenceProfile.load(Path("data/benchmark/prevalence_train.json"))
eps = [(f, prof, (256, 1024)) for f in sorted(glob.glob("data/benchmark/episodes/ood-attack-h1-*.parquet"))]
eps += [(f, None, (0.01, 0.05)) for f in sorted(glob.glob("data/benchmark/episodes/otrf_native_train-*.parquet"))]
cache = []
for f, pr, caps in eps:
    e = pd.read_parquet(f); k = action_keys(e)
    core = set(k[e.gt_tier.eq("core").to_numpy()]); supp = set(k[e.gt_tier.eq("supporting").to_numpy()])
    if core: cache.append((f, pr, caps, e, k, core, supp))
def run(sel):
    out = []
    for f, pr, caps, e, k, core, supp in cache:
        for c in caps:
            cap = int(max(1, round(c * len(e)))) if c < 1 else int(c)
            kept = set(k[e.record_id.isin(set(sel(e, cap, pr).selected.record_id)).to_numpy()])
            out.append({"dom": "atlas_h1" if "ood" in f else "otrf_train", "cap": c, "core": len(core & kept) / len(core),
                        "supp": len(supp & kept) / len(supp) if supp else np.nan})
    return pd.DataFrame(out).groupby(["dom", "cap"])[["core", "supp"]].mean()
res = {"v3": run(lambda e, c, p: select_evictguard_v2(e, c, profile=p, disable={"redundancy"}))}
for s, t in itertools.product((0.1, 0.2, 0.3, 0.4), (0.4, 0.5, 0.6)):
    res[f"v4 s={s} t={t}"] = run(lambda e, c, p, s=s, t=t: select_evictguard_v4(e, c, profile=p, sigma=s, theta=t))
tab = pd.concat(res, names=["method"]).round(3)
print(tab.unstack(["dom", "cap"]).to_string())
tab.to_csv("results/paper/v4_dev_sweep.csv")
