"""Human label-validation kit for the OTRF labels (held-out splits).

make:   python -m scripts.label_review_kit make      -> ~/Desktop/EVICTGuard_label_review.csv (60 rows)
score:  python -m scripts.label_review_kit score     -> agreement + Cohen's kappa from the filled sheet

The reviewer fills ONE column, ``reviewer_is_attack`` (yes / no / unsure), using the attack description
shown in each row. The automatic label is hidden in a separate column at the far right, so it doesn't
bias the reviewer; sort by ``row`` to keep the original order.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

OUT = Path.home() / "Desktop" / "EVICTGuard_label_review.csv"
QUOTA = {"core": 20, "supporting": 20, "ambiguous": 10, "background": 10}


def _brief(raw: str) -> str:
    try:
        j = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return ""
    keys = ["CommandLine", "ParentImage", "TargetFilename", "TargetObject", "TargetImage", "ObjectName", "ScriptBlockText",
            "Payload", "DestinationIp", "QueryName", "ServiceName", "TaskName"]
    return " | ".join(f"{k}={str(j[k])[:150]}" for k in keys if j.get(k) not in (None, "", "-"))


def make(seed: int = 7) -> None:
    eps = pd.read_csv("data/benchmark/episodes.csv")
    eps = eps[eps.split.isin(["otrf_native_test", "otrf_native_val"])]
    index = pd.read_csv("data/otrf/index.csv").set_index("recording_id")
    frames = []
    for ep in eps.itertuples():
        f = pd.read_parquet(f"data/benchmark/episodes/{ep.episode_id}.parquet")
        f["recording_id"] = ep.attack_recordings
        frames.append(f)
    allev = pd.concat(frames, ignore_index=True)
    rng = np.random.default_rng(seed)
    picks = []
    for tier, n in QUOTA.items():
        part = allev[allev.gt_tier == tier]
        picks.append(part.iloc[rng.choice(len(part), size=min(n, len(part)), replace=False)])
    sample = pd.concat(picks).sample(frac=1, random_state=seed).reset_index(drop=True)
    rows = []
    for i, r in enumerate(sample.itertuples()):
        rec = index.loc[r.recording_id] if r.recording_id in index.index else None
        meta_path = Path("data/otrf/metadata") / f"{rec.dataset_id}.yaml" if rec is not None else None
        desc = ""
        if meta_path is not None and meta_path.exists():
            desc = str((yaml.safe_load(meta_path.read_text()) or {}).get("description", ""))[:300]
        rows.append({"row": i + 1, "attack_simulated_in_this_recording": f"{rec.title if rec is not None else ''}: {desc}",
                     "time": r.timestamp, "host": r.host, "log": f"{r.channel} / EventID {r.event_id}", "process": r.image,
                     "details": _brief(r.original_json), "reviewer_is_attack": "", "reviewer_notes": "",
                     "auto_label_DO_NOT_LOOK": r.gt_tier, "record_id": r.record_id})
    out = pd.DataFrame(rows)
    out.to_csv(OUT, index=False)
    print(f"wrote {len(out)} rows to {OUT}")


def score(path: Path = OUT) -> dict:
    d = pd.read_csv(path)
    d["rev"] = d.reviewer_is_attack.astype(str).str.strip().str.lower().map({"yes": 1, "y": 1, "no": 0, "n": 0})
    d = d.dropna(subset=["rev"])
    d = d[d.auto_label_DO_NOT_LOOK != "ambiguous"]   # ambiguous is excluded from scoring by design
    if d.empty:
        print("no reviewed rows yet"); return {}
    auto = d.auto_label_DO_NOT_LOOK.isin(["core", "supporting"]).astype(int)
    rev = d.rev.astype(int)
    po = float((auto == rev).mean())
    pe = float(auto.mean() * rev.mean() + (1 - auto.mean()) * (1 - rev.mean()))
    kappa = (po - pe) / (1 - pe) if pe < 1 else float("nan")
    res = {"reviewed": int(len(d)), "agreement": round(po, 3), "cohens_kappa": round(kappa, 3),
           "auto_attack_precision": round(float(rev[auto == 1].mean()), 3) if (auto == 1).any() else None,
           "auto_benign_precision": round(float(1 - rev[auto == 0].mean()), 3) if (auto == 0).any() else None,
           "by_tier": d.groupby("auto_label_DO_NOT_LOOK").rev.mean().round(3).to_dict()}
    print(json.dumps(res, indent=2))
    Path("results/paper").mkdir(parents=True, exist_ok=True)
    Path("results/paper/human_label_agreement.json").write_text(json.dumps(res, indent=2))
    return res


if __name__ == "__main__":
    {"make": make, "score": score}[sys.argv[1] if len(sys.argv) > 1 else "make"]()
