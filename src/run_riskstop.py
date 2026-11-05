"""End-to-end (no-LLM) investigation benchmark: heuristic investigator + memory (EVICTGuard or FIFO) + stopping policy.

Stages
  collect   run every investigation once to its full budget and record RISKSTOP's state at each step
            (the investigator's plan does not depend on the stopping decision, so any policy can be
            replayed on the identical trajectory)
  evaluate  fit risk models on TRAIN, calibrate thresholds on VAL, report TEST for RISKSTOP and baselines,
            for EVICTGuard memory and for FIFO memory

Gold verdicts: ATTACK episodes -> ATTACK; BENIGN episodes -> BENIGN; ATTACK episodes whose remaining core
evidence after the missing-critical transform is < 50% -> DEFER (rule fixed in src/run_benchmark.gold_verdict).
"""
from __future__ import annotations

import argparse
import json
import pickle
import re
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np
import pandas as pd

from .evictguard_v2 import PrevalenceProfile, action_keys
from .noise import inject_noise
from .run_benchmark import gold_verdict

B = Path("data/benchmark")
OUT = Path("data/riskstop")
NOISE = {"none": None, "background-flood": 1.0, "missing-critical": 0.6}


# ------------------------------------------------------------------ episode catalogue
def catalogue() -> pd.DataFrame:
    eps = pd.read_csv(B / "episodes.csv")
    rows = []
    for r in eps[eps.split.str.startswith("otrf_native")].itertuples():
        split = r.split.replace("otrf_native_", "")
        rows.append({"id": r.episode_id, "domain": "otrf", "split": split, "kind": "attack", "path": str(B / "episodes" / f"{r.episode_id}.parquet"), "twin": False})
        rows.append({"id": r.episode_id + "::benign_twin", "domain": "otrf", "split": split, "kind": "benign", "path": str(B / "episodes" / f"{r.episode_id}.parquet"), "twin": True})
    for r in eps[eps.split == "ood"].itertuples():
        rows.append({"id": r.episode_id, "domain": "atlas", "split": "train" if "-h1-" in r.episode_id else "test", "kind": "attack",
                     "path": str(B / "episodes" / f"{r.episode_id}.parquet"), "twin": False})
    seg = pd.read_csv(B / "background_segments.csv")
    for s in seg.itertuples():
        path = Path("data/atlasv2/standardized/benign") / f"{s.segment_id}.parquet"
        if not path.exists():
            continue
        n = len(pd.read_parquet(path, columns=["record_id"]))
        for w in range(min(4, max(1, n // 20000))):
            rows.append({"id": f"atlas-benign-{s.segment_id}-w{w}", "domain": "atlas", "split": s.split, "kind": "benign", "path": str(path),
                         "twin": False, "window": (w * 20000, (w + 1) * 20000)})
    cdb = B / "episodes" / "cdb-filtered-seed176.parquet"
    if cdb.exists():
        n = len(pd.read_parquet(cdb, columns=["record_id"]))
        size = n // 20
        for w in range(20):
            rows.append({"id": f"cdb-w{w}", "domain": "cdb", "split": "test", "kind": "window", "path": str(cdb), "twin": False, "window": (w * size, (w + 1) * size)})
    return pd.DataFrame(rows)


def load_episode(row) -> pd.DataFrame:
    e = pd.read_parquet(row["path"])
    win = row.get("window")
    if isinstance(win, tuple):
        e = e.sort_values("timestamp", kind="stable").iloc[win[0]:win[1]].copy()
        if row["domain"] == "atlas":   # benign ATLASv2 parquet lacks benchmark columns
            e["event_type"], e["source"], e["is_synthetic"] = e.event_id.astype(str), e.channel, False
            e["timestamp"] = pd.to_datetime(e.timestamp, utc=True).map(lambda t: t.isoformat().replace("+00:00", "Z"))
            e["record_id"] = [f"{row['id']}:{r}" for r in e.record_id]
    if row.get("twin"):
        e = e[~e.gt_label.isin(["attack", "ambiguous"])].copy()
    return e.reset_index(drop=True)


# ------------------------------------------------------------------ collection
def _collect_one(args):
    row, noise, memory, budget, capacity = args
    from .investigation import run_investigation
    try:
        e = load_episode(row)
        if row["kind"] == "window":
            row = {**row, "kind": "attack" if (e.gt_tier == "core").any() else "benign"}
        if row["kind"] == "benign" and noise == "missing-critical":
            return None
        if noise != "none":
            e, _ = inject_noise(e, noise, NOISE[noise], 17)
            e = e.reset_index(drop=True)
        clean_core = int((e.gt_tier == "core").sum()) if noise != "missing-critical" else None
        profile = PrevalenceProfile.load(B / "prevalence_train.json") if row["domain"] == "atlas" else None
        res = run_investigation(e, lambda f, s: ("CONTINUE", {}), budget=budget, capacity=capacity, memory_policy=memory, profile=profile)
        keys = action_keys(e)
        core_mask = e.gt_tier.eq("core").to_numpy()
        attack_mask = e.gt_label.eq("attack").to_numpy()
        core_actions = set(keys[core_mask])
        retrieved = res["retrieved_rows"]
        traj = []
        for f in res["trajectory"]:
            n = int(f.get("_retrieved_n", 0))
            got = set(keys[retrieved[:n]]) & core_actions if n else set()
            top = f.get("_top_rows", [])
            traj.append({**{k: v for k, v in f.items() if not k.startswith("_")},
                         "_core_frac_seen": len(got) / len(core_actions) if core_actions else 1.0,
                         "_cites_attack": bool(attack_mask[top].any()) if top else False,
                         "_cites_core": bool(core_mask[top].any()) if top else False,
                         "_top_ids": e.record_id.to_numpy()[top].tolist() if top else []})
        if row["kind"] == "attack":
            if noise == "missing-critical":
                # gold DEFER if < 50% of the original core survived (original count from the clean episode)
                orig = load_episode(row)
                gold = gold_verdict("ATTACK", int((orig.gt_tier == "core").sum()), int(core_mask.sum()))
            else:
                gold = "ATTACK"
        else:
            gold = "BENIGN"
        return {"id": row["id"], "domain": row["domain"], "split": row["split"], "noise": noise, "memory": memory, "gold": gold,
                "events": len(e), "trajectory": traj, "queries": res["queries"], "budget_used": res["budget_used"]}
    except Exception as exc:  # keep the batch alive; report failures
        return {"id": row["id"], "error": repr(exc), "noise": noise, "memory": memory}


def collect(budget: int, capacity: int, workers: int, memories: list[str]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    cat = catalogue()
    cat.to_csv(OUT / "catalogue.csv", index=False)
    jobs = []
    for row in cat.to_dict("records"):
        for noise in NOISE:
            for memory in memories:
                if memory == "fifo" and row["split"] != "test":
                    continue   # FIFO memory is a test-time comparison; its risk models are trained on its own train runs below
                jobs.append((row, noise, memory, budget, capacity))
    # FIFO also needs train/val trajectories for a fair (separately trained) RISKSTOP
    if "fifo" in memories:
        jobs += [(row, noise, "fifo", budget, capacity) for row in cat.to_dict("records") for noise in NOISE if row["split"] != "test"]
    done = 0
    with ProcessPoolExecutor(max_workers=workers) as ex, open(OUT / "trajectories.pkl", "ab") as fh:
        futs = [ex.submit(_collect_one, j) for j in jobs]
        for fut in as_completed(futs):
            res = fut.result()
            done += 1
            if res is not None:
                pickle.dump(res, fh)
            if done % 25 == 0:
                print(f"{done}/{len(jobs)} investigations", flush=True)
    print(f"collected {done} investigations")


def load_trajectories() -> list[dict]:
    out = []
    with open(OUT / "trajectories.pkl", "rb") as fh:
        while True:
            try:
                out.append(pickle.load(fh))
            except EOFError:
                break
    return out


# ------------------------------------------------------------------ evaluation
def _labels(traj_rec):
    y_att = 0 if traj_rec["gold"] == "BENIGN" else 1
    rows = traj_rec["trajectory"]
    return rows, np.full(len(rows), y_att), np.array([0.0 if y_att == 0 else 1.0 - r["_core_frac_seen"] for r in rows])


def evaluate_policy(recs, models, policy, name):
    from .riskstop import replay
    out = []
    for rec in recs:
        rows = rec["trajectory"]
        if not rows:
            continue
        cache = rec.setdefault("_pred", {})
        if id(models) not in cache:           # predictions don't depend on the policy: compute once per model
            cache[id(models)] = models.predict(rows)
        p, r = cache[id(models)]
        action, i, why = replay(rows, p, r, policy)
        st = rows[i]
        out.append({"id": rec["id"], "domain": rec["domain"], "noise": rec["noise"], "memory": rec["memory"], "gold": rec["gold"], "policy": name,
                    "action": action, "step": i, "budget_used_frac": st["budget_used_frac"], "core_seen": st["_core_frac_seen"],
                    "cites_attack": st["_cites_attack"], "cites_core": st["_cites_core"], "p_attack": float(p[i]), "residual": float(r[i]), "why": why})
    return pd.DataFrame(out)


def metrics(df: pd.DataFrame) -> dict:
    att = df.gold.isin(["ATTACK", "DEFER"])
    ben = df.gold.eq("BENIGN")
    m = {"n": len(df),
         "accuracy": float((df.action == df.gold).mean()),
         "missed_attack_rate": float((df.action[att] == "BENIGN").mean()) if att.any() else np.nan,
         "false_alarm_rate": float((df.action[ben] == "ATTACK").mean()) if ben.any() else np.nan,
         "defer_rate": float((df.action == "DEFER").mean()),
         "correct_defer_rate": float((df.action[df.gold == "DEFER"] == "DEFER").mean()) if (df.gold == "DEFER").any() else np.nan,
         "decided_accuracy": float((df.action[df.action != "DEFER"] == df.gold[df.action != "DEFER"].replace({"DEFER": "ATTACK"})).mean()) if (df.action != "DEFER").any() else np.nan,
         "budget_used": float(df.budget_used_frac.mean()),
         "premature_attack_rate": float(((df.action == "ATTACK") & att & (df.core_seen == 0)).sum() / max((df.action[att] == "ATTACK").sum(), 1)),
         "grounded_attack_rate": float(df.cites_attack[(df.action == "ATTACK") & att].mean()) if ((df.action == "ATTACK") & att).any() else np.nan}
    return m


def calibrate(recs, models, alpha: float, beta: float):
    from .riskstop import RiskStopParams, make_riskstop
    best, best_key = None, None
    for ta in (0.6, 0.7, 0.8, 0.9, 0.95):
        for tb in (0.05, 0.1, 0.2, 0.3, 0.4):
            if tb >= ta:
                continue
            for rho in (0.2, 0.35, 0.5, 0.7, 1.0):
                for lam in (0.0, 0.001, 0.005):
                    params = RiskStopParams(ta, tb, rho, lam)
                    m = metrics(evaluate_policy(recs, models, make_riskstop(params), "riskstop"))
                    viol = max(0, (m["missed_attack_rate"] or 0) - beta) + max(0, (m["false_alarm_rate"] or 0) - alpha)
                    util = m["accuracy"] - 0.2 * m["budget_used"]
                    key = (viol, -util)
                    if best_key is None or key < best_key:
                        best, best_key = params, key
    return best, best_key


def calibrate_conformal(recs, models, alpha, beta):
    from .riskstop import baseline_conformal_deferral
    best, best_key = None, None
    for ta in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
        for tb in (0.05, 0.1, 0.2, 0.3, 0.4, 0.5):
            if tb > ta:
                continue
            m = metrics(evaluate_policy(recs, models, baseline_conformal_deferral(ta, tb), "conformal"))
            viol = max(0, (m["missed_attack_rate"] or 0) - beta) + max(0, (m["false_alarm_rate"] or 0) - alpha)
            key = (viol, -m["accuracy"])
            if best_key is None or key < best_key:
                best, best_key = (ta, tb), key
    return best


def evaluate(alpha: float, beta: float) -> None:
    from .riskstop import RiskModels, baseline_bagen, baseline_confidence_stop, baseline_conformal_deferral, baseline_fixed_budget, make_riskstop
    recs = [r for r in load_trajectories() if "error" not in r and r["trajectory"]]
    errors = [r for r in load_trajectories() if "error" in r]
    print(f"{len(recs)} trajectories, {len(errors)} errors")
    results, chosen = [], {}
    for memory in sorted({r["memory"] for r in recs}):
        tr = [r for r in recs if r["memory"] == memory and r["split"] == "train"]
        va = [r for r in recs if r["memory"] == memory and r["split"] == "val"]
        te = [r for r in recs if r["memory"] == memory and r["split"] == "test"]
        if not tr or not te:
            continue
        rows, ya, yr = [], [], []
        for rec in tr:
            a, b, c = _labels(rec)
            rows += a; ya.append(b); yr.append(c)
        models = RiskModels().fit(rows, np.concatenate(ya), np.concatenate(yr))
        params, key = calibrate(va, models, alpha, beta)
        cta, ctb = calibrate_conformal(va, models, alpha, beta)
        chosen[memory] = {"riskstop": params.__dict__, "calibration_violation_utility": key, "conformal": (cta, ctb)}
        policies = {"RISKSTOP": make_riskstop(params), "Fixed budget": baseline_fixed_budget(), "Confidence stop": baseline_confidence_stop(),
                    "BAGEN-style (gain stall)": baseline_bagen(), "Conformal deferral (end only)": baseline_conformal_deferral(cta, ctb)}
        for name, pol in policies.items():
            results.append(evaluate_policy(te, models, pol, name))
        with open(OUT / f"models_{memory}.pkl", "wb") as fh:
            pickle.dump(models, fh)
    res = pd.concat(results, ignore_index=True)
    res.to_csv(OUT / "test_decisions.csv", index=False)
    table = []
    for (memory, policy), part in res.groupby(["memory", "policy"]):
        table.append({"memory": memory, "policy": policy, **metrics(part)})
        for dom, sub in part.groupby("domain"):
            table.append({"memory": memory, "policy": policy, "domain": dom, **metrics(sub)})
    t = pd.DataFrame(table)
    t.to_csv(OUT / "test_metrics.csv", index=False)
    (OUT / "chosen_params.json").write_text(json.dumps(chosen, indent=2, default=str))
    with pd.option_context("display.width", 250, "display.max_columns", 20):
        print(t[t.get("domain").isna()].round(3).to_string(index=False) if "domain" in t else t.round(3).to_string(index=False))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stage", choices=["collect", "evaluate"])
    ap.add_argument("--budget", type=int, default=20)
    ap.add_argument("--capacity", type=int, default=256)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--memories", nargs="+", default=["evictguard", "fifo"])
    ap.add_argument("--alpha", type=float, default=0.05, help="max false-ATTACK rate on validation")
    ap.add_argument("--beta", type=float, default=0.05, help="max missed-attack rate on validation")
    a = ap.parse_args()
    if a.stage == "collect":
        collect(a.budget, a.capacity, a.workers, a.memories)
    else:
        evaluate(a.alpha, a.beta)


if __name__ == "__main__":
    main()
