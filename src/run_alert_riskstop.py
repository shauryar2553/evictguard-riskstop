"""RISKSTOP on the alert-driven ATLASv2 Carbon Black benchmark, with Learn-then-Test risk control.

collect   one investigation per (alert, noise, memory), run to full budget, state recorded per step
evaluate  fit risk models on TRAIN; calibrate on VAL with Learn-then-Test (LTT); report TEST with
          guarantees, expected cost, regret vs a hindsight oracle, ablations and significance tests.

Learn-then-Test (Angelopoulos et al., 2021) for sequential stopping
  For every candidate threshold setting lambda in a grid G, test H0: missed-attack rate > alpha and
  H0': false-alarm rate > alpha, using exact binomial p-values on the validation investigations. Settings
  whose p-values are <= delta / (2|G|) (Bonferroni) are certified: with probability >= 1 - delta, ALL certified
  settings have true risk <= alpha simultaneously (under exchangeability of validation and test alerts).
  Among certified settings we pick the one with the lowest expected cost.

Cost model (fixed before evaluation): missed attack 10, false alarm 3, defer 1, investigation budget 0.5 per full budget.
"""
from __future__ import annotations

import argparse
import json
import pickle
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np
import pandas as pd

OUT = Path("data/alert_bench")
NOISE = {"none": None, "background-flood": 1.0, "missing-critical": 0.6}
COST = {"miss": 10.0, "false_alarm": 3.0, "defer": 1.0, "budget": 0.5}


# ------------------------------------------------------------------ collection
def _profile():
    from .evictguard_v2 import PrevalenceProfile
    path = OUT / "prevalence_cbc_train.json"
    if path.exists():
        return PrevalenceProfile.load(path)
    al = pd.read_csv(OUT / "alerts.csv", parse_dates=["time"])
    src = OUT / "sources" / "h2-benign.parquet"
    if not src.exists():
        return None
    b = pd.read_parquet(src)
    train_days = set(al[(al.kind == "benign_period") & (al.split == "train")].time.dt.strftime("%Y-%m-%d"))
    days = pd.to_datetime(b.timestamp, utc=True, errors="coerce").dt.strftime("%Y-%m-%d")
    prof = PrevalenceProfile.build([b[days.isin(train_days)]])
    prof.save(path)
    return prof


def _one(args):
    alert, noise, memory, budget, capacity = args
    from .alert_benchmark import episode_for
    from .evictguard_v2 import action_keys
    from .investigation import run_investigation
    from .noise import inject_noise
    from .run_benchmark import gold_verdict
    try:
        e, seed = episode_for(alert)
        if len(e) == 0:
            return None
        gold = alert["gold"]
        if noise == "missing-critical":
            if gold != "ATTACK":
                return None
            before = int(e.gt_label.eq("attack").sum())
            e, _ = inject_noise(e, noise, NOISE[noise], 17)
            e = e.reset_index(drop=True)
            gold = gold_verdict("ATTACK", before, int(e.gt_label.eq("attack").sum()))
            seed = np.flatnonzero(e.process_guid_cbc.to_numpy() == alert["process_guid"]).tolist()[:1]
        elif noise != "none":
            e, _ = inject_noise(e, noise, NOISE[noise], 17)
            e = e.reset_index(drop=True)
        prof = _profile()
        res = run_investigation(e, lambda f, s: ("CONTINUE", {}), budget=budget, capacity=capacity, memory_policy=memory,
                                profile=prof, seed_rows=seed or None, alert=alert)
        attack_mask = e.gt_label.eq("attack").to_numpy()
        attack_procs = set(e.process_guid_cbc.to_numpy()[attack_mask])
        retrieved = res["retrieved_rows"]
        traj = []
        for f in res["trajectory"]:
            n = int(f.get("_retrieved_n", 0))
            seen = set(e.process_guid_cbc.to_numpy()[retrieved[:n]]) & attack_procs if n else set()
            top = f.get("_top_rows", [])
            traj.append({**{k: v for k, v in f.items() if not k.startswith("_")},
                         "_core_frac_seen": len(seen) / len(attack_procs) if attack_procs else 1.0,
                         "_cites_attack": bool(attack_mask[top].any()) if top else False,
                         "_cites_core": bool(attack_mask[top].any()) if top else False})
        return {"id": alert["alert_id"], "domain": alert["kind"], "split": alert["split"], "noise": noise, "memory": memory, "gold": gold,
                "events": len(e), "trajectory": traj, "queries": res["queries"], "budget_used": res["budget_used"],
                "report": alert.get("report_name"), "severity": alert.get("severity")}
    except Exception as exc:
        return {"id": alert.get("alert_id"), "error": repr(exc), "noise": noise, "memory": memory}


def collect(budget: int, capacity: int, workers: int) -> None:
    al = pd.read_csv(OUT / "alerts.csv", parse_dates=["time"])
    _profile()
    jobs = [(a, n, m, budget, capacity) for a in al.to_dict("records") for n in NOISE for m in ("evictguard", "fifo")]
    path = OUT / "trajectories.pkl"
    path.unlink(missing_ok=True)
    done = 0
    with ProcessPoolExecutor(max_workers=workers) as ex, open(path, "ab") as fh:
        for fut in as_completed([ex.submit(_one, j) for j in jobs]):
            r = fut.result()
            done += 1
            if r is not None:
                pickle.dump(r, fh)
            if done % 50 == 0:
                print(f"{done}/{len(jobs)}", flush=True)
    print(f"collected {done}")


def load() -> list[dict]:
    out = []
    with open(OUT / "trajectories.pkl", "rb") as fh:
        while True:
            try:
                out.append(pickle.load(fh))
            except EOFError:
                return out


# ------------------------------------------------------------------ risk control and costs
def binom_cdf(k: int, n: int, p: float) -> float:
    from math import comb
    return float(sum(comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(0, k + 1)))


def expected_cost(df: pd.DataFrame) -> pd.Series:
    att = df.gold.isin(["ATTACK", "DEFER"])
    c = np.zeros(len(df))
    c += np.where(att & (df.action == "BENIGN"), COST["miss"], 0)
    c += np.where((df.gold == "BENIGN") & (df.action == "ATTACK"), COST["false_alarm"], 0)
    c += np.where((df.action == "DEFER") & (df.gold != "DEFER"), COST["defer"], 0)
    c += np.where((df.gold == "DEFER") & (df.action == "ATTACK"), 0.5 * COST["defer"], 0)   # grounded attack on thin evidence: half credit
    c += COST["budget"] * df.budget_used_frac.to_numpy()
    return pd.Series(c, index=df.index)


def oracle_cost(recs, models) -> pd.DataFrame:
    """Hindsight-optimal stopping for the SAME classifier: stop at the step that minimises the cost of the verdict the
    classifier gives there (ATTACK if p >= 0.5 else BENIGN), or DEFER. A lower bound on any policy using these models."""
    rows = []
    for rec in recs:
        p, _ = rec["_pred"][id(models)]
        best = None
        for i, f in enumerate(rec["trajectory"]):
            for act in ("ATTACK" if p[i] >= 0.5 else "BENIGN", "DEFER"):
                df = pd.DataFrame([{"gold": rec["gold"], "action": act, "budget_used_frac": f["budget_used_frac"]}])
                c = float(expected_cost(df).iloc[0])
                best = c if best is None or c < best else best
        rows.append({"id": rec["id"], "noise": rec["noise"], "oracle_cost": best})
    return pd.DataFrame(rows)


def ltt_calibrate(recs, models, alpha: float, delta: float):
    """Fixed-sequence Learn-then-Test (valid family-wise error control without a Bonferroni penalty over the path).

    For each residual-risk cap rho in a small set R (Bonferroni over |R| and the two risks):
      1. false alarms: walk tau_attack from most conservative (0.99) downwards, holding tau_benign at its most
         conservative value; certify while the exact binomial p-value of H0 "false-alarm rate > alpha" is
         <= delta / (2|R|); keep the most decisive certified tau_attack.
      2. missed attacks: walk tau_benign from most conservative (0.01) upwards with that tau_attack; certify
         while H0 "missed-attack rate > alpha" is rejected at delta / (2|R|); keep the most decisive certified one.
    Among rho values where both are certified, pick the lowest validation cost.
    Guarantee (exchangeable alerts): with probability >= 1 - delta, the chosen thresholds have false-alarm and
    missed-attack rates <= alpha.
    """
    from .riskstop import RiskStopParams, make_riskstop
    from .run_riskstop import evaluate_policy
    R = (0.5, 0.7, 1.0)
    thr = delta / (2 * len(R))
    TA = (0.99, 0.98, 0.95, 0.9, 0.85, 0.8, 0.7, 0.6, 0.5)
    TB = (0.01, 0.02, 0.05, 0.1, 0.15, 0.2, 0.3, 0.4, 0.49)

    def risks(prm):
        d = evaluate_policy(recs, models, make_riskstop(prm), "riskstop")
        att, ben = d.gold.isin(["ATTACK", "DEFER"]), d.gold.eq("BENIGN")
        k1, n1 = int((d.action[att] == "BENIGN").sum()), int(att.sum())
        k2, n2 = int((d.action[ben] == "ATTACK").sum()), int(ben.sum())
        return binom_cdf(k1, n1, alpha), binom_cdf(k2, n2, alpha), float(expected_cost(d).mean()), k1 / max(n1, 1), k2 / max(n2, 1)

    cands = []
    for rho in R:
        ta_ok = None
        for ta in TA:
            if risks(RiskStopParams(ta, TB[0], rho, 0.002))[1] <= thr:
                ta_ok = ta
            else:
                break
        if ta_ok is None:
            continue
        tb_ok = None
        for tb in TB:
            if tb >= ta_ok:
                break
            if risks(RiskStopParams(ta_ok, tb, rho, 0.002))[0] <= thr:
                tb_ok = tb
            else:
                break
        if tb_ok is None:
            continue
        p1, p2, cost, miss, fa = risks(RiskStopParams(ta_ok, tb_ok, rho, 0.002))
        cands.append({"params": RiskStopParams(ta_ok, tb_ok, rho, 0.002), "cost": cost, "miss": miss, "fa": fa, "p_miss": p1, "p_fa": p2})
    if not cands:
        return None, {"certified": 0, "threshold": thr, "note": "no setting certified at this alpha/delta with this many validation investigations"}
    best = min(cands, key=lambda c: c["cost"])
    return best["params"], {"certified_rhos": len(cands), "threshold": thr, "val_cost": best["cost"], "val_miss": best["miss"], "val_fa": best["fa"],
                            "p_miss": best["p_miss"], "p_fa": best["p_fa"]}


def clopper_pearson(k: int, n: int, conf: float = 0.95) -> tuple[float, float]:
    from scipy.stats import beta
    lo = 0.0 if k == 0 else beta.ppf((1 - conf) / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - (1 - conf) / 2, k + 1, n - k)
    return float(lo), float(hi)


def evaluate(alpha: float, delta: float) -> None:
    from .riskstop import (RiskModels, RiskStopParams, baseline_bagen, baseline_confidence_stop, baseline_conformal_deferral, baseline_fixed_budget,
                           make_riskstop)
    from .run_riskstop import _labels, calibrate_conformal, evaluate_policy, metrics
    recs = [r for r in load() if "error" not in r and r.get("trajectory")]
    errs = [r for r in load() if "error" in r]
    print(f"{len(recs)} investigations, {len(errs)} errors")
    report, tables, decisions = {}, [], []
    for memory in ("evictguard", "fifo"):
        tr = [r for r in recs if r["memory"] == memory and r["split"] == "train"]
        va = [r for r in recs if r["memory"] == memory and r["split"] == "val"]
        te = [r for r in recs if r["memory"] == memory and r["split"] == "test"]
        rows, ya, yr = [], [], []
        for r in tr:
            a, b, c = _labels(r); rows += a; ya.append(b); yr.append(c)
        models = RiskModels().fit(rows, np.concatenate(ya), np.concatenate(yr))
        for r in va + te:
            r.setdefault("_pred", {})[id(models)] = models.predict(r["trajectory"])
        params, info = ltt_calibrate(va, models, alpha, delta)
        cta, ctb = calibrate_conformal(va, models, alpha, alpha)
        policies = {"Fixed budget": baseline_fixed_budget(), "Confidence stop": baseline_confidence_stop(), "BAGEN-style (gain stall)": baseline_bagen(),
                    "Conformal deferral (end only)": baseline_conformal_deferral(cta, ctb)}
        if params is not None:
            policies["RISKSTOP (LTT-certified)"] = make_riskstop(params)
            policies["RISKSTOP - no residual risk"] = make_riskstop(RiskStopParams(params.tau_attack, params.tau_benign, 1.0, params.lam))
            policies["RISKSTOP - no query value"] = make_riskstop(RiskStopParams(params.tau_attack, params.tau_benign, params.rho, 0.0))
        policies["RISKSTOP - uncalibrated defaults"] = make_riskstop(RiskStopParams())
        orc = oracle_cost(te, models)
        report[memory] = {"ltt": info, "params": params.__dict__ if params else None, "conformal": (cta, ctb)}
        for name, pol in policies.items():
            d = evaluate_policy(te, models, pol, name)
            d["cost"] = expected_cost(d).to_numpy()
            d = d.merge(orc, on=["id", "noise"], how="left")
            decisions.append(d)
            m = metrics(d)
            att = d.gold.isin(["ATTACK", "DEFER"]); ben = d.gold.eq("BENIGN")
            k1, n1 = int((d.action[att] == "BENIGN").sum()), int(att.sum())
            k2, n2 = int((d.action[ben] == "ATTACK").sum()), int(ben.sum())
            m.update({"memory": memory, "policy": name, "expected_cost": float(d.cost.mean()), "regret_vs_oracle": float((d.cost - d.oracle_cost).mean()),
                      "miss_CI95": clopper_pearson(k1, n1), "fa_CI95": clopper_pearson(k2, n2)})
            tables.append(m)
    dec = pd.concat(decisions, ignore_index=True)
    dec.to_csv(OUT / "test_decisions.csv", index=False)
    t = pd.DataFrame(tables)
    t.to_csv(OUT / "test_metrics.csv", index=False)
    # significance: RISKSTOP vs each baseline on per-investigation cost (paired sign-flip / bootstrap)
    sig = []
    for memory in ("evictguard", "fifo"):
        d = dec[dec.memory == memory].pivot_table(index=["id", "noise"], columns="policy", values="cost")
        if "RISKSTOP (LTT-certified)" not in d:
            continue
        rs = d["RISKSTOP (LTT-certified)"]
        rng = np.random.default_rng(17)
        for b in d.columns:
            if b == "RISKSTOP (LTT-certified)":
                continue
            diff = (rs - d[b]).dropna().to_numpy()
            boots = [diff[rng.integers(0, len(diff), len(diff))].mean() for _ in range(2000)]
            sig.append({"memory": memory, "vs": b, "n": len(diff), "mean_cost_diff": float(diff.mean()),
                        "CI95": (float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))),
                        "riskstop_better_share": float((diff < 0).mean()), "worse_share": float((diff > 0).mean())})
    pd.DataFrame(sig).to_csv(OUT / "significance.csv", index=False)
    (OUT / "report.json").write_text(json.dumps(report, indent=2, default=str))
    cols = ["memory", "policy", "n", "accuracy", "missed_attack_rate", "false_alarm_rate", "defer_rate", "budget_used", "grounded_attack_rate", "expected_cost", "regret_vs_oracle"]
    with pd.option_context("display.width", 250, "display.max_columns", 20):
        print(t[cols].round(3).to_string(index=False))
        print(json.dumps(report, indent=1, default=str))
        print(pd.DataFrame(sig).round(3).to_string(index=False))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stage", choices=["collect", "evaluate"])
    ap.add_argument("--budget", type=int, default=20)
    ap.add_argument("--capacity", type=int, default=256)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--alpha", type=float, default=0.10, help="target missed-attack and false-alarm rate")
    ap.add_argument("--delta", type=float, default=0.10, help="LTT failure probability")
    a = ap.parse_args()
    collect(a.budget, a.capacity, a.workers) if a.stage == "collect" else evaluate(a.alpha, a.delta)


if __name__ == "__main__":
    main()
