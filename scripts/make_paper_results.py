"""Publication tables, figures and significance tests from the benchmark outputs.

Inputs (results/benchmark/):
    episodes_ood_main.csv          v2 / FIFO / Random on 16 native ATLASv2 attacks
    episodes_ood_v1.csv            original EVICTGuard (v1) on the same episodes
    episodes_ood_ablation_dev.csv  feature ablations, development scenarios only (h1-*)
    episodes_val.csv / episodes_test.csv   spliced OTRF-into-ATLASv2 episodes (optional)
Outputs (results/paper/): tables (.md + .tex), figures (.png + .pdf), stats.json

Protocol: h1-* = development (design decisions were made here); h2-* = held-out (never inspected
before the design was frozen; see results/evictguard_v2.sha256).
"""
from __future__ import annotations

import json
from itertools import product
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

R = Path("results/benchmark")
OUT = Path("results/paper")
OUT.mkdir(parents=True, exist_ok=True)
# Reference palette, first three categorical slots (validated all-pairs); v1 drawn as neutral dashed reference.
COLORS = {"evictguard_v2": "#2a78d6", "random": "#eb6834", "fifo": "#1baf7a", "evictguard_v1": "#8a8a85", "nodoze": "#4a4a46"}
LABELS = {"evictguard_v2": "EVICTGuard v2 (ours)", "evictguard_v1": "EVICTGuard v1", "fifo": "FIFO", "random": "Random",
          "evictguard_online": "EVICTGuard-Online (ours)", "online-protected_only": "Online, protected reservoir only",
          "recency_dedup": "Recency + dedup", "rare_action": "Rare-action anomaly", "nodoze": "NoDoze-style triage",
          "sigma_priority": "Sigma alert prioritisation", "evictguard_v3": "EVICTGuard v3", "evictguard_online_v2": "EVICTGuard-Online v2 (ours)",
          "online_v2-protected_only": "Online v2, protected reservoir only"}
ORDER = ["evictguard_v2", "evictguard_v3", "evictguard_online_v2", "evictguard_online", "nodoze", "sigma_priority", "rare_action", "recency_dedup", "evictguard_v1", "random", "fifo"]
INK, MUTED, GRID = "#1f1f1e", "#6b6b66", "#e6e5e0"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
                     "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False})


def load(name: str) -> pd.DataFrame | None:
    path = R / f"episodes_{name}.csv"
    return pd.read_csv(path) if path.exists() else None


def subset_label(ep: str) -> str:
    return "held-out (h2)" if "-h2-" in ep else "development (h1)"


def boot_ci(values: np.ndarray, n: int = 2000, seed: int = 17) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    if len(values) == 0:
        return (np.nan, np.nan)
    samples = values[rng.integers(0, len(values), (n, len(values)))].mean(axis=1)
    return float(np.percentile(samples, 2.5)), float(np.percentile(samples, 97.5))


def paired_permutation(a: np.ndarray, b: np.ndarray) -> float:
    """Exact two-sided sign-flip test on paired episode differences."""
    d = a - b
    d = d[~np.isnan(d)]
    n = len(d)
    if n == 0:
        return np.nan
    obs = abs(d.mean())
    signs = np.array(list(product([-1, 1], repeat=n))) if n <= 16 else np.random.default_rng(0).choice([-1, 1], (20000, n))
    return float((np.abs((signs * d).mean(axis=1)) >= obs - 1e-12).mean())


def fmt(m, lo, hi):
    return f"{m:.3f} [{lo:.3f}, {hi:.3f}]"


def main() -> None:
    main_df, v1, base = load("ood_main"), load("ood_v1"), load("ood_baselines")
    rt = load("ood_baselines_rt")   # anomaly baselines re-run with a fair random tie-break (supersedes time tie-break)
    if base is not None and rt is not None:
        base = pd.concat([base[~base.method.isin(rt.method.unique())], rt], ignore_index=True)
    if main_df is None:
        raise SystemExit("run the OOD benchmark first")
    df = pd.concat([main_df] + [x for x in (v1, base) if x is not None], ignore_index=True)
    df["subset"] = df.episode_id.map(subset_label)
    stats: dict = {"design_sha256": Path("results/evictguard_v2.sha256").read_text().split()[0] if Path("results/evictguard_v2.sha256").exists() else None}

    # ---------------- Table 1: core action recall, clean, per capacity and subset
    rows = []
    for subset in ("development (h1)", "held-out (h2)"):
        for cap in sorted(df.capacity.unique()):
            for m in [x for x in ORDER if x in df.method.unique()]:
                part = df[(df.subset == subset) & (df.capacity == cap) & (df.noise == "none") & (df.method == m)]
                if part.empty:
                    continue
                vals = part.groupby("episode_id").core_action_recall.mean().to_numpy()
                lo, hi = boot_ci(vals)
                rec = part.groupby("episode_id").core_recall.mean().to_numpy()
                rows.append({"subset": subset, "capacity": cap, "method": LABELS[m], "episodes": len(vals),
                             "core action recall [95% CI]": fmt(vals.mean(), lo, hi), "core record recall": f"{rec.mean():.3f}",
                             "core AP": f"{part.core_ap.mean():.3f}" if part.core_ap.notna().any() else "n/a",
                             "kept / input": f"{cap / part.input_events.mean():.2%}"})
    t1 = pd.DataFrame(rows)
    (OUT / "table1_ood_clean.md").write_text(t1.to_markdown(index=False))
    (OUT / "table1_ood_clean.tex").write_text(t1.to_latex(index=False, escape=True))

    # ---------------- Table 2: robustness under noise (capacity 1024)
    rows = []
    for subset in ("development (h1)", "held-out (h2)"):
        for noise in df.noise.unique():
            for m in [x for x in ORDER if x in df.method.unique()]:
                part = df[(df.subset == subset) & (df.capacity == 1024) & (df.noise == noise) & (df.method == m)]
                if part.empty:
                    continue
                vals = part.core_action_recall.to_numpy()
                lo, hi = boot_ci(vals)
                rows.append({"subset": subset, "noise": noise, "method": LABELS[m], "core action recall [95% CI]": fmt(vals.mean(), lo, hi),
                             "injected-noise share of context": f"{part.noise_share.mean():.3f}"})
    t2 = pd.DataFrame(rows)
    (OUT / "table2_ood_noise.md").write_text(t2.to_markdown(index=False))
    (OUT / "table2_ood_noise.tex").write_text(t2.to_latex(index=False, escape=True))

    # ---------------- significance: v2 vs each baseline, paired over episodes
    sig = []
    for subset in ("development (h1)", "held-out (h2)"):
        for noise in sorted(df.noise.unique()):
            for cap in sorted(df.capacity.unique()):
                base = df[(df.subset == subset) & (df.noise == noise) & (df.capacity == cap)]
                ours = base[base.method == "evictguard_v2"].set_index("episode_id").core_action_recall
                for m in [x for x in ORDER[2:] if x in base.method.unique()]:
                    other = base[base.method == m].set_index("episode_id").core_action_recall
                    common = ours.index.intersection(other.index)
                    if len(common) == 0:
                        continue
                    a, b = ours.loc[common].to_numpy(), other.loc[common].to_numpy()
                    sig.append({"subset": subset, "noise": noise, "capacity": int(cap), "vs": m, "n": len(common),
                                "mean_diff": float((a - b).mean()), "wins": int((a > b).sum()), "p_value": paired_permutation(a, b)})
    stats["significance"] = sig
    pd.DataFrame(sig).to_csv(OUT / "significance.csv", index=False)

    # ---------------- Figure 1: capacity curve (small multiples: dev | held-out), clean
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.9), sharey=True)
    for ax, subset in zip(axes, ("development (h1)", "held-out (h2)")):
        for m in ["evictguard_v2", "random", "fifo", "evictguard_v1", "nodoze"]:
            part = df[(df.subset == subset) & (df.noise == "none") & (df.method == m)]
            if part.empty:
                continue
            g = part.groupby("capacity").core_action_recall.mean()
            style = dict(color=COLORS[m], lw=2, marker="o", ms=5, mec="white", mew=1.2)
            if m == "evictguard_v1":
                style.update(ls="--", marker="s")
            if m == "nodoze":
                style.update(ls=":", marker="^")
            ax.plot(g.index, g.values, **style, label=LABELS[m])
            if m == "evictguard_v2":
                ax.annotate(f"{g.values[-1]:.2f}", (g.index[-1], g.values[-1]), xytext=(0, 8), textcoords="offset points",
                            ha="center", fontsize=8, color=INK)
        ax.set_xscale("log", base=2)
        ax.set_title(subset, fontsize=9, color=INK, loc="left")
        ax.set_xlabel("Context capacity (events kept)")
        ax.grid(axis="y", color=GRID, lw=0.8)
        ax.set_ylim(-0.02, 1.02)
        caps = sorted(df.capacity.unique())
        ax.set_xticks(caps)
        ax.set_xticklabels([f"{int(c):,}" for c in caps])
        ax.minorticks_off()
    axes[0].set_ylabel("Core attack-evidence recall")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=4, frameon=False, fontsize=8, bbox_to_anchor=(0.5, 1.04))
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    for ext in ("png", "pdf"):
        fig.savefig(OUT / f"fig1_capacity_curve.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)

    # ---------------- Figure 2: robustness under noise, capacity 1024, held-out (dot plot)
    held = df[(df.subset == "held-out (h2)") & (df.capacity == 1024)]
    noises = [n for n in ["none", "duplicate-flooding", "background-flood", "mimic-flood"] if n in held.noise.unique()]
    fig, ax = plt.subplots(figsize=(6.4, 2.6))
    methods = [m for m in ["evictguard_v2", "nodoze", "random", "fifo"] if m in held.method.unique()]
    for j, m in enumerate(methods):
        for i, n in enumerate(noises):
            vals = held[(held.method == m) & (held.noise == n)].core_action_recall.to_numpy()
            if len(vals) == 0:
                continue
            y = i + (j - (len(methods) - 1) / 2) * 0.18
            lo, hi = boot_ci(vals)
            ax.plot([lo, hi], [y, y], color=COLORS[m], lw=3, solid_capstyle="round", alpha=0.45)
            ax.plot(vals.mean(), y, "o", color=COLORS[m], ms=7, mec="white", mew=1.5, label=LABELS[m] if i == 0 else None)
    ax.set_yticks(range(len(noises)))
    ax.set_yticklabels([n.replace("-", " ") for n in noises])
    ax.invert_yaxis()
    ax.set_xlabel("Core attack-evidence recall at capacity 1,024 (held-out h2; mean, 95% CI)")
    ax.set_xlim(-0.02, 1.02)
    ax.grid(axis="x", color=GRID, lw=0.8)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=4, frameon=False, fontsize=8)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(OUT / f"fig2_noise_robustness.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)

    # ---------------- Figure 3 + Table 3: ablation (development only)
    abl = load("ood_ablation_dev")
    if abl is not None:
        full = abl[abl.method == "evictguard_v2"].groupby("noise").core_action_recall.mean()
        rows = []
        for m in sorted(abl.method.unique()):
            if m == "evictguard_v2":
                continue
            for noise, part in abl[abl.method == m].groupby("noise"):
                drop = full[noise] - part.core_action_recall.mean()
                rows.append({"removed": m.replace("v2-no_", ""), "noise": noise, "recall": part.core_action_recall.mean(), "drop": drop})
        t3 = pd.DataFrame(rows).pivot(index="removed", columns="noise", values="drop").sort_values("none", ascending=False)
        (OUT / "table3_ablation_dev.md").write_text("Drop in core action recall (capacity 1,024, development h1) when one component is removed; "
                                                  f"full model: {full.round(3).to_dict()}\n\n" + t3.round(3).to_markdown())
        (OUT / "table3_ablation_dev.tex").write_text(t3.round(3).to_latex())
        fig, ax = plt.subplots(figsize=(5.2, 3.2))
        order = t3["none"].sort_values()
        ax.barh(range(len(order)), order.values, color=COLORS["evictguard_v2"], height=0.6)
        for i, v in enumerate(order.values):
            ax.annotate(f"{v:+.3f}", (v, i), xytext=(4 if v >= 0 else -4, 0), textcoords="offset points", va="center",
                        ha="left" if v >= 0 else "right", fontsize=8, color=INK)
        lo_x = min(order.min(), 0)
        ax.set_xlim(lo_x - 0.06, order.max() + 0.04)
        ax.set_yticks(range(len(order)))
        ax.set_yticklabels([s.replace("_", " ") for s in order.index])
        ax.axvline(0, color=MUTED, lw=0.8)
        ax.set_xlabel("Recall lost when removed (dev h1, no noise)")
        ax.grid(axis="x", color=GRID, lw=0.8)
        fig.tight_layout()
        for ext in ("png", "pdf"):
            fig.savefig(OUT / f"fig3_ablation.{ext}", dpi=300, bbox_inches="tight")
        plt.close(fig)

    # ---------------- spliced episodes (secondary)
    for split in ("val", "test"):
        sp = load(split)
        if sp is None or "core_action_recall" not in sp:
            continue
        s = sp[sp.noise == "none"].groupby(["capacity", "method"]).core_action_recall.mean().unstack()
        (OUT / f"table4_spliced_{split}.md").write_text(f"Spliced OTRF-into-ATLASv2 episodes ({split}), core action recall, no noise\n\n" + s.round(3).to_markdown())


    # ---------------- Table 5: second dataset, native OTRF (frozen v2, cold start), per split
    nat = []
    for sp in ("train", "val", "test"):
        x, rt2 = load(f"otrf_native_{sp}_frozen"), load(f"otrf_native_{sp}_baselines_rt")
        if x is not None and rt2 is not None:
            x = pd.concat([x[~x.method.isin(rt2.method.unique())], rt2], ignore_index=True)
        elif x is not None and sp != "test":
            x = x[~x.method.isin(["nodoze", "rare_action"])]   # only report anomaly baselines with the fair tie-break
        nat.append(x)
    nat = pd.concat([x for x in nat if x is not None], ignore_index=True) if any(x is not None for x in nat) else None
    if nat is not None:
        rows = []
        for (split, cap, noise), part in nat.groupby(["split", "capacity", "noise"]):
            for m in [x for x in ORDER if x in part.method.unique()]:
                vals = part[part.method == m].groupby("episode_id").core_action_recall.mean().dropna().to_numpy()
                if len(vals) == 0:
                    continue
                lo, hi = boot_ci(vals)
                rows.append({"split": split, "capacity (fraction)": cap, "noise": noise, "method": LABELS.get(m, m),
                             "episodes": len(vals), "core action recall [95% CI]": fmt(vals.mean(), lo, hi)})
        t5 = pd.DataFrame(rows)
        (OUT / "table5_otrf_native.md").write_text("Native OTRF episodes (real attack + real lab background, Windows 10), cold start (no history). "
                                                  "Frozen EVICTGuard v2 never saw this dataset.\n\n" + t5.to_markdown(index=False))
        (OUT / "table5_otrf_native.tex").write_text(t5.to_latex(index=False, escape=True))
        sig2 = []
        for (split, cap, noise), part in nat.groupby(["split", "capacity", "noise"]):
            ours = part[part.method == "evictguard_v2"].set_index("episode_id").core_action_recall
            for m in [x for x in ORDER[2:] if x in part.method.unique()]:
                other = part[part.method == m].set_index("episode_id").core_action_recall
                common = ours.dropna().index.intersection(other.dropna().index)
                if len(common):
                    a, b = ours.loc[common].to_numpy(), other.loc[common].to_numpy()
                    sig2.append({"split": split, "capacity": cap, "noise": noise, "vs": m, "n": len(common), "mean_diff": float((a - b).mean()),
                                 "wins": int((a > b).sum()), "ties": int((a == b).sum()), "p_value": paired_permutation(a, b)})
        pd.DataFrame(sig2).to_csv(OUT / "significance_otrf_native.csv", index=False)
        stats["significance_otrf_native"] = sig2

    # ---------------- Table 6: online (streaming) vs batch, and reservoir ablation
    on = [x for x in (load("ood_online_dev"), load("ood_online_test"), load("otrf_native_train_online_dev"), load("otrf_native_test_online_test")) if x is not None]
    if on:
        on = pd.concat(on, ignore_index=True)
        on["set"] = np.where(on.split.str.startswith("otrf"), on.split, np.where(on.episode_id.str.contains("-h2-"), "atlas_h2 (held-out)", "atlas_h1 (dev)"))
        t6 = on.groupby(["set", "noise", "capacity", "method"]).core_action_recall.mean().unstack().round(3)
        (OUT / "table6_online_vs_batch.md").write_text("Core action recall: streaming (online) vs batch EVICTGuard; reservoir ablation\n\n" + t6.to_markdown())


    # ---------------- Table 7: v3 fresh test (OTRF train) - also the full train-split comparison
    v3 = load("otrf_native_train_v3test")
    if v3 is not None:
        rows = []
        for (cap, noise), part in v3.groupby(["capacity", "noise"]):
            for m in [x for x in ORDER if x in part.method.unique()]:
                vals = part[part.method == m].groupby("episode_id").core_action_recall.mean().dropna().to_numpy()
                lo, hi = boot_ci(vals)
                rows.append({"capacity (fraction)": cap, "noise": noise, "method": LABELS.get(m, m), "episodes": len(vals), "core action recall [95% CI]": fmt(vals.mean(), lo, hi)})
        (OUT / "table7_v3_fresh_test_otrf_train.md").write_text("EVICTGuard v3 (frozen, results/evictguard_v3.json) on its fresh test: OTRF native train split, cold start.\n\n"
                                                                 + pd.DataFrame(rows).to_markdown(index=False))
        sig3 = []
        for (cap, noise), part in v3.groupby(["capacity", "noise"]):
            a = part[part.method == "evictguard_v3"].set_index("episode_id").core_action_recall
            for m in [x for x in part.method.unique() if x != "evictguard_v3"]:
                b = part[part.method == m].set_index("episode_id").core_action_recall
                c = a.dropna().index.intersection(b.dropna().index)
                if len(c):
                    sig3.append({"capacity": cap, "noise": noise, "vs": m, "n": len(c), "mean_diff": float((a[c] - b[c]).mean()),
                                 "wins": int((a[c] > b[c]).sum()), "ties": int((a[c] == b[c]).sum()), "p_value": paired_permutation(a[c].to_numpy(), b[c].to_numpy())})
        pd.DataFrame(sig3).to_csv(OUT / "significance_v3_otrf_train.csv", index=False)

    # ---------------- Table 8: anomaly baselines under 5 tie-break seeds
    import glob as _glob
    seeds = [pd.read_csv(f) for f in _glob.glob(str(R / "episodes_*_tieseed*.csv"))]
    if seeds:
        t = pd.concat(seeds, ignore_index=True)
        t["set"] = np.where(t.split == "ood", np.where(t.episode_id.str.contains("-h2-"), "ATLASv2 h2 (held-out)", "ATLASv2 h1 (dev)"), t.split)
        per = t.groupby(["set", "capacity", "method", "episode_id"]).core_action_recall.agg(["mean", "std"])
        t8 = per.groupby(["set", "capacity", "method"]).agg(mean_recall=("mean", "mean"), mean_seed_sd=("std", "mean")).round(3)
        (OUT / "table8_tiebreak_seeds.md").write_text("Anomaly baselines with 5 random tie-break seeds (no noise): mean recall and mean per-episode SD across seeds\n\n" + t8.to_markdown())

    # ---------------- Table 9: CDB (independent labels) raw and sensitivity
    for tag, title in (("cdb_all", "CDB public sample, CDB's own labels (raw)"), ("cdb_filtered_all", "CDB sensitivity: flags that are pure Azure guest-agent activity excluded")):
        c = load(tag)
        if c is None:
            continue
        cols = ["core_timestamp_recall", "core_action_recall", "attack_process_coverage", "noise_share"]
        t9 = c.pivot_table(index=["noise", "capacity_events", "method"], values=cols).round(3)
        (OUT / f"table9_{tag}.md").write_text(title + " (1 campaign, 155,350 events; cold start)\n\n" + t9.to_markdown())

    # ---------------- Table 10: reservoirs - coverage, not recall (held-out)
    cov = [x for x in (load("ood_coverage_test"), load("otrf_native_val_online2_test")) if x is not None]
    if cov:
        cv = pd.concat(cov, ignore_index=True)
        cv["set"] = np.where(cv.split == "ood", "ATLASv2 h2 (held-out)", cv.split)
        t10 = cv[cv.noise == "none"].groupby(["set", "capacity", "method"])[["core_action_recall", "attack_process_coverage", "stratum_coverage", "supporting_action_recall"]].mean().round(3)
        (OUT / "table10_reservoirs_coverage.md").write_text("Stratified reservoirs: recall vs coverage (held-out, no noise)\n\n" + t10.to_markdown())

    # ---------------- weight sensitivity (development)
    ws = Path("results/paper/weight_sensitivity_dev.csv")
    if ws.exists():
        w = pd.read_csv(ws)
        pert = w[~w["default"]].recall
        stats["weight_sensitivity_dev"] = {"default": float(w.recall.iloc[0]), "perturbed_mean": float(pert.mean()), "perturbed_min": float(pert.min()),
                                           "perturbed_max": float(pert.max()), "perturbed_std": float(pert.std()), "draws": int(len(pert))}

    (OUT / "stats.json").write_text(json.dumps(stats, indent=2))
    print(t1.to_string(index=False))
    print()
    print(pd.DataFrame(sig).query("noise == 'none'").to_string(index=False))


if __name__ == "__main__":
    main()
