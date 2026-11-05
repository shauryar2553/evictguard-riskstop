"""Evaluate EVICTGuard vs FIFO vs Random on labelled episodes.

For every ATTACK episode of a split, every noise setting and every capacity,
all three selectors receive the identical noisy candidate set. Metrics use the
event-level ground truth:

* ``core_recall`` / ``supporting_recall`` / ``attack_recall``: fraction of
  *unique* attack evidence units still present in the noisy input that ends up
  in the selected context. A retained duplicate counts for its parent (``dup_of``).
* ``noise_share``: fraction of the selected context made of injected events.
* ``gold_verdict_after_noise``: the RISKSTOP gold label for the episode after
  the transformation (see ``gold_verdict``), recorded for later phases.

Aggregates report the mean and a 95% bootstrap CI resampled over attack-
recording clusters (episodes sharing recordings are not independent).
Thresholds/weights must be tuned on ``val``; report ``test`` once.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .noise import inject_noise
from .selection import select_evictguard, select_fifo, select_random

DEFAULT_NOISE = ["none:0", "duplicate-flooding:0.5", "background-flood:1.0", "mimic-flood:0.2", "missing-critical:0.3"]
CORE_COVERAGE_FOR_ATTACK = 0.5  # gold DEFER rule: <50% of original core evidence left -> DEFER


def gold_verdict(original_verdict: str, core_before: int, core_after: int) -> str:
    """Gold RISKSTOP verdict: decided *before* any experiment is run.

    BENIGN episodes stay BENIGN. ATTACK episodes stay ATTACK while at least
    ``CORE_COVERAGE_FOR_ATTACK`` of their core evidence (and >= 1 core event)
    survives; otherwise the evidence is insufficient and the correct action is DEFER.
    """
    if original_verdict != "ATTACK":
        return original_verdict
    if core_before == 0:
        return "DEFER"
    return "ATTACK" if core_after >= 1 and core_after / core_before >= CORE_COVERAGE_FOR_ATTACK else "DEFER"


def _units(frame: pd.DataFrame, tier: str | None) -> set[str]:
    mask = frame.gt_label.astype(str).eq("attack")
    if tier:
        mask &= frame.gt_tier.astype(str).eq(tier)
    dup = frame.get("dup_of", pd.Series(None, index=frame.index))
    ids = [str(d) if isinstance(d, str) and d else str(r) for r, d in zip(frame.record_id, dup)]
    return {i for i, m in zip(ids, mask) if m}


def evaluate_selection(noisy: pd.DataFrame, selected: pd.DataFrame) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, tier in (("core", "core"), ("supporting", "supporting"), ("attack", None)):
        available, kept = _units(noisy, tier), _units(selected, tier)
        out[f"{name}_available"] = len(available)
        out[f"{name}_recall"] = len(kept & available) / len(available) if available else np.nan
    synthetic = selected.get("is_synthetic", pd.Series(False, index=selected.index)).map(lambda v: str(v).lower() in {"true", "1"})
    out["selected"] = len(selected)
    out["noise_share"] = float(synthetic.mean()) if len(selected) else np.nan
    out["background_share"] = float((selected.gt_tier.astype(str) == "background").mean()) if len(selected) else np.nan
    return out


METHODS = ["evictguard_v2", "evictguard_v1", "fifo", "random"]
BASELINES = ["recency_dedup", "rare_action", "nodoze", "sigma_priority"]
ABLATIONS = ["prevalence", "lineage", "propagation", "location", "lolbin", "sensitivity", "novelty", "target_location", "command", "redundancy", "type"]


def _average_precision(score: np.ndarray, positive: np.ndarray) -> float:
    if not positive.any():
        return np.nan
    order = np.argsort(-score, kind="stable")
    y = positive[order]
    hits = np.cumsum(y)
    return float(((hits / np.arange(1, len(y) + 1)) * y).sum() / y.sum())


def load_profile(bench_dir: Path):
    """Historical prevalence profile from TRAIN-split benign background only (built once, cached)."""
    from .evictguard_v2 import PrevalenceProfile
    path = bench_dir / "prevalence_train.json"
    if path.exists():
        return PrevalenceProfile.load(path)
    seg = pd.read_csv(bench_dir / "background_segments.csv")
    seg = seg[seg.split == "train"]
    atlas = Path("data/atlasv2/standardized/benign")
    frames = (pd.read_parquet(atlas / f"{s}.parquet") for s in seg.segment_id if (atlas / f"{s}.parquet").exists())
    profile = PrevalenceProfile.build(frames)
    profile.save(path)
    return profile


def _select(method: str, noisy: pd.DataFrame, cap: int, seed: int, profile):
    from .evictguard_v2 import select_evictguard_v2
    if method == "evictguard_v1":
        return select_evictguard(noisy, cap, seed=seed), "retention_score"
    if method == "fifo":
        return select_fifo(noisy, cap), None
    if method == "random":
        return select_random(noisy, cap, seed=seed), None
    from . import baselines as B
    if method == "recency_dedup":
        return B.select_recency_dedup(noisy, cap), "baseline_score"
    if method == "rare_action":
        return B.select_rare_action(noisy, cap, seed=seed), "baseline_score"
    if method == "nodoze":
        return B.select_nodoze(noisy, cap, profile=profile, seed=seed), "baseline_score"
    if method == "sigma_priority":
        return B.select_sigma_priority(noisy, cap), "baseline_score"
    if method == "evictguard_v4":   # frozen: results/evictguard_v4.json
        from .evictguard_v4 import select_evictguard_v4
        return select_evictguard_v4(noisy, cap, profile=profile, seed=seed, sigma=0.4, theta=0.4), None
    if method == "evictguard_v3":   # frozen: v2 without redundancy weighting (results/evictguard_v3.json)
        return select_evictguard_v2(noisy, cap, profile=profile, seed=seed, disable={"redundancy"}), "eg_value"
    if method == "evictguard_online_v2":
        from .evictguard_online_v2_fast import select_evictguard_online_v2_fast   # identical decisions, ~2x faster (tested)
        return select_evictguard_online_v2_fast(noisy, cap, profile=profile, seed=seed), None
    if method == "online_v2-protected_only":
        from .evictguard_online_v2 import OnlineConfig as OC2, select_evictguard_online_v2
        return select_evictguard_online_v2(noisy, cap, profile=profile, seed=seed, config=OC2(protected=1.0, entity=0.0, exploration=0.0)), None
    if method == "evictguard_online":
        from .evictguard_online import select_evictguard_online
        return select_evictguard_online(noisy, cap, profile=profile, seed=seed), None
    if method == "online-protected_only":
        from .evictguard_online import OnlineConfig, select_evictguard_online
        return select_evictguard_online(noisy, cap, profile=profile, seed=seed, config=OnlineConfig(protected=1.0, entity=0.0, exploration=0.0)), None
    if method == "evictguard_v2":
        return select_evictguard_v2(noisy, cap, profile=profile, seed=seed), "eg_value"
    if method == "v2-no_history":
        return select_evictguard_v2(noisy, cap, profile=None, seed=seed), "eg_value"
    if method.startswith("v2-no_"):
        return select_evictguard_v2(noisy, cap, profile=profile, seed=seed, disable={method[len("v2-no_"):]}), "eg_value"
    raise ValueError(f"unknown method {method}")


def run(bench_dir: Path, split: str, noise_specs: list[str], capacities: list[float], seed: int, limit: int | None,
        methods: list[str] | None = None, episode_filter: str | None = None, no_history: bool = False) -> pd.DataFrame:
    from .evictguard_v2 import action_keys
    methods = methods or METHODS
    episodes = pd.read_csv(bench_dir / "episodes.csv")
    episodes = episodes[(episodes.split == split) & (episodes.gold_verdict == "ATTACK")]
    if episode_filter:
        episodes = episodes[episodes.episode_id.str.contains(episode_filter, regex=True)]
    if limit:
        episodes = episodes.head(limit)
    needs = any(m.startswith(("evictguard_v2", "evictguard_v3", "evictguard_v4", "v2-", "nodoze", "evictguard_online", "online-", "online_v2")) and m != "v2-no_history" for m in methods)
    profile = load_profile(bench_dir) if needs and not no_history else None
    rows = []
    for ep in episodes.itertuples():
        clean = pd.read_parquet(bench_dir / "episodes" / f"{ep.episode_id}.parquet")
        core_before = int((clean.gt_tier == "core").sum())
        for spec in noise_specs:
            kind, prop = spec.split(":")
            noisy, manifest = (clean.copy(), {}) if kind == "none" else inject_noise(clean, kind, float(prop), seed)
            noisy = noisy.reset_index(drop=True)
            core_after = int(((noisy.gt_tier == "core") & ~noisy.get("is_synthetic", False).astype(bool)).sum())
            keys = pd.Series(action_keys(noisy), index=noisy.record_id.astype(str))
            core_mask = noisy.gt_tier.astype(str).eq("core").to_numpy()
            core_actions = set(keys.to_numpy()[core_mask])
            supp_actions = set(keys.to_numpy()[noisy.gt_tier.astype(str).eq("supporting").to_numpy()])
            proc = pd.Series(["|".join(k.split("|")[:3]) for k in keys.to_numpy()], index=keys.index)
            attack_procs = set(proc.to_numpy()[noisy.gt_label.astype(str).eq("attack").to_numpy()])
            stratum = pd.Series(list(zip(noisy.host.astype(str), noisy.channel.astype(str), noisy.event_id.astype(str))), index=keys.index)
            all_strata = set(stratum)
            ts = pd.Series(noisy.timestamp.astype(str).to_numpy(), index=keys.index)
            core_ts = set(ts.to_numpy()[core_mask])
            for cap_spec in capacities:
                cap = int(max(1, round(cap_spec * len(noisy)))) if cap_spec < 1 else int(cap_spec)
                for method in methods:
                    start = time.perf_counter()
                    result, score_col = _select(method, noisy, cap, seed, profile)
                    runtime = time.perf_counter() - start
                    kept_ids = result.selected.record_id.astype(str)
                    kept_actions = set(keys.reindex(kept_ids).dropna())
                    kept_procs = set(proc.reindex(kept_ids).dropna())
                    coverage = {"attack_process_coverage": len(attack_procs & kept_procs) / len(attack_procs) if attack_procs else np.nan,
                                "supporting_action_recall": len(supp_actions & kept_actions) / len(supp_actions) if supp_actions else np.nan,
                                "stratum_coverage": len(set(stratum.reindex(kept_ids).dropna()) & all_strata) / len(all_strata) if all_strata else np.nan,
                                # CDB-style scoring: a flagged (core) timestamp counts as found if any kept event carries it
                                "core_timestamp_recall": len(core_ts & set(ts.reindex(kept_ids).dropna())) / len(core_ts) if core_ts else np.nan}
                    ap = _average_precision(result.scored[score_col].to_numpy(dtype=float), core_mask) if score_col and len(result.scored) == len(noisy) else np.nan
                    rows.append({"episode_id": ep.episode_id, "cluster": ep.attack_recordings, "split": split, "noise": kind, "proportion": float(prop),
                                 "capacity": cap_spec, "capacity_events": cap, "method": method, "input_events": len(noisy), "runtime_s": runtime,
                                 "gold_verdict_after_noise": gold_verdict(ep.gold_verdict, core_before, core_after),
                                 "core_action_recall": len(core_actions & kept_actions) / len(core_actions) if core_actions else np.nan,
                                 "core_ap": ap, **coverage, **evaluate_selection(noisy, result.selected)})
        print(f"{ep.episode_id} done ({len(clean)} events)", flush=True)
    return pd.DataFrame(rows)


def bootstrap_ci(frame: pd.DataFrame, metric: str, n: int = 1000, seed: int = 17) -> tuple[float, float, float]:
    data = frame.dropna(subset=[metric])
    if data.empty:
        return (np.nan, np.nan, np.nan)
    clusters = data.groupby("cluster")[metric].mean()
    rng = np.random.default_rng(seed)
    values = clusters.to_numpy()
    samples = [values[rng.integers(0, len(values), len(values))].mean() for _ in range(n)]
    return float(data[metric].mean()), float(np.percentile(samples, 2.5)), float(np.percentile(samples, 97.5))


def summarize(results: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for keys, part in results.groupby(["noise", "proportion", "capacity", "method"]):
        row = dict(zip(["noise", "proportion", "capacity", "method"], keys))
        row["episodes"] = part.episode_id.nunique()
        for metric in ("core_action_recall", "core_timestamp_recall", "core_recall", "core_ap", "attack_process_coverage", "supporting_action_recall", "stratum_coverage",
                       "supporting_recall", "attack_recall", "noise_share"):
            mean, lo, hi = bootstrap_ci(part, metric)
            row[metric] = round(mean, 4) if not np.isnan(mean) else np.nan
            row[f"{metric}_ci95"] = f"[{lo:.3f}, {hi:.3f}]" if not np.isnan(lo) else ""
        row["runtime_s"] = round(part.runtime_s.mean(), 3)
        rows.append(row)
    return pd.DataFrame(rows)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bench", type=Path, default=Path("data/benchmark"))
    p.add_argument("--split", default="val", choices=["train", "val", "test", "ood", "otrf_native_train", "otrf_native_val", "otrf_native_test", "cdb", "cdb_filtered", "cbc"])
    p.add_argument("--noise", nargs="+", default=DEFAULT_NOISE, help="type:proportion, e.g. duplicate-flooding:0.5")
    p.add_argument("--capacity", nargs="+", type=float, default=[256, 512], help="events kept; values < 1 are a fraction of each episode")
    p.add_argument("--no-history", action="store_true", help="cold start: no historical prevalence profile (e.g. OTRF native)")
    p.add_argument("--seed", type=int, default=17)
    p.add_argument("--limit", type=int, default=None, help="evaluate only the first N attack episodes")
    p.add_argument("--out", type=Path, default=Path("results/benchmark"))
    p.add_argument("--methods", nargs="+", default=None, help=f"default {METHODS}; ablations: v2-no_<feature> for {ABLATIONS}, v2-no_history")
    p.add_argument("--episode-filter", default=None, help="regex on episode_id, e.g. 'h1-' (dev) or 'h2-' (held-out)")
    p.add_argument("--tag", default="", help="suffix for output files")
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    results = run(a.bench, a.split, a.noise, a.capacity, a.seed, a.limit, a.methods, a.episode_filter, a.no_history)
    name = f"{a.split}{('_' + a.tag) if a.tag else ''}"
    results.to_csv(a.out / f"episodes_{name}.csv", index=False)
    summary = summarize(results)
    summary.to_csv(a.out / f"summary_{name}.csv", index=False)
    config = {"no_history": a.no_history, "split": a.split, "noise": a.noise, "capacity": a.capacity, "seed": a.seed, "methods": a.methods or METHODS,
              "episode_filter": a.episode_filter, "gold_defer_core_coverage": CORE_COVERAGE_FOR_ATTACK}
    (a.out / f"config_{name}.json").write_text(json.dumps(config, indent=2))
    with pd.option_context("display.width", 200, "display.max_columns", 20):
        print(summary[["noise", "capacity", "method", "episodes", "core_action_recall", "core_action_recall_ci95", "core_recall", "core_ap", "noise_share"]].to_string(index=False))


if __name__ == "__main__":
    main()
