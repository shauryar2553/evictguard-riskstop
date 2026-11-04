"""Compose labelled ATTACK / BENIGN investigation episodes with leakage-safe splits.

Inputs
    * Attack pool: labelled OTRF recordings (``src.label`` output). Only
      recordings with ``label_status == labelled`` are used. From each, the
      core + supporting (+ ambiguous, kept as ambiguous) events are spliced.
    * Background pool: standardized benign segments.
        - ``atlasv2``  ATLASv2 benign period (``src.atlas_adapter``), verified
                       benign by the dataset design.  -> preferred
        - ``otrf``     background-tier events of OTRF recordings. INTERIM ONLY:
                       presumed benign (no Sigma hit, not in attack tree) but
                       not verified.

Episodes
    * ATTACK: a contiguous background window plus 1..k attack recordings,
      time-shifted into the window, hosts rewritten to background hosts.
    * BENIGN: a background window only (gold verdict BENIGN).

Splits (no leakage)
    * Attack recordings are grouped by ATT&CK technique family (first mapped
      technique, else dataset id); whole groups go to train/val/test.
    * Background segments are grouped by ``segment_group`` (host-day for
      ATLASv2; source recording for the OTRF interim pool) and assigned the
      same way. An episode only mixes pools of the same split.

Output: data/benchmark/episodes/<episode_id>.parquet and episodes.csv
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

SPLITS = (("train", 0.6), ("val", 0.2), ("test", 0.2))
HOST_FIELDS = ("Hostname", "host", "Computer", "SourceHostname", "DestinationHostname", "WorkstationName")


def stable_split(group: str, salt: str = "evictguard-v1") -> str:
    value = int(hashlib.sha256(f"{salt}:{group}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    edge = 0.0
    for name, share in SPLITS:
        edge += share
        if value <= edge:
            return name
    return SPLITS[-1][0]


def balanced_split(groups: pd.Series, salt: str = "evictguard-v1") -> dict[str, str]:
    """Assign whole groups to splits so recording counts approach 60/20/20.

    Largest groups first (ties broken by a salted hash, so the assignment is
    deterministic); each goes to the split furthest below its target share.
    """
    sizes = groups.value_counts()
    order = sorted(sizes.index, key=lambda g: (-sizes[g], hashlib.sha256(f"{salt}:{g}".encode()).hexdigest()))
    total, filled, out = int(sizes.sum()), {name: 0 for name, _ in SPLITS}, {}
    for g in order:
        name = max(SPLITS, key=lambda s: s[1] * total - filled[s[0]])[0]
        out[g] = name
        filled[name] += int(sizes[g])
    return out


def technique_group(techniques: Any, dataset_id: str) -> str:
    text = str(techniques) if isinstance(techniques, str) and techniques else ""
    first = sorted(t.split(".")[0] for t in text.split(";") if t)
    return first[0] if first else f"dataset:{dataset_id}"


# ------------------------------------------------------------------ pools
def load_attack_pool(labels_dir: Path) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
    summary = pd.read_csv(labels_dir / "recording_summary.csv")
    summary = summary[summary.label_status == "labelled"].copy()
    index = pd.read_csv(labels_dir.parent / "otrf" / "index.csv") if (labels_dir.parent / "otrf" / "index.csv").exists() else None
    if index is not None:
        summary = summary.merge(index[["recording_id", "techniques"]], on="recording_id", how="left")
    else:
        summary["techniques"] = summary.get("metadata_techniques")
    summary["group"] = [technique_group(t, d) for t, d in zip(summary.techniques, summary.dataset_id)]
    summary["split"] = summary.group.map(balanced_split(summary.group))
    return summary, LazyAttackEvents(labels_dir)


class LazyAttackEvents:
    """Attack-tier events of a recording, read on demand (small cache) to bound RAM."""

    def __init__(self, labels_dir: Path, size: int = 8):
        self.labels_dir, self.size, self._cache = labels_dir, size, {}

    def __getitem__(self, rid: str) -> pd.DataFrame:
        if rid not in self._cache:
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", rid)
            if len(self._cache) >= self.size:
                self._cache.pop(next(iter(self._cache)))
            self._cache[rid] = read_tiers(self.labels_dir / "events" / f"{safe}.parquet", {"core", "supporting", "ambiguous"})
        return self._cache[rid]


def read_tiers(path: Path, tiers: set[str], cap: int | None = None) -> pd.DataFrame:
    """Read only rows whose gt_tier is in ``tiers``, one row group at a time (bounded RAM)."""
    import pyarrow.parquet as pq
    parts, kept = [], 0
    handle = pq.ParquetFile(path)
    for i in range(handle.num_row_groups):
        tier = handle.read_row_group(i, columns=["gt_tier"]).column(0).to_pandas()
        mask = tier.isin(tiers).to_numpy()
        if not mask.any():
            continue
        part = handle.read_row_group(i).to_pandas()[mask]
        parts.append(part)
        kept += len(part)
        if cap and kept >= cap:
            break
    frame = pd.concat(parts, ignore_index=True) if parts else handle.schema_arrow.empty_table().to_pandas()
    return frame.iloc[:cap] if cap else frame


class BackgroundPool:
    """Background segments loaded lazily (one at a time, small LRU cache) to keep RAM low."""

    def __init__(self, segments: pd.DataFrame, paths: dict[str, Path], otrf: bool, cap: int):
        self.segments, self.paths, self.otrf, self.cap = segments, paths, otrf, cap
        self._cache: dict[str, pd.DataFrame] = {}

    def __getitem__(self, segment_id: str) -> pd.DataFrame:
        if segment_id not in self._cache:
            frame = read_tiers(self.paths[segment_id], {"background"}, cap=self.cap)
            frame = frame.sort_values("timestamp", kind="stable").iloc[: self.cap].copy()
            if len(self._cache) >= 3:
                self._cache.pop(next(iter(self._cache)))
            self._cache[segment_id] = frame
        return self._cache[segment_id]


def load_background_pool(source: str, labels_dir: Path, atlas_dir: Path, attack_summary: pd.DataFrame, cap: int = 50_000) -> tuple[pd.DataFrame, BackgroundPool]:
    segments, paths = [], {}
    if source == "atlasv2":
        import pyarrow.parquet as pq
        for path in sorted((atlas_dir / "benign").glob("*.parquet")):
            meta = pq.read_table(path, columns=["segment_group"])
            seg = path.stem
            paths[seg] = path
            segments.append({"segment_id": seg, "segment_group": str(meta.column(0)[0]) if meta.num_rows else seg,
                             "events": meta.num_rows, "verified_benign": True})
        if not segments:
            raise FileNotFoundError(f"No ATLASv2 benign segments in {atlas_dir/'benign'}; run src.atlas_adapter first")
        seg = pd.DataFrame(segments)
        seg["split"] = seg.segment_group.map(balanced_split(seg.segment_group))
        return seg, BackgroundPool(seg, paths, otrf=False, cap=cap)
    # Interim OTRF background: background-tier events of each labelled recording, split with that recording.
    import pyarrow.parquet as pq
    split_of = dict(zip(attack_summary.recording_id, attack_summary.split))
    group_of = dict(zip(attack_summary.recording_id, attack_summary.group))
    for rid in attack_summary.recording_id:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", rid)
        path = labels_dir / "events" / f"{safe}.parquet"
        tiers = pq.read_table(path, columns=["gt_tier"]).column(0).to_pandas()
        n = int((tiers == "background").sum())
        if n < 200:
            continue
        paths[rid] = path
        segments.append({"segment_id": rid, "segment_group": group_of[rid], "events": min(n, cap), "verified_benign": False, "split": split_of[rid]})
    seg = pd.DataFrame(segments)
    return seg, BackgroundPool(seg, paths, otrf=True, cap=cap)


# ------------------------------------------------------------------ splicing
def _rewrite_json_hosts(raw: str, mapping: dict[str, str]) -> str:
    try:
        obj = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return raw
    for key in HOST_FIELDS:
        if key in obj and isinstance(obj[key], str):
            short = obj[key].split(".")[0].lower()
            if short in mapping:
                obj[key] = mapping[short]
    return json.dumps(obj, sort_keys=True, default=str)


def _window(bg: pd.DataFrame, max_events: int, rng: np.random.Generator) -> pd.DataFrame:
    bg = bg.sort_values("timestamp", kind="stable").reset_index(drop=True)
    if len(bg) <= max_events:
        return bg
    start = int(rng.integers(0, len(bg) - max_events + 1))
    return bg.iloc[start:start + max_events]


def splice(background: pd.DataFrame, attacks: list[tuple[str, pd.DataFrame]], episode_id: str, rng: np.random.Generator) -> pd.DataFrame:
    parts = [background.assign(origin="background", attack_recording=None)]
    bg_hosts = [h for h in background.host.dropna().value_counts().index.tolist()] or ["host-bg"]
    t0, t1 = background.timestamp.min(), background.timestamp.max()
    for rid, attack in attacks:
        attack = attack.copy()
        a0, a1 = attack.timestamp.min(), attack.timestamp.max()
        span = (t1 - t0) - (a1 - a0) if pd.notna(t0) and pd.notna(a0) else pd.Timedelta(0)
        offset = t0 + span * float(rng.random()) - a0 if span > pd.Timedelta(0) else (t0 - a0 if pd.notna(t0) and pd.notna(a0) else pd.Timedelta(0))
        attack["timestamp"] = attack.timestamp + offset
        attack_hosts = attack.host.dropna().value_counts().index.tolist()
        mapping = {h: bg_hosts[i % len(bg_hosts)] for i, h in enumerate(attack_hosts)}
        attack["host"] = attack.host.map(lambda h: mapping.get(h, h))
        attack["original_json"] = [_rewrite_json_hosts(x, mapping) for x in attack.original_json]
        parts.append(attack.assign(origin="attack", attack_recording=rid))
    episode = pd.concat(parts, ignore_index=True).sort_values("timestamp", kind="stable").reset_index(drop=True)
    episode["record_id"] = [f"{episode_id}:{r}" for r in episode.record_id]
    episode["episode_id"] = episode_id
    # Columns expected by the existing selection/evaluation code.
    episode["event_type"] = episode.event_id.astype(str)
    episode["source"] = episode.channel
    episode["timestamp"] = episode.timestamp.map(lambda t: t.isoformat().replace("+00:00", "Z") if pd.notna(t) else None)
    episode["is_synthetic"] = False
    for col in ("gt_tier", "gt_label"):
        episode[col] = episode[col].fillna("background" if col == "gt_tier" else "benign")
    episode.loc[episode.origin == "background", ["gt_tier", "gt_label"]] = ["background", "benign"]
    return episode


def _ood_episodes(atlas_dir: Path, out_dir: Path) -> list[dict[str, Any]]:
    """ATLASv2 attack scenarios as-is (real attack inside real background): split 'ood'."""
    rows = []
    for path in sorted((atlas_dir / "attack").glob("*.parquet")):
        frame = pd.read_parquet(path)
        if not (frame.gt_label == "attack").any():
            continue
        episode_id = f"ood-attack-{path.stem}"
        frame = frame.sort_values("timestamp", kind="stable").reset_index(drop=True)
        frame["record_id"] = [f"{episode_id}:{r}" for r in frame.record_id]
        frame["episode_id"], frame["origin"], frame["attack_recording"] = episode_id, "atlasv2", path.stem
        frame["event_type"], frame["source"], frame["is_synthetic"] = frame.event_id.astype(str), frame.channel, False
        frame["timestamp"] = frame.timestamp.map(lambda t: t.isoformat().replace("+00:00", "Z") if pd.notna(t) else None)
        frame.to_parquet(out_dir / "episodes" / f"{episode_id}.parquet", index=False, compression="zstd")
        rows.append({"episode_id": episode_id, "split": "ood", "gold_verdict": "ATTACK", "background_source": "atlasv2_native",
                     "background_segment": path.stem, "background_verified_benign": False, "attack_recordings": f"atlasv2:{path.stem}",
                     "techniques": "", "events": len(frame), "n_core": int((frame.gt_tier == "core").sum()),
                     "n_supporting": int((frame.gt_tier == "supporting").sum()), "n_ambiguous": int((frame.gt_tier == "ambiguous").sum())})
    return rows


def _sensor_profile(segments: pd.DataFrame, pool: "BackgroundPool") -> set[tuple[str, int]]:
    """(channel, EventID) pairs the background's logging configuration produces."""
    import pyarrow.parquet as pq
    types: set[tuple[str, int]] = set()
    for seg in segments.segment_id:
        t = pq.read_table(pool.paths[seg], columns=["channel", "event_id"]).to_pandas().dropna().drop_duplicates()
        types |= set(zip(t.channel, t.event_id.astype(int)))
    return types


def compose_native_otrf(labels_dir: Path, out_dir: Path) -> list[dict[str, Any]]:
    """Each labelled OTRF recording as a native episode: real attack + real lab background, no splicing.

    Splits reuse the technique-family assignment of the attack pool (otrf_native_train/val/test), so the
    same ATT&CK family never appears in two splits.
    """
    attack_summary, _ = load_attack_pool(labels_dir)
    rows = []
    for rec in attack_summary.itertuples():
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", rec.recording_id)
        frame = pd.read_parquet(labels_dir / "events" / f"{safe}.parquet")
        frame = frame.sort_values("timestamp", kind="stable").reset_index(drop=True)
        episode_id = f"otrf_native_{rec.split}-{safe}"
        frame["record_id"] = [f"{episode_id}:{r}" for r in frame.record_id]
        frame["episode_id"], frame["origin"], frame["attack_recording"] = episode_id, "otrf_native", rec.recording_id
        frame["event_type"], frame["source"], frame["is_synthetic"] = frame.event_id.astype(str), frame.channel, False
        frame["timestamp"] = frame.timestamp.map(lambda t: t.isoformat().replace("+00:00", "Z") if pd.notna(t) else None)
        frame.to_parquet(out_dir / "episodes" / f"{episode_id}.parquet", index=False, compression="zstd")
        rows.append({"episode_id": episode_id, "split": f"otrf_native_{rec.split}", "gold_verdict": "ATTACK", "background_source": "otrf_native",
                     "background_segment": rec.recording_id, "background_verified_benign": False, "attack_recordings": rec.recording_id,
                     "techniques": rec.techniques, "events": len(frame), "n_core": int((frame.gt_tier == "core").sum()),
                     "n_supporting": int((frame.gt_tier == "supporting").sum()), "n_ambiguous": int((frame.gt_tier == "ambiguous").sum())})
    return rows


def compose_cdb(sample_dir: Path, out_dir: Path) -> list[dict[str, Any]]:
    """Cyber Defense Benchmark public sample as an episode with CDB's OWN labels (independent of ours).

    CDB (Chona et al., 2026) labels malicious events by timestamp ("flags") with relevance 1 (core),
    2 (supporting) and 3 (incidental), produced by Simbian's Sigma + LLM pipeline. Events whose TimeCreated
    matches a relevance-1 flag become ``core`` and relevance-2 become ``supporting``; everything else is background.
    """
    import json as _json
    from .label import standardize
    flags = _json.loads((sample_dir / "sample_flags.json").read_text())
    rel = {}
    for f in flags["flags"]:
        rel[f["value"]] = min(rel.get(f["value"], 9), int(f["relevance"]))
    logs = _json.loads((sample_dir / "sample.json").read_text())["logs"]
    raw = pd.DataFrame(logs)
    del logs
    times = raw["TimeCreated"].astype(str).tolist()
    std = standardize(raw, "cdb:sample")
    del raw
    # CDB's authoritative clock is TimeCreated (campaign time after stitching/shifting). The generic parser
    # prefers Sysmon UtcTime, which still holds the ORIGINAL recording time and would scramble event order.
    std["timestamp"] = pd.to_datetime(pd.Series(times, index=std.index), errors="coerce", utc=True)
    tier = ["core" if rel.get(t) == 1 else "supporting" if rel.get(t) == 2 else "background" for t in times]
    std["gt_tier"] = tier
    std["gt_label"] = ["attack" if x != "background" else "benign" for x in tier]
    std["label_source"] = ["cdb_flag" if x != "background" else None for x in tier]
    std = std.sort_values("timestamp", kind="stable").reset_index(drop=True)
    episode_id = "cdb-sample-seed176"
    std["record_id"] = [f"{episode_id}:{r}" for r in std.record_id]
    std["episode_id"], std["origin"], std["attack_recording"] = episode_id, "cdb", "cdb:sample"
    std["event_type"], std["source"], std["is_synthetic"] = std.event_id.astype(str), std.channel, False
    std["timestamp"] = std.timestamp.map(lambda t: t.isoformat().replace("+00:00", "Z") if pd.notna(t) else None)
    std.to_parquet(out_dir / "episodes" / f"{episode_id}.parquet", index=False, compression="zstd", row_group_size=20_000)
    return [{"episode_id": episode_id, "split": "cdb", "gold_verdict": "ATTACK", "background_source": "cdb_sample", "background_segment": "cdb",
             "background_verified_benign": False, "attack_recordings": "cdb:sample", "techniques": ";".join(flags.get("tactic_ids", [])),
             "events": len(std), "n_core": int((std.gt_tier == "core").sum()), "n_supporting": int((std.gt_tier == "supporting").sum()), "n_ambiguous": 0}]


def compose_cdb_filtered(out_dir: Path) -> list[dict[str, Any]]:
    """Sensitivity analysis: CDB labels minus flags that are pure Azure guest-agent activity.

    Pre-stated rule: a flagged timestamp whose matched events are ALL Azure guest-agent processes
    (path contains \\windowsazure\\) is treated as ambiguous (excluded from scoring). Evidence: the same
    agent produces identical bursts of low-privilege (0x1000) process-access events in 4 unrelated OTRF
    attack recordings (T1047, T1021.002, T1021.003, T1546.003), i.e. it is lab infrastructure. Mixed
    timestamps (agent + other events) keep their labels. Raw CDB results are always reported alongside.
    """
    from .evictguard_v2 import parse_events
    src_id = "cdb-sample-seed176"
    e = pd.read_parquet(out_dir / "episodes" / f"{src_id}.parquet")
    az = parse_events(e).actor.str.contains(r"\\windowsazure\\", regex=True).to_numpy()
    flagged = e.gt_tier.isin(["core", "supporting"]).to_numpy()
    g = pd.DataFrame({"ts": e.timestamp.astype(str), "az": az})[flagged].groupby("ts").az.all()
    pure = set(g[g].index)
    drop = flagged & e.timestamp.astype(str).isin(pure).to_numpy()
    e.loc[drop, ["gt_tier", "gt_label"]] = ["ambiguous", "ambiguous"]
    e.loc[drop, "label_source"] = "cdb_flag_excluded_azure_agent"
    episode_id = "cdb-filtered-seed176"
    e["record_id"] = e.record_id.str.replace(src_id, episode_id, regex=False)
    e["episode_id"] = episode_id
    e.to_parquet(out_dir / "episodes" / f"{episode_id}.parquet", index=False, compression="zstd", row_group_size=20_000)
    return [{"episode_id": episode_id, "split": "cdb_filtered", "gold_verdict": "ATTACK", "background_source": "cdb_sample", "background_segment": "cdb",
             "background_verified_benign": False, "attack_recordings": "cdb:sample", "techniques": "", "events": len(e),
             "n_core": int((e.gt_tier == "core").sum()), "n_supporting": int((e.gt_tier == "supporting").sum()), "n_ambiguous": int(drop.sum()),
             "excluded_flag_timestamps": len(pure)}]


def compose(labels_dir: Path, out_dir: Path, background_source: str, atlas_dir: Path, per_split: dict[str, tuple[int, int]],
            window_events: int, max_attacks: int, seed: int, harmonize: bool = False) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    attack_summary, attack_events = load_attack_pool(labels_dir)
    segments, bg_frames = load_background_pool(background_source, labels_dir, atlas_dir, attack_summary)
    sensor_types = _sensor_profile(segments, bg_frames) if harmonize else None
    # Visit segments in a stable order so the lazy cache is effective.
    (out_dir / "episodes").mkdir(parents=True, exist_ok=True)
    rows = []
    for split, (n_attack, n_benign) in per_split.items():
        recs = attack_summary[attack_summary.split == split].recording_id.tolist()
        segs = segments[segments.split == split].segment_id.tolist()
        if not segs:
            print(f"[{split}] no background segments; skipped"); continue
        plan = [(kind, i, segs[int(rng.integers(len(segs)))]) for kind, count in (("ATTACK", n_attack if recs else 0), ("BENIGN", n_benign)) for i in range(count)]
        # Visit episodes grouped by background segment so each segment is loaded once.
        for kind, i, seg in sorted(plan, key=lambda x: (x[2], x[0], x[1])):
            if True:
                episode_id = f"{split}-{kind.lower()}-{i:04d}"
                bg = _window(bg_frames[seg], window_events, rng)
                if background_source == "otrf":
                    # never splice a recording into its own background
                    pool = [r for r in recs if r != seg]
                else:
                    pool = recs
                chosen = []
                if kind == "ATTACK" and pool:
                    k = int(rng.integers(1, min(max_attacks, len(pool)) + 1))
                    chosen = list(rng.choice(pool, size=k, replace=False))
                attacks = [(r, attack_events[r]) for r in chosen]
                dropped = 0
                if sensor_types is not None:
                    kept = []
                    for r, ev in attacks:
                        mask = pd.Series(list(zip(ev.channel, ev.event_id)), index=ev.index).isin(sensor_types)
                        dropped += int((~mask).sum())
                        kept.append((r, ev[mask]))
                    attacks = kept
                episode = splice(bg, attacks, episode_id, rng)
                bg_types = set(zip(bg.channel, bg.event_id))
                core = episode[episode.gt_tier == "core"]
                novel_share = float(sum((c, i) not in bg_types for c, i in zip(core.channel, core.event_id)) / len(core)) if len(core) else None
                episode.to_parquet(out_dir / "episodes" / f"{episode_id}.parquet", index=False, compression="zstd")
                techs = attack_summary.set_index("recording_id").loc[chosen, "techniques"].dropna().astype(str).tolist() if chosen else []
                rows.append({"episode_id": episode_id, "split": split, "gold_verdict": kind, "background_source": background_source,
                             "harmonized": harmonize, "attack_events_dropped_by_harmonization": dropped,
                             "core_novel_event_type_share": novel_share,
                             "background_segment": seg, "background_verified_benign": bool(segments.set_index("segment_id").loc[seg, "verified_benign"]),
                             "attack_recordings": ";".join(chosen), "techniques": ";".join(sorted({t for x in techs for t in x.split(";") if t})),
                             "events": len(episode), "n_core": int((episode.gt_tier == "core").sum()),
                             "n_supporting": int((episode.gt_tier == "supporting").sum()), "n_ambiguous": int((episode.gt_tier == "ambiguous").sum())})
    rows += _ood_episodes(atlas_dir, out_dir)
    rows += compose_native_otrf(labels_dir, out_dir)
    frame = pd.DataFrame(rows)
    frame.to_csv(out_dir / "episodes.csv", index=False)
    attack_summary[["recording_id", "group", "split"]].to_csv(out_dir / "attack_split_assignment.csv", index=False)
    segments.to_csv(out_dir / "background_segments.csv", index=False)
    return frame


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--labels", type=Path, default=Path("data/labels"))
    p.add_argument("--out", type=Path, default=Path("data/benchmark"))
    p.add_argument("--background", choices=["otrf", "atlasv2"], default="otrf")
    p.add_argument("--atlas-dir", type=Path, default=Path("data/atlasv2/standardized"))
    p.add_argument("--train", default="120,60", help="attack,benign episodes")
    p.add_argument("--val", default="40,20")
    p.add_argument("--test", default="40,20")
    p.add_argument("--window-events", type=int, default=4000)
    p.add_argument("--max-attacks", type=int, default=3)
    p.add_argument("--seed", type=int, default=17)
    p.add_argument("--harmonize", action="store_true",
                   help="splice only attack event types the background sensor config also emits (removes the Win10-vs-Win7 artefact)")
    a = p.parse_args()
    per_split = {s: tuple(int(x) for x in getattr(a, s).split(",")) for s in ("train", "val", "test")}
    frame = compose(a.labels, a.out, a.background, a.atlas_dir, per_split, a.window_events, a.max_attacks, a.seed, a.harmonize)
    if "core_novel_event_type_share" in frame:
        print("mean share of core events with an event type absent from their background window:",
              round(frame.core_novel_event_type_share.dropna().mean(), 3))
    print(frame.groupby(["split", "gold_verdict"]).agg(episodes=("episode_id", "count"), mean_events=("events", "mean"), mean_core=("n_core", "mean")).round(1).to_string())


if __name__ == "__main__":
    main()
