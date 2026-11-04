"""Event-level ground truth for OTRF recordings (Sigma + causal expansion).

Method (adapted from CDB's Sigma+causal-neighbour labelling and REAPr's
process-only forward trace; no LLM is used, so labels are reproducible):

1. Root causes ("roots")
   a. ``adversary_view``: OTRF metadata contains the attacker's C2 console.
      Agent tables there name machine, process and PID of attacker-controlled
      processes; these are resolved to Sysmon ProcessGuids.
   b. Sigma hits of level high/critical on process-creation events (the
      created process is treated as attacker-controlled).
2. Causal expansion: process-only forward trace over Sysmon
   ProcessGuid -> ParentProcessGuid edges from every root ("attack tree").
3. Tiers (``gt_tier``)
   * ``core``       Sigma hit (level >= medium) inside the attack tree.
   * ``supporting`` no qualifying hit, but the actor process is in the attack
                    tree (target-only involvement does not count).
   * ``core`` also: medium hit outside the tree whose ATT&CK technique family
                    matches the recording's documented technique.
   * ``ambiguous``  any other medium hit outside the attack tree (possible
                    false positive *or* uncovered attack activity) -> excluded
                    from scoring.
   * ``background`` everything else. In OTRF this is lab background
                    activity: *presumed* benign, not verified.
4. Provenance: every label records ``label_source`` (sigma:<id>,
   adversary_view, ancestry:<root guid>, creator_of:<root guid>).
5. Validation: ``--review-sample`` writes a stratified sample with blank
   reviewer columns for manual checking; agreement is computed later by
   ``label_agreement``.

``gt_label`` is the binary view: attack (core|supporting), benign
(background), ambiguous.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml

from .sigma_engine import load_rules, evaluate
from .utils import content_hash, load_records

LEVEL_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SYSMON = "microsoft-windows-sysmon/operational"
AGENT_ROW = re.compile(r"^\s*[A-Z0-9]{6,10}\s+\S+\s+\d{1,3}(?:\.\d{1,3}){3}\s+(?P<machine>\S+)\s+(?P<user>\S+)\s+(?P<proc>\S+)\s+(?P<pid>\d+)\s", re.M)
STANDARD_COLUMNS = ["recording_id", "record_id", "source_index", "timestamp", "host", "channel", "event_id", "process_guid",
                    "parent_process_guid", "process_id", "image", "command_line", "user", "target_process_guid"]


def _norm_host(value: Any) -> str | None:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return None
    text = str(value).strip().lower()
    return text.split(".")[0] if text else None


def _parse_pid(value: Any) -> float:
    """Sysmon PIDs are decimal; Security 4688/4689 PIDs are hex strings like '0x890'."""
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return np.nan
    text = str(value).strip().lower()
    try:
        return float(int(text, 16)) if text.startswith("0x") else float(text)
    except ValueError:
        return np.nan


def _col(frame: pd.DataFrame, *names: str) -> pd.Series:
    out = pd.Series(np.nan, index=frame.index, dtype=object)
    for name in names:
        if name in frame:
            out = out.where(out.notna() & (out.astype(str) != ""), frame[name])
    return out


def standardize(frame: pd.DataFrame, recording_id: str) -> pd.DataFrame:
    """Canonical columns used by the labeller, episode composer and EVICTGuard."""
    std = pd.DataFrame(index=frame.index)
    std["recording_id"] = recording_id
    std["source_index"] = np.arange(len(frame))
    std["timestamp"] = pd.to_datetime(_col(frame, "@timestamp", "UtcTime", "EventTime", "TimeCreated"), errors="coerce", utc=True)
    std["host"] = _col(frame, "Hostname", "host", "Computer").map(_norm_host)
    std["channel"] = _col(frame, "Channel").astype(str).str.lower()
    std["event_id"] = pd.to_numeric(_col(frame, "EventID"), errors="coerce").astype("Int64")
    std["process_guid"] = _col(frame, "ProcessGuid", "SourceProcessGuid", "SourceProcessGUID").astype(str).str.lower().str.strip("{}").replace({"nan": None})
    std["parent_process_guid"] = _col(frame, "ParentProcessGuid").astype(str).str.lower().str.strip("{}").replace({"nan": None})
    std["target_process_guid"] = _col(frame, "TargetProcessGuid", "TargetProcessGUID").astype(str).str.lower().str.strip("{}").replace({"nan": None})
    pid = _col(frame, "ProcessId", "SourceProcessId", "NewProcessId", "ExecutionProcessID").map(_parse_pid)
    std["process_id"] = pid.astype("Int64")
    std["image"] = _col(frame, "Image", "NewProcessName", "SourceImage", "ProcessName")
    std["command_line"] = _col(frame, "CommandLine")
    std["user"] = _col(frame, "User", "SubjectUserName", "TargetUserName", "AccountName")
    std["original_json"] = [json.dumps({k: v for k, v in row.items() if not (isinstance(v, float) and np.isnan(v))}, sort_keys=True, default=str)
                            for row in frame.to_dict(orient="records")]
    std["content_hash"] = [content_hash(x) for x in std["original_json"]]
    std["record_id"] = [f"{recording_id}#{i}" for i in std["source_index"]]
    return std


def adversary_roots(meta: dict[str, Any]) -> list[dict[str, Any]]:
    view = ((meta.get("simulation") or {}).get("adversary_view") or "") if isinstance(meta.get("simulation"), dict) else ""
    roots = []
    for m in AGENT_ROW.finditer(view):
        proc = m.group("proc").lower()
        roots.append({"machine": _norm_host(m.group("machine")), "process": proc if proc.endswith(".exe") else proc + ".exe", "pid": int(m.group("pid"))})
    uniq = {(r["machine"], r["process"], r["pid"]): r for r in roots}
    return list(uniq.values())


def _resolve_roots(std: pd.DataFrame, roots: list[dict[str, Any]]) -> dict[str, str]:
    """Map adversary_view (machine, process, pid) to Sysmon ProcessGuids."""
    found: dict[str, str] = {}
    sysmon = std[(std.channel == SYSMON) & std.process_guid.notna()]
    for r in roots:
        cand = sysmon[(sysmon.host == r["machine"]) & (sysmon.process_id == r["pid"])]
        cand = cand[cand.image.astype(str).str.lower().str.endswith("\\" + r["process"])]
        for guid in cand.process_guid.dropna().unique():
            found[guid] = f"adversary_view:{r['machine']}/{r['process']}/{r['pid']}"
    return found


def _forward_trace(std: pd.DataFrame, roots: set[str]) -> dict[str, str]:
    created = std[(std.channel == SYSMON) & (std.event_id == 1) & std.process_guid.notna() & std.parent_process_guid.notna()]
    children: dict[str, set[str]] = defaultdict(set)
    for child, parent in zip(created.process_guid, created.parent_process_guid):
        children[parent].add(child)
    tree: dict[str, str] = {}
    queue = deque((r, r) for r in roots)
    while queue:
        node, root = queue.popleft()
        if node in tree:
            continue
        tree[node] = root
        for child in children.get(node, ()):
            queue.append((child, root))
    return tree


def label_recording(raw: pd.DataFrame, recording_id: str, meta: dict[str, Any], rules: list) -> tuple[pd.DataFrame, dict[str, Any]]:
    raw = raw.reset_index(drop=True)
    std = standardize(raw, recording_id)
    hits, runtime_skips = evaluate(raw, rules)
    hits["rank"] = hits["rule_level"].map(LEVEL_RANK).fillna(0)
    per_row = hits.sort_values("rank", ascending=False).groupby("row").agg(
        sigma_rule_ids=("rule_id", lambda s: ";".join(dict.fromkeys(s))),
        sigma_titles=("rule_title", lambda s: ";".join(dict.fromkeys(s))),
        sigma_max_rank=("rank", "max"),
        sigma_techniques=("rule_techniques", lambda s: ";".join(sorted({t for x in s for t in str(x).split(";") if t}))),
        sigma_tactics=("rule_tactics", lambda s: ";".join(sorted({t for x in s for t in str(x).split(";") if t}))),
    ) if len(hits) else pd.DataFrame(columns=["sigma_rule_ids", "sigma_titles", "sigma_max_rank", "sigma_techniques", "sigma_tactics"])
    std = std.join(per_row)
    std["sigma_max_rank"] = std["sigma_max_rank"].fillna(-1).astype(int)

    av_roots = _resolve_roots(std, adversary_roots(meta))
    strong_hit = (std.sigma_max_rank >= LEVEL_RANK["high"])
    proc_create = ((std.channel == SYSMON) & (std.event_id == 1)).fillna(False).astype(bool)
    sigma_roots = {g: f"sigma_process_creation:{rid}" for g, rid in zip(std.loc[strong_hit & proc_create, "process_guid"], std.loc[strong_hit & proc_create, "sigma_rule_ids"]) if g}
    root_sources = {**sigma_roots, **av_roots}
    tree = _forward_trace(std, set(root_sources))
    tree_guids = set(tree)

    # PID attribution for non-Sysmon events (PowerShell / Security) on the same host.
    tree_pids = {(h, int(p)) for h, p, g in zip(std.host, std.process_id, std.process_guid) if g in tree_guids and pd.notna(p)}
    # Only the *actor* process counts. "Attacker process is the target" (e.g. csrss or
    # svchost opening a new attacker process) is normal OS behaviour, not attack evidence.
    in_tree = std.process_guid.isin(tree_guids).astype(bool)
    pid_attr = (~std.channel.eq(SYSMON)) & pd.Series([(h, int(p)) in tree_pids if pd.notna(p) else False for h, p in zip(std.host, std.process_id)], index=std.index)
    in_tree = in_tree | pid_attr
    creator = proc_create & std.process_guid.isin(set(root_sources)) & ~in_tree

    tier = pd.Series("background", index=std.index, dtype=object)
    source = pd.Series(None, index=std.index, dtype=object)
    medium_hit = std.sigma_max_rank >= LEVEL_RANK["medium"]
    tier[in_tree | creator] = "supporting"
    source[in_tree] = ["ancestry:" + str(tree.get(g) or "pid") for g in std.process_guid[in_tree]]
    source[creator] = ["creator_of:" + str(g) for g in std.process_guid[creator]]
    # High/critical hits on process creation are roots, hence inside the tree.
    core = medium_hit & (in_tree | creator)
    tier[core] = "core"
    source[core] = "sigma:" + std.sigma_rule_ids[core].astype(str)
    # Hits (any level >= medium) outside the attack tree: keep as core only when the rule's ATT&CK
    # technique family matches the recording's documented technique (prior knowledge
    # from the dataset's ground-truth documentation, cf. REAPr step 1). Typical case:
    # activity on a lateral-movement target spawned via WMI/DCOM with no parent link.
    # Everything else is ambiguous (possible false positive or uncovered activity).
    meta_families = {t.split(".")[0] for t in str(meta.get("_techniques") or "").split(";") if t}
    hit_families = std.sigma_techniques.fillna("").map(lambda x: {t.split(".")[0] for t in x.split(";") if t})
    technique_match = hit_families.map(lambda fams: bool(fams & meta_families)).astype(bool)
    outside = medium_hit & ~core
    promoted = outside & technique_match
    tier[promoted] = "core"
    source[promoted] = "sigma_technique_match:" + std.sigma_rule_ids[promoted].astype(str)
    ambiguous = outside & ~technique_match
    tier[ambiguous] = "ambiguous"
    source[ambiguous] = "sigma_outside_tree:" + std.sigma_rule_ids[ambiguous].astype(str)
    std["gt_tier"] = tier
    std["gt_label"] = tier.map({"core": "attack", "supporting": "attack", "ambiguous": "ambiguous", "background": "benign"})
    std["label_source"] = source
    std["root_source"] = std.process_guid.map(lambda g: root_sources.get(g) if g else None)

    techniques_meta = sorted({str(t) for t in ((meta.get("_techniques") or "").split(";")) if t})
    hit_techniques = {t for x in std.sigma_techniques.dropna() for t in str(x).split(";") if t}
    family = lambda t: t.split(".")[0]
    summary = {
        "recording_id": recording_id, "events": len(std), "hosts": int(std.host.nunique()),
        "duration_seconds": float((std.timestamp.max() - std.timestamp.min()).total_seconds()) if std.timestamp.notna().any() else None,
        "adversary_view_roots_declared": len(adversary_roots(meta)), "adversary_view_roots_resolved": len(av_roots),
        "sigma_roots": len(sigma_roots), "attack_tree_processes": len(tree_guids),
        **{f"n_{t}": int((tier == t).sum()) for t in ("core", "supporting", "ambiguous", "background")},
        "sigma_hit_events": int((std.sigma_max_rank >= 0).sum()), "runtime_rule_skips": runtime_skips,
        "metadata_techniques": ";".join(techniques_meta),
        "technique_agreement": bool({family(t) for t in techniques_meta} & {family(t) for t in hit_techniques}) if techniques_meta else None,
    }
    summary["label_status"] = "labelled" if summary["n_core"] > 0 else "no_core_evidence"
    return std, summary


def label_corpus(index_csv: Path, rules_root: Path, out_dir: Path, review_sample: int = 0, seed: int = 17) -> pd.DataFrame:
    index = pd.read_csv(index_csv)
    rules, report = load_rules(rules_root)
    print(f"Sigma rules loaded: {report.loaded}; skipped at load: {report.skipped}")
    (out_dir / "events").mkdir(parents=True, exist_ok=True)
    summaries, samples = [], []
    for row in index.itertuples():
        meta_path = Path(index_csv).parent / "metadata" / f"{row.dataset_id}.yaml"
        meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        meta["_techniques"] = row.techniques if isinstance(row.techniques, str) else ""
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", row.recording_id)
        cached = out_dir / "events" / f"{safe}.summary.json"
        if cached.exists() and (out_dir / "events" / f"{safe}.parquet").exists():
            summaries.append(json.loads(cached.read_text()))
            if review_sample:
                labelled = pd.read_parquet(out_dir / "events" / f"{safe}.parquet")
                for _, part in labelled.groupby("gt_tier"):
                    samples.append(part.sample(n=min(review_sample, len(part)), random_state=seed))
            continue
        try:
            records = [r for r in load_records(row.archive) if "__parse_error__" not in r]
        except Exception as exc:
            summaries.append({"recording_id": row.recording_id, "label_status": f"load_error: {exc}"}); continue
        if not records:
            summaries.append({"recording_id": row.recording_id, "label_status": "empty"}); continue
        raw = pd.DataFrame(records)
        try:
            labelled, summary = label_recording(raw, row.recording_id, meta, rules)
        except Exception as exc:  # one bad recording must not abort the corpus
            print(f"{row.recording_id}: LABEL ERROR {exc!r}")
            summaries.append({"recording_id": row.recording_id, "label_status": f"label_error: {exc!r}"}); continue
        summary.update({"dataset_id": row.dataset_id, "title": row.title, "tactics": row.tactics, "kind": row.kind})
        labelled.to_parquet(out_dir / "events" / f"{safe}.parquet", index=False, compression="zstd", row_group_size=20_000)
        cached.write_text(json.dumps(summary, default=str))
        summaries.append(summary)
        print(f"{row.recording_id}: {summary['events']} events, core={summary['n_core']} supporting={summary['n_supporting']} ambiguous={summary['n_ambiguous']} roots(av/sigma)={summary['adversary_view_roots_resolved']}/{summary['sigma_roots']}")
        if review_sample:
            for tier_name, part in labelled.groupby("gt_tier"):
                samples.append(part.sample(n=min(review_sample, len(part)), random_state=seed))
    frame = pd.DataFrame(summaries)
    frame.to_csv(out_dir / "recording_summary.csv", index=False)
    if samples:
        review = pd.concat(samples, ignore_index=True)[["recording_id", "record_id", "timestamp", "host", "channel", "event_id", "image", "command_line",
                                                         "gt_tier", "label_source", "sigma_titles", "original_json"]]
        review["reviewer_tier"] = ""
        review["reviewer_notes"] = ""
        review.to_csv(out_dir / "review_sample.csv", index=False)
    return frame


def label_agreement(review_csv: Path) -> dict[str, Any]:
    """Agreement between automatic and reviewer tiers on the filled review sample."""
    review = pd.read_csv(review_csv).dropna(subset=["reviewer_tier"])
    review = review[review.reviewer_tier.astype(str).str.strip() != ""]
    if review.empty:
        return {"reviewed": 0}
    binary = lambda s: s.map({"core": "attack", "supporting": "attack"}).fillna(s)
    return {"reviewed": len(review), "tier_agreement": float((review.gt_tier == review.reviewer_tier).mean()),
            "binary_agreement": float((binary(review.gt_tier) == binary(review.reviewer_tier)).mean()),
            "confusion": pd.crosstab(review.gt_tier, review.reviewer_tier).to_dict()}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--index", type=Path, default=Path("data/otrf/index.csv"))
    p.add_argument("--rules", type=Path, default=Path("data/sigma/sigmahq/rules/windows"))
    p.add_argument("--out", type=Path, default=Path("data/labels"))
    p.add_argument("--review-sample", type=int, default=5, help="events per tier per recording for manual review (0 = none)")
    p.add_argument("--agreement", type=Path, help="compute agreement from a filled review CSV and exit")
    a = p.parse_args()
    if a.agreement:
        print(json.dumps(label_agreement(a.agreement), indent=2)); return
    frame = label_corpus(a.index, a.rules, a.out, a.review_sample)
    ok = frame[frame.label_status == "labelled"]
    print(f"\n{len(ok)}/{len(frame)} recordings have core evidence; summary -> {a.out/'recording_summary.csv'}")


if __name__ == "__main__":
    main()
