"""Compare EVICTGuard selection with FIFO and seeded random retention."""
from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pandas as pd

from .ledger import register_evidence, update_retention_status
from .noise import inject_noise
from .selection import (
    DEFAULT_WEIGHTS,
    SelectionResult,
    extract_features,
    linked_duplicate_ids,
    score_evidence,
    select_evictguard,
    select_fifo,
    select_random,
)
from .utils import content_hash


def _evidence_payload(row: pd.Series) -> dict[str, Any]:
    raw = row.get("original_json")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    ignored = {"record_id", "source_record_id", "source_path", "source_index", "content_hash", "original_json", "source_label_provenance", "inferred_label", "synthetic_label"}
    return {str(k): (None if pd.isna(v) else v) for k, v in row.items() if k not in ignored}


def _register_candidates(database: str | Path, frame: pd.DataFrame, experiment_id: str) -> dict[str, str]:
    """Ensure each input candidate has a ledger record and return candidate ID mapping."""
    with sqlite3.connect(database) as con:
        source_ids = {row[0] for row in con.execute("SELECT record_id FROM events")}
        sources = dict(con.execute("SELECT record_id,source_path FROM events"))
    by_source: dict[str, str] = {}
    candidate_to_evidence: dict[str, str] = {}
    rows = list(frame.iterrows())
    # Register Phase 1 events first so synthetic copies can link to them.
    for _, row in rows:
        candidate_id = str(row.get("record_id", ""))
        if candidate_id in source_ids:
            item = register_evidence(database, source_dataset=sources[candidate_id], origin_type="original", source_record_id=candidate_id)
            candidate_to_evidence[candidate_id] = item["evidence_id"]
            by_source[candidate_id] = item["evidence_id"]
    for _, row in rows:
        candidate_id = str(row.get("record_id", ""))
        if candidate_id in candidate_to_evidence:
            continue
        is_synthetic = str(row.get("is_synthetic", "")).lower() in {"true", "1", "yes"}
        parent_source_id = row.get("source_record_id")
        parent_source_id = str(parent_source_id) if parent_source_id is not None and pd.notna(parent_source_id) and str(parent_source_id).strip() else None
        parent_evidence_id = by_source.get(parent_source_id) if parent_source_id else None
        origin = "derived" if parent_evidence_id else "synthetic" if is_synthetic else "derived"
        candidate_fingerprint = content_hash({
            "candidate_id": candidate_id,
            "content": _evidence_payload(row),
            "origin_type": origin,
            "parent_evidence_id": parent_evidence_id,
        })[:24]
        evidence_id = f"phase3:{experiment_id}:{candidate_fingerprint}"
        item = register_evidence(
            database,
            source_dataset=str(row.get("source_path") or "Phase 3 experiment input"),
            origin_type=origin,
            content=_evidence_payload(row),
            parent_evidence_id=parent_evidence_id,
            evidence_id=evidence_id,
        )
        candidate_to_evidence[candidate_id] = item["evidence_id"]
    return candidate_to_evidence


def _sync_ledger(database: str | Path, result: SelectionResult, candidate_to_evidence: dict[str, str]) -> None:
    reasons: dict[str, tuple[str, str]] = {}
    for candidate_id in result.redundant_ids:
        reasons[candidate_id] = ("redundant", "Exact content duplicate; retained representative in EVICTGuard context")
    for candidate_id in result.evicted_ids:
        reasons[candidate_id] = ("evicted", "Outside configured EVICTGuard context capacity")
    for candidate_id in result.protected_ids:
        reasons[candidate_id] = ("protected", "Selected in protected high-score set by EVICTGuard policy")
    id_col = "_stable_id" if "_stable_id" in result.selected else "record_id"
    selected_ids = set(result.selected.get(id_col, pd.Series(dtype=str)).astype(str))
    for candidate_id in selected_ids:
        if candidate_id not in reasons:
            reasons[candidate_id] = ("available", "Selected in context; below protected-set threshold")
    for candidate_id, (status, reason) in reasons.items():
        evidence_id = candidate_to_evidence.get(candidate_id)
        if evidence_id:
            update_retention_status(database, evidence_id, status, reason)


def _synthetic_mask(data: pd.DataFrame) -> pd.Series:
    if "is_synthetic" not in data:
        return pd.Series(False, index=data.index)
    return data["is_synthetic"].map(lambda value: str(value).lower() in {"true", "1", "yes"} if pd.notna(value) else False)


def _diversity(data: pd.DataFrame) -> dict[str, Any]:
    scored, _ = extract_features(data)
    host_values = scored["_host_category"]
    event_values = scored["_event_category"]
    source = scored["source"].fillna("__unknown_source__").astype(str) if "source" in scored else pd.Series("__unknown_source__", index=scored.index)
    strata = list(zip(host_values, event_values))
    return {
        "unique_hosts": int(host_values[host_values != "__unknown_host__"].nunique()),
        "unique_event_categories": int(event_values[event_values != "__unknown_event__"].nunique()),
        "unique_sources": int(source[source != "__unknown_source__"].nunique()),
        "unique_host_event_strata": len(set(strata)),
    }


def _source_diversity(data: pd.DataFrame) -> dict[str, Any]:
    """Diversity among non-synthetic source records only."""
    return _diversity(data.loc[~_synthetic_mask(data)])


def _method_metrics(
    method: str,
    result: SelectionResult,
    input_frame: pd.DataFrame,
    capacity: int,
    runtime_seconds: float,
    *,
    ground_truth_column: str | None = None,
    positive_values: set[str] | None = None,
    ground_truth_reliable: bool = False,
) -> dict[str, Any]:
    selected = result.selected
    input_duplicate_ids = linked_duplicate_ids(input_frame)
    selected_record_ids = set(selected.get("record_id", pd.Series(dtype=str)).dropna().astype(str))
    selected_duplicate_ids = input_duplicate_ids & selected_record_ids
    input_duplicate_rows = len(input_duplicate_ids)
    selected_duplicate_rows = len(selected_duplicate_ids)
    if input_duplicate_rows:
        duplicate_reduction = input_duplicate_rows - selected_duplicate_rows
        duplicate_reduction_fraction = duplicate_reduction / input_duplicate_rows
    else:
        duplicate_reduction = 0
        duplicate_reduction_fraction = None
    critical = None
    critical_note = "Unavailable: no reliable event-level ground truth was declared."
    if ground_truth_reliable and ground_truth_column and ground_truth_column in input_frame and positive_values:
        positives = input_frame[input_frame[ground_truth_column].astype(str).isin(positive_values)]
        selected_ids = set(selected.get("record_id", pd.Series(dtype=str)).astype(str))
        total_positives = len(positives)
        retained = int(positives[positives["record_id"].astype(str).isin(selected_ids)].shape[0]) if "record_id" in positives else 0
        critical = {"eligible_positive_records": total_positives, "retained_positive_records": retained, "retention_fraction": retained / total_positives if total_positives else None}
        critical_note = "Computed only from the explicitly declared reliable label column and positive values."
    return {
        "method": method,
        "selected_records": len(selected),
        "capacity": capacity,
        "capacity_utilization": len(selected) / capacity if capacity else None,
        "duplicate_rows_in_input": input_duplicate_rows,
        "duplicate_rows_selected": selected_duplicate_rows,
        "duplicate_reduction_rows": duplicate_reduction,
        "duplicate_reduction_fraction": duplicate_reduction_fraction,
        "diversity": _diversity(selected),
        "source_diversity": _source_diversity(selected),
        "synthetic_records_selected": int(_synthetic_mask(selected).sum()),
        "critical_evidence_retention": critical,
        "critical_evidence_note": critical_note,
        "selection_runtime_seconds": runtime_seconds,
    }


def run_comparison(
    database: str | Path,
    episode: str | Path,
    output: str | Path,
    *,
    capacity: int = 8,
    seed: int = 17,
    noise_type: str = "duplicate-flooding",
    noise_proportion: float = 0.20,
    protected_fraction: float = 0.25,
    weights: dict[str, float] | None = None,
    ground_truth_column: str | None = None,
    positive_values: set[str] | None = None,
    ground_truth_reliable: bool = False,
    method: str = "v1",
) -> dict[str, Any]:
    """Create a noisy experimental copy and compare all three selectors.

    ``method`` chooses the EVICTGuard scorer whose decisions are written to the ledger:
    ``v1`` (original) or ``v2`` (provenance- and prevalence-aware, src/evictguard_v2.py).
    """
    if capacity < 0:
        raise ValueError("capacity must be non-negative")
    clean = pd.read_csv(episode)
    # CSV contents plus the noise settings identify the experiment. The
    # timestamp in the noise manifest is intentionally excluded so repeating
    # the same experiment produces the same ledger evidence IDs.
    experiment_id = content_hash({
        "episode": content_hash(clean.to_json(orient="records", date_format="iso")),
        "noise_type": noise_type,
        "noise_proportion": noise_proportion,
        "seed": seed,
    })[:24]
    experimental, noise_manifest = inject_noise(clean, noise_type, noise_proportion, seed)
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    noisy_path = target.with_name(target.stem + "_input.csv")
    experimental.to_csv(noisy_path, index=False)
    noisy_path.with_suffix(noisy_path.suffix + ".manifest.json").write_text(json.dumps(noise_manifest, indent=2), encoding="utf-8")

    weight_config = weights or DEFAULT_WEIGHTS
    # Runtime measures selection only; ledger I/O and noise creation are kept
    # separate so methods are comparable on the same candidate frame.
    start = time.perf_counter()
    if method == "v2":
        from .evictguard_v2 import PrevalenceProfile, select_evictguard_v2
        profile_path = Path("data/benchmark/prevalence_train.json")
        profile = PrevalenceProfile.load(profile_path) if profile_path.exists() else None
        evict_result = select_evictguard_v2(experimental, capacity, profile=profile, protected_fraction=protected_fraction, seed=seed)
    else:
        evict_result = select_evictguard(experimental, capacity, weights=weight_config, protected_fraction=protected_fraction, seed=seed)
    evict_runtime = time.perf_counter() - start
    start = time.perf_counter()
    fifo_result = select_fifo(experimental, capacity)
    fifo_runtime = time.perf_counter() - start
    start = time.perf_counter()
    random_result = select_random(experimental, capacity, seed)
    random_runtime = time.perf_counter() - start

    candidate_map = _register_candidates(database, experimental, experiment_id)
    _sync_ledger(database, evict_result, candidate_map)
    methods = [
        _method_metrics("evictguard", evict_result, experimental, capacity, evict_runtime, ground_truth_column=ground_truth_column, positive_values=positive_values, ground_truth_reliable=ground_truth_reliable),
        _method_metrics("fifo", fifo_result, experimental, capacity, fifo_runtime, ground_truth_column=ground_truth_column, positive_values=positive_values, ground_truth_reliable=ground_truth_reliable),
        _method_metrics("random", random_result, experimental, capacity, random_runtime, ground_truth_column=ground_truth_column, positive_values=positive_values, ground_truth_reliable=ground_truth_reliable),
    ]
    _, unavailable = score_evidence(experimental, weight_config)
    report = {
        "input_episode": str(episode),
        "experimental_input": str(noisy_path),
        "input_records": len(experimental),
        "noise_configuration": noise_manifest,
        "selection_configuration": {"capacity": capacity, "seed": seed, "protected_fraction": protected_fraction, "weights": weight_config},
        "features_unavailable": unavailable,
        "duplicate_metric_scope": "Counts only synthetic duplicate-flooding records with a source_record_id link to an in-input parent with matching content; identical hashes alone are not considered duplicates.",
        "diversity_metric_scope": "diversity covers all selected rows, while source_diversity excludes synthetic rows; generated categories are not treated as source categories.",
        "ground_truth_limitation": "The selected OTRF corpus does not provide verified event-level labels; critical retention is unreported unless the caller explicitly supplies reliable labels.",
        "methods": methods,
        "evictguard_protected_evidence_ids": list(evict_result.protected_ids),
        "evictguard_redundant_evidence_ids": list(evict_result.redundant_ids),
        "evictguard_evicted_evidence_ids": list(evict_result.evicted_ids),
    }
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default="database/evictguard.sqlite")
    parser.add_argument("--episode", default="data/episodes/demo_episode.csv")
    parser.add_argument("--output", default="results/phase3_comparison.json")
    parser.add_argument("--capacity", type=int, default=8)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--noise-type", choices=["benign-looking", "duplicate-flooding", "missing-evidence"], default="duplicate-flooding")
    parser.add_argument("--noise-proportion", type=float, default=0.20)
    parser.add_argument("--protected-fraction", type=float, default=0.25)
    parser.add_argument("--method", choices=["v1", "v2"], default="v1", help="EVICTGuard scorer whose decisions update the ledger")
    parser.add_argument("--weight-rarity", type=float, default=DEFAULT_WEIGHTS["rarity"])
    parser.add_argument("--weight-corroboration", type=float, default=DEFAULT_WEIGHTS["corroboration"])
    parser.add_argument("--weight-non-redundancy", type=float, default=DEFAULT_WEIGHTS["non_redundancy"])
    args = parser.parse_args()
    try:
        weights = {"rarity": args.weight_rarity, "corroboration": args.weight_corroboration, "non_redundancy": args.weight_non_redundancy}
        report = run_comparison(args.database, args.episode, args.output, capacity=args.capacity, seed=args.seed, noise_type=args.noise_type, noise_proportion=args.noise_proportion, protected_fraction=args.protected_fraction, weights=weights, method=args.method)
    except Exception as exc:
        parser.error(str(exc))
    print(json.dumps({"input_records": report["input_records"], "methods": report["methods"], "output": args.output}, indent=2))


if __name__ == "__main__":
    main()
