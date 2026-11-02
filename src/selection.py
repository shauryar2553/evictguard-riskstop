"""Deterministic evidence ranking, deduplication, and context selection."""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

from .utils import content_hash

DEFAULT_WEIGHTS = {"rarity": 0.45, "corroboration": 0.35, "non_redundancy": 0.20}
UNAVAILABLE_FEATURES = {
    "asset_sensitivity": "The current dataset has no documented asset criticality field.",
    "attack_stage_relevance": "No event-level attack-stage annotation is available.",
}
ROW_METADATA = {
    "record_id", "source_record_id", "source_path", "source_index", "content_hash",
    "original_json", "is_synthetic", "noise_type", "label", "source_label_provenance",
    "inferred_label", "synthetic_label", "parent_evidence_id", "evidence_id",
}


@dataclass(frozen=True)
class SelectionResult:
    method: str
    selected: pd.DataFrame
    scored: pd.DataFrame
    protected_ids: tuple[str, ...] = ()
    redundant_ids: tuple[str, ...] = ()
    evicted_ids: tuple[str, ...] = ()


def _value(row: pd.Series, *names: str) -> Any:
    for name in names:
        if name in row and pd.notna(row[name]) and str(row[name]).strip():
            return row[name]
    raw = row.get("original_json")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            lowered = {str(k).lower(): v for k, v in parsed.items()}
            for name in names:
                value = lowered.get(name.lower())
                if value is not None and str(value).strip():
                    return value
        except (json.JSONDecodeError, AttributeError):
            pass
    return None


def _content_key(row: pd.Series) -> str:
    existing = row.get("content_hash")
    if existing is not None and pd.notna(existing) and str(existing).strip():
        return str(existing)
    raw = row.get("original_json")
    if isinstance(raw, str) and raw.strip():
        try:
            return content_hash(json.loads(raw))
        except json.JSONDecodeError:
            return content_hash(raw)
    payload = {str(k): v for k, v in row.items() if k not in ROW_METADATA and not str(k).startswith("source_label")}
    return content_hash(payload)


def linked_duplicate_ids(data: pd.DataFrame) -> set[str]:
    """Return only explicit duplicate-flooding copies linked to matching parents.

    Equal hashes alone are insufficient: separate source rows may represent
    legitimate repeated events. A row is treated as an injected duplicate
    only when it is marked synthetic, has duplicate-flooding provenance, and
    points to an in-input parent with matching content.
    """
    if data.empty or "record_id" not in data or "source_record_id" not in data:
        return set()
    rows = list(data.reset_index(drop=True).iterrows())
    identifiers = {str(row.get("record_id")): _content_key(row) for _, row in rows if pd.notna(row.get("record_id"))}
    duplicates: set[str] = set()
    for _, row in rows:
        candidate_id = row.get("record_id")
        parent_id = row.get("source_record_id")
        is_synthetic = str(row.get("is_synthetic", "")).lower() in {"true", "1", "yes"} if pd.notna(row.get("is_synthetic")) else False
        noise_type = str(row.get("noise_type", "")).lower()
        if candidate_id is None or pd.isna(candidate_id) or parent_id is None or pd.isna(parent_id):
            continue
        candidate_id, parent_id = str(candidate_id), str(parent_id)
        if is_synthetic and noise_type == "duplicate-flooding" and parent_id in identifiers and identifiers[parent_id] == _content_key(row):
            duplicates.add(candidate_id)
    return duplicates


def extract_features(data: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, str]]:
    """Add normalized rarity, corroboration, and non-redundancy features.

    Rarity is inverse log-frequency of event category. Corroboration is the
    capped log-scaled count of distinct, non-identical events sharing a host.
    Non-redundancy is 1 / exact-content duplicate-group size. Ground-truth
    labels are never read by this function.
    """
    frame = data.copy(deep=True).reset_index(drop=True)
    if frame.empty:
        for column in ("_event_category", "_host_category", "_content_key", "feature_rarity", "feature_corroboration", "feature_non_redundancy"):
            frame[column] = pd.Series(dtype="object" if column.endswith("category") or column == "_content_key" else "float64")
        return frame, dict(UNAVAILABLE_FEATURES)
    categories = [_value(row, "event_type", "EventType", "Channel", "EventID", "event_id") for _, row in frame.iterrows()]
    hosts = [_value(row, "host", "Hostname", "Computer", "hostname") for _, row in frame.iterrows()]
    frame["_event_category"] = [str(x) if x is not None else "__unknown_event__" for x in categories]
    frame["_host_category"] = [str(x) if x is not None else "__unknown_host__" for x in hosts]
    frame["_content_key"] = [_content_key(row) for _, row in frame.iterrows()]
    if "is_synthetic" in frame:
        synthetic_mask = frame["is_synthetic"].map(lambda value: str(value).lower() in {"true", "1", "yes"} if pd.notna(value) else False)
    else:
        synthetic_mask = pd.Series(False, index=frame.index)

    unique_category_content = set(zip(frame["_event_category"], frame["_content_key"]))
    category_counts = Counter(category for category, _ in unique_category_content)
    max_frequency = max(category_counts.values(), default=1)
    denominator = math.log(max_frequency) if max_frequency > 1 else 1.0
    frame["feature_rarity"] = [1.0 - math.log(category_counts[c]) / denominator if max_frequency > 1 else 1.0 for c in frame["_event_category"]]

    # Count distinct content hashes per host; exact duplicate floods do not
    # artificially increase corroboration.
    host_hashes: dict[str, set[str]] = defaultdict(set)
    for host, digest, is_synthetic in zip(frame["_host_category"], frame["_content_key"], synthetic_mask):
        if host != "__unknown_host__" and not is_synthetic:
            host_hashes[host].add(digest)
    max_support = math.log1p(5)
    frame["feature_corroboration"] = [
        min(math.log1p(max(0, len(host_hashes[h]) - 1)) / max_support, 1.0) if h in host_hashes and not is_synthetic else 0.0
        for h, is_synthetic in zip(frame["_host_category"], synthetic_mask)
    ]
    duplicate_ids = linked_duplicate_ids(frame)
    frame["feature_non_redundancy"] = [0.0 if _stable_id(row, i) in duplicate_ids else 1.0 for i, (_, row) in enumerate(frame.iterrows())]
    return frame, dict(UNAVAILABLE_FEATURES)


def score_evidence(data: pd.DataFrame, weights: dict[str, float] | None = None) -> tuple[pd.DataFrame, dict[str, str]]:
    """Calculate a weighted 0..1 retention score without consulting labels."""
    weights = dict(weights or DEFAULT_WEIGHTS)
    if set(weights) != set(DEFAULT_WEIGHTS):
        raise ValueError(f"weights must contain exactly {sorted(DEFAULT_WEIGHTS)}")
    if any(not math.isfinite(v) or v < 0 for v in weights.values()) or not math.isclose(sum(weights.values()), 1.0, abs_tol=1e-8):
        raise ValueError("weights must be finite, non-negative, and sum to 1")
    frame, unavailable = extract_features(data)
    frame["retention_score"] = sum(frame[f"feature_{feature}"] * weight for feature, weight in weights.items())
    frame["score_weights"] = json.dumps(weights, sort_keys=True)
    return frame, unavailable


def _stable_id(row: pd.Series, index: int) -> str:
    value = row.get("record_id")
    return str(value) if value is not None and pd.notna(value) else f"row-{index:09d}"


def _representatives(scored: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    if scored.empty:
        return scored.copy(), []
    frame = scored.copy()
    frame["_stable_id"] = [_stable_id(row, i) for i, (_, row) in enumerate(frame.iterrows())]
    if "is_synthetic" in frame:
        synthetic = frame["is_synthetic"].map(lambda value: str(value).lower() in {"true", "1", "yes"} if pd.notna(value) else False)
    else:
        synthetic = pd.Series(False, index=frame.index)
    frame["_synthetic_rank"] = synthetic.astype(int)
    duplicate_ids = linked_duplicate_ids(frame)
    parent_ids = set()
    if "source_record_id" in frame:
        parent_ids = set(frame.loc[frame["_stable_id"].isin(duplicate_ids), "source_record_id"].dropna().astype(str))
    frame["_duplicate_group"] = [
        f"linked:{str(row.get('source_record_id'))}" if stable_id in duplicate_ids
        else f"linked:{stable_id}" if stable_id in parent_ids
        else f"record:{stable_id}"
        for stable_id, (_, row) in zip(frame["_stable_id"], frame.iterrows())
    ]
    ordered = frame.sort_values(["_duplicate_group", "_synthetic_rank", "retention_score", "_stable_id"], ascending=[True, True, False, True], kind="stable")
    keep_indexes = ordered.drop_duplicates("_duplicate_group", keep="first").index
    redundant = frame.loc[~frame.index.isin(keep_indexes), "_stable_id"].astype(str).tolist()
    return frame.loc[keep_indexes].copy(), redundant


def _stratum(row: pd.Series) -> tuple[str, ...]:
    host, event, source = row.get("_host_category"), row.get("_event_category"), _value(row, "source", "SourceName", "ProviderName")
    if host and host != "__unknown_host__" and event and event != "__unknown_event__":
        return (str(host), str(event))
    if host and host != "__unknown_host__":
        return (str(host),)
    if event and event != "__unknown_event__":
        return (str(event),)
    if source is not None:
        return (str(source),)
    return ("__all__",)


def select_evictguard(
    data: pd.DataFrame,
    capacity: int,
    *,
    weights: dict[str, float] | None = None,
    protected_fraction: float = 0.25,
    seed: int = 17,
) -> SelectionResult:
    """Select exact-deduplicated, scored evidence with a diversity-aware fill.

    The top ``ceil(capacity * protected_fraction)`` representatives are
    protected first. Remaining capacity is filled by round-robin strata,
    ranking within each stratum by score and stable ID. ``seed`` rotates the
    deterministic starting stratum to make the configured seed explicit.
    """
    if capacity < 0:
        raise ValueError("capacity must be non-negative")
    if not 0 <= protected_fraction <= 1:
        raise ValueError("protected_fraction must be between 0 and 1")
    scored, _ = score_evidence(data, weights)
    representatives, redundant = _representatives(scored)
    representatives["_stable_id"] = [_stable_id(row, i) for i, (_, row) in enumerate(representatives.iterrows())]
    candidates = representatives.sort_values(["retention_score", "_stable_id"], ascending=[False, True], kind="stable")
    limit = min(capacity, len(candidates))
    protected_count = min(limit, math.ceil(limit * protected_fraction)) if protected_fraction else 0
    protected = candidates.head(protected_count)
    chosen_indexes = list(protected.index)
    remaining = candidates.loc[~candidates.index.isin(chosen_indexes)].copy()

    strata: dict[tuple[str, ...], deque[int]] = defaultdict(deque)
    for idx, row in remaining.iterrows():
        strata[_stratum(row)].append(idx)
    for key in strata:
        strata[key] = deque(sorted(strata[key], key=lambda i: (-float(remaining.loc[i, "retention_score"]), str(remaining.loc[i, "_stable_id"]))))
    stratum_keys = sorted(strata)
    if stratum_keys:
        offset = int(seed) % len(stratum_keys)
        stratum_keys = stratum_keys[offset:] + stratum_keys[:offset]
    while len(chosen_indexes) < limit and stratum_keys:
        advanced = False
        for key in stratum_keys:
            if strata[key] and len(chosen_indexes) < limit:
                chosen_indexes.append(strata[key].popleft())
                advanced = True
        if not advanced:
            break
    selected = candidates.loc[chosen_indexes].copy() if chosen_indexes else candidates.head(0).copy()
    selected_ids = set(selected["_stable_id"].astype(str))
    protected_ids = tuple(protected["_stable_id"].astype(str).tolist())
    evicted = tuple(candidates.loc[~candidates["_stable_id"].isin(selected_ids), "_stable_id"].astype(str).tolist())
    # Drop internal columns from the user-facing selected records, retain scores.
    selected = selected.drop(columns=["_synthetic_rank"], errors="ignore")
    return SelectionResult("evictguard", selected, scored, protected_ids, tuple(redundant), evicted)


def select_fifo(data: pd.DataFrame, capacity: int) -> SelectionResult:
    """Retain the newest rows; stable input order breaks timestamp ties."""
    if capacity < 0:
        raise ValueError("capacity must be non-negative")
    frame = data.copy(deep=True).reset_index(drop=True)
    if "timestamp" in frame:
        parsed = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
        frame["_fifo_time"] = parsed
        frame["_fifo_order"] = np.arange(len(frame))
        frame = frame.sort_values(["_fifo_time", "_fifo_order"], ascending=[False, False], na_position="last", kind="stable")
    selected = frame.head(capacity).drop(columns=["_fifo_time", "_fifo_order"], errors="ignore")
    return SelectionResult("fifo", selected, frame)


def select_random(data: pd.DataFrame, capacity: int, seed: int = 17) -> SelectionResult:
    """Select up to capacity rows uniformly without replacement."""
    if capacity < 0:
        raise ValueError("capacity must be non-negative")
    frame = data.copy(deep=True).reset_index(drop=True)
    count = min(capacity, len(frame))
    indexes = np.random.default_rng(seed).choice(len(frame), size=count, replace=False) if count else []
    selected = frame.iloc[sorted(indexes)].copy() if count else frame.head(0).copy()
    return SelectionResult("random", selected, frame)
