"""Baselines from the literature, re-implemented on our candidate sets (same inputs as EVICTGuard).

* ``recency_dedup``  FIFO improved with exact-action de-duplication (keeps the newest distinct actions).
* ``rare_action``    Unsupervised rare-event ranking: -log frequency of (actor, event type, target) in the
                     candidate set (the classic log-anomaly heuristic).
* ``nodoze``         NoDoze-style provenance triage (Hassan et al., NDSS 2019), simplified re-implementation:
                     each event's anomaly = 1 - P(action | actor) estimated from the historical frequency
                     database (here: the same train-split prevalence profile EVICTGuard v2 receives), smoothed;
                     anomaly is then propagated along the process tree (an event inherits the max anomaly of
                     its actor's ancestry, decayed), and events are ranked by the propagated score.
* ``sigma_priority`` Detection-rule alert prioritisation (AlertPro-style SOC practice): events that trigger
                     Sigma rules first, by rule level, then the most recent events. NOTE: not valid on OTRF,
                     whose labels are partly Sigma-derived; used on ATLASv2 only (independent ground truth).

None of them read labels or injected-noise markers.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

from .evictguard_v2 import PrevalenceProfile, _base, parse_events
from .selection import SelectionResult

_SIGMA_CACHE: dict = {}
_RULES: dict = {}


def _random_tie(n: int, seed: int = 17) -> np.ndarray:
    """Seeded random tie-break. Anomaly scores tie on thousands of 'never seen' events; breaking ties by
    time (earliest/newest) would decide the result arbitrarily, so ties are broken uniformly at random."""
    return np.random.default_rng(seed).permutation(n)


def _result(name: str, frame: pd.DataFrame, score: np.ndarray, capacity: int, tie: np.ndarray | None = None) -> SelectionResult:
    order = np.lexsort(((tie if tie is not None else np.zeros(len(frame))), -score))
    chosen = order[: min(capacity, len(frame))]
    scored = frame.copy()
    scored["baseline_score"] = score
    return SelectionResult(name, frame.iloc[np.sort(chosen)].copy(), scored)


def _time_rank(frame: pd.DataFrame) -> np.ndarray:
    t = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    return t.rank(method="first", na_option="bottom").to_numpy()


def _action_key(p: pd.DataFrame) -> pd.Series:
    return p.host + "|" + p.actor.map(_base) + "|" + p.fam + "|" + p.eid.astype(str) + "|" + p.target


def select_recency_dedup(data: pd.DataFrame, capacity: int) -> SelectionResult:
    frame = data.reset_index(drop=True)
    p = parse_events(frame)
    recency = _time_rank(frame)
    key = _action_key(p)
    # keep the newest instance of each distinct action; older repeats score -inf
    newest = pd.Series(recency).groupby(key.values).transform("max").to_numpy()
    score = np.where(recency == newest, recency, -np.inf)
    return _result("recency_dedup", frame, score, capacity)


def select_rare_action(data: pd.DataFrame, capacity: int, seed: int = 17) -> SelectionResult:
    frame = data.reset_index(drop=True)
    p = parse_events(frame)
    tpl = p.actor.map(_base) + "|" + p.fam + "|" + p.eid.astype(str) + "|" + p.target_tpl
    freq = tpl.map(tpl.value_counts()).to_numpy(dtype=float)
    first = ~_action_key(p).duplicated().to_numpy()   # one instance per exact action
    score = np.where(first, -np.log(freq), -np.inf)
    return _result("rare_action", frame, score, capacity, tie=_random_tie(len(frame), seed))


def select_nodoze(data: pd.DataFrame, capacity: int, profile: PrevalenceProfile | None = None, decay: float = 0.85, seed: int = 17) -> SelectionResult:
    frame = data.reset_index(drop=True)
    p = parse_events(frame)
    actor_base = p.actor.map(_base)
    if profile is None:  # candidate-set frequencies as the "historical" database
        actions = Counter(zip(actor_base, p.fam, p.eid, p.target_tpl))
    else:
        actions = profile.actions
    per_actor: dict[str, int] = defaultdict(int)
    for (a, _f, _e, _t), c in actions.items():
        per_actor[a] += c
    # transition probability with add-one smoothing; anomaly = 1 - P(action | actor)
    vocab = max(len(actions), 1)
    prob = [(actions.get((a, f, e, t), 0) + 1) / (per_actor.get(a, 0) + vocab) for a, f, e, t in zip(actor_base, p.fam, p.eid, p.target_tpl)]
    anomaly = 1.0 - np.asarray(prob)
    # propagate along the process tree: a process's anomaly is the max anomaly of its own events and decayed ancestors
    key = (p.host + "|" + p.apid.astype(str) + "|" + actor_base).to_numpy()
    child = (p.host + "|" + p.cpid.astype(str) + "|" + p.child.map(_base)).to_numpy()
    proc = pd.Series(anomaly).groupby(key).max().to_dict()
    parent_of = {c: k for c, k, ch in zip(child, key, p.child) if ch}
    for _ in range(8):
        changed = False
        for c, par in parent_of.items():
            v = decay * proc.get(par, 0.0)
            if v > proc.get(c, 0.0) + 1e-12:
                proc[c] = v
                changed = True
        if not changed:
            break
    path = np.array([proc.get(k, 0.0) for k in key])
    score = 0.5 * anomaly + 0.5 * path
    first = ~_action_key(p).duplicated().to_numpy()
    score = np.where(first, score, -np.inf)
    return _result("nodoze", frame, score, capacity, tie=_random_tie(len(frame), seed))


def select_sigma_priority(data: pd.DataFrame, capacity: int, rules_root: str = "data/sigma/sigmahq/rules/windows") -> SelectionResult:
    from .sigma_engine import evaluate, load_rules
    from .label import LEVEL_RANK
    frame = data.reset_index(drop=True)
    cache_key = (id(data), len(frame))
    if "rules" not in _RULES:
        _RULES["rules"] = load_rules(rules_root)[0]
    if cache_key not in _SIGMA_CACHE:
        raw = pd.DataFrame([json.loads(x) for x in frame.original_json])
        hits, _ = evaluate(raw, _RULES["rules"])
        level = np.full(len(frame), -1.0)
        if len(hits):
            best = hits.assign(rank=hits.rule_level.map(LEVEL_RANK)).groupby("row")["rank"].max()
            level[best.index.to_numpy()] = best.to_numpy()
        _SIGMA_CACHE.clear()  # one candidate set at a time
        _SIGMA_CACHE[cache_key] = level
    level = _SIGMA_CACHE[cache_key]
    recency = _time_rank(frame)
    score = level * 1e7 + recency      # rule hits first (by level), then newest
    return _result("sigma_priority", frame, score, capacity)
