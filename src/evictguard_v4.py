"""EVICTGuard v4: v3 scoring + a supporting-evidence quota.

Motivation (measured): v2/v3 keep 0.96-0.99 of core attack actions but only 0.01-0.05 of the
supporting context around them (DLL loads, registry and file side effects of attacker processes),
which also appears to explain the gap on CDB, whose labels count such side effects as core.

Selection with capacity C:
  1. main      (1 - sigma - eps) * C  highest-valued evidence (v3 scoring: v2 without redundancy weighting)
  2. support   sigma * C               side effects of suspicious processes (actor suspicion >= theta):
               round-robin over processes in order of suspicion; within a process, one event per
               (event type, target directory) template first (diverse side effects), then by value
  3. explore   eps * C                 round-robin over (host, log family, event id) strata (as in v2)
Unused quota flows back to the main ranking. Label-free, like all EVICTGuard versions.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque

import numpy as np
import pandas as pd

from .evictguard_v2 import PrevalenceProfile, score_events
from .selection import SelectionResult


def select_evictguard_v4(data: pd.DataFrame, capacity: int, *, profile: PrevalenceProfile | None = None, sigma: float = 0.2,
                         theta: float = 0.5, eps: float = 0.1, seed: int = 17) -> SelectionResult:
    if capacity < 0:
        raise ValueError("capacity must be non-negative")
    frame = data.reset_index(drop=True)
    sc = score_events(frame, profile, disable={"redundancy"})
    reps = (sc.sort_values(["_tpl_group", "eg_value", "_time_rank"], ascending=[True, False, True], kind="stable")
              .drop_duplicates("_tpl_group", keep="first"))
    ranked = reps.sort_values(["eg_value", "_time_rank"], ascending=[False, True], kind="stable")
    limit = min(capacity, len(ranked))
    n_support = int(round(limit * sigma))
    n_explore = int(round(limit * eps))
    n_main = max(0, limit - n_support - n_explore)
    chosen = list(ranked.index[:n_main])
    taken = set(chosen)

    # 2. supporting side effects of suspicious processes
    pool = ranked[(ranked.f_actor >= theta) & ~ranked.index.isin(taken)]
    if n_support and len(pool):
        tdir = pool.target.str.replace(r"\\[^\\]*$", "", regex=True)
        pool = pool.assign(_tmpl=pool.fam + "|" + pool.eid.astype(str) + "|" + tdir)
        order = pool.groupby("actor_key").f_actor.max().sort_values(ascending=False).index
        queues = []
        for ak in order:
            part = pool[pool.actor_key == ak]
            first = part.drop_duplicates("_tmpl")                # one per side-effect template, best value first
            rest = part.loc[~part.index.isin(first.index)]
            queues.append(deque(list(first.index) + list(rest.index)))
        added = 0
        while added < n_support and any(queues):
            for q in queues:
                if q and added < n_support:
                    idx = q.popleft()
                    if idx not in taken:
                        chosen.append(idx); taken.add(idx); added += 1

    # 3. exploration over strata
    if n_explore:
        rest = ranked.loc[~ranked.index.isin(taken)]
        strata = rest.groupby([rest.host, rest.fam, rest.eid], sort=True).groups
        queues = [deque(idx) for _, idx in sorted(strata.items(), key=lambda kv: str(kv[0]))]
        rng = np.random.default_rng(seed)
        rng.shuffle(queues)
        added = 0
        while added < n_explore and any(queues):
            for q in queues:
                if q and added < n_explore:
                    idx = q.popleft()
                    if idx not in taken:
                        chosen.append(idx); taken.add(idx); added += 1

    # unused quota flows back to the main ranking
    for idx in ranked.index:
        if len(chosen) >= limit:
            break
        if idx not in taken:
            chosen.append(idx); taken.add(idx)
    selected = frame.loc[chosen].copy()
    selected["eg_value"] = sc.loc[chosen, "eg_value"].to_numpy()
    return SelectionResult("evictguard_v4", selected, sc)
