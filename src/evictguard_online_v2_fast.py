"""EVICTGuard-Online v2 (FAST implementation; identical decisions to src/evictguard_online_v2.py, verified by tests).

Only change: per-event pandas look-ups (p.col.iat[i]) are replaced by plain Python lists built once.

EVICTGuard-Online v2: streaming eviction, fixed after the online-v1 development diagnosis.

Changes from EVICTGuard-Online (v1; frozen, src/evictguard_online.py), all decided on development
data only (ATLASv2 h1 + OTRF native train):
  1. Adaptive reservoirs: the first ``min_protected`` slots are always protected; the entity and
     exploration fractions apply only to memory beyond that. In tiny memories (about 20 slots), splitting
     into reservoirs cost about 0.065 recall.
  2. Causal re-scoring (cold start): with no history, every program looks new early in the stream. Every
     ``rescore_every`` events, process suspicion and novelty of the retained evidence are recomputed
     from the statistics seen *so far* and the heaps are rebuilt. No look-ahead.
  3. EVICTGuard v3 scoring: no redundancy weighting (exact repeats are still dropped).

Original description follows.

EVICTGuard-Online: streaming evidence eviction with stratified reservoirs (proposal slide 15).

Events are processed in time order with a fixed memory of ``capacity`` events. Every decision uses
only the past (no look-ahead): process suspicion, parent resolution, redundancy counts and stratum
statistics are all incremental. Scoring reuses the frozen EVICTGuard v2 evidence model.

Memory is partitioned into reservoirs:
  * protected   (default 70%): min-heap of the highest-value evidence seen so far.
  * entity      (default 15%): coverage for suspicious processes (suspicion >= ``entity_threshold``):
                each keeps up to ``per_entity`` of its best events; when full, the entity holding the
                most slots gives up its lowest-value item.
  * exploration (default 15%): one representative per (host, log family, event id) stratum, reservoir-
                sampled when strata outnumber slots (source/stratum diversity, rare/new event kinds).
Exact repeats of an action already in memory are dropped as redundant.
"""
from __future__ import annotations

import heapq
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass

import numpy as np
import pandas as pd

from .evictguard_v2 import (DEFAULT_PROCESS_WEIGHTS, DEFAULT_WEIGHTS, DEFAULTS, LOLBINS, RISKY_PARENTS, SENSITIVE_TARGET, SHELLISH,
                            SYSTEM_LIBRARY, TYPE_INFO, USER_WRITABLE, PrevalenceProfile, _B64, _base, _rarity, parse_events)
from .selection import SelectionResult


@dataclass
class OnlineConfig:
    protected: float = 0.70
    entity: float = 0.15
    exploration: float = 0.15
    entity_threshold: float = 0.5
    min_protected: int = 64
    rescore_every: int = 512
    redundancy_weighting: bool = False
    per_entity: int = 4
    decay: float = DEFAULTS["decay"]


def _unresolved_mask(frame: pd.DataFrame, parsed: pd.DataFrame) -> np.ndarray:
    """Rows whose actor was filled by v2's whole-frame PID lookup (look-ahead); online resolves them incrementally."""
    raw_has_actor = []
    for raw, fam, eid in zip(frame.original_json, parsed.fam, parsed.eid):
        try:
            j = json.loads(raw) if isinstance(raw, str) else {}
        except json.JSONDecodeError:
            j = {}
        if fam == "security" and eid == 4688:
            raw_has_actor.append(bool(j.get("ParentProcessName")))
        elif fam == "security":
            raw_has_actor.append(bool(j.get("ProcessName") or j.get("Application") or j.get("NewProcessName")))
        else:
            raw_has_actor.append(True)
    return ~np.asarray(raw_has_actor)


def select_evictguard_online_v2_fast(data: pd.DataFrame, capacity: int, *, profile: PrevalenceProfile | None = None,
                             config: OnlineConfig | None = None, seed: int = 17) -> SelectionResult:
    cfg = config or OnlineConfig()
    frame = data.reset_index(drop=True)
    p = parse_events(frame)
    unresolved = _unresolved_mask(frame, p)
    L_host, L_fam, L_eid = p.host.tolist(), p.fam.tolist(), [int(x) for x in p.eid.tolist()]
    L_actor, L_apid, L_child, L_cpid, L_parent = p.actor.tolist(), p.apid.tolist(), p.child.tolist(), p.cpid.tolist(), p.parent.tolist()
    L_target, L_tpl, L_cmd = p.target.tolist(), p.target_tpl.tolist(), p.cmd.tolist()
    L_apid = [None if (x is None or (isinstance(x, float) and x != x)) else x for x in L_apid]
    L_cpid = [None if (x is None or (isinstance(x, float) and x != x)) else x for x in L_cpid]
    t = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    order = np.argsort(t.to_numpy(), kind="stable")
    w, pw = DEFAULT_WEIGHTS, DEFAULT_PROCESS_WEIGHTS
    prof = profile or PrevalenceProfile()
    use_local_history = profile is None
    local_images: Counter = Counter()
    local_pairs: Counter = Counter()
    local_actions: Counter = Counter()

    reservable = max(0, capacity - cfg.min_protected)        # (1) adaptive reservoirs
    cap_ent = int(round(reservable * cfg.entity))
    cap_exp = int(round(reservable * cfg.exploration))
    cap_prot = capacity - cap_ent - cap_exp
    proc_info: dict[str, tuple[str, str, str]] = {}          # key -> (image path, parent base, parent key)
    proc_order: list[str] = []
    row_comp: dict[int, tuple] = {}                          # row -> components needed for re-scoring

    known_image: dict[tuple, str] = {}
    susp: dict[str, float] = {}
    action_count: Counter = Counter()
    in_memory: set[str] = set()                       # action keys currently stored
    prot_heap: list[tuple[float, int, int]] = []      # (value, -time_rank, row)
    ent_items: dict[str, list[tuple[float, int]]] = defaultdict(list)   # actor -> [(value,row)]
    ent_total = 0
    exp_slots: list[int] = []
    strata_seen = 0
    strata: set[tuple] = set()
    rng = np.random.default_rng(seed)
    row_key: dict[int, str] = {}

    def prior_of(image_path: str, parent_base: str) -> float:
        base = _base(image_path)
        images = local_images if use_local_history else prof.images
        pairs = local_pairs if use_local_history else prof.pairs
        loc = 1.0 if USER_WRITABLE.search(image_path) else 0.0
        lol = 1.0 if base in LOLBINS else 0.0
        prev = _rarity(images.get(base, 0))
        lin = 0.0
        if parent_base:
            risky = parent_base in RISKY_PARENTS and (base in SHELLISH or loc > 0)
            lin = max(1.0 if risky else 0.0, _rarity(pairs.get((parent_base, base), 0)) * 0.5)
        terms = [pw["location"] * loc, pw["prevalence"] * prev, pw["lineage"] * lin, pw["lolbin"] * lol]
        return 1.0 - float(np.prod([1.0 - min(max(x, 0.0), 1.0) for x in terms]))

    def store_entity(actor: str, value: float, row: int) -> int | None:
        """Add to entity reservoir; return an evicted row or None."""
        nonlocal ent_total
        items = ent_items[actor]
        if len(items) >= cfg.per_entity:
            worst = min(items)
            if value <= worst[0]:
                return row
            items.remove(worst)
            items.append((value, row))
            return worst[1]
        items.append((value, row))
        ent_total += 1
        if ent_total > cap_ent:
            # the entity holding the most slots gives up its lowest-value item
            donor = max(ent_items, key=lambda a: (len(ent_items[a]), -min(ent_items[a])[0] if ent_items[a] else 0))
            worst = min(ent_items[donor])
            ent_items[donor].remove(worst)
            ent_total -= 1
            return worst[1]
        return None

    def forget(row: int | None) -> None:
        if row is not None and row in row_key:
            in_memory.discard(row_key.pop(row))

    for rank, i in enumerate(order):
        host, fam, eid = L_host[i], L_fam[i], L_eid[i]
        actor, apid, child, cpid = L_actor[i], L_apid[i], L_child[i], L_cpid[i]
        parent_path = L_parent[i]
        if unresolved[i]:
            actor = known_image.get((host, apid), "") if apid is not None else ""
            if child:
                parent_path = actor
        if apid is not None and actor:
            known_image.setdefault((host, apid), actor)
        if cpid is not None and child:
            known_image[(host, cpid)] = child
        akey = f"{host}|{apid}|{_base(actor)}" if actor else ""
        if akey and akey not in susp:
            susp[akey] = prior_of(actor, "")
            proc_info[akey] = (actor, "", "")
            proc_order.append(akey)
        if child:
            ckey = f"{host}|{cpid}|{_base(child)}"
            pr = prior_of(child, _base(parent_path))
            susp[ckey] = max(pr, cfg.decay * susp.get(akey, 0.0))
            if ckey not in proc_info:
                proc_order.append(ckey)
            proc_info[ckey] = (child, _base(parent_path), akey)
            f_actor = max(susp.get(akey, 0.0), susp[ckey])
        else:
            f_actor = susp.get(akey, 0.0)
        target, tpl, cmd = L_target[i], L_tpl[i], L_cmd[i]
        f_type = TYPE_INFO.get((fam, eid), 0.4)
        f_sens = 1.0 if target and SENSITIVE_TARGET.search(target) else 0.0
        actions = local_actions if use_local_history else prof.actions
        f_novel = 0.3 if not tpl else _rarity(actions.get((_base(actor), fam, eid, tpl), 0))
        if target and target[1:3] == ":\\":
            f_tloc = 1.0 if USER_WRITABLE.search(target) else (0.0 if SYSTEM_LIBRARY.search(target) else 0.4)
        else:
            f_tloc = 0.5
        f_cmd = 0.0
        if cmd:
            f_cmd = min(1.0, 0.5 * (1.0 if _B64.search(cmd) else 0.0) + 0.5 * min(max((len(cmd) - 120) / 400, 0.0), 1.0))
        action = f"{akey}§{fam}§{eid}§{target}"
        action_count[action] += 1
        nonred = 1.0 / math.sqrt(action_count[action]) if cfg.redundancy_weighting else 1.0   # (3) v3 scoring
        boost = max(f_actor, 0.25)
        value = (w["actor"] * f_actor + w["sensitivity"] * f_sens + w["novelty"] * f_novel * boost
                 + w["target_location"] * f_tloc * boost + w["command"] * f_cmd) * f_type * (0.5 + 0.5 * nonred)
        if use_local_history:  # cold start: the stream itself becomes the history, strictly after scoring
            local_images[_base(actor)] += 1
            if child:
                local_images[_base(child)] += 1
                local_pairs[(_base(parent_path), _base(child))] += 1
            local_actions[(_base(actor), fam, eid, tpl)] += 1
        if action in in_memory:
            continue  # identical action already retained
        row_comp[i] = (ckey if child else akey, akey, f_sens, f_tloc, f_cmd, f_type, (_base(actor), fam, eid, tpl), bool(tpl))
        evicted: int | None = None
        admitted = False
        prot_limit = capacity - ent_total - len(exp_slots)   # protected borrows unused reserved slots
        if prot_limit > 0 and (len(prot_heap) < prot_limit or value > prot_heap[0][0]):
            row_key[i] = action
            in_memory.add(action)
            admitted = True
            if len(prot_heap) < prot_limit:
                heapq.heappush(prot_heap, (value, -rank, i))
            else:
                v_out, _, evicted = heapq.heapreplace(prot_heap, (value, -rank, i))
                # demoted protected evidence may still earn an entity slot
                out_actor = L_actor[evicted]
                out_key = f"{L_host[evicted]}|{L_apid[evicted]}|{_base(out_actor)}"
                if cap_ent and susp.get(out_key, 0.0) >= cfg.entity_threshold:
                    evicted = store_entity(out_key, v_out, evicted)
        elif cap_ent and f_actor >= cfg.entity_threshold:
            row_key[i] = action
            in_memory.add(action)
            admitted = True
            evicted = store_entity(akey, value, i)
        forget(evicted if evicted != i else None)
        if evicted == i:
            in_memory.discard(action)
            row_key.pop(i, None)
            admitted = False
        if not admitted and cap_exp and len(exp_slots) <= cap_exp:
            stratum = (host, fam, eid)
            if stratum not in strata:
                strata.add(stratum)
                strata_seen += 1
                if len(exp_slots) < cap_exp:
                    exp_slots.append(i); row_key[i] = action; in_memory.add(action)
                else:
                    j = int(rng.integers(0, strata_seen))
                    if j < cap_exp:
                        forget(exp_slots[j])
                        exp_slots[j] = i; row_key[i] = action; in_memory.add(action)

        while prot_heap and len(prot_heap) + ent_total + len(exp_slots) > capacity:
            v_out, _, out = heapq.heappop(prot_heap)
            forget(out)

        # (2) causal re-scoring from statistics seen so far (cold start only: with a history profile priors are fixed)
        if use_local_history and cfg.rescore_every and rank and rank % cfg.rescore_every == 0:
            for k in proc_order:
                path, pbase, pkey = proc_info[k]
                pr = prior_of(path, pbase)
                susp[k] = max(pr, cfg.decay * susp.get(pkey, 0.0)) if pkey else pr

            def revalue(row: int) -> float:
                key_main, key_actor, fs, ft, fc, fty, akey4, has_tpl = row_comp[row]
                fa = max(susp.get(key_main, 0.0), susp.get(key_actor, 0.0))
                fn = _rarity(local_actions.get(akey4, 0)) if has_tpl else 0.3
                b = max(fa, 0.25)
                return (w["actor"] * fa + w["sensitivity"] * fs + w["novelty"] * fn * b + w["target_location"] * ft * b + w["command"] * fc) * fty

            prot_heap = [(revalue(r), tr, r) for _, tr, r in prot_heap]
            heapq.heapify(prot_heap)
            for a in list(ent_items):
                ent_items[a] = [(revalue(r), r) for _, r in ent_items[a]]

    chosen = sorted({r for _, _, r in prot_heap} | {r for items in ent_items.values() for _, r in items} | set(exp_slots))
    selected = frame.iloc[chosen].copy()
    scored = frame.copy()
    return SelectionResult("evictguard_online_v2", selected, scored,
                           tuple(selected.record_id.astype(str)) if "record_id" in selected else ())
