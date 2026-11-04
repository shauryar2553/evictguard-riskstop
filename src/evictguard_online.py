"""EVICTGuard-Online: streaming evidence eviction with stratified reservoirs (proposal slide 15).

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


def select_evictguard_online(data: pd.DataFrame, capacity: int, *, profile: PrevalenceProfile | None = None,
                             config: OnlineConfig | None = None, seed: int = 17) -> SelectionResult:
    cfg = config or OnlineConfig()
    frame = data.reset_index(drop=True)
    p = parse_events(frame)
    unresolved = _unresolved_mask(frame, p)
    t = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    order = np.argsort(t.to_numpy(), kind="stable")
    w, pw = DEFAULT_WEIGHTS, DEFAULT_PROCESS_WEIGHTS
    prof = profile or PrevalenceProfile()
    use_local_history = profile is None
    local_images: Counter = Counter()
    local_pairs: Counter = Counter()
    local_actions: Counter = Counter()

    cap_prot = int(round(capacity * cfg.protected))
    cap_ent = int(round(capacity * cfg.entity))
    cap_exp = max(0, capacity - cap_prot - cap_ent)

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
        host, fam, eid = p.host.iat[i], p.fam.iat[i], int(p.eid.iat[i])
        actor, apid, child, cpid = p.actor.iat[i], p.apid.iat[i], p.child.iat[i], p.cpid.iat[i]
        parent_path = p.parent.iat[i]
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
        if child:
            ckey = f"{host}|{cpid}|{_base(child)}"
            pr = prior_of(child, _base(parent_path))
            susp[ckey] = max(pr, cfg.decay * susp.get(akey, 0.0))
            f_actor = max(susp.get(akey, 0.0), susp[ckey])
        else:
            f_actor = susp.get(akey, 0.0)
        target, tpl, cmd = p.target.iat[i], p.target_tpl.iat[i], p.cmd.iat[i]
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
        nonred = 1.0 / math.sqrt(action_count[action])
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
                out_actor = p.actor.iat[evicted]
                out_key = f"{p.host.iat[evicted]}|{p.apid.iat[evicted]}|{_base(out_actor)}"
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

    chosen = sorted({r for _, _, r in prot_heap} | {r for items in ent_items.values() for _, r in items} | set(exp_slots))
    selected = frame.iloc[chosen].copy()
    scored = frame.copy()
    return SelectionResult("evictguard_online", selected, scored,
                           tuple(selected.record_id.astype(str)) if "record_id" in selected else ())
