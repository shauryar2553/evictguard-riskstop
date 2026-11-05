"""Investigation environment: budgeted queries over the evidence ledger, an investigator, bounded memory.

This is the "Telemetry & Query Layer" + "LLM Investigator" loop of the proposal (slides 12-13), with a
deterministic rule-based investigator standing in for the LLM. The interface is the same one the LLM
investigator will use later (``Investigator.next_query``), so it can be swapped in without changes.

Loop per investigation:
    seed alert -> [investigator proposes query -> query layer returns events (cost) ->
                   evidence memory (EVICTGuard or FIFO, fixed capacity) -> RISKSTOP decides] ...

Queries (cost in budget units):
    process(p)      events of process p                      1
    children(p)     processes created by p and their events  2
    parent(p)       the creator of p and its events           1
    target(o)       every event touching object o              1
    network(h)      network activity on host h                 1
    window(h, t)    everything on host h within +/- 60 s      3   (broad sweep; most exposed to flooding)
Each query returns at most ``per_query`` events not returned before.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

import numpy as np
import pandas as pd

from .evictguard_v2 import PrevalenceProfile, _base, parse_events, score_events

_PID_FLOAT = __import__("re").compile(r"\|(\d+)\.0\|")


def nk(key: str) -> str:
    """Normalise a process key: '7312.0' and '7312' must name the same process."""
    return _PID_FLOAT.sub(lambda m: f"|{m.group(1)}|", key) if isinstance(key, str) else key


COST = {"process": 1, "children": 2, "parent": 1, "target": 1, "network": 1, "window": 3}
NET_EVENTS = {("sysmon", 3), ("sysmon", 22), ("security", 5156), ("security", 5158)}


@dataclass
class Query:
    kind: str
    arg: Any

    @property
    def cost(self) -> int:
        return COST[self.kind]

    def __str__(self) -> str:
        return f"{self.kind}({self.arg})"


class QueryEngine:
    """Indexes an episode once; answers budgeted queries. Never exposes labels."""

    def __init__(self, episode: pd.DataFrame, per_query: int = 150):
        self.frame = episode.reset_index(drop=True)
        self.per_query = per_query
        p = parse_events(self.frame)
        self.p = p
        self.time = pd.to_datetime(self.frame["timestamp"], errors="coerce", utc=True).astype("int64").to_numpy() // 10**9
        self.pkey = np.array([nk(k) for k in (p.host + "|" + p.apid.astype(str) + "|" + p.actor.map(_base))])
        ckey = np.array([nk(k) for k in (p.host + "|" + p.cpid.astype(str) + "|" + p.child.map(_base))])
        self.by_proc: dict[str, list[int]] = defaultdict(list)
        self.by_target: dict[str, list[int]] = defaultdict(list)
        self.by_host_net: dict[str, list[int]] = defaultdict(list)
        self.children: dict[str, set[str]] = defaultdict(set)
        self.parent_of: dict[str, str] = {}
        self.creation_row: dict[str, int] = {}
        for i, (pk, ck, ch, tgt, host, fam, eid) in enumerate(zip(self.pkey, ckey, p.child, p.target, p.host, p.fam, p.eid)):
            self.by_proc[pk].append(i)
            if tgt:
                self.by_target[f"{host}|{tgt}"].append(i)
            if (fam, int(eid)) in NET_EVENTS:
                self.by_host_net[host].append(i)
            if ch:
                self.children[pk].add(ck)
                self.parent_of.setdefault(ck, pk)
                self.creation_row.setdefault(ck, i)
                self.by_proc[ck].append(i)
        self.hosts = p.host.to_numpy()
        self.returned = np.zeros(len(self.frame), dtype=bool)

    def _take(self, rows: list[int]) -> list[int]:
        fresh = [r for r in rows if not self.returned[r]]
        fresh = fresh[: self.per_query]
        self.returned[fresh] = True
        return fresh

    def run(self, q: Query) -> list[int]:
        if q.kind in ("process", "children", "parent"):
            q = Query(q.kind, nk(q.arg))
        if q.kind == "process":
            return self._take(self.by_proc.get(q.arg, []))
        if q.kind == "children":
            rows = []
            for c in sorted(self.children.get(q.arg, ())):
                rows += self.by_proc.get(c, [])
            return self._take(rows)
        if q.kind == "parent":
            par = self.parent_of.get(q.arg)
            return self._take(self.by_proc.get(par, [])) if par else []
        if q.kind == "target":
            return self._take(self.by_target.get(q.arg, []))
        if q.kind == "network":
            return self._take(self.by_host_net.get(q.arg, []))
        if q.kind == "window":
            host, t = q.arg
            idx = np.flatnonzero((self.hosts == host) & (np.abs(self.time - t) <= 60))
            return self._take(idx.tolist())
        raise ValueError(q.kind)


class Memory:
    """Bounded evidence memory: EVICTGuard (v3 scoring over retrieved evidence) or FIFO."""

    def __init__(self, capacity: int, policy: str = "evictguard", profile: PrevalenceProfile | None = None):
        self.capacity, self.policy, self.profile = capacity, policy, profile
        self.retrieved: list[int] = []
        self.context: list[int] = []

    def update(self, engine: QueryEngine, new_rows: list[int]) -> pd.DataFrame:
        self.retrieved += new_rows
        if not self.retrieved:
            self.context = []
            return pd.DataFrame()
        if self.policy == "fifo" or len(self.retrieved) <= self.capacity:
            self.context = self.retrieved[-self.capacity:] if self.policy == "fifo" else list(self.retrieved)
        else:
            sub = engine.frame.iloc[self.retrieved]
            sc = score_events(sub, self.profile, disable={"redundancy"})   # EVICTGuard v3 scoring, label-free
            sc["_row"] = self.retrieved
            sc = sc.sort_values(["eg_value", "_time_rank"], ascending=[False, True], kind="stable").drop_duplicates("_tpl_group")
            self.context = sc._row.head(self.capacity).tolist()
        return engine.frame.iloc[self.context]


@dataclass
class InvestigationState:
    step: int = 0
    budget_used: int = 0
    queries: list[str] = field(default_factory=list)
    leads_queried: set = field(default_factory=set)


class Investigator:
    """Interface: given the bounded context, propose the next query (or None)."""

    def next_query(self, engine: QueryEngine, context_scored: pd.DataFrame, state: InvestigationState) -> Query | None:
        raise NotImplementedError


class HeuristicInvestigator(Investigator):
    """Rule-based stand-in for the LLM investigator: follow the most suspicious open lead.

    Leads, in priority order for the most suspicious process in context not yet expanded:
    its own events -> its children -> its parent -> objects it touched in user-writable places ->
    host network activity -> a time-window sweep around its first event.
    """

    PLAN = ("process", "children", "parent", "target", "network", "window")

    def next_query(self, engine, context_scored, state):
        if context_scored is None or context_scored.empty:
            return None
        leads = pd.concat([context_scored[["actor_key", "f_actor", "eg_value"]].rename(columns={"actor_key": "k"}),
                           context_scored[["lead_key", "f_actor", "eg_value"]].rename(columns={"lead_key": "k"})])
        procs = leads[leads.k != ""].groupby("k").agg(susp=("f_actor", "max"), val=("eg_value", "max")).sort_values(["susp", "val"], ascending=False)
        for pk in procs.index:
            if not pk:
                continue
            for kind in self.PLAN:
                key = (kind, pk)
                if key in state.leads_queried:
                    continue
                state.leads_queried.add(key)
                if kind in ("process", "children", "parent"):
                    return Query(kind, pk)
                part = context_scored[(context_scored.actor_key == pk) | (context_scored.lead_key == pk)]
                host = part.host.iloc[0]
                if kind == "target":
                    tg = part[part.f_tloc >= 1.0].sort_values("eg_value", ascending=False).target
                    for t in tg:
                        if ("target_obj", host, t) not in state.leads_queried:
                            state.leads_queried.add(("target_obj", host, t))
                            return Query("target", f"{host}|{t}")
                    continue
                if kind == "network":
                    if ("network", host) in state.leads_queried:
                        continue
                    state.leads_queried.add(("network", host))
                    return Query("network", host)
                if kind == "window":
                    t0 = int(pd.to_datetime(part.timestamp.min(), utc=True).value // 10**9) if "timestamp" in part else 0
                    return Query("window", (host, t0))
        return None


def seed_alert(engine: QueryEngine, profile: PrevalenceProfile | None) -> int:
    """The alert that opens the investigation: the single highest-valued event under EVICTGuard v3 scoring
    of the whole telemetry stream (an anomaly detector's top alert). Label-free; benign episodes get one too."""
    sc = score_events(engine.frame, profile, disable={"redundancy"})
    return int(sc.eg_value.to_numpy().argmax())


def score_context(engine: QueryEngine, rows: list[int], profile) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame()
    sub = engine.frame.iloc[rows]
    sc = score_events(sub, profile, disable={"redundancy"})
    sc["actor_key"] = sc.actor_key.map(nk)
    # a created process is a lead in its own right (Win7 4688 events may not name the creator)
    child_key = [nk(f"{h}|{c}|{_base(ch)}") if ch else "" for h, c, ch in zip(sc.host, sc.cpid, sc.child)]
    sc["lead_key"] = [ck if ck else ak for ck, ak in zip(child_key, sc.actor_key)]
    sc["_row"] = rows
    sc["timestamp"] = sub["timestamp"].values
    return sc


def run_investigation(episode: pd.DataFrame, decide: Callable, *, budget: int = 20, capacity: int = 256, memory_policy: str = "evictguard",
                      profile: PrevalenceProfile | None = None, investigator: Investigator | None = None, per_query: int = 150,
                      record: bool = True) -> dict[str, Any]:
    """Run one investigation. ``decide(features, state) -> (action, info)`` is the stopping policy
    (RISKSTOP or a baseline). Returns the trajectory (features per step), final action and certificate inputs."""
    from .riskstop import state_features
    engine = QueryEngine(episode, per_query=per_query)
    investigator = investigator or HeuristicInvestigator()
    memory = Memory(capacity, memory_policy, profile)
    state = InvestigationState()
    seed = seed_alert(engine, profile)
    engine.returned[seed] = True
    memory.update(engine, [seed])
    trajectory = []
    gains: list[float] = []
    action, info = "CONTINUE", {}
    while True:
        ctx = score_context(engine, memory.context, profile)
        feats = state_features(ctx, engine, memory, state, budget, gains)
        if record:
            trajectory.append(feats)
        action, info = decide(feats, state)
        if action != "CONTINUE":
            break
        q = investigator.next_query(engine, ctx, state)
        if q is None or state.budget_used + q.cost > budget:
            action, info = decide({**feats, "forced_final": 1.0, "budget_left": 0.0}, state)
            if action == "CONTINUE":
                action, info = "DEFER", {"reason": "budget exhausted or no leads"}
            break
        before = feats.get("ctx_value_top5", 0.0)
        rows = engine.run(q)
        state.budget_used += q.cost
        state.step += 1
        state.queries.append(str(q))
        memory.update(engine, rows)
        after_ctx = score_context(engine, memory.context, profile)
        top5 = float(np.sort(after_ctx.eg_value.to_numpy())[-5:].mean()) if len(after_ctx) else 0.0
        gains.append(max(0.0, top5 - before) + (len(rows) > 0) * 0.0)
    ctx = score_context(engine, memory.context, profile)
    return {"action": action, "info": info, "trajectory": trajectory, "queries": list(state.queries), "budget_used": state.budget_used,
            "context_rows": list(memory.context), "retrieved_rows": list(memory.retrieved), "context_scored": ctx, "engine": engine}
