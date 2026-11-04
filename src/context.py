"""Context assembly (proposal slide 15): turn the retained evidence into a bounded, LLM-ready context.

The context is grouped by acting process (entity), ordered by suspicion. Each item keeps a pointer
(``record_id``) to the full raw event in the evidence ledger, so the investigator can retrieve the
original on demand ("summaries with raw pointers"). Coverage and budget statistics are included so
that RISKSTOP can reason about what is and isn't in context.
"""
from __future__ import annotations

import json
from typing import Any

import pandas as pd

from .evictguard_v2 import _base, parse_events, score_events

EVENT_NAMES = {("security", 4688): "process created", ("security", 4663): "object accessed", ("security", 4656): "handle requested",
               ("security", 5156): "network connection allowed", ("security", 4624): "logon", ("security", 4625): "failed logon",
               ("sysmon", 1): "process created", ("sysmon", 3): "network connection", ("sysmon", 7): "image loaded",
               ("sysmon", 8): "remote thread created", ("sysmon", 10): "process accessed", ("sysmon", 11): "file created",
               ("sysmon", 12): "registry key created/deleted", ("sysmon", 13): "registry value set", ("sysmon", 22): "DNS query",
               ("powershell", 4104): "PowerShell script block", ("powershell", 4103): "PowerShell module"}


def assemble_context(selected: pd.DataFrame, candidates_total: int, capacity: int, max_items_per_entity: int = 12,
                     profile=None) -> dict[str, Any]:
    """Structured context for the LLM investigator built from the retained evidence."""
    sel = selected.reset_index(drop=True)
    if sel.empty:
        return {"budget": {"capacity": capacity, "retained": 0, "candidates": candidates_total}, "entities": []}
    scored = score_events(sel, profile)
    scored["record_id"] = sel["record_id"].astype(str).values
    scored["timestamp"] = sel["timestamp"].values
    entities = []
    for actor_key, part in scored.groupby("actor_key", sort=False):
        part = part.sort_values("eg_value", ascending=False)
        items = [{"record_id": r.record_id, "time": str(r.timestamp), "action": EVENT_NAMES.get((r.fam, int(r.eid)), f"{r.fam} {r.eid}"),
                  "target": r.target[:160], "value": round(float(r.eg_value), 3)} for r in part.head(max_items_per_entity).itertuples()]
        entities.append({"process": part.actor.iloc[0] or "(unknown)", "process_key": actor_key, "host": part.host.iloc[0],
                         "suspicion": round(float(part.f_actor.max()), 3), "retained_events": len(part),
                         "distinct_targets": int(part.target.nunique()), "top_evidence": items,
                         "more_available": max(0, len(part) - max_items_per_entity)})
    entities.sort(key=lambda e: (-e["suspicion"], -e["retained_events"]))
    return {
        "budget": {"capacity": capacity, "retained": len(sel), "candidates": candidates_total,
                   "retained_share": round(len(sel) / max(candidates_total, 1), 5)},
        "coverage": {"hosts": int(scored.host.nunique()), "log_sources": sorted(scored.fam.unique().tolist()),
                     "event_kinds": int(scored[["fam", "eid"]].drop_duplicates().shape[0]), "processes": len(entities)},
        "entities": entities,
        "note": "Each item's record_id points to the full raw event in the evidence ledger.",
    }


def render_text(context: dict[str, Any], max_entities: int = 15) -> str:
    """Compact plain-text rendering for an LLM prompt."""
    b, c = context["budget"], context.get("coverage", {})
    lines = [f"EVIDENCE CONTEXT: {b['retained']} of {b['candidates']} events retained (capacity {b['capacity']}).",
             f"Coverage: {c.get('hosts', 0)} host(s), sources {', '.join(c.get('log_sources', []))}, {c.get('processes', 0)} processes.", ""]
    for e in context["entities"][:max_entities]:
        lines.append(f"[{e['host']}] {e['process']}  suspicion={e['suspicion']}  events={e['retained_events']}  distinct targets={e['distinct_targets']}")
        for it in e["top_evidence"]:
            lines.append(f"   - {it['time']} {it['action']}: {it['target']}  (ref {it['record_id']})")
        if e["more_available"]:
            lines.append(f"   ... {e['more_available']} more retained events for this process (retrievable by ref)")
    return "\n".join(lines)


def main() -> None:
    import argparse
    from pathlib import Path
    from .evictguard_v2 import PrevalenceProfile, select_evictguard_v2
    ap = argparse.ArgumentParser(description="Build an LLM-ready context from an episode with EVICTGuard v2")
    ap.add_argument("episode", type=Path)
    ap.add_argument("--capacity", type=int, default=1024)
    ap.add_argument("--profile", type=Path, default=Path("data/benchmark/prevalence_train.json"))
    ap.add_argument("--json", type=Path, default=None)
    a = ap.parse_args()
    frame = pd.read_parquet(a.episode)
    prof = PrevalenceProfile.load(a.profile) if a.profile.exists() else None
    sel = select_evictguard_v2(frame, a.capacity, profile=prof)
    ctx = assemble_context(sel.selected, len(frame), a.capacity, profile=prof)
    if a.json:
        a.json.write_text(json.dumps(ctx, indent=2, default=str))
    print(render_text(ctx))


if __name__ == "__main__":
    main()
