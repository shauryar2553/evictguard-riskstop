import json

import numpy as np
import pandas as pd

from src.investigation import Query, QueryEngine, nk, run_investigation
from src.riskstop import (RiskStopParams, baseline_conformal_deferral, baseline_fixed_budget, make_riskstop, replay, riskstop_policy)

SYS = "Microsoft-Windows-Sysmon/Operational"


def ev(i, eid, raw, host="h1"):
    return {"record_id": f"r{i}", "timestamp": f"2022-07-19T13:00:{i % 60:02d}Z", "host": host, "channel": SYS, "event_id": eid,
            "original_json": json.dumps(raw), "gt_tier": "background", "gt_label": "benign"}


def episode():
    rows = [ev(0, 1, {"Image": "C:\\Users\\bob\\evil.exe", "ProcessId": 50, "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentProcessId": 40}),
            ev(1, 1, {"Image": "C:\\Windows\\System32\\whoami.exe", "ProcessId": 60, "ParentImage": "C:\\Users\\bob\\evil.exe", "ParentProcessId": 50})]
    rows += [ev(2 + i, 11, {"Image": "C:\\Users\\bob\\evil.exe", "ProcessId": 50, "TargetFilename": f"C:\\Users\\bob\\loot{i}.txt"}) for i in range(10)]
    rows += [ev(20 + i, 3, {"Image": "C:\\Windows\\System32\\svchost.exe", "ProcessId": 9, "DestinationIp": "10.0.0.1", "DestinationPort": 443}) for i in range(5)]
    return pd.DataFrame(rows)


def test_process_keys_normalised_and_queries_return_fresh_events_only():
    assert nk("h1|7312.0|x.exe") == "h1|7312|x.exe"
    eng = QueryEngine(episode(), per_query=5)
    first = eng.run(Query("process", "h1|50.0|evil.exe"))
    second = eng.run(Query("process", "h1|50|evil.exe"))
    assert len(first) == 5 and first and set(first).isdisjoint(second)
    eng2 = QueryEngine(episode(), per_query=50)
    kids = eng2.run(Query("children", "h1|50|evil.exe"))
    assert 1 in kids                      # the whoami.exe launched by evil.exe
    assert Query("window", ("h1", 0)).cost == 3


def test_investigation_respects_budget_and_never_needs_labels():
    e = episode()
    marked = e.assign(gt_tier="core", gt_label="attack")
    calls = []
    def decide(f, s):
        calls.append(f["budget_used_frac"])
        return "CONTINUE", {}
    a = run_investigation(e, decide, budget=6, capacity=8)
    b = run_investigation(marked, lambda f, s: ("CONTINUE", {}), budget=6, capacity=8)
    assert a["budget_used"] <= 6 and a["queries"] == b["queries"]        # labels do not change the investigation
    assert max(calls) <= 1.0


def test_riskstop_policy_rules():
    p = RiskStopParams(tau_attack=0.8, tau_benign=0.2, rho=0.3)
    assert riskstop_policy(0.9, 0.1, {"unresolved": 1}, p)[0] == "ATTACK"
    assert riskstop_policy(0.9, 0.6, {"unresolved": 2}, p)[0] == "CONTINUE"          # confident but evidence may be missing
    assert riskstop_policy(0.1, 0.1, {"unresolved": 0}, p)[0] == "BENIGN"
    assert riskstop_policy(0.1, 0.1, {"unresolved": 3, "budget_used_frac": 0.1}, p)[0] == "CONTINUE"   # too early to clear
    assert riskstop_policy(0.5, 0.5, {"forced_final": 1.0}, p)[0] == "DEFER"


def test_replay_and_baselines_are_deterministic():
    traj = [{"unresolved": 2, "budget_used_frac": i / 4, "recent_gain": 0.1} for i in range(4)]
    p = np.array([0.5, 0.6, 0.85, 0.95]); r = np.array([0.6, 0.5, 0.2, 0.1])
    assert replay(traj, p, r, make_riskstop(RiskStopParams())) == replay(traj, p, r, make_riskstop(RiskStopParams()))
    assert replay(traj, p, r, make_riskstop(RiskStopParams()))[0] == "ATTACK"
    assert replay(traj, p, r, baseline_fixed_budget())[1] == 3
    assert replay(traj, np.full(4, 0.5), r, baseline_conformal_deferral(0.8, 0.2))[0] == "DEFER"
