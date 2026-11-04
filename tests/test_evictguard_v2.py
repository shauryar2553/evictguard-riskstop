import json

import numpy as np
import pandas as pd

from src.evictguard_v2 import PrevalenceProfile, action_keys, parse_events, score_events, select_evictguard_v2

SEC = "security"
SYS = "microsoft-windows-sysmon/operational"


def ev(i, channel, eid, raw, host="h1"):
    return {"record_id": f"r{i}", "timestamp": f"2022-07-19T13:00:{i:02d}Z", "host": host, "channel": channel, "event_id": eid,
            "original_json": json.dumps(raw)}


def episode():
    rows = [
        ev(0, SYS, 1, {"Image": "C:\\Users\\bob\\evil.exe", "ProcessId": 50, "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentProcessId": 40, "CommandLine": "evil.exe"}),
        ev(1, SYS, 1, {"Image": "C:\\Windows\\System32\\whoami.exe", "ProcessId": 60, "ParentImage": "C:\\Users\\bob\\evil.exe", "ParentProcessId": 50}),
        ev(2, SEC, 4663, {"ProcessName": "C:\\Users\\bob\\evil.exe", "ProcessId": "0x32", "ObjectName": "C:\\Users\\bob\\secrets.docx"}),
        ev(3, SEC, 4663, {"ProcessName": "C:\\Users\\bob\\evil.exe", "ProcessId": "0x32", "ObjectName": "C:\\Users\\bob\\secrets.docx"}),
        ev(4, SEC, 4663, {"ProcessName": "C:\\Users\\bob\\evil.exe", "ProcessId": "0x32", "ObjectName": "C:\\Windows\\winsxs\\x\\a.dll"}),
    ]
    rows += [ev(10 + i, SEC, 4658, {"ProcessName": "C:\\Windows\\System32\\svchost.exe", "ProcessId": "0x10", "HandleId": str(i)}) for i in range(20)]
    return pd.DataFrame(rows)


def test_scoring_ignores_labels_and_noise_markers():
    base = episode()
    marked = base.assign(gt_tier="core", gt_label="attack", is_synthetic=True, noise_type="x", dup_of="r0", source_record_id="r1")
    a = score_events(base).eg_value.to_numpy()
    b = score_events(marked).eg_value.to_numpy()
    assert np.allclose(a, b)
    sa = select_evictguard_v2(base, 3).selected.record_id.tolist()
    sb = select_evictguard_v2(marked, 3).selected.record_id.tolist()
    assert sa == sb


def test_lineage_propagates_suspicion_and_win7_hex_pids_parse():
    sc = score_events(episode())
    whoami = sc.loc[1, "f_actor"]
    svchost = sc.loc[10, "f_actor"]
    assert whoami > svchost  # child of a user-folder executable inherits suspicion
    p = parse_events(episode())
    assert p.loc[2, "apid"] == 50 and p.loc[2, "actor"].endswith("evil.exe")


def test_user_writable_targets_outrank_system_library_reads_and_duplicates_collapse():
    sc = score_events(episode())
    assert sc.loc[2, "eg_value"] > sc.loc[4, "eg_value"]
    sel = select_evictguard_v2(episode(), 3)
    kept = set(sel.selected.record_id)
    assert not {"r2", "r3"} <= kept  # identical action kept once
    assert len(set(action_keys(episode())[[2, 3]])) == 1


def test_history_profile_lowers_known_processes():
    hist = pd.DataFrame([ev(i, SEC, 4663, {"ProcessName": "C:\\Users\\bob\\evil.exe", "ProcessId": "0x32", "ObjectName": "C:\\Users\\bob\\secrets.docx"}) for i in range(50)])
    prof = PrevalenceProfile.build([hist])
    assert score_events(episode(), prof).loc[2, "f_novel"] < score_events(episode(), PrevalenceProfile()).loc[2, "f_novel"]


def test_online_matches_capacity_uses_only_past_and_ignores_labels():
    from src.evictguard_online import select_evictguard_online
    base = episode()
    a = select_evictguard_online(base, 3)
    assert len(a.selected) <= 3
    marked = base.assign(gt_tier="core", gt_label="attack", is_synthetic=True, noise_type="x", dup_of="r0")
    assert a.selected.record_id.tolist() == select_evictguard_online(marked, 3).selected.record_id.tolist()
    # causality: with enough memory for everything, every distinct action is retained regardless of order
    full = select_evictguard_online(base, 100)
    assert len(full.selected) == len(set(action_keys(base)))


def test_context_assembly_groups_by_process_with_pointers():
    from src.context import assemble_context, render_text
    sel = select_evictguard_v2(episode(), 5).selected
    ctx = assemble_context(sel, candidates_total=25, capacity=5)
    assert ctx["budget"]["retained"] == len(sel) and ctx["entities"]
    refs = {it["record_id"] for e in ctx["entities"] for it in e["top_evidence"]}
    assert refs <= set(sel.record_id)
    assert "ref r" in render_text(ctx)


def test_baselines_respect_capacity_and_ignore_labels():
    from src.baselines import select_nodoze, select_rare_action, select_recency_dedup
    base = episode()
    marked = base.assign(gt_tier="core", gt_label="attack", is_synthetic=True)
    for fn in (select_recency_dedup, select_rare_action, select_nodoze):
        a, b = fn(base, 4), fn(marked, 4)
        assert len(a.selected) <= 4 and a.selected.record_id.tolist() == b.selected.record_id.tolist()
