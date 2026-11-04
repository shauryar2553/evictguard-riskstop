import json

import pandas as pd
import pytest

from src.compose_episodes import splice, stable_split
from src.label import adversary_roots, label_recording
from src.noise import inject_noise
from src.run_benchmark import evaluate_selection, gold_verdict
from src.sigma_engine import SigmaRule, _Condition, evaluate

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def rule(detection, condition, level="high", category=("microsoft-windows-sysmon/operational", {1})):
    return SigmaRule("r1", "test rule", level, "test", "x.yml", ["attack.execution", "attack.t1059.001"], category[0], category[1], detection, condition)


def events():
    return pd.DataFrame([
        {"Channel": SYSMON, "EventID": 1, "Hostname": "WS1.lab.local", "@timestamp": "2020-01-01T00:00:00Z", "ProcessGuid": "{A}", "ParentProcessGuid": "{P}",
         "ProcessId": 10, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell -nop -w hidden -enc AAAA"},
        {"Channel": SYSMON, "EventID": 1, "Hostname": "WS1.lab.local", "@timestamp": "2020-01-01T00:00:01Z", "ProcessGuid": "{B}", "ParentProcessGuid": "{A}",
         "ProcessId": 11, "Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami"},
        {"Channel": SYSMON, "EventID": 3, "Hostname": "WS1.lab.local", "@timestamp": "2020-01-01T00:00:02Z", "ProcessGuid": "{B}", "ProcessId": 11,
         "Image": "C:\\Windows\\System32\\whoami.exe", "DestinationIp": "10.0.0.5"},
        {"Channel": SYSMON, "EventID": 1, "Hostname": "WS1.lab.local", "@timestamp": "2020-01-01T00:00:03Z", "ProcessGuid": "{C}", "ParentProcessGuid": "{X}",
         "ProcessId": 12, "Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad"},
    ])


def test_sigma_modifiers_and_conditions():
    r = rule({"selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains|all": ["-nop", "-enc"]},
              "filter": {"CommandLine|contains": "benign"}}, "selection and not filter")
    hits, skips = evaluate(events(), [r])
    assert hits.row.tolist() == [0] and not skips
    windash = rule({"sel": {"CommandLine|contains|windash": "-enc"}}, "1 of sel*")
    frame = events().assign(CommandLine=["powershell /enc AAAA", "x", None, "y"])
    assert evaluate(frame, [windash])[0].row.tolist() == [0]
    cidr = rule({"sel": {"DestinationIp|cidr": "10.0.0.0/8"}}, "all of them", category=("microsoft-windows-sysmon/operational", {3}))
    assert evaluate(events(), [cidr])[0].row.tolist() == [2]
    assert rule({}, "x").techniques == ["T1059.001"] and rule({}, "x").tactics == ["execution"]


def test_condition_parser_precedence():
    idents = {"a": pd.Series([True, False]), "b": pd.Series([False, False]), "c": pd.Series([True, True])}
    assert _Condition("a or b and not c", idents).parse().tolist() == [True, False]
    assert _Condition("(a or b) and c", idents).parse().tolist() == [True, False]


def test_label_tiers_and_causal_expansion():
    r = rule({"selection": {"CommandLine|contains": "-enc"}}, "selection")
    std, summary = label_recording(events(), "rec", {"_techniques": "T1059.001"}, [r])
    tiers = dict(zip(std.source_index, std.gt_tier))
    assert tiers == {0: "core", 1: "supporting", 2: "supporting", 3: "background"}
    assert summary["technique_agreement"] is True and summary["label_status"] == "labelled"
    assert std.loc[std.source_index == 1, "label_source"].iloc[0].startswith("ancestry:")
    assert set(std.host) == {"ws1"}


def test_adversary_view_roots_parse_and_make_unrelated_hits_ambiguous():
    view = "A7BWPR32 ps 172.18.39.5     WS1      *LAB\\user      powershell         10    5/0.0    2020-09-18 17:07:59  http\n"
    meta = {"simulation": {"adversary_view": view}, "_techniques": ""}
    assert adversary_roots(meta) == [{"machine": "ws1", "process": "powershell.exe", "pid": 10}]
    notepad_rule = rule({"selection": {"Image|endswith": "\\notepad.exe"}}, "selection", level="medium")
    std, summary = label_recording(events(), "rec", meta, [notepad_rule])
    assert summary["adversary_view_roots_resolved"] == 1
    assert std.set_index("source_index").gt_tier.to_dict() == {0: "supporting", 1: "supporting", 2: "supporting", 3: "ambiguous"}


def labelled_episode():
    rows = []
    for i in range(20):
        tier = "core" if i < 2 else "supporting" if i < 5 else "background"
        rows.append({"record_id": f"e{i}", "timestamp": f"2020-01-01T00:00:{i:02d}Z", "host": "ws1", "event_type": "1", "source": "sysmon",
                     "gt_tier": tier, "gt_label": "attack" if tier != "background" else "benign", "original_json": json.dumps({"n": i}), "content_hash": f"h{i}"})
    return pd.DataFrame(rows)


@pytest.mark.parametrize("kind", ["background-flood", "mimic-flood"])
def test_floods_are_benign_by_construction(kind):
    noisy, manifest = inject_noise(labelled_episode(), kind, 1.0, 3)
    injected = noisy[noisy.noise_type == kind]
    assert len(injected) == 20 and injected.gt_label.eq("benign").all() and injected.gt_tier.eq("injected_noise").all()
    assert injected.content_hash.nunique() == 20 and manifest["output_attack_records"] == 5
    assert set(injected.source_record_id) <= {f"e{i}" for i in range(5, 20)}  # floods copy benign events only


def test_duplicates_inherit_labels_and_missing_critical_records_removals():
    noisy, _ = inject_noise(labelled_episode(), "duplicate-flooding", 1.0, 1)
    dups = noisy[noisy.noise_type == "duplicate-flooding"]
    parents = labelled_episode().set_index("record_id").gt_tier
    assert (dups.gt_tier.values == parents.loc[dups.dup_of].values).all()
    removed, manifest = inject_noise(labelled_episode(), "missing-critical", 0.4, 1)
    assert len(manifest["removed_attack_record_ids"]) == 2 and manifest["output_attack_records"] == 3


def test_selection_metrics_count_duplicates_for_parent_and_gold_defer():
    noisy, _ = inject_noise(labelled_episode(), "duplicate-flooding", 1.0, 1)
    dup_of_core = noisy[(noisy.noise_type == "duplicate-flooding") & (noisy.gt_tier == "core")].head(1)
    metrics = evaluate_selection(noisy, dup_of_core)
    assert metrics["core_recall"] == 0.5 and metrics["noise_share"] == 1.0
    assert gold_verdict("ATTACK", 4, 2) == "ATTACK" and gold_verdict("ATTACK", 4, 1) == "DEFER" and gold_verdict("BENIGN", 0, 0) == "BENIGN"


def test_splice_shifts_time_rewrites_hosts_and_keeps_labels():
    import numpy as np
    bg = pd.DataFrame({"record_id": ["b1", "b2"], "timestamp": pd.to_datetime(["2022-07-15T10:00:00Z", "2022-07-15T11:00:00Z"]), "host": ["h1", "h1"],
                       "event_id": [1, 1], "channel": ["sysmon"] * 2, "gt_tier": ["background"] * 2, "gt_label": ["benign"] * 2, "original_json": ["{}", "{}"]})
    atk = pd.DataFrame({"record_id": ["a1"], "timestamp": pd.to_datetime(["2020-01-01T00:00:00Z"]), "host": ["ws1"], "event_id": [1], "channel": ["sysmon"],
                        "gt_tier": ["core"], "gt_label": ["attack"], "original_json": [json.dumps({"Hostname": "WS1.lab.local"})]})
    ep = splice(bg, [("rec", atk)], "ep", np.random.default_rng(0))
    attack_row = ep[ep.origin == "attack"].iloc[0]
    assert attack_row.host == "h1" and json.loads(attack_row.original_json)["Hostname"] == "h1" and attack_row.gt_tier == "core"
    assert "2022-07-15T10:00:00Z" <= attack_row.timestamp <= "2022-07-15T11:00:00Z" and ep.record_id.is_unique
    assert stable_split("T1059") == stable_split("T1059") and stable_split("x") in {"train", "val", "test"}


def test_balanced_split_keeps_groups_whole_and_near_target():
    from src.compose_episodes import balanced_split
    groups = pd.Series(["A"] * 16 + ["B"] * 15 + ["C"] * 12 + ["D"] * 10 + [f"g{i}" for i in range(47)])
    mapping = balanced_split(groups)
    counts = groups.map(mapping).value_counts()
    assert set(mapping.values()) == {"train", "val", "test"}
    assert abs(counts["train"] - 60) <= 3 and abs(counts["val"] - 20) <= 3 and abs(counts["test"] - 20) <= 3
    assert mapping == balanced_split(groups)


def test_zip_loader_skips_macos_resource_forks(tmp_path):
    import zipfile
    from src.utils import load_records
    archive = tmp_path / "x.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("__MACOSX/._data.json", b"\x00\x05\x16\x07\xff\xb4")
        z.writestr("data.json", '{"EventID": 1}\n{"EventID": 3}\n')
    assert [r["EventID"] for r in load_records(archive)] == [1, 3]


def test_outside_tree_medium_hit_is_core_only_with_matching_technique():
    view = "A7BWPR32 ps 172.18.39.5     WS1      *LAB\\user      powershell         10    5/0.0    2020-09-18 17:07:59  http\n"
    notepad_rule = rule({"selection": {"Image|endswith": "\\notepad.exe"}}, "selection", level="medium")  # tagged T1059.001
    std, _ = label_recording(events(), "rec", {"simulation": {"adversary_view": view}, "_techniques": "T1059.003"}, [notepad_rule])
    row = std.set_index("source_index").loc[3]
    assert row.gt_tier == "core" and row.label_source.startswith("sigma_technique_match:")
    std, _ = label_recording(events(), "rec", {"simulation": {"adversary_view": view}, "_techniques": "T1003"}, [notepad_rule])
    assert std.set_index("source_index").loc[3].gt_tier == "ambiguous"


def test_atlas_cumulative_exports_are_deduplicated_and_split_by_day(tmp_path):
    from src.atlas_adapter import rebuild_daily_segments
    from src.label import standardize
    def export(days):
        recs = [{"Channel": SYSMON, "EventID": 1, "Hostname": "h1", "RecordNumber": str(i), "@timestamp": f"2022-07-{15 + d}T10:00:0{i % 10}Z"}
                for d in range(days) for i in range(d * 10, d * 10 + 3)]
        std = standardize(pd.DataFrame(recs), "x")
        std["segment_group"], std["gt_tier"], std["gt_label"] = "x", "background", "benign"
        return std
    (tmp_path / "benign").mkdir()
    export(1).to_parquet(tmp_path / "benign" / "sysmon-1.parquet")
    export(2).to_parquet(tmp_path / "benign" / "sysmon-2.parquet")  # cumulative: contains day 1 again
    written = rebuild_daily_segments(tmp_path)
    frames = {p.stem: pd.read_parquet(p) for p in written}
    assert sorted(frames) == ["h1-2022-07-15", "h1-2022-07-16"]
    assert all(len(f) == 3 and f.record_id.is_unique for f in frames.values())
    assert not (tmp_path / "benign" / "sysmon-1.parquet").exists()
