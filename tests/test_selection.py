import json
import sqlite3

import pandas as pd
from src.evaluate import run_comparison
from src.ingest import ingest
from src.ledger import get_evidence, get_status_history, register_evidence
from src.selection import extract_features, score_evidence, select_evictguard, select_fifo, select_random


def test_features_scoring_are_normalized_and_ignore_labels():
    frame = pd.DataFrame([
        {"record_id": "a", "content_hash": "h1", "event_type": "common", "host": "h", "label": "attack"},
        {"record_id": "b", "content_hash": "h2", "event_type": "common", "host": "h", "label": "benign"},
        {"record_id": "c", "content_hash": "h3", "event_type": "rare", "host": "other", "label": "unknown"},
    ])
    scored, unavailable = score_evidence(frame)
    assert scored.retention_score.between(0, 1).all()
    assert scored.loc[scored.record_id == "c", "feature_rarity"].iloc[0] > scored.loc[scored.record_id == "a", "feature_rarity"].iloc[0]
    assert unavailable["asset_sensitivity"] and unavailable["attack_stage_relevance"]
    changed_labels = frame.assign(label=["x", "x", "x"])
    changed, _ = score_evidence(changed_labels)
    assert scored.retention_score.tolist() == changed.retention_score.tolist()
    features, _ = extract_features(frame)
    assert features.feature_corroboration.between(0, 1).all()


def test_duplicate_representative_protection_and_capacity_are_deterministic():
    frame = pd.DataFrame([
        {"record_id": "original", "content_hash": "same", "event_type": "process", "host": "h", "timestamp": "2025-01-01", "is_synthetic": False},
        {"record_id": "copy", "content_hash": "same", "event_type": "process", "host": "h", "timestamp": "2025-01-01", "is_synthetic": True, "noise_type": "duplicate-flooding", "source_record_id": "original"},
        {"record_id": "rare", "content_hash": "unique", "event_type": "rare", "host": "x", "timestamp": "2025-01-02", "is_synthetic": False},
        {"record_id": "other", "content_hash": "other", "event_type": "other", "host": "y", "timestamp": "2025-01-03", "is_synthetic": False},
    ])
    first = select_evictguard(frame, 2, seed=4, protected_fraction=0.5)
    second = select_evictguard(frame, 2, seed=4, protected_fraction=0.5)
    assert len(first.selected) == 2 and first.selected.record_id.tolist() == second.selected.record_id.tolist()
    assert "original" in first.selected.record_id.tolist() and "copy" in first.redundant_ids
    assert len(first.protected_ids) == 1 and len(first.evicted_ids) == 1
    assert len(select_evictguard(frame, 0).selected) == 0


def test_identical_source_hashes_are_not_collapsed_without_duplicate_provenance():
    frame = pd.DataFrame([
        {"record_id": "source-a", "content_hash": "same-hash", "event_type": "10", "host": "host-a", "is_synthetic": False},
        {"record_id": "source-b", "content_hash": "same-hash", "event_type": "10", "host": "host-a", "is_synthetic": False},
    ])
    result = select_evictguard(frame, 2)
    assert len(result.selected) == 2
    assert result.redundant_ids == ()


def test_baselines_respect_capacity_and_seed():
    frame = pd.DataFrame([{"record_id": str(i), "timestamp": f"2025-01-01T00:00:0{i}Z"} for i in range(5)])
    assert select_fifo(frame, 2).selected.record_id.tolist() == ["4", "3"]
    a = select_random(frame, 3, seed=9).selected.record_id.tolist()
    b = select_random(frame, 3, seed=9).selected.record_id.tolist()
    assert a == b and len(a) == 3


def test_actual_comparison_updates_ledger_without_deleting_phase1_rows(tmp_path):
    source = tmp_path / "source.jsonl"
    source.write_text('\n'.join(json.dumps(x) for x in [
        {"@timestamp": "2025-01-01T00:00:00Z", "host": "host-a", "EventID": 1, "msg": "one"},
        {"@timestamp": "2025-01-01T00:01:00Z", "host": "host-a", "EventID": 2, "msg": "two"},
    ]), encoding="utf-8")
    db = tmp_path / "events.sqlite"
    ingest(source, db)
    with sqlite3.connect(db) as con:
        rows = con.execute("SELECT record_id,original_json FROM events ORDER BY source_index").fetchall()
    episode = tmp_path / "episode.csv"
    frame = pd.DataFrame([
        {"record_id": record_id, "original_json": raw, "timestamp": json.loads(raw).get("@timestamp"), "host": "host-a", "event_type": json.loads(raw).get("EventID"), "source_path": "fixture"}
        for record_id, raw in rows
    ])
    frame.to_csv(episode, index=False)
    with sqlite3.connect(db) as con:
        source_snapshot = con.execute("SELECT record_id,content_hash,original_json FROM events ORDER BY source_index").fetchall()
    before = len(source_snapshot)
    result = run_comparison(db, episode, tmp_path / "comparison.json", capacity=1, seed=3, noise_type="duplicate-flooding", noise_proportion=0.5)
    with sqlite3.connect(db) as con:
        first_phase3_ids = {row[0] for row in con.execute("SELECT evidence_id FROM evidence_ledger WHERE evidence_id LIKE 'phase3:%'")}
    repeated = run_comparison(db, episode, tmp_path / "comparison_repeat.json", capacity=1, seed=3, noise_type="duplicate-flooding", noise_proportion=0.5)
    with sqlite3.connect(db) as con:
        repeated_phase3_ids = {row[0] for row in con.execute("SELECT evidence_id FROM evidence_ledger WHERE evidence_id LIKE 'phase3:%'")}
    changed_frame = frame.copy()
    changed_record = json.loads(changed_frame.loc[0, "original_json"])
    changed_record["msg"] = "different experiment content"
    changed_frame.loc[0, "original_json"] = json.dumps(changed_record)
    changed_episode = tmp_path / "episode_changed.csv"
    changed_frame.to_csv(changed_episode, index=False)
    changed = run_comparison(db, changed_episode, tmp_path / "comparison_changed.json", capacity=1, seed=3, noise_type="duplicate-flooding", noise_proportion=0.5)
    with sqlite3.connect(db) as con:
        changed_phase3_ids = {row[0] for row in con.execute("SELECT evidence_id FROM evidence_ledger WHERE evidence_id LIKE 'phase3:%'")}
    with sqlite3.connect(db) as con:
        after_snapshot = con.execute("SELECT record_id,content_hash,original_json FROM events ORDER BY source_index").fetchall()
    after = len(after_snapshot)
    assert before == after == 2
    assert source_snapshot == after_snapshot
    assert first_phase3_ids == repeated_phase3_ids
    assert changed_phase3_ids - repeated_phase3_ids
    assert result["input_records"] == repeated["input_records"] == changed["input_records"]
    metrics = {row["method"]: row for row in result["methods"]}
    assert all(metrics[name]["selected_records"] <= 1 for name in ("evictguard", "fifo", "random"))
    assert metrics["evictguard"]["duplicate_reduction_rows"] >= 1
    assert metrics["evictguard"]["duplicate_rows_in_input"] == 1
    ledger_rows = [register_evidence(db, source_dataset="fixture", origin_type="original", source_record_id=row[0]) for row in rows]
    statuses = [get_evidence(db, row["evidence_id"])["retention_status"] for row in ledger_rows]
    assert "protected" in statuses and "evicted" in statuses
    protected_id = next(row["evidence_id"] for row in ledger_rows if get_evidence(db, row["evidence_id"])["retention_status"] == "protected")
    assert len(get_status_history(db, protected_id)) >= 2
    assert all(item["critical_evidence_retention"] is None for item in metrics.values())
