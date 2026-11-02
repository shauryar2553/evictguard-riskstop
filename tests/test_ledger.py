import json
import sqlite3

import pytest

from src.ingest import ingest
from src.ledger import (
    export_report,
    get_evidence,
    get_status_history,
    initialize,
    list_evidence,
    register_evidence,
    update_retention_status,
    verify_content_hash,
)
from src.utils import content_hash


@pytest.fixture
def setup_db(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text('\n'.join(json.dumps(x) for x in [
        {"@timestamp": "2025-01-01T00:00:00Z", "host": "host-a", "EventID": 1, "msg": "one"},
        {"@timestamp": "2025-01-01T00:01:00Z", "host": "host-a", "EventID": 2, "msg": "two"},
    ]), encoding="utf-8")
    db = tmp_path / "events.sqlite"
    ingest(source, db)
    con = sqlite3.connect(db)
    source_rows = con.execute("SELECT record_id,original_json FROM events ORDER BY source_index").fetchall()
    con.close()
    return db, source_rows


def test_register_retrieve_hash_and_idempotent_source(setup_db):
    db, rows = setup_db
    first = register_evidence(db, source_dataset="fixture", origin_type="original", source_record_id=rows[0][0])
    again = register_evidence(db, source_dataset="fixture", origin_type="original", source_record_id=rows[0][0])
    assert first["evidence_id"] == again["evidence_id"]
    assert first["content_hash"] == content_hash(json.loads(rows[0][1]))
    assert get_evidence(db, first["evidence_id"])["source_record_id"] == rows[0][0]


def test_hash_verification_and_provenance_links(setup_db):
    db, rows = setup_db
    source_id = rows[0][0]
    original = register_evidence(db, source_dataset="fixture", origin_type="original", source_record_id=source_id)
    original_record = json.loads(rows[0][1])
    assert verify_content_hash(db, original["evidence_id"])["matches"]
    modified = dict(original_record, msg="tampered")
    assert not verify_content_hash(db, original["evidence_id"], modified)["matches"]
    duplicate = register_evidence(db, source_dataset="fixture", origin_type="derived", parent_evidence_id=original["evidence_id"], content=original_record)
    synthetic = register_evidence(db, source_dataset="fixture synthetic", origin_type="synthetic", content={"event_type": "synthetic", "is_synthetic": True})
    assert duplicate["parent_evidence_id"] == original["evidence_id"]
    assert duplicate["content_hash"] == original["content_hash"] and duplicate["evidence_id"] != original["evidence_id"]
    assert synthetic["origin_type"] == "synthetic" and synthetic["source_record_id"] is None
    assert get_evidence(db, duplicate["evidence_id"])["record_json"] == json.dumps(original_record, sort_keys=True, separators=(",", ":"))


def test_explicit_id_is_idempotent_but_rejects_content_or_provenance_reuse(setup_db):
    db, rows = setup_db
    first_parent = register_evidence(db, source_dataset="fixture", origin_type="original", source_record_id=rows[0][0])
    second_parent = register_evidence(db, source_dataset="fixture", origin_type="original", source_record_id=rows[1][0])
    content = {"event_type": "derived-copy", "value": 7}
    item = register_evidence(db, source_dataset="experiment-a", origin_type="derived", content=content, parent_evidence_id=first_parent["evidence_id"], evidence_id="fixed-evidence-id")
    repeated = register_evidence(db, source_dataset="experiment-a", origin_type="derived", content=content, parent_evidence_id=first_parent["evidence_id"], evidence_id="fixed-evidence-id")
    assert item["evidence_id"] == repeated["evidence_id"]
    with pytest.raises(ValueError, match="different content or provenance"):
        register_evidence(db, source_dataset="experiment-a", origin_type="derived", content=content, parent_evidence_id=second_parent["evidence_id"], evidence_id="fixed-evidence-id")
    with pytest.raises(ValueError, match="different content or provenance"):
        register_evidence(db, source_dataset="experiment-b", origin_type="derived", content=content, parent_evidence_id=first_parent["evidence_id"], evidence_id="fixed-evidence-id")
    with pytest.raises(ValueError, match="different content or provenance"):
        register_evidence(db, source_dataset="experiment-a", origin_type="derived", content={"event_type": "changed"}, parent_evidence_id=first_parent["evidence_id"], evidence_id="fixed-evidence-id")


def test_status_validation_history_and_source_preservation(setup_db):
    db, rows = setup_db
    original = register_evidence(db, source_dataset="fixture", origin_type="original", source_record_id=rows[0][0])
    before = sqlite3.connect(db).execute("SELECT COUNT(*) FROM events").fetchone()[0]
    update_retention_status(db, original["evidence_id"], "evicted", "test active-set eviction")
    assert get_evidence(db, original["evidence_id"])["retention_status"] == "evicted"
    history = get_status_history(db, original["evidence_id"])
    assert [(x["previous_status"], x["new_status"]) for x in history] == [(None, "available"), ("available", "evicted")]
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM events").fetchone()[0] == before
    with pytest.raises(ValueError, match="status must"):
        update_retention_status(db, original["evidence_id"], "deleted", "invalid")


def test_filter_export_and_missing_optional_fields(setup_db, tmp_path):
    db, rows = setup_db
    item = register_evidence(db, source_dataset="fixture", origin_type="original", source_record_id=rows[0][0])
    assert item["event_type"] == "1"
    assert len(list_evidence(db, {"host": "host-a"})) == 1
    output = tmp_path / "ledger.json"
    assert export_report(db, output) == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report[0]["evidence_id"] == item["evidence_id"] and json.loads(report[0]["record_json"])["msg"] == "one"
    initialize(db)
    with pytest.raises(ValueError, match="Unsupported evidence filter"):
        list_evidence(db, {"bad_column": "x"})
