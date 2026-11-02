"""SQLite evidence ledger referencing Phase 1 events without copying them."""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .utils import canonical_json, content_hash

ORIGIN_TYPES = {"original", "synthetic", "derived"}
RETENTION_STATUSES = {"available", "protected", "redundant", "evicted"}
FILTER_COLUMNS = {
    "source_record_id", "source_dataset", "content_hash", "origin_type",
    "parent_evidence_id", "timestamp", "event_type", "host", "retention_status",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _connect(database: str | Path):
    path = Path(database)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        with con:
            yield con
    finally:
        con.close()


def initialize(database: str | Path) -> None:
    """Create ledger tables in the existing Phase 1 database."""
    with _connect(database) as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS evidence_ledger (
            evidence_id TEXT PRIMARY KEY,
            source_record_id TEXT UNIQUE REFERENCES events(record_id),
            source_dataset TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            origin_type TEXT NOT NULL CHECK(origin_type IN ('original','synthetic','derived')),
            parent_evidence_id TEXT REFERENCES evidence_ledger(evidence_id),
            timestamp TEXT,
            event_type TEXT,
            host TEXT,
            retention_status TEXT NOT NULL CHECK(retention_status IN ('available','protected','redundant','evicted')),
            content_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ledger_status ON evidence_ledger(retention_status);
        CREATE INDEX IF NOT EXISTS idx_ledger_hash ON evidence_ledger(content_hash);
        CREATE INDEX IF NOT EXISTS idx_ledger_host ON evidence_ledger(host);
        CREATE TABLE IF NOT EXISTS evidence_status_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT NOT NULL REFERENCES evidence_ledger(evidence_id),
            previous_status TEXT,
            new_status TEXT NOT NULL,
            changed_at TEXT NOT NULL,
            reason TEXT NOT NULL
        );
        """)


def register_evidence(
    database: str | Path,
    *,
    source_dataset: str,
    origin_type: str,
    source_record_id: str | None = None,
    content: dict[str, Any] | None = None,
    parent_evidence_id: str | None = None,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    """Register one item; source events are referenced, generated content stored inline.

    Registering a Phase 1 source ID again returns its existing ledger record.
    Hash equality never merges evidence records.
    """
    if origin_type not in ORIGIN_TYPES:
        raise ValueError(f"origin_type must be one of {sorted(ORIGIN_TYPES)}")
    if not source_dataset.strip():
        raise ValueError("source_dataset must not be empty")
    if source_record_id is None and content is None:
        raise ValueError("Provide source_record_id or content")
    initialize(database)
    with _connect(database) as con:
        if source_record_id:
            existing = con.execute("SELECT * FROM evidence_ledger WHERE source_record_id=?", (source_record_id,)).fetchone()
            if existing:
                return dict(existing)
            source = con.execute("SELECT * FROM events WHERE record_id=?", (source_record_id,)).fetchone()
            if source is None:
                raise ValueError(f"Phase 1 source record does not exist: {source_record_id}")
            if origin_type == "original":
                content = json.loads(source["original_json"])
            source_path = source["source_path"]
            timestamp = source["timestamp"]
            event_type = source["event_type"]
            host = source["host"]
        else:
            source_path = source_dataset
            timestamp = (content or {}).get("timestamp", (content or {}).get("@timestamp"))
            event_type = (content or {}).get("event_type", (content or {}).get("EventType"))
            host = (content or {}).get("host", (content or {}).get("Hostname"))
        if parent_evidence_id and not con.execute("SELECT 1 FROM evidence_ledger WHERE evidence_id=?", (parent_evidence_id,)).fetchone():
            raise ValueError(f"Parent evidence does not exist: {parent_evidence_id}")
        if origin_type == "original" and source_record_id is None:
            raise ValueError("Original evidence must reference a Phase 1 source_record_id")
        if origin_type in {"synthetic", "derived"} and content is None:
            raise ValueError(f"{origin_type} evidence requires content")
        now = _now()
        event_json = canonical_json(content) if content is not None and source_record_id is None else None
        event_hash = content_hash(content) if content is not None else str(source["content_hash"])
        identifier = evidence_id or uuid.uuid4().hex
        existing_id = con.execute("SELECT * FROM evidence_ledger WHERE evidence_id=?", (identifier,)).fetchone()
        if existing_id:
            same_content = existing_id["content_hash"] == event_hash
            same_provenance = (
                existing_id["origin_type"] == origin_type
                and existing_id["source_record_id"] == source_record_id
                and existing_id["source_dataset"] == source_dataset
                and existing_id["parent_evidence_id"] == parent_evidence_id
            )
            if not same_content or not same_provenance:
                raise ValueError(f"Evidence ID already exists with different content or provenance: {identifier}")
            return dict(existing_id)
        con.execute("""INSERT INTO evidence_ledger
            (evidence_id,source_record_id,source_dataset,content_hash,origin_type,parent_evidence_id,
             timestamp,event_type,host,retention_status,content_json,created_at,updated_at)
             VALUES(?,?,?,?,?,?,?,?,?,'available',?,?,?)""",
             (identifier, source_record_id, source_dataset, event_hash, origin_type, parent_evidence_id,
              timestamp, event_type, host, event_json, now, now))
        con.execute("INSERT INTO evidence_status_history(evidence_id,previous_status,new_status,changed_at,reason) VALUES(?,NULL,'available',?,?)", (identifier, now, "Evidence registered"))
        return dict(con.execute("SELECT * FROM evidence_ledger WHERE evidence_id=?", (identifier,)).fetchone())


def get_evidence(database: str | Path, evidence_id: str) -> dict[str, Any] | None:
    """Retrieve an evidence record and its source JSON when available."""
    initialize(database)
    with _connect(database) as con:
        row = con.execute("""SELECT l.*, COALESCE(l.content_json,e.original_json) AS record_json
            FROM evidence_ledger l LEFT JOIN events e ON e.record_id=l.source_record_id
            WHERE l.evidence_id=?""", (evidence_id,)).fetchone()
        return dict(row) if row else None


def list_evidence(database: str | Path, filters: dict[str, Any] | None = None, limit: int = 1000) -> list[dict[str, Any]]:
    """List ledger entries using a whitelist of parameterized equality filters."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    initialize(database)
    filters = filters or {}
    invalid = set(filters) - FILTER_COLUMNS
    if invalid:
        raise ValueError(f"Unsupported evidence filter(s): {', '.join(sorted(invalid))}")
    clauses = []
    values: list[Any] = []
    for field, value in filters.items():
        clauses.append(f"{field} = ?")
        values.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with _connect(database) as con:
        rows = con.execute("SELECT * FROM evidence_ledger" + where + " ORDER BY created_at,evidence_id LIMIT ?", (*values, limit)).fetchall()
        return [dict(row) for row in rows]


def verify_content_hash(database: str | Path, evidence_id: str, modified_content: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recompute ledger content's hash, optionally against supplied content."""
    item = get_evidence(database, evidence_id)
    if item is None:
        raise ValueError(f"Evidence does not exist: {evidence_id}")
    if modified_content is not None:
        computed = content_hash(modified_content)
    else:
        raw = item["record_json"]
        if raw is None:
            raise ValueError("Evidence has no retrievable content to verify")
        computed = content_hash(json.loads(raw))
    return {"evidence_id": evidence_id, "expected_hash": item["content_hash"], "computed_hash": computed, "matches": computed == item["content_hash"]}


def update_retention_status(database: str | Path, evidence_id: str, status: str, reason: str) -> dict[str, Any]:
    """Change active investigation status and record the transition."""
    if status not in RETENTION_STATUSES:
        raise ValueError(f"status must be one of {sorted(RETENTION_STATUSES)}")
    if not reason.strip():
        raise ValueError("A non-empty reason is required for status changes")
    initialize(database)
    with _connect(database) as con:
        current = con.execute("SELECT retention_status FROM evidence_ledger WHERE evidence_id=?", (evidence_id,)).fetchone()
        if current is None:
            raise ValueError(f"Evidence does not exist: {evidence_id}")
        old = current[0]
        if old == status:
            return dict(con.execute("SELECT * FROM evidence_ledger WHERE evidence_id=?", (evidence_id,)).fetchone())
        now = _now()
        con.execute("UPDATE evidence_ledger SET retention_status=?,updated_at=? WHERE evidence_id=?", (status, now, evidence_id))
        con.execute("INSERT INTO evidence_status_history(evidence_id,previous_status,new_status,changed_at,reason) VALUES(?,?,?,?,?)", (evidence_id, old, status, now, reason))
        return dict(con.execute("SELECT * FROM evidence_ledger WHERE evidence_id=?", (evidence_id,)).fetchone())


def get_status_history(database: str | Path, evidence_id: str) -> list[dict[str, Any]]:
    initialize(database)
    with _connect(database) as con:
        return [dict(row) for row in con.execute("SELECT * FROM evidence_status_history WHERE evidence_id=? ORDER BY history_id", (evidence_id,))]


def export_report(database: str | Path, output: str | Path, filters: dict[str, Any] | None = None) -> int:
    """Export ledger entries as JSON or CSV, including referenced event content."""
    rows = list_evidence(database, filters, limit=1_000_000)
    for row in rows:
        row["record_json"] = get_evidence(database, row["evidence_id"])["record_json"]
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.suffix.lower() == ".json":
        target.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    elif target.suffix.lower() == ".csv":
        with target.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["evidence_id"])
            writer.writeheader()
            writer.writerows(rows)
    else:
        raise ValueError("Report output must end in .csv or .json")
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Register a small Phase 1 sample in the evidence ledger.")
    parser.add_argument("--database", default="database/evictguard.sqlite")
    parser.add_argument("--episode", default="data/episodes/demo_episode.csv")
    parser.add_argument("--output", default="results/evidence_ledger_report.json")
    args = parser.parse_args()
    import pandas as pd
    with _connect(args.database) as con:
        phase1_count_before = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    initialize(args.database)
    frame = pd.read_csv(args.episode).head(5)
    originals = []
    for row in frame.to_dict(orient="records"):
        item = register_evidence(args.database, source_dataset="OTRF DCOM host archive", origin_type="original", source_record_id=row["record_id"])
        originals.append(item)
    parent = originals[0]
    source_content = json.loads(get_evidence(args.database, parent["evidence_id"])["record_json"])
    synthetic_content = {"timestamp": "2020-09-18T17:08:00Z", "host": "LAB-SYNTHETIC", "event_type": "synthetic_background_activity", "label": None, "is_synthetic": True}
    synthetic = register_evidence(args.database, source_dataset="Phase 1 demonstration", origin_type="synthetic", content=synthetic_content, evidence_id="phase2-demo-synthetic")
    duplicate = register_evidence(args.database, source_dataset="Phase 1 demonstration", origin_type="derived", content=source_content, parent_evidence_id=parent["evidence_id"], evidence_id=f"phase2-demo-copy-{parent['evidence_id']}")
    update_retention_status(args.database, originals[-1]["evidence_id"], "protected", "Demonstrate audited status transition")
    for item in [*originals, synthetic, duplicate]:
        verified = verify_content_hash(args.database, item["evidence_id"])
        print(json.dumps({"evidence_id": item["evidence_id"], "origin_type": item["origin_type"], "source_record_id": item["source_record_id"], "parent_evidence_id": item["parent_evidence_id"], "retention_status": get_evidence(args.database, item["evidence_id"])["retention_status"], "hash_matches": verified["matches"]}))
    print("Audit history:", json.dumps(get_status_history(args.database, originals[-1]["evidence_id"]), indent=2))
    print(f"Exported {export_report(args.database, args.output)} evidence records to {args.output}")
    with _connect(args.database) as con:
        phase1_count_after = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"Phase 1 source events unchanged: {phase1_count_before} before, {phase1_count_after} after")


if __name__ == "__main__":
    main()
