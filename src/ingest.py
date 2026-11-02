"""Traceable JSON/JSONL/CSV to SQLite ingestion."""
from __future__ import annotations
import argparse, json, logging, sqlite3
from pathlib import Path
from typing import Any
from .utils import content_hash, first, load_records

LOG=logging.getLogger("evictguard.ingest")
FIELDS={"timestamp":("@timestamp","timestamp","timecreated","datetime","time"),"host":("computer","hostname","host","host_name"),"user":("user","username","subjectusername","accountname"),"event_type":("eventid","event_id","eventtype","event_type","channel"),"source":("source","providername","provider","channel"),"label":("label","ground_truth","attack_label","class")}

def ingest(source: str|Path, database: str|Path, *, allow_reingest: bool=False, deduplicate: bool=False) -> dict[str,Any]:
    source,database=Path(source),Path(database)
    records=load_records(source); database.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(database)
    con.execute("CREATE TABLE IF NOT EXISTS sources (source_path TEXT PRIMARY KEY, source_sha256 TEXT NOT NULL, record_count INTEGER NOT NULL)")
    con.execute("""CREATE TABLE IF NOT EXISTS events (record_id TEXT PRIMARY KEY, source_path TEXT NOT NULL, source_index INTEGER NOT NULL,
        content_hash TEXT NOT NULL, original_json TEXT NOT NULL, timestamp TEXT, host TEXT, user TEXT, event_type TEXT, source TEXT, label TEXT,
        is_synthetic INTEGER NOT NULL DEFAULT 0, noise_type TEXT, source_record_id TEXT)""")
    source_key=str(source.resolve()); source_hash=content_hash(source.read_bytes().hex())
    exists=con.execute("SELECT source_sha256 FROM sources WHERE source_path=?",(source_key,)).fetchone()
    if exists and not allow_reingest:
        con.close(); raise ValueError(f"Source already ingested ({source_key}); use --allow-reingest to replace its records")
    if exists:
        con.execute("DELETE FROM events WHERE source_path=?",(source_key,)); con.execute("DELETE FROM sources WHERE source_path=?",(source_key,))
    seen=set(); exact_dupes=0; rejected=0; stored=0
    for index,record in enumerate(records):
        if "__parse_error__" in record: rejected+=1; LOG.warning("Rejected source record %d: %s",index,record["__parse_error__"]); continue
        digest=content_hash(record)
        is_duplicate=digest in seen
        exact_dupes += is_duplicate
        if deduplicate and is_duplicate: continue
        seen.add(digest)
        record_id=content_hash({"source":source_key,"index":index,"record":digest})[:32]
        normalized=[first(record,FIELDS[k]) for k in FIELDS]
        con.execute("INSERT INTO events(record_id,source_path,source_index,content_hash,original_json,timestamp,host,user,event_type,source,label) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(record_id,source_key,index,digest,json.dumps(record,sort_keys=True,ensure_ascii=False,default=str),*normalized)); stored+=1
    con.execute("INSERT INTO sources VALUES(?,?,?)",(source_key,source_hash,stored)); con.commit()
    ts=con.execute("SELECT COUNT(timestamp),COUNT(*) FROM events WHERE source_path=?",(source_key,)).fetchone(); labels=con.execute("SELECT COUNT(label) FROM events WHERE source_path=?",(source_key,)).fetchone()[0]
    con.close()
    return {"records_read":len(records),"stored":stored,"rejected":rejected,"exact_duplicates":exact_dupes,"timestamp_available":ts[0],"label_available":labels,"database":str(database.resolve()),"source_path":source_key}

def main()->None:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("source"); p.add_argument("--database",default="database/evictguard.sqlite"); p.add_argument("--allow-reingest",action="store_true"); p.add_argument("--deduplicate",action="store_true"); a=p.parse_args()
    logging.basicConfig(level=logging.INFO,format="%(levelname)s %(message)s")
    try:
        result=ingest(a.source,a.database,allow_reingest=a.allow_reingest,deduplicate=a.deduplicate); print(json.dumps(result,indent=2))
    except Exception as exc: p.error(str(exc))
if __name__=="__main__": main()
