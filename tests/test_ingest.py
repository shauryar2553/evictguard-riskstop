import json
import pytest
from src.ingest import ingest
import sqlite3

def test_ingest_preserves_fields_hashes_and_duplicates(tmp_path):
    source=tmp_path/"events.jsonl"; record={"Computer":"host-a","EventID":1,"Message":"x"}; source.write_text(json.dumps(record)+"\n"+json.dumps(record)+"\n")
    db=tmp_path/"events.db"; summary=ingest(source,db)
    assert (summary["records_read"],summary["stored"],summary["exact_duplicates"])==(2,2,1)
    con=sqlite3.connect(db); rows=con.execute("select record_id,content_hash,original_json,host from events").fetchall(); con.close()
    assert rows[0][0]!=rows[1][0] and rows[0][1]==rows[1][1] and json.loads(rows[0][2])==record and rows[0][3]=="host-a"

def test_malformed_and_repeat_ingestion(tmp_path):
    source=tmp_path/"a.jsonl"; source.write_text('{"ok":1}\nnot json\n'); db=tmp_path/"a.db"
    result=ingest(source,db); assert result["stored"]==1 and result["rejected"]==1
    with pytest.raises(ValueError,match="already ingested"): ingest(source,db)
    ingest(source,db,allow_reingest=True)
