import json, sqlite3
from src.episode import create_episode
import pandas as pd

def test_episode_seed_order_and_manifest(tmp_path):
    db=tmp_path/"data.db"; con=sqlite3.connect(db); con.execute("create table events(record_id text, timestamp text, label text)"); con.executemany("insert into events values(?,?,?)",[(str(i),f"2025-01-01T00:00:{i:02d}Z",None) for i in range(5)]); con.commit(); con.close()
    out=tmp_path/"sample.csv"; meta=create_episode(db,out,3,11,True); frame=pd.read_csv(out)
    assert len(frame)==3 and frame.timestamp.is_monotonic_increasing and meta["records_written"]==3
    assert json.loads(out.with_suffix(".csv.manifest.json").read_text())["seed"]==11

def test_empty_episode(tmp_path):
    db=tmp_path/"empty.db"; con=sqlite3.connect(db); con.execute("create table events(record_id text,timestamp text,label text)"); con.commit(); con.close()
    assert create_episode(db,tmp_path/"empty.csv",10)["records_written"]==0
