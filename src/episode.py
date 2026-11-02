"""Create seeded, traceable sample episodes from the SQLite event table."""
from __future__ import annotations
import argparse, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import pandas as pd

def create_episode(database: str|Path, output: str|Path, size: int=100, seed: int=17, time_ordered: bool=False)->dict[str,Any]:
    if size<0: raise ValueError("size must be non-negative")
    con=sqlite3.connect(database)
    frame=pd.read_sql_query("SELECT * FROM events",con); con.close()
    sampled=frame.sample(n=min(size,len(frame)),random_state=seed) if len(frame) else frame.copy()
    if time_ordered and "timestamp" in sampled: sampled=sampled.sort_values("timestamp",kind="stable",na_position="last")
    sampled["source_label_provenance"]="source_dataset_field"; sampled["inferred_label"]=None; sampled["synthetic_label"]=None
    target=Path(output); target.parent.mkdir(parents=True,exist_ok=True); sampled.to_csv(target,index=False)
    manifest={"created_at_utc":datetime.now(timezone.utc).isoformat(),"source_database":str(Path(database).resolve()),"output":str(target),"requested_size":size,"records_written":len(sampled),"seed":seed,"time_ordered":time_ordered,"source_label_field":"label","label_limitations":"Labels are retained only if present in source. No labels were inferred or manufactured; scenario context is not record-level truth."}
    target.with_suffix(target.suffix+".manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    return manifest

def main()->None:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--database",default="database/evictguard.sqlite"); p.add_argument("--size",type=int,default=100); p.add_argument("--seed",type=int,default=17); p.add_argument("--time-ordered",action="store_true"); p.add_argument("--output",default="data/episodes/episode.csv"); a=p.parse_args()
    try: print(json.dumps(create_episode(a.database,a.output,a.size,a.seed,a.time_ordered),indent=2))
    except Exception as exc: p.error(str(exc))
if __name__=="__main__": main()
