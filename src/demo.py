"""Run a deterministic local demo; downloads only when --download is passed."""
from __future__ import annotations
import argparse, json, sqlite3
from pathlib import Path
import os
os.environ.setdefault("MPLCONFIGDIR",str(Path(".matplotlib").resolve()))
import matplotlib.pyplot as plt
plt.switch_backend("Agg")
import pandas as pd
from .download_dataset import download
from .episode import create_episode
from .ingest import ingest
from .inspect_dataset import inspect
from .noise import inject_noise

def main()->None:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--download",action="store_true",help="download selected OTRF archive if absent"); a=p.parse_args()
    raw=Path("data/raw/empire_dcom_shellwindows_stager.zip"); db=Path("database/evictguard.sqlite")
    if not raw.exists():
        if a.download: download(output=raw)
        else:
            # deterministic demo fixture, explicitly marked synthetic
            raw=Path("data/generated/demo_events.jsonl"); raw.parent.mkdir(parents=True,exist_ok=True)
            if not raw.exists(): raw.write_text("\n".join(json.dumps({"timestamp":f"2025-01-01T00:00:{i:02d}Z","host":"demo-host","event_type":"demo_event","label":None,"demo_fixture":True}) for i in range(20)),encoding="utf-8")
    inspect(raw)
    try: result=ingest(raw,db)
    except ValueError as exc:
        if "already ingested" not in str(exc): raise
        result={"database":str(db)}
    print("Ingestion:",json.dumps(result,indent=2))
    manifest=create_episode(db,"data/episodes/demo_episode.csv",size=15,seed=2026,time_ordered=True)
    clean=pd.read_csv("data/episodes/demo_episode.csv")
    counts={"clean":len(clean)}
    for kind in ("benign-looking","duplicate-flooding","missing-evidence"):
        changed,meta=inject_noise(clean,kind,.1,2026); out=Path("data/generated")/f"demo_{kind}.csv"; changed.to_csv(out,index=False); out.with_suffix(out.suffix+".manifest.json").write_text(json.dumps(meta,indent=2),encoding="utf-8"); counts[kind]=len(changed)
    Path("results").mkdir(exist_ok=True); plt.figure(figsize=(8,4)); plt.bar(counts.keys(),counts.values()); plt.ylabel("Records"); plt.xticks(rotation=15); plt.tight_layout(); plt.savefig("results/demo_record_counts.png"); plt.close()
    print("Before/after record counts:",json.dumps(counts)); print("Episode manifest:",json.dumps(manifest,indent=2)); print("Plot: results/demo_record_counts.png")
if __name__=="__main__": main()
