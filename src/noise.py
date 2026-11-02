"""Reproducible noise transformations on experimental copies only."""
from __future__ import annotations
import argparse, json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import numpy as np
import pandas as pd

NOISE_TYPES={"benign-looking","duplicate-flooding","missing-evidence"}
def inject_noise(data: pd.DataFrame, noise_type: str, proportion: float, seed: int) -> tuple[pd.DataFrame,dict[str,Any]]:
    if noise_type not in NOISE_TYPES: raise ValueError(f"noise_type must be one of {sorted(NOISE_TYPES)}")
    if not 0 <= proportion <= 1: raise ValueError("proportion must be between 0 and 1")
    original=data.copy(deep=True); output=data.copy(deep=True); rng=np.random.default_rng(seed); removed=[]; added=0
    if noise_type=="missing-evidence":
        count=min(len(output),math.ceil(len(output)*proportion))
        indexes=sorted(rng.choice(len(output),size=count,replace=False).tolist()) if count else []
        id_col="record_id" if "record_id" in output else ("original_record_id" if "original_record_id" in output else None)
        removed=output.iloc[indexes][id_col].astype(str).tolist() if id_col else [str(i) for i in indexes]
        output=output.drop(output.index[indexes]).reset_index(drop=True)
    elif noise_type=="duplicate-flooding":
        count=math.ceil(len(output)*proportion)
        if count and len(output):
            selected=rng.choice(len(output),size=count,replace=True)
            copies=output.iloc[selected].copy(deep=True)
            copies["source_record_id"]=copies.get("record_id",pd.Series(copies.index,index=copies.index)).astype(str).values
            copies["is_synthetic"]=True; copies["noise_type"]=noise_type
            if "record_id" in copies: copies["record_id"]=[f"synthetic-{seed}-{i}" for i in range(count)]
            output=pd.concat([output,copies],ignore_index=True); added=count
    else:
        count=math.ceil(len(output)*proportion)
        for col, default in (("is_synthetic",False),("noise_type",None),("synthetic_label",None),("source_record_id",None)):
            if col not in output.columns: output[col]=default
        time_col=next((c for c in output.columns if str(c).lower() in {"timestamp","@timestamp","eventtime","utctime"}),None)
        host_col=next((c for c in output.columns if str(c).lower() in {"host","hostname","computer","host_name"}),None)
        source_hosts=(output[host_col].dropna().astype(str).drop_duplicates().tolist() if host_col else [])
        time_values=[]
        if time_col:
            parsed=pd.to_datetime(output[time_col],errors="coerce",utc=True).dropna()
            if len(parsed):
                start_time,end_time=parsed.min(),parsed.max()
                for i in range(count):
                    fraction=(i+1)/(count+1)
                    generated=start_time+(end_time-start_time)*fraction
                    time_values.append(generated.isoformat().replace("+00:00","Z"))
        synthetic=[]
        for i in range(count):
            row={c:None for c in output.columns}
            synthetic_time=time_values[i] if i<len(time_values) else None
            synthetic_host=source_hosts[i%len(source_hosts)] if source_hosts else None
            synthetic_event={"synthetic_event_id":f"synthetic-benign-{seed}-{i}","timestamp":synthetic_time,"host":synthetic_host,"event_type":"synthetic_background_activity","source":"EVICTGuard synthetic generator","label":None,"synthetic_label":"unlabeled_synthetic","is_synthetic":True,"noise_type":noise_type}
            for col,value in (("record_id",f"synthetic-benign-{seed}-{i}"),("timestamp",synthetic_time),("@timestamp",synthetic_time),("host",synthetic_host),("hostname",synthetic_host),("computer",synthetic_host),("event_type","synthetic_background_activity"),("source","EVICTGuard synthetic generator"),("label",None),("source_label",None),("synthetic_label","unlabeled_synthetic"),("is_synthetic",True),("noise_type",noise_type),("source_record_id",None),("content_hash",None),("original_json",json.dumps(synthetic_event,sort_keys=True,separators=(",",":"))),("synthetic_event_id",synthetic_event["synthetic_event_id"])):
                if col in output.columns: row[col]=value
            synthetic.append(row)
        if synthetic: output=pd.concat([output,pd.DataFrame(synthetic,columns=output.columns)],ignore_index=True); added=count
    manifest={"created_at_utc":datetime.now(timezone.utc).isoformat(),"noise_type":noise_type,"proportion":proportion,"seed":seed,"input_records":len(original),"output_records":len(output),"added_records":added,"removed_record_ids":removed,"label_note":"Synthetic events are not source ground truth; source label fields are preserved.","synthetic_field_note":"Generated timestamps and reused host identifiers are experimental placeholders, not source observations." if noise_type=="benign-looking" else None}
    return output,manifest

def main()->None:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("input"); p.add_argument("--noise-type",choices=sorted(NOISE_TYPES),required=True); p.add_argument("--proportion",type=float,default=.05); p.add_argument("--seed",type=int,default=17); p.add_argument("--output",required=True); a=p.parse_args()
    try:
        frame=pd.read_csv(a.input); output,manifest=inject_noise(frame,a.noise_type,a.proportion,a.seed); target=Path(a.output); target.parent.mkdir(parents=True,exist_ok=True); output.to_csv(target,index=False); manifest["input"]=a.input; manifest["output"]=str(target); target.with_suffix(target.suffix+".manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8"); print(json.dumps(manifest,indent=2))
    except Exception as exc: p.error(str(exc))
if __name__=="__main__": main()
