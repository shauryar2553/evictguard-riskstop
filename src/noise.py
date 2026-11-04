"""Reproducible noise transformations on experimental copies only."""
from __future__ import annotations
import argparse, json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import numpy as np
import pandas as pd

NOISE_TYPES={"benign-looking","duplicate-flooding","missing-evidence","background-flood","mimic-flood","missing-critical"}
ATTACK_LABEL="attack"
# Benign administrative commands that superficially resemble attacker tradecraft
# (adversarial "mimic" flooding). They are benign *by construction*.
MIMIC_COMMANDS=[
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-Service | Where-Object Status -eq Running\""),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","powershell.exe -NoProfile -WindowStyle Hidden -Command \"Get-ScheduledTask | Out-Null\""),
    ("C:\\Windows\\System32\\cmd.exe","cmd.exe /c whoami /groups > %TEMP%\\inventory.txt"),
    ("C:\\Windows\\System32\\net.exe","net.exe user %USERNAME% /domain"),
    ("C:\\Windows\\System32\\reg.exe","reg.exe query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("C:\\Windows\\System32\\wbem\\WMIC.exe","wmic.exe process list brief"),
    ("C:\\Windows\\System32\\schtasks.exe","schtasks.exe /query /fo LIST /v"),
    ("C:\\Windows\\System32\\certutil.exe","certutil.exe -verify C:\\Windows\\System32\\drivers\\etc\\hosts"),
    ("C:\\Windows\\System32\\rundll32.exe","rundll32.exe shell32.dll,Control_RunDLL desk.cpl"),
    ("C:\\Windows\\System32\\nltest.exe","nltest.exe /dsgetdc:%USERDOMAIN%"),
]


def _is_attack(frame: pd.DataFrame) -> pd.Series:
    return frame["gt_label"].astype(str).eq(ATTACK_LABEL) if "gt_label" in frame else pd.Series(False,index=frame.index)


def _mark_injected(frame: pd.DataFrame, noise_type: str) -> pd.DataFrame:
    frame=frame.copy()
    frame["is_synthetic"]=True; frame["noise_type"]=noise_type
    frame["gt_label"]="benign"; frame["gt_tier"]="injected_noise"; frame["label_source"]=f"injected:{noise_type}"
    return frame


def _rewrite_payload(raw: Any, updates: dict[str,Any]) -> str:
    try: obj=json.loads(raw) if isinstance(raw,str) else {}
    except json.JSONDecodeError: obj={"_raw":raw}
    obj.update({k:v for k,v in updates.items() if v is not None})
    return json.dumps(obj,sort_keys=True,default=str)


def _labelled_noise(data: pd.DataFrame, noise_type: str, proportion: float, seed: int) -> tuple[pd.DataFrame,dict[str,Any]]:
    """Noise types that require/keep event-level ground truth (``gt_label``)."""
    from .utils import content_hash
    rng=np.random.default_rng(seed); output=data.copy(deep=True)
    for col,default in (("is_synthetic",False),("noise_type",None),("source_record_id",None),("dup_of",None)):
        if col not in output.columns: output[col]=default
    removed=[]; removed_attack=[]; added=0
    if noise_type=="missing-critical":
        attack_idx=np.flatnonzero(_is_attack(output).to_numpy())
        count=min(len(attack_idx),math.ceil(len(attack_idx)*proportion))
        drop=sorted(rng.choice(attack_idx,size=count,replace=False).tolist()) if count else []
        removed=output.iloc[drop]["record_id"].astype(str).tolist(); removed_attack=removed
        output=output.drop(output.index[drop]).reset_index(drop=True)
    else:
        count=math.ceil(len(output)*proportion)
        benign=output[~_is_attack(output) & ~output.get("gt_label",pd.Series("",index=output.index)).astype(str).eq("ambiguous")]
        pool=benign if len(benign) else output
        if count and len(pool):
            picks=pool.iloc[rng.choice(len(pool),size=count,replace=True)].copy()
            times=pd.to_datetime(output["timestamp"],errors="coerce",utc=True) if "timestamp" in output else pd.Series(dtype="datetime64[ns, UTC]")
            t0,t1=(times.min(),times.max()) if times.notna().any() else (None,None)
            new_times=[(t0+(t1-t0)*float(f)).isoformat().replace("+00:00","Z") if t0 is not None else None for f in rng.random(count)]
            picks["source_record_id"]=picks["record_id"].astype(str).values
            picks["record_id"]=[f"{noise_type}-{seed}-{i}" for i in range(count)]
            picks["timestamp"]=new_times
            payloads=[]
            for i,(raw,ts) in enumerate(zip(picks.get("original_json",pd.Series([None]*count,index=picks.index)),new_times)):
                updates={"@timestamp":ts,"RecordNumber":f"replay-{seed}-{i}"}
                if noise_type=="mimic-flood":
                    image,cmd=MIMIC_COMMANDS[int(rng.integers(len(MIMIC_COMMANDS)))]
                    updates.update({"Image":image,"CommandLine":cmd,"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational"})
                payloads.append(_rewrite_payload(raw,updates))
            picks["original_json"]=payloads
            if noise_type=="mimic-flood":
                picks["image"]=[json.loads(x)["Image"] for x in payloads]; picks["command_line"]=[json.loads(x)["CommandLine"] for x in payloads]
                picks["event_id"]=1; picks["event_type"]="1"; picks["channel"]=picks["source"]="microsoft-windows-sysmon/operational"
            picks["content_hash"]=[content_hash(json.loads(x)) for x in payloads]
            picks=_mark_injected(picks,noise_type)
            output=pd.concat([output,picks],ignore_index=True); added=count
    manifest={"created_at_utc":datetime.now(timezone.utc).isoformat(),"noise_type":noise_type,"proportion":proportion,"seed":seed,
              "input_records":len(data),"output_records":len(output),"added_records":added,"removed_record_ids":removed,
              "removed_attack_record_ids":removed_attack,"input_attack_records":int(_is_attack(data).sum()),"output_attack_records":int(_is_attack(output).sum()),
              "label_note":"Injected events are benign by construction (gt_tier=injected_noise); removed events are recorded so remaining evidence coverage is known."}
    return output,manifest


def inject_noise(data: pd.DataFrame, noise_type: str, proportion: float, seed: int) -> tuple[pd.DataFrame,dict[str,Any]]:
    if noise_type not in NOISE_TYPES: raise ValueError(f"noise_type must be one of {sorted(NOISE_TYPES)}")
    if not 0 <= proportion <= 1: raise ValueError("proportion must be between 0 and 1")
    if noise_type in {"background-flood","mimic-flood","missing-critical"}:
        if noise_type=="missing-critical" and "gt_label" not in data: raise ValueError("missing-critical requires a gt_label column")
        return _labelled_noise(data,noise_type,proportion,seed)
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
            copies["dup_of"]=copies["source_record_id"]  # duplicates inherit gt_label/gt_tier of their parent
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
        if synthetic:
            frame=pd.DataFrame(synthetic,columns=output.columns)
            if "gt_label" in output.columns: frame["gt_label"]="benign"; frame["gt_tier"]="injected_noise"
            output=pd.concat([output,frame],ignore_index=True); added=count
    manifest={"created_at_utc":datetime.now(timezone.utc).isoformat(),"noise_type":noise_type,"proportion":proportion,"seed":seed,"input_records":len(original),"output_records":len(output),"added_records":added,"removed_record_ids":removed,"removed_attack_record_ids":[r for r in removed if r in set(original.loc[_is_attack(original),"record_id"].astype(str))] if "record_id" in original else [],"label_note":"Synthetic events are not source ground truth; source label fields are preserved.","synthetic_field_note":"Generated timestamps and reused host identifiers are experimental placeholders, not source observations." if noise_type=="benign-looking" else None}
    return output,manifest

def main()->None:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("input"); p.add_argument("--noise-type",choices=sorted(NOISE_TYPES),required=True); p.add_argument("--proportion",type=float,default=.05); p.add_argument("--seed",type=int,default=17); p.add_argument("--output",required=True); a=p.parse_args()
    try:
        frame=pd.read_csv(a.input); output,manifest=inject_noise(frame,a.noise_type,a.proportion,a.seed); target=Path(a.output); target.parent.mkdir(parents=True,exist_ok=True); output.to_csv(target,index=False); manifest["input"]=a.input; manifest["output"]=str(target); target.with_suffix(target.suffix+".manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8"); print(json.dumps(manifest,indent=2))
    except Exception as exc: p.error(str(exc))
if __name__=="__main__": main()
