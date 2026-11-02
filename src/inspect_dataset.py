"""Inspect source files and write a schema/quality report."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import pandas as pd
from .utils import load_records

def inspect(path: str|Path, output: str|Path="results/dataset_inspection.json") -> dict:
    source=Path(path); records=load_records(source); valid=[r for r in records if "__parse_error__" not in r]; frame=pd.DataFrame(valid); columns=list(frame.columns)
    timestamp_candidates=[c for c in columns if any(t in str(c).lower() for t in ("time","date"))]
    ts={}
    for col in timestamp_candidates:
        parsed=pd.to_datetime(frame[col],errors="coerce",utc=True); ts[col]={"missing_or_unparseable_percent":round(float(parsed.isna().mean()*100),2)}
    report={"files":[{"name":source.name,"format":source.suffix.lower(),"size_bytes":source.stat().st_size,"records":len(records)}],"valid_records":len(valid),"malformed_records":len(records)-len(valid),"columns":columns,"examples":frame.head(3).where(pd.notna(frame.head(3)),None).to_dict(orient="records"),"timestamp_candidates":ts,"candidate_fields":{"event":[c for c in columns if any(x in c.lower() for x in ("event","channel","provider"))],"host":[c for c in columns if any(x in c.lower() for x in ("host","computer"))],"user":[c for c in columns if "user" in c.lower() or "account" in c.lower()],"process":[c for c in columns if "process" in c.lower() or "image" in c.lower()],"source":[c for c in columns if "source" in c.lower() or "provider" in c.lower()],"label":[c for c in columns if any(x in c.lower() for x in ("label","class","ground_truth"))]},"exact_duplicate_records":int(frame.astype(str).duplicated().sum()),"exact_duplicate_rate_percent":round(float(frame.astype(str).duplicated().mean()*100),2) if len(frame) else 0,"missing_values":{str(k):int(v) for k,v in frame.isna().sum().items()},"labels":{c:frame[c].value_counts(dropna=False).head(30).to_dict() for c in columns if any(x in c.lower() for x in ("label","class","ground_truth"))},"attack_timeline_metadata":"Not embedded in the selected archive; see linked scenario documentation.","assumptions":["JSONL is interpreted as one JSON object per non-empty line.","Archive loader selects the first supported JSON/JSONL/CSV member by name; verify the report for multi-member archives."]}
    target=Path(output); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps(report,indent=2,default=str),encoding="utf-8")
    print(f"Dataset inspection: {source.name} ({source.stat().st_size:,} bytes)")
    print(f"Records: {len(valid):,} valid, {len(records)-len(valid):,} malformed; exact duplicates: {report['exact_duplicate_records']:,} ({report['exact_duplicate_rate_percent']}%)")
    print(f"Columns ({len(columns)}): {', '.join(columns)}")
    print(f"Timestamp candidates: {json.dumps(ts)}")
    print(f"Candidate fields: {json.dumps(report['candidate_fields'])}")
    print(f"Inspection report: {target}")
    return report

def main()->None:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("source"); p.add_argument("--output",default="results/dataset_inspection.json"); a=p.parse_args()
    try: inspect(a.source,a.output)
    except Exception as exc: p.error(str(exc))
if __name__=="__main__": main()
