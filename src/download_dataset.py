"""Download one documented OTRF Security-Datasets scenario."""
from __future__ import annotations
import argparse, json, urllib.request, zipfile
from datetime import datetime, timezone
from pathlib import Path

URL="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_dcom_shellwindows_stager.zip"
SCENARIO="Empire Invoke DCOM ShellWindows (host telemetry)"
PAGE="https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-190518211052.html"

def download(url: str=URL, output: Path=Path("data/raw/empire_dcom_shellwindows_stager.zip"), max_bytes: int=100_000_000) -> Path:
    request=urllib.request.Request(url, headers={"User-Agent":"EVICTGuard-Phase1/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            length=response.headers.get("Content-Length")
            if length and int(length)>max_bytes: raise ValueError(f"Download is too large ({length} bytes; limit {max_bytes})")
            output.parent.mkdir(parents=True, exist_ok=True)
            temp=output.with_suffix(output.suffix+".part")
            total=0
            with temp.open("wb") as handle:
                while chunk:=response.read(1024*1024):
                    total+=len(chunk)
                    if total>max_bytes: temp.unlink(missing_ok=True); raise ValueError(f"Download exceeded {max_bytes} byte limit")
                    handle.write(chunk)
            if total==0: temp.unlink(missing_ok=True); raise ValueError("Downloaded file is empty")
            with zipfile.ZipFile(temp) as archive:
                valid=[n for n in archive.namelist() if not n.endswith("/")]
                if not valid: raise ValueError("Downloaded ZIP has no files")
            temp.replace(output)
    except Exception as exc:
        raise RuntimeError(f"Could not download/verify {url}: {exc}. Manual source: {PAGE}") from exc
    manifest={"scenario":SCENARIO,"source_url":url,"documentation_url":PAGE,"downloaded_at_utc":datetime.now(timezone.utc).isoformat(),"file":str(output),"format":"ZIP containing OTRF JSON Lines host telemetry","size_bytes":output.stat().st_size,"limitations":["Telemetry comes from a simulated Empire DCOM scenario.","Scenario association does not make every record an independently verified malicious event.","The accompanying narrative is not a complete event-by-event ground-truth label set."]}
    output.with_suffix(output.suffix+".manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    return output

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--url",default=URL); parser.add_argument("--output",type=Path,default=Path("data/raw/empire_dcom_shellwindows_stager.zip")); parser.add_argument("--max-bytes",type=int,default=100_000_000); args=parser.parse_args()
    try: print(f"Verified download: {download(args.url,args.output,args.max_bytes)} ({args.output.stat().st_size} bytes)")
    except Exception as exc: parser.error(str(exc))
if __name__=="__main__": main()
