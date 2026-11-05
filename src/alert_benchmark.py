"""Alert-driven investigation benchmark on ATLASv2 Carbon Black (realistic SOC triage).

Every investigation starts from a REAL vendor alert (Carbon Black EDR watchlist hit) and investigates the
Carbon Black EDR telemetry of the same host around the alert time. Same sensor and same hosts for attack
and benign cases, so there's no environment shortcut.

Gold verdict per alert (exact joins, no heuristic labelling):
  * attack-day alert whose process_guid is a REAPr attack process     -> ATTACK
  * attack-day alert on any other process (vendor false positive)     -> BENIGN   (hard negative)
  * benign-period alert (no attack running on the host)               -> BENIGN
  * ATTACK alert after the missing-critical transform leaves < 50% of the attack events in the window -> DEFER

Splits (no leakage): attack-day alerts by scenario (h1-s1,s2,s3,m1,m2,m3 train; h1-s4,m4,m5,m6 val;
all h2 scenarios test); benign-period alerts by calendar day.

Label-free side information computed once per telemetry source: Sigma rule level and ATT&CK tactics per event
(r2026-04-01), used by RISKSTOP as kill-chain progression features. These labels are independent of REAPr.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .compose_episodes import balanced_split
from .label import LEVEL_RANK, standardize

ROOT = Path("data/atlasv2/standardized")
ALERTS = ROOT / "cbc_alerts"
OUT = Path("data/alert_bench")
EMAP = {"procstart": 1, "netconn": 3, "procend": 5, "moduleload": 7, "scriptload": 7, "crossproc": 10, "filemod": 11, "regmod": 13}
# All REAPr-matched (ATTACK) alerts are on host h1, so h1 scenarios are divided across splits; all h2 attack-day
# alerts (vendor false positives) go to test. 19 / 15 / 25 ATTACK alerts in train / val / test.
TRAIN = {"h1-s1", "h1-s2", "h1-s3", "h1-m1", "h1-m2", "h1-m3"}
VAL = {"h1-s4", "h1-m4"}
TACTICS = ["execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "discovery",
           "lateral_movement", "collection", "command_and_control", "exfiltration", "impact", "initial_access"]


def cbc_to_event(r: dict) -> dict | None:
    kind = str(r.get("type", "")).rsplit(".", 1)[-1]
    eid = EMAP.get(kind)
    if eid is None:
        return None
    ts = str(r.get("device_timestamp", "")).replace(" +0000 UTC", "Z").replace(" ", "T")
    ev = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": eid, "Hostname": r.get("device_name"), "@timestamp": ts,
          "Image": r.get("process_path"), "ProcessId": r.get("process_pid"), "ProcessGuid": r.get("process_guid"),
          "ParentImage": r.get("parent_path"), "ParentProcessId": r.get("parent_pid"), "ParentProcessGuid": r.get("parent_guid"),
          "CommandLine": r.get("process_cmdline"), "User": r.get("process_username"), "cbc_type": kind}
    if eid == 11:
        ev["TargetFilename"] = r.get("filemod_name")
    elif eid == 7:
        ev["ImageLoaded"] = r.get("modload_name") or r.get("scriptload_name")
    elif eid == 13:
        ev["TargetObject"] = r.get("regmod_name")
    elif eid == 3:
        ev["DestinationIp"], ev["DestinationPort"] = r.get("remote_ip"), r.get("remote_port")
    elif eid == 10:
        ev["SourceImage"], ev["SourceProcessId"], ev["TargetImage"] = r.get("process_path"), r.get("process_pid"), r.get("crossproc_name")
    return ev


def build_source(name: str, lines, attack_guids: set[str], rules) -> pd.DataFrame:
    """Convert Carbon Black EDR lines to the standard schema, attach REAPr labels and Sigma side information."""
    from .sigma_engine import evaluate
    recs, guids = [], []
    for line in lines:
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        ev = cbc_to_event(r)
        if ev is None:
            continue
        recs.append(ev)
        guids.append(str(r.get("process_guid", "")).strip())
    raw = pd.DataFrame(recs)
    std = standardize(raw, f"cbc:{name}")
    std["process_guid_cbc"] = guids
    is_attack = std.process_guid_cbc.isin(attack_guids).to_numpy()
    std["gt_tier"] = np.where(is_attack, "supporting", "background")
    std["gt_label"] = np.where(is_attack, "attack", "benign")
    hits, _ = evaluate(raw, rules)
    std["sigma_rank"] = -1
    std["sigma_tactics"] = ""
    if len(hits):
        agg = hits.assign(rank=hits.rule_level.map(LEVEL_RANK)).groupby("row").agg(rank=("rank", "max"), tac=("rule_tactics", lambda s: ";".join(sorted({t for x in s for t in str(x).split(";") if t}))))
        std.loc[agg.index, "sigma_rank"] = agg["rank"].astype(int).to_numpy()
        std.loc[agg.index, "sigma_tactics"] = agg["tac"].to_numpy()
    std["event_type"], std["source"], std["is_synthetic"] = std.event_id.astype(str), std.channel, False
    std = std.sort_values("timestamp", kind="stable").reset_index(drop=True)
    std["record_id"] = [f"{name}#{i}" for i in range(len(std))]
    return std


def reapr_attack(scen: str) -> set[str]:
    lab = pd.read_csv(ROOT.parent / "reapr" / f"{scen}.labels", skipinitialspace=True)
    lab.columns = [c.strip() for c in lab.columns]
    return set(lab.process_uuid.astype(str).str.strip())


def prepare(max_benign_lines: int | None = None) -> pd.DataFrame:
    """Build telemetry sources (parquet) and the alert table."""
    from .sigma_engine import load_rules
    rules, _ = load_rules("data/sigma/sigmahq/rules/windows")
    (OUT / "sources").mkdir(parents=True, exist_ok=True)
    alerts = []
    # attack-day scenarios
    for path in sorted((ROOT / "cbc_edr").glob("*.jsonl.gz")):
        scen = path.name.split(".")[0]
        attack = reapr_attack(scen)
        src = OUT / "sources" / f"{scen}.parquet"
        if not src.exists():
            build_source(scen, gzip.open(path), attack, rules).to_parquet(src, index=False, compression="zstd")
        host = scen.split("-")[0]
        apath = ALERTS / f"attack__{host}__cbc-edr-alerts__edr-alerts-{scen}.jsonl.gz"
        for line in (gzip.open(apath) if apath.exists() else []):
            a = json.loads(line)
            alerts.append(_alert_row(a, scen, "attack_day", attack))
    # benign period (h2)
    bpath = ALERTS / "benign__h2__cbc-edr__edr-h2-benign.jsonl.gz"
    if not bpath.exists():
        cands = sorted(ALERTS.glob("benign__h2__cbc-edr__*.gz"))
        bpath = cands[0] if cands else None
    if bpath is not None:
        src = OUT / "sources" / "h2-benign.parquet"
        if not src.exists():
            import itertools
            lines = gzip.open(bpath)
            if max_benign_lines:
                lines = itertools.islice(lines, max_benign_lines)
            build_source("h2-benign", lines, set(), rules).to_parquet(src, index=False, compression="zstd", row_group_size=50_000)
        for apath in sorted(ALERTS.glob("benign__h2__cbc-edr-alerts__*.gz")):
            for line in gzip.open(apath):
                alerts.append(_alert_row(json.loads(line), "h2-benign", "benign_period", set()))
    al = pd.DataFrame(alerts)
    al = al.dropna(subset=["time"]).drop_duplicates(["source", "process_guid", "report_name"]).reset_index(drop=True)
    al["alert_id"] = [f"A{i:04d}" for i in range(len(al))]
    is_attack_day = al.kind == "attack_day"
    al.loc[is_attack_day, "split"] = al.loc[is_attack_day, "source"].map(lambda s: "train" if s in TRAIN else "val" if s in VAL else "test")
    days = al.loc[~is_attack_day, "time"].dt.strftime("%Y-%m-%d")
    if len(days):
        al.loc[~is_attack_day, "split"] = days.map(balanced_split(days))
    al.to_csv(OUT / "alerts.csv", index=False)
    return al


def _alert_row(a: dict, source: str, kind: str, attack: set[str]) -> dict[str, Any]:
    guid = str(a.get("process_guid", "")).strip()
    t = pd.to_datetime(a.get("create_time") or a.get("first_event_time"), errors="coerce", utc=True)
    wl = ";".join(w.get("name", "") for w in (a.get("watchlists") or []) if isinstance(w, dict))
    return {"source": source, "kind": kind, "host": str(a.get("device_name", "")).lower(), "time": t, "process_guid": guid,
            "process_path": a.get("process_path"), "severity": a.get("severity"), "report_name": a.get("report_name"), "watchlists": wl,
            "gold": "ATTACK" if guid in attack else "BENIGN"}


def episode_for(alert: dict, window_s: int = 900, cap: int = 20_000) -> tuple[pd.DataFrame, list[int]]:
    """Telemetry of the alert's host within +/- window_s of the alert (at most ``cap`` events nearest the alert),
    plus the seed rows: the alerted process's own events."""
    t = pd.to_datetime(alert["time"], utc=True)
    lo, hi = t - pd.Timedelta(seconds=window_s), t + pd.Timedelta(seconds=window_s)
    src = pd.read_parquet(OUT / "sources" / f"{alert['source']}.parquet", filters=[("timestamp", ">=", lo), ("timestamp", "<=", hi)])
    ts = pd.to_datetime(src.timestamp, utc=True, errors="coerce")
    host = str(alert["host"]).split(".")[0]
    m = (src.host == host) & ((ts - t).abs() <= pd.Timedelta(seconds=window_s))
    win = src[m].copy()
    if len(win) > cap:
        win = win.assign(_d=(ts[m] - t).abs()).nsmallest(cap, "_d").drop(columns="_d")
    win = win.sort_values("timestamp", kind="stable").reset_index(drop=True)
    win["timestamp"] = pd.to_datetime(win.timestamp, utc=True).map(lambda x: x.isoformat().replace("+00:00", "Z"))
    win["record_id"] = [f"{alert['alert_id']}:{r}" for r in win.record_id]
    seed = np.flatnonzero(win.process_guid_cbc.to_numpy() == alert["process_guid"]).tolist()
    return win, seed[:1]


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-benign-lines", type=int, default=None)
    a = ap.parse_args()
    al = prepare(a.max_benign_lines)
    print(al.groupby(["split", "kind", "gold"]).size().to_string())


if __name__ == "__main__":
    main()
