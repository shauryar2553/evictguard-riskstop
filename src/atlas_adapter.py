"""ATLASv2 adapter: Event Viewer XML -> standardized, labelled parquet segments.

Only the Sysmon and Windows Security folders are needed (NOT the whole 160 GB):

    data/atlasv2/raw/benign/h1/sysmon/*.xml          data/atlasv2/raw/benign/h1/msft-security/*.xml
    data/atlasv2/raw/benign/h2/sysmon/*.xml          data/atlasv2/raw/benign/h2/msft-security/*.xml
    data/atlasv2/raw/attack/h1|h2/sysmon/*.xml       data/atlasv2/raw/attack/h1|h2/msft-security/*.xml   (optional, OOD test)

Download those folders from the ATLASv2 Box link in
https://bitbucket.org/sts-lab/atlasv2 (keep the same folder layout).

Outputs
    data/atlasv2/standardized/benign/<host>-<file>.parquet   verified-benign background segments,
        segment_group = "<host>-<file>" (one file per day -> host-day groups)
    data/atlasv2/standardized/attack/<host>-<scenario>.parquet  labelled with REAPr process labels
        (gt_tier=supporting for REAPr attack processes; Sigma >= medium inside them -> core)

``python -m src.atlas_adapter --fetch-reapr`` downloads the REAPr label files (small).
"""
from __future__ import annotations

import argparse
import re
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

from .label import LEVEL_RANK, standardize
from .sigma_engine import evaluate, load_rules

REAPR_BASE = "https://bitbucket.org/sts-lab/reapr-ground-truth/raw/HEAD/atlasv2/"
SCENARIOS = [f"h1-s{i}" for i in range(1, 5)] + [f"h{h}-m{i}" for h in (1, 2) for i in range(1, 7)]


def iter_events(path: Path) -> Iterator[dict[str, Any]]:
    """Stream Event Viewer XML into flat dicts using OTRF-compatible field names."""
    for _, elem in ET.iterparse(path, events=("end",)):
        if not elem.tag.endswith("}Event") and elem.tag != "Event":
            continue
        record: dict[str, Any] = {}
        for child in elem:
            tag = child.tag.split("}")[-1]
            if tag == "System":
                for s in child:
                    stag = s.tag.split("}")[-1]
                    if stag == "Provider":
                        record["SourceName"] = s.attrib.get("Name")
                    elif stag == "TimeCreated":
                        record["@timestamp"] = s.attrib.get("SystemTime")
                    elif stag == "Computer":
                        record["Hostname"] = s.text
                    elif stag == "Execution":
                        record["ExecutionProcessID"] = s.attrib.get("ProcessID")
                    elif stag in ("EventID", "Channel", "EventRecordID", "Task", "Opcode", "Level", "Keywords"):
                        record[stag if stag != "EventRecordID" else "RecordNumber"] = s.text
            elif tag in ("EventData", "UserData"):
                for d in child.iter():
                    name = d.attrib.get("Name")
                    if name:
                        record[name] = d.text
        elem.clear()
        if record:
            yield record


def convert_folder(raw_root: Path, out_root: Path, phase: str) -> list[Path]:
    written = []
    base = raw_root / phase
    if not base.exists():
        return written
    for host_dir in sorted(p for p in base.iterdir() if p.is_dir()):
        groups: dict[str, list[Path]] = {}
        for stream in ("sysmon", "msft-security"):
            for xml in sorted((host_dir / stream).glob("*.xml")):
                # benign: one file per day ("...-1.xml"); attack: one per scenario ("...-s1.xml")
                key = re.sub(r"^(sysmon|security|msft-security)[-_]?", "", xml.stem.lower())
                key = re.sub(rf"^{host_dir.name}[-_]?", "", key)
                groups.setdefault(key, []).append(xml)
        for key, files in sorted(groups.items()):
            records = [r for f in files for r in iter_events(f)]
            if not records:
                continue
            seg = f"{host_dir.name}-{key}"
            std = standardize(pd.DataFrame(records), f"atlasv2:{phase}:{seg}")
            std["segment_group"] = seg
            std["gt_tier"] = "background" if phase == "benign" else "background"
            std["gt_label"] = "benign"
            std["label_source"] = "atlasv2_benign_period" if phase == "benign" else None
            target = out_root / phase / f"{seg}.parquet"
            target.parent.mkdir(parents=True, exist_ok=True)
            std.to_parquet(target, index=False)
            written.append(target)
            print(f"{phase}/{seg}: {len(std)} events")
    return written


def fetch_reapr(target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for s in SCENARIOS:
        for ext in ("labels", "seeds"):
            data = urllib.request.urlopen(REAPR_BASE + f"{s}.{ext}", timeout=60).read()
            (target / f"{s}.{ext}").write_bytes(data)
    print(f"REAPr labels saved to {target}")


def read_reapr(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, skipinitialspace=True)
    frame.columns = [c.strip() for c in frame.columns]
    frame["process_name"] = frame.process_name.astype(str).str.strip().str.lower()
    frame["process_id"] = pd.to_numeric(frame.process_id, errors="coerce").astype("Int64")
    return frame[frame.label.astype(str).str.strip() == "attack"]


def label_attack_segments(std_root: Path, reapr_dir: Path, rules_root: Path) -> None:
    """Apply REAPr process labels (+ Sigma core tier) to standardized attack segments."""
    rules, _ = load_rules(rules_root)
    for path in sorted((std_root / "attack").glob("*.parquet")):
        frame = pd.read_parquet(path)
        scenario = path.stem
        reapr_file = reapr_dir / f"{scenario}.labels"
        if not reapr_file.exists():
            print(f"skip {scenario}: no REAPr labels"); continue
        attack = read_reapr(reapr_file)
        keys = set(zip(attack.process_name, attack.process_id))
        image = frame.image.astype(str).str.lower()
        hit = [(img, pid) in keys if pd.notna(pid) else False for img, pid in zip(image, frame.process_id)]
        frame.loc[hit, ["gt_tier", "gt_label", "label_source"]] = ["supporting", "attack", "reapr_process"]
        raw = pd.json_normalize([__import__("json").loads(x) for x in frame.original_json])
        hits, _ = evaluate(raw, rules)
        strong = set(hits[hits.rule_level.map(LEVEL_RANK) >= LEVEL_RANK["medium"]].row)
        core = frame.index.isin(list(strong)) & (frame.gt_label == "attack")
        frame.loc[core, ["gt_tier", "label_source"]] = ["core", "reapr_process+sigma"]
        # ATLAS's own ground truth: EventRecordIDs of malicious Security events -> core.
        gt_file = path.with_name(f"{scenario}.groundtruth.txt")
        if gt_file.exists():
            ids = {line.strip() for line in gt_file.read_text().splitlines() if line.strip().isdigit()}
            record = frame.original_json.map(lambda x: str(__import__("json").loads(x).get("RecordNumber", "")))
            is_sec = frame.channel.eq("security")
            atlas_core = is_sec & record.isin(ids)
            frame.loc[atlas_core, ["gt_tier", "gt_label"]] = ["core", "attack"]
            frame.loc[atlas_core, "label_source"] = frame.loc[atlas_core, "label_source"].fillna("").map(lambda x: (x + "+" if x else "") + "atlas_groundtruth")
            print(f"{scenario}: ATLAS ground truth lists {len(ids)} record IDs, {int(atlas_core.sum())} found in the kept events")
        frame.to_parquet(path, index=False, compression="zstd")
        print(f"{scenario}: {int(sum(hit))} REAPr-attributed events, {int((frame.gt_tier == 'core').sum())} core")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--raw", type=Path, default=Path("data/atlasv2/raw"))
    p.add_argument("--out", type=Path, default=Path("data/atlasv2/standardized"))
    p.add_argument("--reapr", type=Path, default=Path("data/atlasv2/reapr"))
    p.add_argument("--rules", type=Path, default=Path("data/sigma/sigmahq/rules/windows"))
    p.add_argument("--fetch-reapr", action="store_true")
    p.add_argument("--stream", action="store_true", help="stream only the needed files from the 12 GB Box archive (no raw XML stored)")
    p.add_argument("--stream-attacks", action="store_true", help="stream all 16 attack scenarios (Sysmon + Security + ATLAS ground truth)")
    p.add_argument("--stream-alerts", action="store_true", help="stream Carbon Black alerts (attack + benign days) and benign-period EDR for h2")
    p.add_argument("--stream-cbc", action="store_true", help="stream the Carbon Black EDR telemetry of all attack scenarios (fresh test sensor)")
    p.add_argument("--host", default="h1")
    p.add_argument("--scenario", default="s1")
    p.add_argument("--cap", type=int, default=100_000, help="max events kept per XML file")
    a = p.parse_args()
    if a.fetch_reapr:
        fetch_reapr(a.reapr); return
    if a.stream_alerts:
        dirs = {f"data/{ph}/{h}/{k}" for ph in ("attack", "benign") for h in ("h1", "h2") for k in ("cbc-edr-alerts", "cbc-ngav-alerts")}
        dirs |= {"data/benign/h2/cbc-edr"}
        stream_members(BOX_URL, a.out / "cbc_alerts", dirs)
        return
    if a.stream_cbc:
        stream_cbc_edr(BOX_URL, a.out)
        return
    if a.stream_attacks:
        stream_attacks(BOX_URL, a.out, cap=max(a.cap, 300_000))
        label_attack_segments(a.out, a.reapr, a.rules)
        return
    if a.stream:
        stream_extract(BOX_URL, a.out, a.host, a.scenario, a.cap, keep_index=a.out / "archive_listing.tsv")
        rebuild_daily_segments(a.out)
        if (a.out / "attack").exists():
            label_attack_segments(a.out, a.reapr, a.rules)
        return
    convert_folder(a.raw, a.out, "benign")
    if convert_folder(a.raw, a.out, "attack"):
        label_attack_segments(a.out, a.reapr, a.rules)



def rebuild_daily_segments(out_root: Path) -> list[Path]:
    """Merge benign files, drop duplicates, and re-cut into one segment per host-day.

    ATLASv2 Sysmon exports are cumulative (sysmon-5 contains days 1-5), so the
    same event appears in several files. Without this step identical background
    would leak across train/val/test. Duplicates are identified by
    (host, channel, EventRecordID); the split group is the calendar day.
    """
    import json
    files = sorted((out_root / "benign").glob("*.parquet"))
    if not files:
        return []
    frame = pd.concat([pd.read_parquet(p) for p in files], ignore_index=True)
    record = frame.original_json.map(lambda x: str(json.loads(x).get("RecordNumber", "")))
    before = len(frame)
    frame = frame.assign(_rec=record).drop_duplicates(["host", "channel", "_rec"]).drop(columns="_rec")
    frame["_day"] = frame.timestamp.dt.strftime("%Y-%m-%d")
    for p in files:
        p.unlink()
    written = []
    for (host, day), part in frame.groupby(["host", "_day"]):
        seg = f"{host}-{day}"
        part = part.drop(columns="_day").sort_values("timestamp", kind="stable").reset_index(drop=True)
        part["recording_id"] = f"atlasv2:benign:{seg}"
        part["record_id"] = [f"atlasv2:benign:{seg}#{i}" for i in range(len(part))]
        part["segment_group"] = seg
        target = out_root / "benign" / f"{seg}.parquet"
        part.to_parquet(target, index=False, compression="zstd", row_group_size=20_000)
        written.append(target)
        print(f"benign segment {seg}: {len(part)} events ({part.channel.value_counts().to_dict()})")
    print(f"deduplicated benign events: {before} -> {len(frame)}")
    return written


# ---------------------------------------------------------------- streaming
BOX_URL = "https://uofi.box.com/index.php?rm=box_download_shared_file&shared_name=feunur7280afxrfeb0af73recexa73yc&file_id=f_1294229670092"


def _iter_xml_records(fileobj, cap: int) -> list[dict[str, Any]]:
    """Parse at most ``cap`` events from an Event Viewer XML stream (rest is skipped)."""
    records: list[dict[str, Any]] = []
    for _, elem in ET.iterparse(fileobj, events=("end",)):
        if not elem.tag.endswith("}Event") and elem.tag != "Event":
            continue
        record: dict[str, Any] = {}
        for child in elem:
            tag = child.tag.split("}")[-1]
            if tag == "System":
                for s in child:
                    stag = s.tag.split("}")[-1]
                    if stag == "Provider":
                        record["SourceName"] = s.attrib.get("Name")
                    elif stag == "TimeCreated":
                        record["@timestamp"] = s.attrib.get("SystemTime")
                    elif stag == "Computer":
                        record["Hostname"] = s.text
                    elif stag == "Execution":
                        record["ExecutionProcessID"] = s.attrib.get("ProcessID")
                    elif stag in ("EventID", "Channel", "EventRecordID"):
                        record[stag if stag != "EventRecordID" else "RecordNumber"] = s.text
            elif tag in ("EventData", "UserData"):
                for d in child.iter():
                    if d.attrib.get("Name"):
                        record[d.attrib["Name"]] = d.text
        elem.clear()
        if record:
            records.append(record)
            if len(records) >= cap:
                break
    return records


class ResumableHTTP:
    """Read-only file object over HTTP that reconnects with a Range header after errors.

    tarfile's ``r|gz`` mode reads sequentially from this object, so a dropped
    connection is resumed at the exact byte offset and decompression continues.
    """

    def __init__(self, url: str, retries: int = 20, timeout: int = 120):
        import urllib.request
        self.url, self.retries, self.timeout, self.offset = url, retries, timeout, 0
        self._urllib = urllib.request
        self._resp = None
        self._open()

    def _open(self) -> None:
        headers = {"User-Agent": "Mozilla/5.0"}
        if self.offset:
            headers["Range"] = f"bytes={self.offset}-"
        # Re-resolve the share link each time: Box's signed redirect URLs expire.
        req = self._urllib.Request(self.url, headers=headers)
        self._resp = self._urllib.urlopen(req, timeout=self.timeout)
        if self.offset and self._resp.status != 206:
            raise RuntimeError(f"Server ignored Range request (HTTP {self._resp.status}); cannot resume")

    def read(self, size: int = -1) -> bytes:
        import time
        for attempt in range(self.retries):
            try:
                data = self._resp.read(size)
                self.offset += len(data)
                return data
            except Exception as exc:  # timeout / reset: reconnect at current offset
                print(f"  connection error at {self.offset/1e9:.2f} GB ({exc!r}); resuming (attempt {attempt+1})", flush=True)
                time.sleep(min(60, 5 * (attempt + 1)))
                try:
                    self._open()
                except Exception as exc2:
                    print(f"  reconnect failed: {exc2!r}", flush=True)
        raise RuntimeError("Too many connection failures")

    def close(self) -> None:
        if self._resp is not None:
            self._resp.close()


def _write_attack(records: list[dict[str, Any]], out_root: Path, host: str, scenario: str) -> None:
    std = standardize(pd.DataFrame(records), f"atlasv2:attack:{host}-{scenario}")
    std["segment_group"] = f"{host}-{scenario}"
    std["gt_tier"], std["gt_label"], std["label_source"] = "background", "benign", None
    target = out_root / "attack" / f"{host}-{scenario}.parquet"
    target.parent.mkdir(parents=True, exist_ok=True)
    std.to_parquet(target, index=False, compression="zstd")
    print(f"attack {host}-{scenario}: {len(std)} events -> {target}", flush=True)


def stream_extract(url: str, out_root: Path, host: str = "h1", scenario: str = "s1", cap: int = 100_000, keep_index: Path | None = None) -> None:
    """Stream the 12 GB ATLASv2 tar.gz once, keeping only what we need.

    Wanted: benign/<host>/{sysmon,msft-security}/*.xml (every day, first ``cap``
    events each) and attack/<host>/{sysmon,msft-security}/*<host>-<scenario>*.xml
    plus its groundtruth. XML is parsed straight from the stream and written as
    standardized parquet; raw XML never touches the disk. Reading stops as soon
    as every wanted folder has been passed.
    """
    import tarfile
    import urllib.request

    wanted_dirs = {f"data/benign/{host}/sysmon", f"data/benign/{host}/msft-security",
                   f"data/attack/{host}/sysmon", f"data/attack/{host}/msft-security"}
    seen, done = set(), set()
    attack_records: list[dict[str, Any]] = []
    listing = []
    resp = ResumableHTTP(url)
    with tarfile.open(fileobj=resp, mode="r|gz") as archive:
        for member in archive:
            rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
            listing.append(f"{member.size}\t{rel}")
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            for d in list(seen - done):
                if not (parent == d or parent.startswith(d + "/")):
                    done.add(d)
            if wanted_dirs <= done:
                print("All wanted folders passed; stopping download early.")
                break
            in_dir = next((d for d in wanted_dirs if parent == d or parent.startswith(d + "/")), None)
            if in_dir is None or not member.isfile():
                continue
            seen.add(in_dir)
            name = rel.rsplit("/", 1)[-1]
            phase = rel.split("/")[1]
            if phase == "attack":
                if f"{host}-{scenario}" not in name.lower() and f"{host}_{scenario}" not in name.lower():
                    continue
                if name.lower().endswith(".xml"):
                    attack_records += _iter_xml_records(archive.extractfile(member), cap)
                    print(f"attack {rel}: kept {len(attack_records)} events so far", flush=True)
                    _write_attack(attack_records, out_root, host, scenario)  # save progress immediately
                else:  # ATLAS's own groundtruth note
                    target = out_root / "attack" / f"{host}-{scenario}.groundtruth.txt"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
                continue
            if not name.lower().endswith(".xml"):
                continue
            records = _iter_xml_records(archive.extractfile(member), cap)
            stream = in_dir.rsplit("/", 1)[-1]
            seg = f"{host}-{stream}-{Path(name).stem.split('-')[-1]}"
            std = standardize(pd.DataFrame(records), f"atlasv2:benign:{seg}")
            std["segment_group"] = f"{host}-day{Path(name).stem.split('-')[-1]}-{stream}"
            std["gt_tier"], std["gt_label"], std["label_source"] = "background", "benign", "atlasv2_benign_period"
            target = out_root / "benign" / f"{seg}.parquet"
            target.parent.mkdir(parents=True, exist_ok=True)
            std.to_parquet(target, index=False, compression="zstd")
            print(f"benign {rel}: {len(std)} events -> {target}", flush=True)
    resp.close()
    if keep_index:
        keep_index.write_text("\n".join(listing))

def stream_attacks(url: str, out_root: Path, cap: int = 300_000) -> list[str]:
    """Stream only the ATLASv2 attack section: every scenario's Sysmon + Security XML and
    ATLAS ground truth, for both hosts. Each file is written as soon as it is parsed
    (bounded RAM); reading stops once both hosts' attack folders have passed."""
    import tarfile
    parts = out_root / "attack_parts"
    parts.mkdir(parents=True, exist_ok=True)
    (out_root / "attack").mkdir(parents=True, exist_ok=True)
    wanted = {f"data/attack/{h}/{s}" for h in ("h1", "h2") for s in ("sysmon", "msft-security")}
    seen, done, scenarios = set(), set(), set()
    resp = ResumableHTTP(url)
    with tarfile.open(fileobj=resp, mode="r|gz") as archive:
        for member in archive:
            rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            for d in list(seen - done):
                if not (parent == d or parent.startswith(d + "/")):
                    done.add(d)
            if wanted <= done or rel.startswith("data/benign"):
                print("Attack section passed; stopping download early.", flush=True)
                break
            in_dir = next((d for d in wanted if parent == d or parent.startswith(d + "/")), None)
            if in_dir is None or not member.isfile():
                continue
            seen.add(in_dir)
            name = rel.rsplit("/", 1)[-1]
            m = re.search(r"(h[12])[-_]([sm]\d)", name.lower())
            if not m:
                continue
            scenario = f"{m.group(1)}-{m.group(2)}"
            if "/groundtruth/" in rel:
                (out_root / "attack" / f"{scenario}.groundtruth.txt").write_bytes(archive.extractfile(member).read())
                continue
            if not name.lower().endswith(".xml"):
                continue
            stream = in_dir.rsplit("/", 1)[-1]
            records = _iter_xml_records(archive.extractfile(member), cap)
            if records:
                std = standardize(pd.DataFrame(records), f"atlasv2:attack:{scenario}:{stream}")
                std.to_parquet(parts / f"{scenario}-{stream}.parquet", index=False, compression="zstd")
                scenarios.add(scenario)
                print(f"attack {rel}: {len(std)} events (offset {resp.offset/1e9:.2f} GB)", flush=True)
    resp.close()
    for scenario in sorted(scenarios):
        frames = [pd.read_parquet(p) for p in sorted(parts.glob(f"{scenario}-*.parquet"))]
        std = pd.concat(frames, ignore_index=True).sort_values("timestamp", kind="stable").reset_index(drop=True)
        std["recording_id"] = f"atlasv2:attack:{scenario}"
        std["record_id"] = [f"atlasv2:attack:{scenario}#{i}" for i in range(len(std))]
        std["segment_group"] = scenario
        std["gt_tier"], std["gt_label"], std["label_source"] = "background", "benign", None
        std.to_parquet(out_root / "attack" / f"{scenario}.parquet", index=False, compression="zstd")
        for p in parts.glob(f"{scenario}-*.parquet"):
            p.unlink()
        print(f"scenario {scenario}: {len(std)} events")
    return sorted(scenarios)

def stream_cbc_edr(url: str, out_root: Path, max_lines: int = 400_000) -> list[str]:
    """Stream the ATLASv2 Carbon Black Cloud EDR telemetry for every attack scenario (raw JSONL lines kept as-is,
    gzip-compressed, one file per scenario). Stops once both hosts' attack/cbc-edr folders have passed."""
    import gzip
    import tarfile
    target = out_root / "cbc_edr"
    target.mkdir(parents=True, exist_ok=True)
    wanted = {"data/attack/h1/cbc-edr", "data/attack/h2/cbc-edr"}
    seen, done, saved = set(), set(), []
    resp = ResumableHTTP(url)
    with tarfile.open(fileobj=resp, mode="r|gz") as archive:
        for member in archive:
            rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            for d in list(seen - done):
                if parent != d:
                    done.add(d)
            if wanted <= done or rel.startswith("data/benign"):
                print("CBC EDR folders passed; stopping download early.", flush=True)
                break
            if parent not in wanted or not member.isfile():
                continue
            seen.add(parent)
            m = re.search(r"(h[12])[-_]([sm]\d)", rel.lower())
            if not m:
                continue
            scen = f"{m.group(1)}-{m.group(2)}"
            src = archive.extractfile(member)
            n = 0
            with gzip.open(target / f"{scen}.jsonl.gz", "wb") as out:
                for line in src:
                    out.write(line)
                    n += 1
                    if n >= max_lines:
                        break
            saved.append(scen)
            print(f"cbc-edr {scen}: {n} lines (offset {resp.offset/1e9:.2f} GB)", flush=True)
    resp.close()
    return saved

def stream_members(url: str, out_dir: Path, wanted_dirs: set[str], max_lines: int | None = None) -> list[str]:
    """Generic resumable streamer: save every file under ``wanted_dirs`` (gzip-compressed, raw lines),
    stop once all wanted folders have passed. Used for Carbon Black alerts and benign-period EDR."""
    import gzip
    import tarfile
    out_dir.mkdir(parents=True, exist_ok=True)
    seen, done, saved = set(), set(), []
    resp = ResumableHTTP(url)
    with tarfile.open(fileobj=resp, mode="r|gz") as archive:
        for member in archive:
            rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            for d in list(seen - done):
                if parent != d:
                    done.add(d)
            required = {d for d in wanted_dirs if not d.startswith("data/benign/h1")}   # benign/h1 alerts are tiny and ~6 GB in; skip
            if required <= done:
                print("all wanted folders passed; stopping early", flush=True)
                break
            if parent not in wanted_dirs or not member.isfile():
                continue
            seen.add(parent)
            name = rel.replace("data/", "").replace("/", "__")
            src = archive.extractfile(member)
            n = 0
            with gzip.open(out_dir / f"{name}.gz", "wb") as out:
                for line in src:
                    out.write(line)
                    n += 1
                    if max_lines and n >= max_lines:
                        break
            saved.append(name)
            print(f"saved {rel}: {n} lines (offset {resp.offset/1e9:.2f} GB)", flush=True)
    resp.close()
    return saved


if __name__ == "__main__":
    main()
