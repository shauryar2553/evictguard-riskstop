"""Download the OTRF Security-Datasets Windows corpus and build a recording index.

Every atomic Windows dataset with a *host* archive is fetched together with its
metadata YAML (ATT&CK mappings, simulation tool, adversary console output).
Selected compound host archives (APT29 day 1/2, LSASS campaigns) can be added
with ``--include-compound``. Network-only (pcap) archives are skipped.

Output:
    data/otrf/raw/<dataset_id>/<archive>.zip
    data/otrf/metadata/<dataset_id>.yaml
    data/otrf/index.csv           one row per downloadable host archive
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

TREE_API = "https://api.github.com/repos/OTRF/Security-Datasets/git/trees/master?recursive=1"
RAW = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
COMPOUND_HOST = {
    # path -> (dataset_id, title, techniques); compound sets have no per-file YAML
    "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip": ("APT29-DAY1", "APT29 evaluation day 1 (manual)", ""),
    "datasets/compound/apt29/day2/apt29_evals_day2_manual.zip": ("APT29-DAY2", "APT29 evaluation day 2 (manual)", ""),
}


def _get(url: str, retries: int = 3, timeout: int = 60) -> bytes:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "EVICTGuard-corpus/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as exc:  # network hiccups
            last = exc
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Failed to fetch {url}: {last}")


def _host_links(meta: dict[str, Any]) -> list[str]:
    links = []
    for item in meta.get("files") or []:
        if str(item.get("type", "")).lower() == "host" and str(item.get("link", "")).endswith(".zip"):
            links.append(item["link"])
    return links


def _mappings(meta: dict[str, Any]) -> tuple[list[str], list[str]]:
    techniques, tactics = [], []
    for m in meta.get("attack_mappings") or []:
        tech = str(m.get("technique") or "").strip()
        sub = str(m.get("sub-technique") or "").strip()
        if tech:
            techniques.append(f"{tech}.{sub}" if sub and sub.lower() != "none" else tech)
        tactics.extend(str(t) for t in (m.get("tactics") or []))
    return sorted(set(techniques)), sorted(set(tactics))


def build_corpus(root: Path = Path("data/otrf"), include_compound: bool = False, limit: int | None = None) -> pd.DataFrame:
    root.mkdir(parents=True, exist_ok=True)
    tree = json.loads(_get(TREE_API))["tree"]
    yaml_paths = sorted(t["path"] for t in tree if t["path"].startswith("datasets/atomic/_metadata/") and t["path"].endswith(".yaml"))
    rows: list[dict[str, Any]] = []
    (root / "metadata").mkdir(exist_ok=True)
    for path in yaml_paths[: limit or None]:
        text = _get(RAW + path).decode("utf-8")
        meta = yaml.safe_load(text) or {}
        if "windows" not in [str(p).lower() for p in (meta.get("platform") or [])]:
            continue
        dataset_id = str(meta.get("id") or Path(path).stem)
        (root / "metadata" / f"{dataset_id}.yaml").write_text(text, encoding="utf-8")
        techniques, tactics = _mappings(meta)
        tools = meta.get("simulation", {}).get("tools") or [] if isinstance(meta.get("simulation"), dict) else []
        for link in _host_links(meta):
            rows.append({
                "dataset_id": dataset_id, "title": meta.get("title"), "kind": "atomic", "url": link,
                "techniques": ";".join(techniques), "tactics": ";".join(tactics),
                "tool": ";".join(str(t.get("name")) for t in tools if isinstance(t, dict)),
                "has_adversary_view": bool((meta.get("simulation") or {}).get("adversary_view")) if isinstance(meta.get("simulation"), dict) else False,
            })
    if include_compound:
        for path, (dataset_id, title, techniques) in COMPOUND_HOST.items():
            rows.append({"dataset_id": dataset_id, "title": title, "kind": "compound", "url": RAW + path, "techniques": techniques, "tactics": "", "tool": "", "has_adversary_view": False})

    index, skipped = [], []
    for row in rows:
        name = row["url"].rsplit("/", 1)[-1]
        target = root / "raw" / row["dataset_id"] / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            try:
                data = _get(row["url"], retries=2, timeout=180)
            except RuntimeError as exc:
                print(f"SKIP {row['dataset_id']} {name}: {exc}")
                skipped.append({**row, "reason": str(exc)})
                continue
            tmp = target.with_suffix(".part")
            tmp.write_bytes(data)
            try:
                with zipfile.ZipFile(tmp) as archive:
                    members = [n for n in archive.namelist() if not n.endswith("/")]
                if not members:
                    raise ValueError("empty archive")
            except Exception as exc:
                tmp.unlink(missing_ok=True)
                print(f"SKIP {row['dataset_id']} {name}: {exc}")
                continue
            tmp.replace(target)
        row["recording_id"] = f"{row['dataset_id']}:{Path(name).stem}"
        row["archive"] = str(target)
        row["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        row["size_bytes"] = target.stat().st_size
        index.append(row)
    frame = pd.DataFrame(index).drop_duplicates("recording_id")
    frame.to_csv(root / "index.csv", index=False)
    pd.DataFrame(skipped).to_csv(root / "skipped.csv", index=False)
    return frame


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", type=Path, default=Path("data/otrf"))
    p.add_argument("--include-compound", action="store_true")
    p.add_argument("--limit", type=int, default=None, help="only read the first N metadata files (testing)")
    a = p.parse_args()
    frame = build_corpus(a.root, a.include_compound, a.limit)
    print(f"{len(frame)} host recordings indexed ({frame['size_bytes'].sum()/1e6:.1f} MB) -> {a.root/'index.csv'}")


if __name__ == "__main__":
    main()
