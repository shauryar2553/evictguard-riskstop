"""Shared JSONL/CSV helpers and deterministic serialization."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any

def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()

def load_records(path: str | Path) -> list[dict[str, Any]]:
    """Load JSON, JSONL, CSV, or ZIP containing a supported event file."""
    import csv, zipfile
    source = Path(path)
    suffix = source.suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(source) as archive:
            # Skip macOS resource-fork entries (__MACOSX/._name.json): they are binary, not event data.
            names = [n for n in archive.namelist() if Path(n).suffix.lower() in {".jsonl", ".ndjson", ".json", ".csv"}
                     and not n.startswith("__MACOSX/") and not Path(n).name.startswith("._")]
            if not names: raise ValueError("ZIP contains no JSON/JSONL/CSV data file")
            # OTRF scenario archives contain one JSONL event file.
            name = sorted(names)[0]
            data = archive.read(name).decode("utf-8-sig")
            inner_suffix = Path(name).suffix.lower()
        return _parse_text(data, inner_suffix)
    return _parse_text(source.read_text(encoding="utf-8-sig"), suffix)

def _parse_text(data: str, suffix: str) -> list[dict[str, Any]]:
    import csv, io
    if suffix in {".jsonl", ".ndjson"}:
        records=[]
        for line_no, line in enumerate(data.splitlines(), 1):
            if not line.strip(): continue
            try:
                item=json.loads(line)
                if not isinstance(item, dict): raise ValueError("record is not a JSON object")
                records.append(item)
            except (json.JSONDecodeError, ValueError) as exc:
                records.append({"__parse_error__": f"line {line_no}: {exc}", "__raw_line__": line})
        return records
    if suffix == ".json":
        try:
            parsed=json.loads(data)
        except json.JSONDecodeError:
            # Some documented JSONL archives use a .json filename suffix.
            return _parse_text(data, ".jsonl")
        if isinstance(parsed, dict): return [parsed]
        if isinstance(parsed, list) and all(isinstance(x,dict) for x in parsed): return parsed
        raise ValueError("JSON must contain an object or a list of objects")
    if suffix == ".csv": return list(csv.DictReader(io.StringIO(data)))
    raise ValueError(f"Unsupported file format: {suffix or '(no extension)'}")

def first(record: dict[str, Any], candidates: tuple[str,...]) -> Any:
    lower={str(k).lower():v for k,v in record.items()}
    return next((lower[k.lower()] for k in candidates if k.lower() in lower and lower[k.lower()] not in (None,"")), None)
