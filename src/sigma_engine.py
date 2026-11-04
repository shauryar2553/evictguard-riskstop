"""Minimal, transparent Sigma rule evaluator for flattened Windows event tables.

Supports the subset of the Sigma specification used by the large majority of
SigmaHQ Windows rules:

* logsource ``category`` (Sysmon / PowerShell categories) and ``service``
  (security, system, sysmon, powershell, ...), mapped to Channel + EventID;
* field maps (AND), value lists (OR), lists of maps (OR), ``null`` values;
* modifiers ``contains``, ``startswith``, ``endswith``, ``all``, ``re``
  (with ``i``/``m``/``s``), ``windash``, ``exists``, ``cidr`` (IPv4/IPv6),
  and numeric ``gt``/``gte``/``lt``/``lte``;
* conditions with ``and``/``or``/``not``/parentheses, ``1 of x*``,
  ``all of x*``, ``1 of them``, ``all of them``.

Rules using anything else (keyword lists, base64offset, fieldref, expand,
correlation rules, ...) are *skipped and reported*, never approximated.
Matching is case-insensitive except for ``re`` without the ``i`` flag, as in
the Sigma specification.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd
import yaml

SYSMON = "microsoft-windows-sysmon/operational"
PS_OP = "microsoft-windows-powershell/operational"
PS_CLASSIC = "windows powershell"
CATEGORY_MAP: dict[str, tuple[str, set[int] | None]] = {
    "process_creation": (SYSMON, {1}),
    "file_change": (SYSMON, {2}),
    "network_connection": (SYSMON, {3}),
    "sysmon_status": (SYSMON, {4, 16}),
    "driver_load": (SYSMON, {6}),
    "image_load": (SYSMON, {7}),
    "create_remote_thread": (SYSMON, {8}),
    "raw_access_thread": (SYSMON, {9}),
    "process_access": (SYSMON, {10}),
    "file_event": (SYSMON, {11}),
    "registry_event": (SYSMON, {12, 13, 14}),
    "registry_add": (SYSMON, {12}),
    "registry_delete": (SYSMON, {12}),
    "registry_set": (SYSMON, {13}),
    "registry_rename": (SYSMON, {14}),
    "create_stream_hash": (SYSMON, {15}),
    "pipe_created": (SYSMON, {17, 18}),
    "wmi_event": (SYSMON, {19, 20, 21}),
    "dns_query": (SYSMON, {22}),
    "file_delete": (SYSMON, {23, 26}),
    "process_tampering": (SYSMON, {25}),
    "sysmon_error": (SYSMON, {255}),
    "ps_module": (PS_OP, {4103}),
    "ps_script": (PS_OP, {4104}),
    "ps_classic_start": (PS_CLASSIC, {400}),
    "ps_classic_provider_start": (PS_CLASSIC, {600}),
    "ps_classic_script": (PS_CLASSIC, {800}),
}
SERVICE_MAP: dict[str, str] = {
    "security": "security",
    "system": "system",
    "sysmon": SYSMON,
    "powershell": PS_OP,
    "powershell-classic": PS_CLASSIC,
    "wmi": "microsoft-windows-wmi-activity/operational",
    "taskscheduler": "microsoft-windows-taskscheduler/operational",
    "application": "application",
    "windefend": "microsoft-windows-windows defender/operational",
    "firewall-as": "microsoft-windows-windows firewall with advanced security/firewall",
    "bits-client": "microsoft-windows-bits-client/operational",
    "dns-client": "microsoft-windows-dns client events/operational",
    "terminalservices-localsessionmanager": "microsoft-windows-terminalservices-localsessionmanager/operational",
    "smbclient-security": "microsoft-windows-smbclient/security",
    "codeintegrity-operational": "microsoft-windows-codeintegrity/operational",
    "applocker": "microsoft-windows-applocker/exe and dll",
    "ntlm": "microsoft-windows-ntlm/operational",
    "driver-framework": "microsoft-windows-driverframeworks-usermode/operational",
}
# Sigma field name -> alternative column names in OTRF's NXLog-flattened JSON.
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "provider_name": ("SourceName", "ProviderName"),
    "eventtype": ("EventTypeOrignal", "EventType"),  # NXLog overwrites Sysmon's EventType
    "computer": ("Hostname", "host"),
    "computername": ("Hostname", "host"),
}
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "windash", "exists", "cidr", "gt", "gte", "lt", "lte"}
DASHES = ["-", "/", "–", "—", "―"]


class UnsupportedRule(Exception):
    pass


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    level: str
    status: str
    path: str
    tags: list[str]
    channel: str
    event_ids: set[int] | None
    detection: dict[str, Any]
    condition: str

    @property
    def techniques(self) -> list[str]:
        return sorted({t.split(".", 1)[1].upper() for t in self.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})

    @property
    def tactics(self) -> list[str]:
        known = {"reconnaissance", "resource_development", "initial_access", "execution", "persistence", "privilege_escalation",
                 "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "command_and_control",
                 "exfiltration", "impact"}
        return sorted({t.split(".", 1)[1].replace("-", "_") for t in self.tags if t.startswith("attack.") and t.split(".", 1)[1].replace("-", "_") in known})


@dataclass
class LoadReport:
    loaded: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


def load_rules(root: str | Path, statuses: Iterable[str] = ("stable", "test", "experimental")) -> tuple[list[SigmaRule], LoadReport]:
    report = LoadReport()
    rules: list[SigmaRule] = []
    allowed = set(statuses)
    for path in sorted(Path(root).rglob("*.yml")):
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except Exception:
            report.skip("yaml_error"); continue
        if len(docs) != 1 or not isinstance(docs[0], dict):
            report.skip("multi_document_or_correlation"); continue
        doc = docs[0]
        if doc.get("status", "experimental") not in allowed:
            report.skip(f"status_{doc.get('status')}"); continue
        ls = doc.get("logsource") or {}
        if str(ls.get("product", "")).lower() != "windows":
            report.skip("not_windows_product"); continue
        if ls.get("category"):
            if ls["category"] not in CATEGORY_MAP:
                report.skip(f"category_unmapped"); continue
            channel, ids = CATEGORY_MAP[ls["category"]]
        elif ls.get("service"):
            if ls["service"] not in SERVICE_MAP:
                report.skip("service_unmapped"); continue
            channel, ids = SERVICE_MAP[ls["service"]], None
        else:
            report.skip("no_logsource"); continue
        det = dict(doc.get("detection") or {})
        cond = det.pop("condition", None)
        det.pop("timeframe", None)
        if isinstance(cond, list):
            if len(cond) != 1:
                report.skip("multiple_conditions"); continue
            cond = cond[0]
        if not isinstance(cond, str) or "|" in cond:
            report.skip("aggregation_condition"); continue
        try:
            _validate_detection(det)
        except UnsupportedRule as exc:
            report.skip(str(exc)); continue
        rules.append(SigmaRule(str(doc.get("id") or path.stem), str(doc.get("title", "")), str(doc.get("level", "medium")).lower(),
                               str(doc.get("status", "")), str(path), [str(t).lower() for t in doc.get("tags") or []], channel, ids, det, cond))
        report.loaded += 1
    return rules, report


def _validate_detection(det: dict[str, Any]) -> None:
    for name, value in det.items():
        items = value if isinstance(value, list) else [value]
        if isinstance(value, list) and value and not all(isinstance(v, dict) for v in value):
            raise UnsupportedRule("keyword_search")
        if not isinstance(value, (dict, list)):
            raise UnsupportedRule("keyword_search")
        for item in items:
            for key in item:
                mods = str(key).split("|")[1:]
                bad = [m for m in mods if m not in SUPPORTED_MODIFIERS]
                if bad:
                    raise UnsupportedRule(f"modifier_{bad[0]}")


# ---------------------------------------------------------------- matching
class _Columns:
    """Lazily materialised, lower-cased string views of event columns."""

    def __init__(self, frame: pd.DataFrame):
        self.frame = frame
        self.lower_map = {str(c).lower(): c for c in frame.columns}
        self.cache: dict[tuple[str, bool], pd.Series | None] = {}

    def get(self, name: str, lower: bool = True) -> pd.Series | None:
        key = (name.lower(), lower)
        if key in self.cache:
            return self.cache[key]
        candidates = [name, *FIELD_ALIASES.get(name.lower(), ())]
        series = None
        for cand in candidates:
            col = self.lower_map.get(cand.lower())
            if col is not None:
                series = self.frame[col]
                break
        if series is not None and not series.notna().any():
            series = None  # an all-empty column behaves like a missing field
        if series is not None:
            present = series.notna()
            text = series.where(present, None).map(_to_text, na_action="ignore")
            series = text.str.lower() if lower else text
        self.cache[key] = series
        return series


def _to_text(v: Any) -> str:
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _glob_regex(value: str) -> str:
    # Sigma wildcards: * and ?; backslash escapes them.
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1])); i += 2; continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return "".join(out)


def _match_value(series: pd.Series, raw_value: Any, mods: list[str], numeric: pd.Series | None) -> pd.Series:
    n = len(series)
    if raw_value is None:
        return series.isna() | (series == "")
    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        if numeric is None:
            return pd.Series(False, index=series.index)
        v = float(raw_value)
        op = next(m for m in mods if m in ("gt", "gte", "lt", "lte"))
        return {"gt": numeric > v, "gte": numeric >= v, "lt": numeric < v, "lte": numeric <= v}[op].fillna(False)
    if "cidr" in mods:
        net = ipaddress.ip_network(str(raw_value), strict=False)
        def in_net(x: Any) -> bool:
            try:
                return ipaddress.ip_address(str(x)) in net
            except ValueError:
                return False
        return series.fillna("").map(in_net).astype(bool)
    if "re" in mods:
        flags = (re.IGNORECASE if "i" in mods else 0) | (re.MULTILINE if "m" in mods else 0) | (re.DOTALL if "s" in mods else 0)
        pattern = re.compile(str(raw_value), flags)
        return series.fillna("").map(lambda x: bool(x) and bool(pattern.search(x))).astype(bool)
    text = _to_text(raw_value).lower()
    variants = [text]
    if "windash" in mods:
        variants = sorted({text} | {re.sub(r"(^|\s)-", lambda m, d=d: m.group(1) + d, text) for d in DASHES})
    result = pd.Series(False, index=series.index)
    for variant in variants:
        has_wild = "*" in variant or "?" in variant
        if "contains" in mods:
            core = _glob_regex(variant) if has_wild else re.escape(variant)
            pat = core
        elif "startswith" in mods:
            pat = "^" + (_glob_regex(variant) if has_wild else re.escape(variant))
        elif "endswith" in mods:
            pat = (_glob_regex(variant) if has_wild else re.escape(variant)) + "$"
        else:
            if not has_wild:
                result |= (series == variant).fillna(False)
                continue
            pat = "^" + _glob_regex(variant) + "$"
        result |= series.str.contains(pat, regex=True, na=False)
    return result


def _eval_map(cols: _Columns, item: dict[str, Any], index: pd.Index) -> pd.Series:
    mask = pd.Series(True, index=index)
    for key, values in item.items():
        parts = str(key).split("|")
        name, mods = parts[0], parts[1:]
        if "exists" in mods:
            series = cols.get(name)
            exists = series is not None and series.notna() & (series != "")
            want = bool(values)
            if series is None:
                col_mask = pd.Series(not want, index=index)
            else:
                col_mask = exists if want else ~exists
            mask &= col_mask
            continue
        case_sensitive_re = "re" in mods and "i" not in mods
        series = cols.get(name, lower=not case_sensitive_re)
        vals = values if isinstance(values, list) else [values]
        if series is None:
            # Missing column: only a null-match can succeed.
            mask &= pd.Series(any(v is None for v in vals), index=index)
            continue
        numeric = pd.to_numeric(series, errors="coerce") if any(m in mods for m in ("gt", "gte", "lt", "lte")) else None
        if "re" in mods and "i" in mods:
            series = cols.get(name, lower=False)
        submasks = [_match_value(series, v, mods, numeric) for v in vals]
        if not submasks:
            continue
        combined = submasks[0].copy()
        for sm in submasks[1:]:
            combined = (combined & sm) if "all" in mods else (combined | sm)
        mask &= combined
    return mask


def _eval_identifier(cols: _Columns, value: Any, index: pd.Index) -> pd.Series:
    if isinstance(value, dict):
        return _eval_map(cols, value, index)
    out = pd.Series(False, index=index)
    for item in value:
        out |= _eval_map(cols, item, index)
    return out


_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class _Condition:
    def __init__(self, text: str, idents: dict[str, pd.Series]):
        self.tokens = [t for t in _TOKEN.findall(text) if t.strip()]
        self.pos = 0
        self.idents = idents

    def parse(self) -> pd.Series:
        result = self._or()
        if self.pos != len(self.tokens):
            raise UnsupportedRule("condition_parse")
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]; self.pos += 1; return tok

    def _or(self) -> pd.Series:
        left = self._and()
        while self._peek() == "or":
            self._next(); left = left | self._and()
        return left

    def _and(self) -> pd.Series:
        left = self._not()
        while self._peek() == "and":
            self._next(); left = left & self._not()
        return left

    def _not(self) -> pd.Series:
        if self._peek() == "not":
            self._next(); return ~self._not()
        return self._atom()

    def _atom(self) -> pd.Series:
        tok = self._peek()
        if tok is None:
            raise UnsupportedRule("condition_parse")
        if tok == "(":
            self._next(); value = self._or()
            if self._peek() != ")":
                raise UnsupportedRule("condition_parse")
            self._next(); return value
        if tok in ("1", "all", "any") and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            quant = self._next().lower(); self._next(); target = self._next()
            names = list(self.idents) if target.lower() == "them" else [n for n in self.idents if fnmatch.fnmatchcase(n, target)]
            if not names:
                raise UnsupportedRule("condition_unknown_identifier")
            masks = [self.idents[n] for n in names]
            out = masks[0].copy()
            for m in masks[1:]:
                out = (out & m) if quant == "all" else (out | m)
            return out
        name = self._next()
        if name not in self.idents:
            raise UnsupportedRule("condition_unknown_identifier")
        return self.idents[name]


def _channel_mask(frame: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    channel = frame["Channel"].astype(str).str.lower() if "Channel" in frame else pd.Series("", index=frame.index)
    event_id = pd.to_numeric(frame["EventID"], errors="coerce") if "EventID" in frame else pd.Series(np.nan, index=frame.index)
    return channel, event_id


def evaluate(frame: pd.DataFrame, rules: list[SigmaRule]) -> tuple[pd.DataFrame, dict[str, int]]:
    """Return one row per (event index, rule) hit plus per-reason runtime skip counts."""
    channel, event_id = _channel_mask(frame)
    hits: list[pd.DataFrame] = []
    runtime_skips: dict[str, int] = {}
    groups: dict[tuple[str, tuple[int, ...] | None], list[SigmaRule]] = {}
    for rule in rules:
        groups.setdefault((rule.channel, tuple(sorted(rule.event_ids)) if rule.event_ids else None), []).append(rule)
    for (chan, ids), group in groups.items():
        mask = channel == chan
        if ids:
            mask &= event_id.isin(ids)
        if not mask.any():
            continue
        subset = frame.loc[mask]
        cols = _Columns(subset)
        for rule in group:
            try:
                idents = {name: _eval_identifier(cols, value, subset.index) for name, value in rule.detection.items()}
                matched = _Condition(rule.condition, idents).parse()
            except UnsupportedRule as exc:
                runtime_skips[str(exc)] = runtime_skips.get(str(exc), 0) + 1
                continue
            except (re.error, ValueError, TypeError):
                runtime_skips["evaluation_error"] = runtime_skips.get("evaluation_error", 0) + 1
                continue
            idx = matched[matched].index
            if len(idx):
                hits.append(pd.DataFrame({"row": idx, "rule_id": rule.rule_id, "rule_title": rule.title, "rule_level": rule.level,
                                          "rule_techniques": ";".join(rule.techniques), "rule_tactics": ";".join(rule.tactics)}))
    columns = ["row", "rule_id", "rule_title", "rule_level", "rule_techniques", "rule_tactics"]
    return (pd.concat(hits, ignore_index=True) if hits else pd.DataFrame(columns=columns)), runtime_skips
