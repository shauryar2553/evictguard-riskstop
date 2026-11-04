"""EVICTGuard v2: provenance- and prevalence-aware evidence retention.

Label-free. The scorer reads only fields a real SOC pipeline would have (the raw event and an
optional historical prevalence profile). It never reads ground-truth columns, injected-noise
markers (``is_synthetic``, ``noise_type``, ``dup_of``, ``source_record_id``) or episode metadata.

Pipeline per candidate set
  1. Parse   - actor process, parent, target object, command line from the raw event (Sysmon,
               Windows Security auditing and PowerShell logs; Win7 and Win10 schemas).
  2. Process graph - nodes = (host, pid, image); edges from Sysmon EID 1 / Security 4688.
  3. Process suspicion  S(p) = noisy-OR of
        location risk   executable in a user-writable path / LOLBin           (ATT&CK T1204, T1036, T1218)
        prevalence      image never or rarely seen in the historical profile  (NoDoze-style)
        lineage anomaly risky parent -> child (browser/Office/script host -> shell)
     then propagated down the process tree: S(child) >= decay * S(parent).
  4. Event value  V(e) = I(type) * [ w_a S(actor) + w_s sens(target) + w_n novel(actor,action,target)
                                     + w_c cmd_anomaly ] * first_occurrence
  5. Template de-duplication - events with the same (actor, event type, normalised target) form one
     group; one representative is kept (the earliest, most informative), the rest are redundant.
  6. Budgeted selection - a protected share of the top-valued evidence, then fill by value with an
     exploration reserve that round-robins over (host, channel, event type) strata.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd

from .selection import SelectionResult

# ------------------------------------------------------------------ domain priors (documented, label-free)
USER_WRITABLE = re.compile(r"\\(users|documents and settings)\\[^\\]+\\|\\appdata\\|\\temp\\|\\tmp\\|\\programdata\\|\\downloads\\|\\desktop\\|\\public\\|\\perflogs\\|\\recycle")
LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
           "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe",
           "msiexec.exe", "schtasks.exe", "at.exe", "sc.exe", "reg.exe", "net.exe", "net1.exe", "whoami.exe", "nltest.exe",
           "psexec.exe", "psexesvc.exe", "wmiprvse.exe", "odbcconf.exe", "forfiles.exe", "hh.exe", "control.exe", "vssadmin.exe",
           "wevtutil.exe", "auditpol.exe", "netsh.exe", "ntdsutil.exe", "esentutl.exe", "dsquery.exe", "adfind.exe", "bcdedit.exe"}
RISKY_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "acrord32.exe", "acrobat.exe",
                 "firefox.exe", "chrome.exe", "iexplore.exe", "msedge.exe", "plugin-container.exe", "wscript.exe", "cscript.exe",
                 "mshta.exe", "wmiprvse.exe", "w3wp.exe", "sqlservr.exe", "java.exe", "javaw.exe"}
SHELLISH = {"cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
            "schtasks.exe", "net.exe", "net1.exe", "whoami.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "sc.exe", "reg.exe"}
SENSITIVE_TARGET = re.compile(
    r"lsass|\\sam$|\\sam\\|\\security$|\\system32\\config\\|ntds\.dit|\\sysvol\\|wdigest|\\lsa\\|\\currentversion\\run|runonce|"
    r"\\services\\|\\winlogon|image file execution options|\\tasks\\|schtasks|\\startup\\|shadowcopy|vss|\\credentials\\|"
    r"\\vault\\|\\protect\\|\.kirbi|\\sekurlsa|security\.evtx|\\winevt\\|\\hosts$|firewallpolicy|\\policies\\|amsi|"
    r"\\microsoft\\windows defender|\\wbem\\|\\.ssh\\|\\cookies|login data|\\recent\\")
# Informativeness of an event type (Windows auditing / Sysmon semantics): actions > requests > bookkeeping.
TYPE_INFO = {
    ("sysmon", 1): 1.0, ("sysmon", 8): 1.0, ("sysmon", 10): 0.9, ("sysmon", 25): 1.0, ("sysmon", 3): 0.7, ("sysmon", 22): 0.6,
    ("sysmon", 11): 0.8, ("sysmon", 23): 0.8, ("sysmon", 26): 0.7, ("sysmon", 2): 0.8, ("sysmon", 12): 0.6, ("sysmon", 13): 0.8,
    ("sysmon", 14): 0.8, ("sysmon", 15): 0.8, ("sysmon", 17): 0.8, ("sysmon", 18): 0.7, ("sysmon", 19): 1.0, ("sysmon", 20): 1.0,
    ("sysmon", 21): 1.0, ("sysmon", 6): 0.9, ("sysmon", 7): 0.3, ("sysmon", 5): 0.2, ("sysmon", 9): 0.7,
    ("security", 4688): 1.0, ("security", 4663): 0.8, ("security", 4656): 0.4, ("security", 4658): 0.05, ("security", 4690): 0.05,
    ("security", 4660): 0.6, ("security", 4670): 0.6, ("security", 4689): 0.15, ("security", 5156): 0.6, ("security", 5158): 0.15,
    ("security", 5152): 0.2, ("security", 5157): 0.2, ("security", 4624): 0.6, ("security", 4625): 0.7, ("security", 4648): 0.8,
    ("security", 4672): 0.4, ("security", 4697): 1.0, ("security", 4698): 1.0, ("security", 4702): 0.9, ("security", 4720): 1.0,
    ("security", 4732): 1.0, ("security", 4662): 0.7, ("security", 4661): 0.5, ("security", 4673): 0.4, ("security", 4703): 0.3,
    ("security", 1102): 1.0, ("security", 4719): 1.0, ("security", 5140): 0.6, ("security", 5145): 0.6, ("security", 4769): 0.6,
    ("security", 4768): 0.6, ("security", 4776): 0.5, ("system", 7045): 1.0, ("system", 104): 1.0,
    ("powershell", 4104): 1.0, ("powershell", 4103): 0.5, ("powershell", 800): 0.5, ("powershell", 400): 0.4,
}
DEFAULT_WEIGHTS = {"actor": 0.35, "sensitivity": 0.15, "novelty": 0.20, "target_location": 0.30, "command": 0.10}
SYSTEM_LIBRARY = re.compile(r"^c:\\windows\\(winsxs|assembly|microsoft\.net|system32\\driverstore|inf|fonts|globalization|servicing|syswow64|system32)\\|^c:\\program files( \(x86\))?\\common files\\")
DEFAULT_PROCESS_WEIGHTS = {"location": 0.55, "prevalence": 0.55, "lineage": 0.6, "lolbin": 0.25}
DEFAULTS = {"decay": 0.85, "protected_fraction": 0.25, "exploration_fraction": 0.10}
_DEVICE = re.compile(r"^\\device\\harddiskvolume\d+\\")
_MASK = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d+")
_B64 = re.compile(r"[A-Za-z0-9+/=]{40,}")


def _norm_path(value: Any) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return ""
    text = str(value).strip().strip('"').lower()
    return _DEVICE.sub("c:\\\\", text)


def _base(path: str) -> str:
    return path.rsplit("\\", 1)[-1] if path else ""


def _pid(value: Any) -> int | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    text = str(value).strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(float(text))
    except ValueError:
        return None


def _family(channel: str) -> str:
    if "sysmon" in channel:
        return "sysmon"
    if "powershell" in channel:
        return "powershell"
    return channel


# ------------------------------------------------------------------ parsing
def parse_events(frame: pd.DataFrame) -> pd.DataFrame:
    """Actor / parent / target / command fields from the raw event JSON (vectorised where possible)."""
    raws = frame["original_json"].tolist() if "original_json" in frame else [None] * len(frame)
    host_col = frame["host"].astype(str).str.lower().str.split(".").str[0].tolist() if "host" in frame else [""] * len(frame)
    chan_col = frame["channel"].astype(str).str.lower().tolist() if "channel" in frame else [""] * len(frame)
    eid_col = pd.to_numeric(frame["event_id"], errors="coerce").fillna(-1).astype(int).tolist() if "event_id" in frame else [-1] * len(frame)
    out = defaultdict(list)
    for raw, host, chan, eid in zip(raws, host_col, chan_col, eid_col):
        try:
            j = json.loads(raw) if isinstance(raw, str) else {}
        except json.JSONDecodeError:
            j = {}
        fam = _family(chan)
        actor = parent = child = target = cmd = ""
        apid = ppid = cpid = None
        if fam == "sysmon":
            if eid in (8, 10):
                actor, apid = _norm_path(j.get("SourceImage")), _pid(j.get("SourceProcessId"))
                target = _norm_path(j.get("TargetImage"))
            else:
                actor, apid = _norm_path(j.get("Image")), _pid(j.get("ProcessId"))
            if eid == 1:
                child, cpid = actor, apid
                parent, ppid = _norm_path(j.get("ParentImage")), _pid(j.get("ParentProcessId"))
                actor, apid = parent, ppid
                target = child
                cmd = str(j.get("CommandLine") or "")
            elif eid not in (8, 10):
                target = _norm_path(j.get("TargetFilename") or j.get("TargetObject") or j.get("ImageLoaded") or j.get("QueryName")
                                    or j.get("PipeName") or ((str(j.get("DestinationIp") or "") + ":" + str(j.get("DestinationPort") or "")) if j.get("DestinationIp") else ""))
        elif fam == "security":
            if eid == 4688:
                child, cpid = _norm_path(j.get("NewProcessName")), _pid(j.get("NewProcessId"))
                parent, ppid = _norm_path(j.get("ParentProcessName")), _pid(j.get("ProcessId"))
                actor, apid, target = parent, ppid, child
                cmd = str(j.get("CommandLine") or "")
            else:
                actor = _norm_path(j.get("ProcessName") or j.get("Application") or j.get("NewProcessName"))
                apid = _pid(j.get("ProcessId") or j.get("ProcessID"))
                target = _norm_path(j.get("ObjectName") or j.get("ServiceName") or j.get("TaskName") or j.get("ShareName")
                                    or ((str(j.get("DestAddress") or "") + ":" + str(j.get("DestPort") or "")) if j.get("DestAddress") else "")
                                    or j.get("TargetUserName"))
        elif fam == "powershell":
            actor, apid = "powershell.exe", _pid(j.get("ExecutionProcessID"))
            text = str(j.get("ScriptBlockText") or j.get("Payload") or j.get("HostApplication") or "")
            cmd, target = text, text[:80].lower()
        else:
            actor = _norm_path(j.get("Image") or j.get("ProcessName"))
            apid = _pid(j.get("ProcessId"))
            target = _norm_path(j.get("ServiceName") or j.get("ImagePath") or j.get("ObjectName"))
        out["fam"].append(fam); out["eid"].append(eid); out["host"].append(host)
        out["actor"].append(actor); out["apid"].append(apid); out["parent"].append(parent); out["ppid"].append(ppid)
        out["child"].append(child); out["cpid"].append(cpid); out["target"].append(target); out["cmd"].append(cmd)
    parsed = pd.DataFrame(out, index=frame.index)
    # Win7 Security 4688 has no ParentProcessName: resolve the creator image from its PID on the same host.
    known = {}
    for h, pid, img in zip(parsed.host, parsed.apid, parsed.actor):
        if pid is not None and img:
            known.setdefault((h, pid), img)
    for h, pid, img in zip(parsed.host, parsed.cpid, parsed.child):
        if pid is not None and img:
            known.setdefault((h, pid), img)
    missing = parsed.actor.eq("") & parsed.apid.notna()
    if missing.any():
        fill = [known.get((h, int(pid)), "") for h, pid in zip(parsed.host[missing], parsed.apid[missing])]
        parsed.loc[missing, "actor"] = fill
        is_create = missing & parsed.child.ne("")
        parsed.loc[is_create, "parent"] = parsed.loc[is_create, "actor"]
    parsed["target_tpl"] = parsed.target.map(lambda t: _MASK.sub("#", t))
    return parsed


# ------------------------------------------------------------------ historical prevalence profile (NoDoze-style)
@dataclass
class PrevalenceProfile:
    images: Counter = field(default_factory=Counter)
    pairs: Counter = field(default_factory=Counter)        # (parent base, child base)
    actions: Counter = field(default_factory=Counter)      # (actor base, family, eid, target template)
    targets: Counter = field(default_factory=Counter)      # target template
    events: int = 0

    @classmethod
    def build(cls, frames: Iterable[pd.DataFrame]) -> "PrevalenceProfile":
        prof = cls()
        for frame in frames:
            p = parse_events(frame)
            prof.events += len(p)
            prof.images.update(_base(x) for x in pd.concat([p.actor, p.child]) if x)
            prof.pairs.update((_base(a), _base(b)) for a, b in zip(p.parent, p.child) if b)
            prof.actions.update(zip(p.actor.map(_base), p.fam, p.eid, p.target_tpl))
            prof.targets.update(t for t in p.target_tpl if t)
        return prof

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"images": list(self.images.items()), "pairs": [[list(k), v] for k, v in self.pairs.items()],
                                    "actions": [[list(k), v] for k, v in self.actions.items()], "targets": list(self.targets.items()),
                                    "events": self.events}))

    @classmethod
    def load(cls, path: Path) -> "PrevalenceProfile":
        d = json.loads(path.read_text())
        return cls(Counter(dict(d["images"])), Counter({tuple(k): v for k, v in d["pairs"]}),
                   Counter({tuple(k): v for k, v in d["actions"]}), Counter(dict(d["targets"])), d["events"])


def _rarity(count: int) -> float:
    """1 for never seen, decaying with historical count."""
    return 1.0 / (1.0 + math.log1p(count))


# ------------------------------------------------------------------ scoring
def _noisy_or(*terms: np.ndarray) -> np.ndarray:
    out = np.ones_like(terms[0], dtype=float)
    for t in terms:
        out *= 1.0 - np.clip(t, 0.0, 1.0)
    return 1.0 - out


def score_events(frame: pd.DataFrame, profile: PrevalenceProfile | None = None, weights: dict[str, float] | None = None,
                 process_weights: dict[str, float] | None = None, decay: float = DEFAULTS["decay"],
                 disable: set[str] | None = None) -> pd.DataFrame:
    """Return the parsed frame with feature columns and ``eg_value``. ``disable`` zeroes named features (ablation)."""
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    pw = {**DEFAULT_PROCESS_WEIGHTS, **(process_weights or {})}
    off = disable or set()
    p = parse_events(frame)
    local = profile is None
    if local:  # fall back to within-candidate-set prevalence
        profile = PrevalenceProfile()
        profile.images.update(_base(x) for x in pd.concat([p.actor, p.child]) if x)
        profile.pairs.update((_base(a), _base(b)) for a, b in zip(p.parent, p.child) if b)
        profile.actions.update(zip(p.actor.map(_base), p.fam, p.eid, p.target_tpl))

    # --- process nodes and edges
    def key(host, pid, image):
        return f"{host}|{pid}|{_base(image)}" if image else ""
    p["actor_key"] = [key(h, a, i) for h, a, i in zip(p.host, p.apid, p.actor)]
    child_keys = [key(h, c, i) for h, c, i in zip(p.host, p.cpid, p.child)]
    parent_of: dict[str, str] = {}
    pair_of: dict[str, tuple[str, str]] = {}
    for ck, ak, par, chi in zip(child_keys, p.actor_key, p.parent, p.child):
        if ck and ak:
            parent_of.setdefault(ck, ak)
            pair_of.setdefault(ck, (_base(par), _base(chi)))
    images = {k: k.rsplit("|", 1)[-1] for k in set(p.actor_key) | set(parent_of) if k}
    full_path: dict[str, str] = {}
    for k, path in zip(p.actor_key, p.actor):
        if k and path:
            full_path.setdefault(k, path)
    for k, path in zip(child_keys, p.child):
        if k and path:
            full_path.setdefault(k, path)

    prior: dict[str, float] = {}
    for k, base in images.items():
        path = full_path.get(k, base)
        loc = 0.0 if "location" in off else (1.0 if USER_WRITABLE.search(path) else 0.0)
        lol = 0.0 if "lolbin" in off else (1.0 if base in LOLBINS else 0.0)
        prev = 0.0 if "prevalence" in off else _rarity(profile.images.get(base, 0))
        lin = 0.0
        if "lineage" not in off and k in pair_of:
            par, chi = pair_of[k]
            risky = par in RISKY_PARENTS and (chi in SHELLISH or bool(USER_WRITABLE.search(path)))
            lin = max(1.0 if risky else 0.0, _rarity(profile.pairs.get((par, chi), 0)) * 0.5)
        prior[k] = float(_noisy_or(np.array([pw["location"] * loc]), np.array([pw["prevalence"] * prev]),
                                   np.array([pw["lineage"] * lin]), np.array([pw["lolbin"] * lol]))[0])
    # lineage propagation: suspicion flows from parent to child
    susp = dict(prior)
    if "propagation" not in off:
        for _ in range(8):
            changed = False
            for child, par in parent_of.items():
                inherited = decay * susp.get(par, 0.0)
                if inherited > susp.get(child, 0.0) + 1e-9:
                    susp[child] = inherited
                    changed = True
            if not changed:
                break
    p["f_actor"] = [susp.get(k, 0.0) for k in p.actor_key]
    # a process-creation event is about the child as much as the parent
    p["f_actor"] = np.maximum(p.f_actor.to_numpy(), [susp.get(ck, 0.0) if ck else 0.0 for ck in child_keys])

    p["f_type"] = [TYPE_INFO.get((f if f in ("sysmon", "security", "powershell", "system") else f, e), 0.4) for f, e in zip(p.fam, p.eid)]
    p["f_sens"] = 0.0 if "sensitivity" in off else p.target.map(lambda t: 1.0 if t and SENSITIVE_TARGET.search(t) else 0.0)
    if "novelty" in off:
        p["f_novel"] = 0.0
    else:
        act = [_rarity(profile.actions.get((_base(a), f, e, t), 0)) for a, f, e, t in zip(p.actor, p.fam, p.eid, p.target_tpl)]
        p["f_novel"] = np.where(p.target_tpl.eq(""), 0.3, act)
    # Target location: staging/collection in user-writable locations is evidential (T1074, T1005, T1105);
    # reads of OS library stores are routine loader activity.
    if "target_location" in off:
        p["f_tloc"] = 0.0
    else:
        is_path = p.target.str.contains(r"^[a-z]:\\", regex=True)
        p["f_tloc"] = np.where(~is_path, 0.5, np.where(p.target.map(lambda t: bool(USER_WRITABLE.search(t))), 1.0,
                                                      np.where(p.target.map(lambda t: bool(SYSTEM_LIBRARY.search(t))), 0.0, 0.4)))
    if "command" in off:
        p["f_cmd"] = 0.0
    else:
        length = p.cmd.str.len().fillna(0).to_numpy()
        b64 = p.cmd.map(lambda c: 1.0 if c and _B64.search(c) else 0.0).to_numpy()
        p["f_cmd"] = np.clip(0.5 * b64 + 0.5 * np.clip((length - 120) / 400, 0, 1), 0, 1)

    # first occurrence of (actor, type, target template) in time = the action itself; repeats are redundant
    order = np.argsort(pd.to_datetime(frame["timestamp"], errors="coerce", utc=True).to_numpy(), kind="stable") if "timestamp" in frame else np.arange(len(p))
    # Exact-action groups (masked templates are used only for history lookups: masking digits would merge
    # genuinely different objects such as api-ms-win-core-file-l1-1-0.dll and ...-l1-2-0.dll).
    p["_tpl_group"] = p.actor_key.astype(str) + "§" + p.fam + "§" + p.eid.astype(str) + "§" + p.target
    ranked = pd.Series(np.empty(len(p), dtype=int), index=p.index)
    ranked.iloc[order] = np.arange(len(p))
    p["_time_rank"] = ranked
    p["_group_size"] = p.groupby("_tpl_group")["_tpl_group"].transform("size")
    p["f_nonredundant"] = 1.0 if "redundancy" in off else 1.0 / np.sqrt(p._group_size.to_numpy())

    core = (w["actor"] * p.f_actor + w["sensitivity"] * p.f_sens + w["novelty"] * p.f_novel * np.maximum(p.f_actor, 0.25)
            + w["target_location"] * p.f_tloc * np.maximum(p.f_actor, 0.25) + w["command"] * p.f_cmd)
    type_weight = 1.0 if "type" in off else p.f_type
    p["eg_value"] = np.clip(core * type_weight, 0, None) * (0.5 + 0.5 * p.f_nonredundant)
    return p


def select_evictguard_v2(data: pd.DataFrame, capacity: int, *, profile: PrevalenceProfile | None = None,
                         weights: dict[str, float] | None = None, process_weights: dict[str, float] | None = None,
                         protected_fraction: float = DEFAULTS["protected_fraction"], exploration_fraction: float = DEFAULTS["exploration_fraction"],
                         decay: float = DEFAULTS["decay"], disable: set[str] | None = None, seed: int = 17) -> SelectionResult:
    if capacity < 0:
        raise ValueError("capacity must be non-negative")
    frame = data.reset_index(drop=True)
    scored = score_events(frame, profile, weights, process_weights, decay, disable)
    # one representative per template group: highest value, then earliest
    rep_order = scored.sort_values(["_tpl_group", "eg_value", "_time_rank"], ascending=[True, False, True], kind="stable")
    reps = rep_order.drop_duplicates("_tpl_group", keep="first")
    redundant_idx = scored.index.difference(reps.index)
    ranked = reps.sort_values(["eg_value", "_time_rank"], ascending=[False, True], kind="stable")
    limit = min(capacity, len(ranked))
    n_explore = int(round(limit * exploration_fraction))
    main = ranked.head(limit - n_explore)
    chosen = list(main.index)
    if n_explore:
        rest = ranked.loc[~ranked.index.isin(chosen)]
        strata = rest.groupby([rest.host, rest.fam, rest.eid], sort=True).groups
        queues = [list(idx) for _, idx in sorted(strata.items(), key=lambda kv: str(kv[0]))]
        rng = np.random.default_rng(seed)
        rng.shuffle(queues)
        while len(chosen) < limit and any(queues):
            for q in queues:
                if q and len(chosen) < limit:
                    chosen.append(q.pop(0))
    protected_n = int(math.ceil(limit * protected_fraction))
    selected = frame.loc[chosen].copy()
    selected["eg_value"] = scored.loc[chosen, "eg_value"].to_numpy()
    sid = frame.get("record_id", pd.Series(frame.index.astype(str), index=frame.index)).astype(str)
    protected_ids = tuple(sid.loc[list(main.index[:protected_n])])
    evicted_ids = tuple(sid.loc[ranked.index.difference(chosen)])
    return SelectionResult("evictguard_v2", selected, scored, protected_ids, tuple(sid.loc[redundant_idx]), evicted_ids)


def action_keys(frame: pd.DataFrame) -> np.ndarray:
    """Evidence unit for evaluation: (host, actor process, log family, event id, exact target).

    Two records with the same key describe the identical action (e.g. the same file read by the
    same process logged several times), so keeping either preserves the same evidence. Used for
    the action-level recall metric, applied identically to every method.
    """
    p = parse_events(frame.reset_index(drop=True))
    return (p.host + "|" + p.apid.astype(str) + "|" + p.actor.map(_base) + "|" + p.fam + "|" + p.eid.astype(str) + "|" + p.target).to_numpy()
