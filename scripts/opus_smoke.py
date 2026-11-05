"""Smoke test + cost projection for the Claude Opus investigator: runs 4 real investigations, reads token usage from the
response cache and extrapolates to the full benchmark (528 alerts, all noise conditions, both memories)."""
import json, time
from pathlib import Path
import pandas as pd
from src.run_alert_riskstop import _one, _profile

PRICE_IN, PRICE_OUT = 4.0, 20.0          # USD per million tokens, claude-opus-5-5
al = pd.read_csv("data/alert_bench/alerts.csv", parse_dates=["time"])
pick = pd.concat([al[al.gold == "ATTACK"].head(2), al[al.gold == "BENIGN"].head(2)])
_profile()
t0, start = time.time(), time.time()
for a in pick.to_dict("records"):
    r = _one((a, "none", "evictguard", 12, 256, "llm_opus"))
    log = (r or {}).get("llm_log") or []
    print(a["alert_id"], a["gold"], "error:" + r["error"] if r and "error" in r else f"calls={len(log)} ok={sum(x['ok'] for x in log)} "
          f"served_by={sorted({str(x.get('served_by')) for x in log})} last_score={log[-1]['score'] if log else None}")
new = [json.loads(p.read_text()) for p in Path("data/llm_cache").glob("*.json") if p.stat().st_mtime >= start]
new = [o for o in new if "usage" in o]
if new:
    i = sum(o["usage"]["in"] for o in new) / len(new); o = sum(o["usage"]["out"] for o in new) / len(new)
    per_call = (i * PRICE_IN + o * PRICE_OUT) / 1e6
    total_calls = 2230 * 9.6
    print(f"\n{len(new)} API calls, {time.time()-t0:.0f}s; avg {i:.0f} input / {o:.0f} output tokens; ${per_call:.4f} per call")
    print(f"projected full run (~{total_calls:.0f} calls): ${per_call*total_calls:.0f} (EVICTGuard memory only: ${per_call*total_calls/2:.0f})")
