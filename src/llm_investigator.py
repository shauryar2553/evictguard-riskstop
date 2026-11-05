"""LLM investigator (proposal slide 12): reads the bounded evidence context, forms a hypothesis, picks the next query.

Provider-agnostic: any OpenAI-compatible chat endpoint.
    LLM_BASE_URL   default http://127.0.0.1:11434/v1   (local Ollama; free, private, reproducible)
    LLM_MODEL      default qwen2.5:7b-instruct
    LLM_API_KEY    optional (Groq, OpenRouter, Anthropic-compatible gateways, ...)

Design for reliability and reproducibility
  * The LLM chooses from a NUMBERED list of valid candidate queries (the open leads), so it can't issue a
    malformed query. If its output is invalid, the rule-based investigator's choice is used and the fallback is logged.
  * Output is JSON: {"hypothesis": str, "attack_likelihood": 0..1, "choice": int}. attack_likelihood is exposed to
    RISKSTOP as a state feature; the hypothesis goes into the decision certificate.
  * temperature 0, and every response is cached on disk by a hash of (model, prompt): reruns are free and identical.
  * The prompt contains only telemetry and alert metadata, never labels.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.request
from pathlib import Path

import pandas as pd

from .investigation import HeuristicInvestigator, Investigator, Query

CACHE = Path("data/llm_cache")
SYSTEM = ("You are a SOC analyst investigating a security alert on a Windows host using endpoint telemetry. "
          "You see a bounded evidence context and a numbered list of queries you can run next. "
          "Decide which query most efficiently confirms or rules out malicious activity. "
          "Answer ONLY with JSON: {\"hypothesis\": \"<one sentence>\", \"attack_likelihood\": <number 0-1>, \"choice\": <query number>}.")


class LLMClient:
    def __init__(self, base_url: str | None = None, model: str | None = None, api_key: str | None = None, timeout: int = 180):
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL", "http://127.0.0.1:11434/v1")).rstrip("/")
        self.model = model or os.environ.get("LLM_MODEL", "qwen2.5:7b-instruct")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.timeout = timeout
        self.calls = self.cache_hits = 0
        CACHE.mkdir(parents=True, exist_ok=True)

    def chat(self, system: str, user: str, max_tokens: int = 160) -> str:
        key = hashlib.sha256(json.dumps([self.model, system, user, max_tokens]).encode()).hexdigest()
        path = CACHE / f"{key}.json"
        if path.exists():
            self.cache_hits += 1
            return json.loads(path.read_text())["content"]
        body = {"model": self.model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0, "max_tokens": max_tokens, "response_format": {"type": "json_object"}}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        last = None
        for attempt in range(4):
            try:
                req = urllib.request.Request(f"{self.base_url}/chat/completions", data=json.dumps(body).encode(), headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    content = json.loads(resp.read())["choices"][0]["message"]["content"]
                path.write_text(json.dumps({"model": self.model, "content": content}))
                self.calls += 1
                return content
            except Exception as exc:   # rate limits / transient errors
                last = exc
                time.sleep(5 * (attempt + 1))
        raise RuntimeError(f"LLM call failed: {last}")


def _evidence_lines(ctx: pd.DataFrame, n: int = 20) -> list[str]:
    names = {(1): "process created", 3: "network connection", 5: "process ended", 7: "module loaded", 10: "process access",
             11: "file write", 13: "registry set", 4663: "object access", 4688: "process created", 5156: "network allowed"}
    top = ctx.sort_values("eg_value", ascending=False).head(n).sort_values("timestamp")
    out = []
    for r in top.itertuples():
        proc = (r.actor or r.child or "?").rsplit("\\", 1)[-1]
        tgt = str(r.target)[-90:]
        out.append(f"{str(r.timestamp)[11:19]} {proc} | {names.get(int(r.eid), f'event {r.eid}')} | {tgt}")
    return out


class AnthropicClient:
    """Claude via the official Anthropic SDK (key from ANTHROPIC_API_KEY; never stored in the repo).

    * model claude-opus-5-5 (override with CLAUDE_MODEL); effort 'low' (CLAUDE_EFFORT) because each call is a short
      choose-a-query decision. Opus 5.5 always thinks and accepts no temperature, so the disk cache is what makes reruns identical.
    * Structured output (JSON schema) guarantees parseable answers.
    * Server-side refusal fallback ('default'): if a safety classifier declines a call, another Claude model answers it.
      The serving model is recorded with every response so such calls can be counted/excluded.
    """

    SCHEMA = {"type": "object", "additionalProperties": False, "required": ["hypothesis", "attack_likelihood", "choice"],
              "properties": {"hypothesis": {"type": "string"}, "attack_likelihood": {"type": "number"}, "choice": {"type": "integer"}}}

    def __init__(self, model: str | None = None, effort: str | None = None):
        import anthropic
        self.model = model or os.environ.get("CLAUDE_MODEL", "claude-opus-5-5")
        self.effort = effort or os.environ.get("CLAUDE_EFFORT", "low")
        self.client = anthropic.Anthropic(max_retries=8, timeout=120)
        self.calls = self.cache_hits = 0
        self.usage = {"input": 0, "output": 0}
        self.last_model = None
        CACHE.mkdir(parents=True, exist_ok=True)

    def chat(self, system: str, user: str, max_tokens: int = 4000) -> str:
        key = hashlib.sha256(json.dumps(["anthropic", self.model, self.effort, system, user]).encode()).hexdigest()
        path = CACHE / f"{key}.json"
        if path.exists():
            self.cache_hits += 1
            obj = json.loads(path.read_text())
            self.last_model = obj.get("served_by", self.model)
            return obj["content"]
        resp = self.client.beta.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": self.SCHEMA}},
            betas=["server-side-fallback-2026-07-01"], fallbacks="default")
        self.calls += 1
        self.usage["input"] += resp.usage.input_tokens
        self.usage["output"] += resp.usage.output_tokens
        self.last_model = resp.model
        if resp.stop_reason == "refusal":
            raise RuntimeError(f"refusal ({getattr(resp.stop_details, 'category', None)})")
        content = next((b.text for b in resp.content if b.type == "text"), "")
        path.write_text(json.dumps({"model": self.model, "served_by": resp.model, "content": content, "request_id": resp._request_id,
                                    "usage": {"in": resp.usage.input_tokens, "out": resp.usage.output_tokens}}))
        return content


def make_client(kind: str):
    """'llm' -> OpenAI-compatible endpoint (local Ollama by default); 'llm_opus' -> Claude via the Anthropic SDK."""
    return AnthropicClient() if kind == "llm_opus" else LLMClient()


class LLMInvestigator(Investigator):
    """LLM chooses among the heuristic investigator's candidate leads; falls back to the heuristic on bad output."""

    def __init__(self, client: LLMClient | None = None, max_candidates: int = 8):
        self.client = client or LLMClient()
        self.fallback = HeuristicInvestigator()
        self.max_candidates = max_candidates
        self.log: list[dict] = []

    def _candidates(self, engine, ctx, state) -> list[tuple[Query, set]]:
        """Enumerate up to N distinct open leads without consuming them (dry run of the heuristic planner).
        Each candidate carries the exact 'lead explored' markers the planner adds for it."""
        import copy
        probe = copy.copy(state)
        probe.leads_queried = set(state.leads_queried)
        cands, seen = [], set()
        for _ in range(self.max_candidates * 3):
            before = set(probe.leads_queried)
            q = self.fallback.next_query(engine, ctx, probe)
            if q is None:
                break
            k = (q.kind, str(q.arg))
            if k not in seen:
                seen.add(k)
                cands.append((q, probe.leads_queried - before))
            if len(cands) >= self.max_candidates:
                break
        return cands

    def next_query(self, engine, ctx, state):
        if ctx is None or ctx.empty:
            return None
        cands = self._candidates(engine, ctx, state)
        if not cands:
            return None
        alert = getattr(state, "alert", {}) or {}
        user = "\n".join([
            f"ALERT: {alert.get('report_name', 'anomaly alert')} (severity {alert.get('severity', '?')}) on process {str(alert.get('process_path', '?')).rsplit(chr(92), 1)[-1]}",
            f"BUDGET LEFT: {getattr(state, '_budget_left', '?')} units. Queries run so far: {len(state.queries)}.",
            "EVIDENCE CONTEXT (most relevant events, time | process | action | target):",
            *_evidence_lines(ctx),
            "CANDIDATE QUERIES:",
            *[f"{i}. {q.kind}: {str(q.arg)[-100:]} (cost {q.cost})" for i, (q, _) in enumerate(cands)],
        ])
        choice, score, hyp, ok = 0, None, "", False
        try:
            raw = self.client.chat(SYSTEM, user)
            m = re.search(r"\{.*\}", raw, re.S)
            obj = json.loads(m.group(0) if m else raw)
            choice = int(obj.get("choice", 0))
            score = float(obj.get("attack_likelihood"))
            hyp = str(obj.get("hypothesis", ""))[:300]
            ok = 0 <= choice < len(cands) and 0 <= score <= 1
        except Exception:
            ok = False
        if not ok:
            choice = 0
        state.llm_attack_score = score if (ok and score is not None) else getattr(state, "llm_attack_score", None)
        state.llm_hypothesis = hyp if ok else getattr(state, "llm_hypothesis", "")
        q, markers = cands[choice]
        state.leads_queried |= markers          # consume exactly what the planner would have consumed for this lead
        self.log.append({"ok": ok, "choice": choice, "n_candidates": len(cands), "score": score, "hypothesis": hyp,
                         "served_by": getattr(self.client, "last_model", None)})
        return q
