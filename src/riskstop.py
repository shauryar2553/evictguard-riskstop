"""RISKSTOP: risk-aware stopping and verdicts for budgeted investigations (proposal slides 16-17).

At every step RISKSTOP reads ONLY the investigation state: the bounded evidence context (from
EVICTGuard), what has been queried, and the remaining budget. No labels, ever.

  State evaluation  label-free features: evidence strength, suspicious-process count and lineage, sensitive
                    targets, unresolved leads (hypotheses), coverage of hosts and log sources, missing
                    telemetry, budget used, recent information gain, novelty (distribution-shift signal).
  Evidence risk     p_attack = P(attack | state)                               (classifier, trained on TRAIN)
                    residual = expected share of attack evidence still unseen  (regressor, trained on TRAIN)
  Query value       value = residual x recent information gain per unit cost
  Decision          ATTACK   if p_attack >= tau_A and (residual <= rho or no open leads or budget spent)
                    BENIGN   if p_attack <= tau_B and residual <= rho and (no open leads, or >= min_budget used)
                    DEFER    if the budget or leads run out while uncertain, or the query value collapses while uncertain
                    CONTINUE otherwise
  Calibration       tau_A, tau_B, rho, lambda chosen on VALIDATION trajectories under explicit error budgets
                    (false-ATTACK rate <= alpha, missed-attack rate <= beta), in the spirit of dual-threshold
                    conformal deferral (Sahin & Mert, 2026), but applied to sequential stopping.
  Certificate       verdict, rationale, supporting evidence IDs, open questions, resources consumed.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import pandas as pd

FEATURES = ["ctx_value_max", "ctx_value_top5", "ctx_value_mean", "n_susp_procs", "max_actor", "n_high", "sens_hits", "tloc_user",
            "lineage_depth", "unresolved", "host_coverage", "missing_telemetry", "budget_used_frac", "budget_left", "recent_gain",
            "novelty_mean", "n_retrieved_log", "steps",
            # alert metadata (alert-driven benchmark) and kill-chain progression (Sigma ATT&CK tags; label-independent)
            "alert_severity", "alert_attack_watchlist", "alert_tactic_execution", "alert_tactic_discovery", "alert_tactic_other",
            "killchain_tactics", "sigma_max_rank", "sigma_hits",
            # LLM investigator's own attack-likelihood estimate (0.5 / unavailable for the rule-based investigator)
            "llm_attack_score", "llm_available"]


def state_features(ctx: pd.DataFrame, engine, memory, state, budget: int, gains: list[float]) -> dict[str, float]:
    f: dict[str, float] = {}
    if ctx is None or ctx.empty:
        f.update({k: 0.0 for k in FEATURES})
    else:
        v = np.sort(ctx.eg_value.to_numpy())
        f["ctx_value_max"] = float(v[-1])
        f["ctx_value_top5"] = float(v[-5:].mean())
        f["ctx_value_mean"] = float(v.mean())
        susp_keys = set(ctx.loc[ctx.f_actor >= 0.5, "actor_key"]) - {""}
        f["n_susp_procs"] = float(len(susp_keys))
        f["max_actor"] = float(ctx.f_actor.max())
        f["n_high"] = float((ctx.eg_value >= 0.4).sum())
        f["sens_hits"] = float((ctx.f_sens > 0).sum())
        f["tloc_user"] = float(((ctx.f_tloc >= 1.0) & (ctx.f_actor >= 0.5)).sum())
        depth = 0
        for k in susp_keys:
            d, cur, seen = 0, k, set()
            while cur in engine.parent_of and cur not in seen:
                seen.add(cur)
                cur = engine.parent_of[cur]
                if cur in susp_keys:
                    d += 1
            depth = max(depth, d)
        f["lineage_depth"] = float(depth)
        f["unresolved"] = float(sum(1 for k in susp_keys if ("process", k) not in state.leads_queried or ("children", k) not in state.leads_queried))
        f["novelty_mean"] = float(ctx.f_novel.mean())
    llm = getattr(state, "llm_attack_score", None)
    f["llm_attack_score"] = float(llm) if llm is not None else 0.5
    f["llm_available"] = 1.0 if llm is not None else 0.0
    f["_llm_hypothesis"] = getattr(state, "llm_hypothesis", "")
    alert = getattr(state, "alert", {}) or {}
    f["alert_severity"] = float(alert.get("severity") or 0)
    f["alert_attack_watchlist"] = 1.0 if "ATT&CK" in str(alert.get("watchlists", "")) else 0.0
    rep = str(alert.get("report_name", "")).lower()
    f["alert_tactic_execution"] = 1.0 if rep.startswith("execution") else 0.0
    f["alert_tactic_discovery"] = 1.0 if rep.startswith("discovery") else 0.0
    f["alert_tactic_other"] = 1.0 if rep and not (rep.startswith("execution") or rep.startswith("discovery")) else 0.0
    if ctx is not None and not ctx.empty and "sigma_rank" in engine.frame:
        rows = ctx._row.to_numpy()
        ranks = engine.frame.sigma_rank.to_numpy()[rows]
        tacs = engine.frame.sigma_tactics.to_numpy()[rows]
        f["killchain_tactics"] = float(len({t for x in tacs for t in str(x).split(";") if t}))
        f["sigma_max_rank"] = float(ranks.max())
        f["sigma_hits"] = float((ranks >= 2).sum())
    else:
        f["killchain_tactics"] = f["sigma_max_rank"] = f["sigma_hits"] = 0.0
    hosts_all = len(set(engine.hosts))
    hosts_seen = len(set(engine.hosts[memory.retrieved])) if memory.retrieved else 0
    f["host_coverage"] = hosts_seen / max(hosts_all, 1)
    fams_all = set(engine.p.fam)
    fams_seen = set(engine.p.fam.to_numpy()[memory.retrieved]) if memory.retrieved else set()
    f["missing_telemetry"] = 1.0 - len(fams_seen & fams_all) / max(len(fams_all), 1)
    f["budget_used_frac"] = state.budget_used / budget
    f["budget_left"] = float(budget - state.budget_used)
    f["recent_gain"] = float(np.mean(gains[-2:])) if gains else 1.0
    f["n_retrieved_log"] = float(np.log1p(len(memory.retrieved)))
    f["steps"] = float(state.step)
    # evaluation bookkeeping (never used by the policy): which context rows would be cited
    if ctx is not None and not ctx.empty:
        f["_top_rows"] = ctx.sort_values("eg_value", ascending=False)._row.head(10).tolist()
        f["_retrieved_n"] = len(memory.retrieved)
    return f


@dataclass
class RiskStopParams:
    tau_attack: float = 0.8
    tau_benign: float = 0.2
    rho: float = 0.35
    lam: float = 0.0
    min_budget_frac: float = 0.25


class RiskModels:
    """p_attack classifier and residual-risk regressor, fitted on TRAIN trajectories only."""

    def __init__(self):
        from sklearn.ensemble import GradientBoostingClassifier, GradientBoostingRegressor
        self.clf = GradientBoostingClassifier(n_estimators=200, max_depth=3, learning_rate=0.05, subsample=0.8, random_state=17)
        self.reg = GradientBoostingRegressor(n_estimators=200, max_depth=3, learning_rate=0.05, subsample=0.8, random_state=17)

    @staticmethod
    def X(rows: list[dict]) -> np.ndarray:
        return np.array([[float(r.get(k, 0.0)) for k in FEATURES] for r in rows])

    def fit(self, rows: list[dict], y_attack: np.ndarray, y_residual: np.ndarray) -> "RiskModels":
        X = self.X(rows)
        self.clf.fit(X, y_attack)
        self.reg.fit(X, y_residual)
        return self

    def predict(self, rows: list[dict]) -> tuple[np.ndarray, np.ndarray]:
        X = self.X(rows)
        return self.clf.predict_proba(X)[:, 1], np.clip(self.reg.predict(X), 0, 1)


def riskstop_policy(p_attack: float, residual: float, feats: dict, params: RiskStopParams) -> tuple[str, str]:
    forced = feats.get("forced_final", 0.0) > 0 or feats.get("budget_left", 1.0) <= 0
    open_leads = feats.get("unresolved", 0.0) > 0
    value = residual * max(feats.get("recent_gain", 0.0), 1e-6)
    if p_attack >= params.tau_attack and (residual <= params.rho or not open_leads or forced):
        return "ATTACK", f"attack confidence {p_attack:.2f} >= {params.tau_attack:.2f}; residual risk {residual:.2f}"
    if p_attack <= params.tau_benign and residual <= params.rho and (not open_leads or feats.get("budget_used_frac", 0) >= params.min_budget_frac or forced):
        return "BENIGN", f"attack confidence {p_attack:.2f} <= {params.tau_benign:.2f}; residual risk {residual:.2f}; open leads {int(feats.get('unresolved', 0))}"
    if forced:
        return "DEFER", f"budget or leads exhausted while uncertain (p={p_attack:.2f}, residual={residual:.2f})"
    if params.lam > 0 and feats.get("steps", 0) >= 3 and value < params.lam:
        return "DEFER", f"query value {value:.3f} below {params.lam:.3f} while uncertain (p={p_attack:.2f})"
    return "CONTINUE", ""


def replay(traj: list[dict], p: np.ndarray, r: np.ndarray, policy) -> tuple[str, int, str]:
    """Apply a stopping policy to a recorded trajectory. Returns (action, step index, rationale)."""
    for i, feats in enumerate(traj):
        last = i == len(traj) - 1
        f = {**feats, "forced_final": 1.0 if last else 0.0}
        action, why = policy(float(p[i]), float(r[i]), f, i)
        if action != "CONTINUE":
            return action, i, why
    return "DEFER", len(traj) - 1, "no decision"


# ---------------------------------------------------------------- baselines (same trajectories, same models)
def baseline_fixed_budget(threshold: float = 0.5):
    """Use the whole budget, then decide by the classifier (no deferral)."""
    def pol(p, r, f, i):
        if f.get("forced_final", 0) > 0:
            return ("ATTACK" if p >= threshold else "BENIGN"), "fixed budget spent"
        return "CONTINUE", ""
    return pol


def baseline_confidence_stop(hi: float = 0.9, lo: float = 0.1):
    """Stop as soon as the classifier is confident either way (no risk or coverage check)."""
    def pol(p, r, f, i):
        if p >= hi:
            return "ATTACK", "confident"
        if p <= lo:
            return "BENIGN", "confident"
        if f.get("forced_final", 0) > 0:
            return ("ATTACK" if p >= 0.5 else "BENIGN"), "budget spent"
        return "CONTINUE", ""
    return pol


def baseline_bagen(patience: int = 2):
    """BAGEN-style budget awareness: stop when information gain has stalled for ``patience`` steps."""
    def pol(p, r, f, i):
        stalled = i >= patience and f.get("recent_gain", 1.0) <= 1e-6
        if stalled or f.get("forced_final", 0) > 0:
            return ("ATTACK" if p >= 0.5 else "BENIGN"), "gain stalled" if stalled else "budget spent"
        return "CONTINUE", ""
    return pol


def baseline_conformal_deferral(tau_a: float, tau_b: float):
    """Dual-threshold conformal deferral at the END only (Sahin & Mert, 2026): full budget, then ATTACK / BENIGN / DEFER."""
    def pol(p, r, f, i):
        if f.get("forced_final", 0) > 0:
            return ("ATTACK" if p >= tau_a else "BENIGN" if p <= tau_b else "DEFER"), "end-of-budget dual threshold"
        return "CONTINUE", ""
    return pol


def make_riskstop(params: RiskStopParams):
    return lambda p, r, f, i: riskstop_policy(p, r, f, params)


@dataclass
class Certificate:
    episode_id: str
    verdict: str
    rationale: str
    supporting_evidence: list[str]
    open_questions: list[str]
    queries_used: int
    budget_used: int
    steps: int
    attack_confidence: float
    residual_risk: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ---------------------------------------------------------------- LLM-only baselines (use the LLM's own attack likelihood)
def baseline_llm_verdict_at_end(threshold: float = 0.5):
    """LLM agent without RISKSTOP: investigate with the full budget, then trust the LLM's attack likelihood."""
    def pol(p, r, f, i):
        if f.get("forced_final", 0) > 0:
            return ("ATTACK" if f.get("llm_attack_score", 0.5) >= threshold else "BENIGN"), "LLM verdict at end of budget"
        return "CONTINUE", ""
    return pol


def baseline_llm_confidence_stop(hi: float = 0.9, lo: float = 0.1):
    """LLM agent that stops as soon as it is confident (typical agentic triage)."""
    def pol(p, r, f, i):
        s = f.get("llm_attack_score", 0.5)
        if f.get("llm_available", 0) > 0 and s >= hi:
            return "ATTACK", "LLM confident: attack"
        if f.get("llm_available", 0) > 0 and s <= lo:
            return "BENIGN", "LLM confident: benign"
        if f.get("forced_final", 0) > 0:
            return ("ATTACK" if s >= 0.5 else "BENIGN"), "budget spent"
        return "CONTINUE", ""
    return pol
