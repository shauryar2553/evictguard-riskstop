# EVICTGuard: final results and claims

Every number here comes from `results/paper/` (built by `scripts/make_paper_results.py` from `results/benchmark/`).
Frozen methods:
* `src/evictguard_v2.py` (batch): SHA-256 `b118c8a5…` (`results/evictguard_v2.sha256`)
* `src/evictguard_online.py` (streaming): SHA-256 `ba2a3ad2…` (`results/evictguard_online.sha256`)

## 1. Protocol
* **Datasets (two independent environments, real attacks, no splicing)**
  * **ATLASv2**: 16 native attack scenarios on 2 Windows 7 hosts, 140k–300k events each.
    Core = ATLAS's ground-truth malicious records (4,580 in total).
  * **OTRF native**: 84 recordings of real attacks with their real lab background, from Windows 10
    labs (different organisation, sensors and tooling). Core = our Sigma + process-tree labels
    (`docs/DATASET.md`). Split by ATT&CK technique family into train 50 / val 17 / test 17.
* **Development vs held-out.** Design decisions used only ATLASv2 host-1 (h1, 10 scenarios), the OTRF
  train split and the spliced validation split. Held-out: ATLASv2 host-2 (h2, 6) and the OTRF val/test
  splits. Both methods were frozen (hashed) before their held-out runs.
* **No labels.** No scorer or baseline reads ground truth or injected-noise markers (enforced by tests).
* **History.** ATLASv2 uses a prevalence profile built only from training-split benign days.
  OTRF runs **cold start**: no history at all.
* **Metrics.**
  * Core *action* recall (primary): an action is (host, process, log family, event id, exact target),
    so repeated logging of one action counts once.
  * Core *record* recall.
  * Average precision.
  * Injected-noise share of the kept context.
  * 95% bootstrap CIs over episodes, and exact paired sign-flip tests.
* **Baselines (re-implemented on our data, same inputs).**
  * FIFO and Random.
  * Original EVICTGuard v1.
  * Recency + exact de-duplication.
  * Rare-action anomaly (classic log-anomaly heuristic).
  * NoDoze-style provenance triage (Hassan et al., NDSS 2019): historical transition anomaly
    propagated along the process tree, given the same history profile.
  * Sigma alert prioritisation (AlertPro-style SOC practice). ATLASv2 only, because OTRF labels use Sigma.
* **Tie-breaking.** The anomaly baselines give the same maximal score to thousands of never-seen
  events (2,383–3,630 per episode). Their ties are broken **uniformly at random**, never by time, so
  that an arbitrary ordering doesn't decide the comparison.

## 2. Main result: ATLASv2 held-out (h2), 6 real attacks, no noise
| Method | 256 (0.13%) | **1,024 (0.51%)** | 4,096 (2.0%) |
|---|---|---|---|
| **EVICTGuard v2 (batch)** | 0.790 | **0.973** [0.960, 0.982] | 0.985 |
| **EVICTGuard-Online (streaming)** | **0.962** | **0.973** | — |
| Rare-action anomaly | 0.014 | 0.048 | 0.167 |
| NoDoze-style triage | 0.004 | 0.006 | 0.021 |
| Sigma alert prioritisation | 0.000 | 0.000 | 0.000 |
| Recency + dedup | 0.000 | 0.000 | 0.004 |
| EVICTGuard v1 | — | 0.000 | 0.023 |
| Random | 0.004 | 0.015 | 0.031 |
| FIFO | 0.000 | 0.000 | 0.000 |

* Values are core action recall; the percentages are the share of the log kept.
* v2 beats every baseline on **6 of 6** held-out and **10 of 10** development episodes, at every capacity
  and noise setting (p = 0.031 held-out, the minimum attainable with n = 6; p = 0.002 development).
* At 1,024 events, record recall is 0.507 (best baseline 0.028), and average precision is 0.377
  (baselines ≤ 0.002, base rate ≈ 0.001).

**Why the baselines fail** (diagnosed per method):
* Recency keeps the newest events, but the attack happened earlier.
* Sigma rules don't fire on the attacker's file activity, yet do fire on the security agent
  (`repwmiutils.exe`), which then fills the memory.
* The anomaly methods flag *every* action of every never-seen program, so the attack ties with
  thousands of other novel events.

v2 separates them with target-location risk and action informativeness.

## 3. Flooding robustness (ATLASv2 held-out, capacity 1,024)
v2 stays at **0.973** under duplicate (+50%), background (+50%) and adversarial mimic (+20%) floods.

| Noise type | v2 junk share of kept context | Random | FIFO |
|---|---|---|---|
| Duplicate flood | 0.000 | 0.30 | 0.34 |
| Background flood | 0.025 | 0.30 | 0.64 |
| Mimic flood | 0.022 | 0.16 | 0.33 |

## 4. Second dataset: OTRF native (held-out test split, 17 attacks, Windows 10, cold start)
| Method | 1% of events | 5% of events |
|---|---|---|
| **EVICTGuard v2 (batch)** | **0.578** | **0.873** |
| EVICTGuard-Online | 0.480 | 0.799 |
| EVICTGuard v1 | 0.191 | 0.667 |
| Rare-action anomaly | 0.074 | 0.338 |
| NoDoze-style triage | 0.044 | 0.279 |
| Recency + dedup | 0.000 | 0.078 |
| Random | 0.020 | 0.020 |
| FIFO | 0.000 | 0.000 |

* Values are core action recall with no noise. Under floods, v2 reaches 0.89–0.93 at 5%.
* OTRF **validation** split (17 further held-out attacks, no noise): v2 0.303 / **0.889** vs v1 0.188 / 0.330,
  recency + dedup 0.079 / 0.481, Random 0.099 / 0.125 (1% / 5%).
* **Significance:** v2 beats every baseline significantly (p ≤ 0.005) **except v1 at 5%**
  (p = 0.087; 5 wins, 11 ties, 1 loss). On these small episodes, 5% of the log is often enough for
  v1's rarity rule to also keep the few core events.

## 5. Online (streaming) vs batch, and the slide-15 reservoirs
| Setting | Online (reservoirs) | Batch v2 | Online, protected reservoir only |
|---|---|---|---|
| ATLASv2 h2, 256 | **0.962** | 0.790 | 0.962 |
| ATLASv2 h2, 1,024 | 0.973 | 0.973 | 0.973 |
| OTRF test, 1% | 0.480 | **0.578** | 0.500 |
| OTRF test, 5% | 0.799 | **0.873** | 0.775 |

* Decisions use only past events, yet online matches or beats batch on ATLASv2 and stays below
  batch on OTRF's tiny cold-start episodes.
* Under OTRF background flooding, online lets in more junk (≈0.20 vs 0.07–0.10).
* **The stratified reservoirs (entity coverage + exploration) don't change core recall measurably.**
  They are justified by coverage and diversity, not recall.

## 6. Robustness of the weights (development)
Each of the 9 weights was perturbed independently by ±50% (30 draws). Recall at 1,024 stayed at
0.817 ± 0.013 (min 0.782, max 0.834), against 0.821 for the defaults. The result does not hinge on
hand-picked weights.

## 7. Ablation (development, capacity 1,024)
Removing a component costs this much recall:
* event-type informativeness −0.245
* target-location risk −0.240
* history −0.029
* prevalence −0.021
* location −0.010
* lineage −0.010
* LOLBin −0.007
* sensitivity −0.003
* propagation, command ≈ 0

Removing **novelty (+0.008)** or the **redundancy weighting (+0.031)** slightly *improves* recall. Both were
kept in the frozen design; changing them after seeing held-out results would be test-set tuning.

## 8. Spliced OTRF-into-ATLASv2 episodes (secondary)
v1 and v2 both saturate (about 1.0). These episodes carry a sensor artefact (Windows 10 attack events
in a Windows 7 background) and don't discriminate between methods. They are reported for completeness only.

## 9. Limitations (state these in the paper)
1. The ATLASv2 held-out hosts belong to the same multi-host campaigns as the development hosts
   (independent by host and records, not by attack chain). The OTRF native test split is the
   chain-independent evidence.
2. OTRF core labels are rule- and process-tree based (validated by review, not by an independent
   red-team log). Human label agreement is still to be measured.
3. The target-location prior was introduced after inspecting development data. It is a standard
   ATT&CK-grounded heuristic, and the second dataset shows it transfers.
4. Baselines are faithful re-implementations of core ideas, not the original systems. NoDoze's full
   path-aggregation and its exact anomaly-score normalisation differ.
5. The noise is synthetic. v1 was compared without noise on ATLASv2 (runtime).
6. There is no end-to-end LLM evaluation yet: does better context change the investigator's
   verdict? That belongs with RISKSTOP.
7. Not run: the OTRF train split for the frozen-v2 baseline table. Only test and val are reported for v2.

---

## 10. Caveats revisited (2026-11-04): what each fix achieved

New frozen methods (hashes in `results/`):
* **EVICTGuard v3** = v2 without the redundancy weighting (`evictguard_v3.json`). Decided on ATLASv2 h1 only.
* **EVICTGuard-Online v2** (`evictguard_online_v2.sha256`) = adaptive reservoirs (64 protected slots
  first), causal re-scoring of retained evidence from past statistics, and v3 scoring. Decided on
  ATLASv2 h1 + OTRF train only.

| # | Caveat | Fix | Outcome |
|---|---|---|---|
| 1 | Anomaly baselines' tie-break | 5 random tie-break seeds | **Closed.** Means are stable, e.g. rare-action on ATLASv2 h2 at 1,024 = 0.047 ± 0.019 (`table8`). Conclusions unchanged. |
| 2 | Online below batch on OTRF | Online v2 (diagnosis: reservoir split in about 20-slot memories, plus cold-start over-suspicion) | **Fixed on fresh data** (OTRF val, never used for any online method). 1%: **0.534** (online v1 0.362, batch v2 0.303); 5%: **0.898** (0.851, 0.889); 1% with flood: **0.679** (0.472, 0.611). Junk share 0.11 vs 0.14 for online v1. |
| 3 | Reservoirs don't raise recall | Coverage metrics | **Justified.** On held-out ATLASv2 h2, reservoirs keep recall identical (0.973) while raising stratum coverage 0.10 → **0.91** and attack-process coverage 0.50 → 0.55–0.60 (`table10`). |
| 4 | Two harmful signals | v3, frozen, then fresh tests | **Mixed, reported as is.** ATLASv2 h2 (first v3 evaluation there): **0.971 vs 0.790 at 256**, 0.985 vs 0.973 at 1,024. OTRF train (fresh, 50 episodes): 0.396 vs 0.436 at 1% (worse), 0.766 vs 0.745 at 5% (better). v3 is not a uniform improvement over v2. |
| 5 | Our own labels | (a) Independent third dataset, CDB, with CDB's labels; (b) labeller-vs-CDB agreement; (c) human review kit | **Partly closed; important new findings.** See §11. The human check (60 rows, `~/Desktop/EVICTGuard_label_review.csv`) still needs a person. |
| 6 | OTRF train split not run | Ran with v3's fresh test | **Closed** (`table7`). v2/v3 0.40–0.44 (1%) and 0.75–0.77 (5%) vs best baseline 0.13 / 0.39. |
| 7 | End-to-end LLM verdicts | — | **Open.** Needs an LLM: API key or local model (user decision). |

## 11. Third dataset: Cyber Defense Benchmark (independent labels), honest results
* **Data.** The public CDB sample: one stitched campaign, 155,350 events, 10 hosts, 3 attack chains,
  9 ATT&CK tactics. Labels are CDB's own flags (Sigma + LLM; relevance 1 → core, 2 → supporting).
* **A bug in our conversion, found and fixed.** CDB's authoritative clock is `TimeCreated`. Our generic
  parser had preferred Sysmon `UtcTime` (the pre-stitching time), which scrambled event order. Now all
  3,393 flagged timestamps match exactly.
* **A finding about CDB's labels.** 2,381 of 3,393 flagged core timestamps (70%) consist only of
  Azure guest-agent events (`collectguestlogs.exe` opening system processes with 0x1000 rights). The
  same agent emits identical bursts in 4 unrelated OTRF attack recordings (T1047, T1021.002, T1021.003,
  T1546.003). It is lab infrastructure, so these flags are very likely false positives of CDB's
  automatic labeller. We report raw results, plus a sensitivity analysis with a pre-stated exclusion rule.
* **Results (cold start, no noise; core timestamp recall, CDB's own scoring rule):**

| CDB, Azure flags excluded | 0.5% | 1% | 5% |
|---|---|---|---|
| EVICTGuard-Online v2 | **0.053** | 0.068 | 0.139 |
| EVICTGuard-Online v1 | 0.050 | 0.073 | 0.172 |
| EVICTGuard v3 / v2 | 0.038 / 0.037 | 0.050 / 0.050 | 0.146 / 0.142 |
| Rare-action anomaly | 0.048 | **0.082** | **0.269** |
| Recency + dedup | 0.006 | 0.006 | 0.208 |
| EVICTGuard v1 | 0.015 | 0.034 | 0.129 |
| Random | 0.013 | 0.023 | 0.111 |

  With raw CDB labels, every method is near random (all ≤ 0.12 at 5%).
* **Interpretation.** On CDB, EVICTGuard is **comparable to rare-action at small memory and behind it at
  5%**. CDB's labels count broad causal side effects as core (e.g. 1,005 DLL image loads), which EVICTGuard
  deliberately ranks low, and CDB obfuscates entity names, weakening path-based signals. **EVICTGuard's
  advantage depends on the evidence definition:** it dominates when ground truth marks the attacker's
  own actions (ATLASv2 expert labels; OTRF), not when an automatic labeller marks broad side effects.
  We did not tune on CDB.
* **Labeller agreement (our method vs CDB's, same 155k events).** Cohen's κ = 0.08 (all labels),
  0.19 (Azure excluded); about 20% mutual precision and recall. Our labeller lacked its usual metadata
  here (CDB strips technique IDs and attacker console output). Two automatic SOC labelling methods agree
  only slightly, so **ATLASv2's expert ground truth is the strongest evidence**. OTRF results should be
  read as "under our labelling method", pending the human check.

## 12. Revised headline claims (defensible)
1. On expert-labelled real attacks (ATLASv2, held-out), EVICTGuard keeps 0.96–0.99 of attack evidence
   at 0.13–0.5% of the log; every literature baseline keeps ≤ 0.05 (p = 0.031, 6/6).
2. On a second environment (OTRF native, Windows 10, cold start, our labels), EVICTGuard keeps
   0.53–0.90 (online v2, held-out val) versus ≤ 0.39 for the best baseline. Batch v2's advantage over every
   baseline is significant on the OTRF test split (p ≤ 0.005), except vs v1 at 5%.
3. A streaming version with fixed memory and no look-ahead matches or beats batch on held-out data,
   and its stratified reservoirs raise evidence diversity about 9× at no recall cost.
4. Under a broad, automatically generated evidence definition (CDB), EVICTGuard is not better than
   simple rare-event ranking. This is a stated limitation and a direction for future work.
