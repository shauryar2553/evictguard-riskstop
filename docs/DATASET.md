# Dataset design for EVICTGuard + RISKSTOP

## Why the original dataset was replaced

The first prototype used one OTRF recording (Empire DCOM ShellWindows):
32,706 events covering about 2 minutes on 4 hosts. It had **no event-level labels and no
benign episodes**, so critical-evidence retention (EVICTGuard) and ATTACK/BENIGN/DEFER
accuracy (RISKSTOP) could not be measured. The Cyber Defense Benchmark (CDB,
Chona et al. 2026) is built from the same OTRF recordings. Its full data is only shared
with organisations on request (only a sample is public), and it contains no benign
episodes (only 500 synthetic benign events per campaign). It therefore cannot be our
primary dataset.

## Final design (hybrid)

| Role | Source | Licence / terms | Labels |
|---|---|---|---|
| Attack pool | OTRF Security-Datasets: 110 Windows host recordings (107 atomic + APT29 day 1/2) | MIT (GitHub metadata) | Event-level, **constructed** (below); ATT&CK technique per recording from metadata YAML |
| Benign background (final) | ATLASv2 benign period: 4 days of human-generated activity on 2 hosts, Sysmon + Security | README: "We encourage you to use the ATLASv2 dataset in your experiments", cite ATLAS + ATLASv2 | Benign by dataset design |
| Out-of-distribution attack test | ATLASv2 attack day (10 attacks, 16 host-scenario pairs) | as above | REAPr process-level labels (Riddle et al.) + Sigma core tier |
| Benign background (interim) | Background-tier events of the OTRF recordings | MIT | *Presumed* benign: no Sigma hit and not in the attack tree |

## Event-level labelling of OTRF (`src/label.py`)

This adapts CDB's "Sigma + causal neighbours" recipe and REAPr's process-only forward trace.
No LLM is used, so the labels are deterministic and reproducible.

1. **Starting points of the attack ("roots").** (a) The attacker processes named in the
   OTRF `adversary_view` (the C2 console output: machine, process, PID), resolved to Sysmon
   ProcessGuids; (b) high/critical Sigma hits on process-creation events.
2. **Causal expansion.** A process-only forward trace over Sysmon `ProcessGuid → ParentProcessGuid`
   from every root gives the attack tree. Non-Sysmon events (PowerShell, Security) are
   attributed by (host, PID).
3. **Tiers.**
   * `core`: a Sigma hit (level ≥ medium) inside the attack tree, **or** outside the tree when the
     rule's ATT&CK technique family matches the recording's documented technique. A typical case is
     activity on a lateral-movement target that was started via WMI/DCOM, so it has no parent link.
   * `supporting`: the acting process is in the attack tree, but the event has no qualifying hit
     (context and corroboration). An event where an attacker process is only the *target* does not count.
   * `ambiguous`: any other Sigma hit outside the attack tree (a possible false positive, or
     attack activity the rules don't cover). **Excluded from scoring.**
   * `background`: everything else (lab background).
4. **Provenance.** Each event stores `label_source` (sigma:<rule ids>, ancestry:<root>, …),
   its Sigma rule titles, and its ATT&CK tags.
5. **Validation.** `data/labels/review_sample.csv` holds up to 5 events per tier per
   recording with blank `reviewer_tier` / `reviewer_notes` columns. Fill in a few hundred rows,
   then run `python -m src.label --agreement data/labels/review_sample.csv` and report the agreement.
6. **Quality summary.** `data/labels/recording_summary.csv` has, per recording: tier counts,
   roots resolved, and `technique_agreement` (whether any Sigma hit's technique family matches
   the metadata's technique). Recordings with no core evidence are excluded from the attack pool.

The rule set is SigmaHQ release **`r2026-04-01`** (commit `0e3b749e0d85cd943706ed610a1447f0d54e8388`).
Do not use newer releases: from `r2026-07-01` onward SigmaHQ uses a renumbered ATT&CK
(for example, T1562.004 became T1686.003), so rule tags no longer match the technique IDs in
OTRF's metadata. Rules using unsupported Sigma features are skipped and reported.

### How the labelling rules were validated (model-assisted review, 2026-11-02)
A stratified sample of 100 events (30 core, 30 supporting, 25 ambiguous, 15 background) was
reviewed with model assistance, *not* by a human. The review found and fixed three problems:
(1) "any high/critical hit = core" let lab housekeeping in (Security log cleared, Sysmon file
shredding, external SMB logons), so 7 of 30 core events were wrong; (2) target-only process
involvement (csrss/svchost opening an attacker process) leaked into `supporting`; (3) the newest
SigmaHQ uses renumbered ATT&CK IDs, so technique matching silently failed and real attack events
(`net1 user /add backdoor`, PsExec service install, Register-CimProvider DLL execution) were left
`ambiguous`. A **human** check of the regenerated `review_sample.csv` is still needed to report
label accuracy.

### Known limitation (state it in the report)
If EVICTGuard ever uses Sigma hits as a scoring feature, the evaluation becomes circular,
because the labels are partly Sigma-derived. Either keep Sigma out of the scorer, or split the
rule set (one half for labels, the other half for features) and say so.

## Episodes (`src/compose_episodes.py`)

* **ATTACK episode**: a contiguous background window (default: up to 4,000 events) plus 1–3
  labelled attack recordings. The attack recordings are time-shifted into the window and their
  hostnames are rewritten to background hosts, both in the canonical columns and in the raw JSON.
* **BENIGN episode**: a background window with no attack added.
* **Splits** (stable hashing, 60/20/20): attack recordings are grouped by **ATT&CK technique
  family**, so the same technique never appears in two splits. Background segments are grouped by
  host-day (ATLASv2) or by source recording (interim). An episode only combines pools from the same split.
* Tune weights and thresholds on `val`. Report `test` once. Keep the ATLASv2 attack day as the
  out-of-distribution test.

## Noise and augmentation (`src/noise.py`): labels are preserved

| Type | What it does | Label handling |
|---|---|---|
| `duplicate-flooding` | Exact copies of random events | Copy inherits the parent's tier; `dup_of` links it to the parent (a retained duplicate counts for its parent) |
| `background-flood` | Replays real benign events with new timestamps and record numbers | `benign` / `injected_noise` |
| `mimic-flood` | Benign admin commands that look like attacker tradecraft (adversarial) | `benign` / `injected_noise` |
| `missing-evidence` | Drops random events | Removed IDs recorded, including which were attack events |
| `missing-critical` | Drops a fraction of the attack evidence | Removed IDs recorded; feeds the gold DEFER rule |
| `benign-looking` | Original placeholder generator, kept for backward compatibility | `benign` / `injected_noise` |

## Gold labels for RISKSTOP (fixed before any experiment)

* BENIGN episode → **BENIGN**
* ATTACK episode with ≥ 50% of its core evidence (and ≥ 1 core event) still present → **ATTACK**
* ATTACK episode with less than that → **DEFER** (the evidence is insufficient)

See `gold_verdict()` in `src/run_benchmark.py`.

## Metrics (`src/run_benchmark.py`)

core / supporting / attack recall of the selected context (counted over unique evidence units),
noise share, background share, and runtime. Results are given as means with 95% bootstrap CIs,
resampled over attack-recording clusters.

## Reproduce

```bash
python -m src.otrf_corpus --include-compound          # ~115 MB
git clone --filter=blob:none --sparse https://github.com/SigmaHQ/sigma data/sigma/sigmahq \
  && (cd data/sigma/sigmahq && git sparse-checkout set rules/windows && git checkout r2026-04-01)
python -m src.label --review-sample 5
python -m src.compose_episodes --background otrf        # interim; use --background atlasv2 once downloaded
python -m src.run_benchmark --split val
# ATLASv2: Box only offers one 12 GB atlasv2.tar.gz. --stream reads it once, keeps only
# benign/h1 + attack/h1-s1 (Sysmon + Security, max 100k events per file) as parquet,
# never stores raw XML, and stops early (~200 MB on disk, <1 GB RAM).
python -m src.atlas_adapter --fetch-reapr && python -m src.atlas_adapter --stream
python -m src.compose_episodes --background atlasv2
```

## ATLASv2 as actually ingested (2026-11-03)

* The Box share holds a single `atlasv2.tar.gz` (12.2 GB). `src.atlas_adapter --stream` reads it
  once over HTTP. It resumes with Range requests after network drops, parses the wanted XML
  directly from the stream, and stops as soon as the wanted folders have passed: about 7 GB read,
  **35 MB kept**, raw XML never stored, under 1 GB RAM. The first 100k events of each file are kept.
* Kept: `benign/h1/{sysmon,msft-security}` (5 Sysmon + 4 Security exports) and
  `attack/h1/*-h1-s1.xml` plus ATLAS's own ground-truth file (EventRecordIDs of malicious events).
* **Sysmon exports are cumulative** (`sysmon-5` contains days 1–5). `rebuild_daily_segments()`
  removes duplicates by (host, channel, EventRecordID): 570,742 → 458,389 events. It then cuts the
  data into one segment per calendar day, and that day is the split group, so no background event
  can appear in two splits.
* Benign segments: h1 on 2022-07-15 … 2022-07-19. The 07-19 segment ends at 13:01, before the
  s1 attack (13:13–13:35).
* **Out-of-distribution episode** `ood-attack-h1-s1`: a real attack inside real background, with
  no splicing. Labels: REAPr process labels → `supporting` (70,027 events); ATLAS ground-truth
  record IDs → `core` (295 of 309; the other 14 fall beyond the 100k-event cap). Run it with
  `python -m src.run_benchmark --split ood`.
* Known artefact: OTRF attacks come from Windows 10 labs (rich Sysmon), while the ATLASv2 background
  is Windows 7 (mostly Security events). Before reporting final numbers, check whether a simple
  classifier can tell spliced events from background by schema alone.
* **Artefact measured (val, ATLASv2 background):** 83% of core events have a (channel, EventID)
  pair that never occurs in their background window, because Windows 10 Sysmon attacks are spliced
  into a Windows 7 background. The rarity feature can therefore find them trivially. That explains
  why val core recall (EVICTGuard 0.78–0.81) is far above the un-spliced OOD episode (about 0.02).
  Report val/test results only together with the OOD result. Reduce the artefact with
  Windows-10-era benign background, or by matching event-type distributions when splicing.

## Final evaluation setup

* **Sensor harmonisation** (`compose_episodes --harmonize`, the default in `run_pipeline.sh atlasv2`):
  only attack event types (channel, EventID) that the background's logging also produces are spliced in.
  This cut the share of core events with an event type unseen in their window from 0.83 to 0.09.
  Spliced validation episodes are still easy (EVICTGuard core recall ≈ 0.93–1.0), and 17 of 40 val
  attack episodes are left with no core event. **Use the spliced splits for development and tuning only.**
* **Out-of-distribution (realistic) test set: all 16 native ATLASv2 attack scenarios** (h1-s1…s4,
  h1-m1…m6, h2-m1…m6). Each has 140k–300k events of real background around a real attack.
  `core` = ATLAS's ground-truth malicious Security records (4,580 total; 100% recovered with the 300k cap).
  `supporting` = REAPr attack-process events. Streamed with `--stream-attacks`: the attack section
  sits at the start of the archive, so the download stops early, and about 200 MB is kept.
  These episodes are the headline benchmark: `python -m src.run_benchmark --split ood`.
* Caveat: ATLASv2's 10 attacks are highly redundant (REAPr README: 4 of 5 steps shared), so treat
  the 16 episodes as variations of a few attack chains, not 16 independent attacks.
