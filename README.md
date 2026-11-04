# EVICTGuard + RISKSTOP (NITK B.Tech Major Project)

**Start here:** `NEXT_STEPS.md` (status and next steps), `docs/RESULTS_EVICTGUARD_V2.md` (final results and caveats),
`docs/DATASET.md` (dataset design), `deliverables/EVICTGuard_Viva_Guide.docx` (plain-language guide).

## Repository map
| Path | Contents |
|---|---|
| `src/` | All code: datasets, labelling, episodes, noise, EVICTGuard v1/v2/v3/Online/Online v2, baselines, ledger, context assembly, benchmark |
| `tests/` | 38 tests (`.venv_mac/bin/python -m pytest -q`) |
| `scripts/` | Paper tables/figures, weight sensitivity, label review kit, viva guide generator, tie-break seeds |
| `results/paper/` | Publication tables (Markdown + LaTeX), figures (PNG + PDF), significance tests |
| `results/benchmark/` | Raw per-episode results of every experiment |
| `results/*.sha256`, `results/evictguard_v3.json` | Fingerprints of the frozen methods |
| `data/` | All datasets, labels and episodes (see licences below) |
| `database/` | SQLite evidence ledger (Phase 1-2) |
| `deliverables/` | Viva guide, human label-review sheet, mid-sem presentation, original Phase 1-3 zip |
| `docs/` | Dataset design, results write-up, slide-11 replacement text |

## Setup (macOS / Linux)
```bash
python3 -m venv .venv_mac && .venv_mac/bin/pip install -r requirements.txt
./scripts/reassemble_large_files.sh                      # rejoins 4 large files uploaded in 15 MB parts (checksum-verified)
unzip data/cdb_sample/sample.zip -d data/cdb_sample      # restores the CDB JSON files (too large for GitHub)
.venv_mac/bin/python -m pytest -q
./run_pipeline.sh atlasv2                                # rebuilds everything (skips steps already done)
```
(Windows: create the venv with `py -3 -m venv .venv` and use `.venv\Scripts\python.exe`.)

## Third-party data and licences (private repository; do not make public without checking these)
* **OTRF Security-Datasets** (`data/otrf/`): MIT per GitHub metadata. Roberto Rodriguez, https://github.com/OTRF/Security-Datasets
* **ATLASv2** (`data/atlasv2/`, derived parquet only): the authors "encourage" research use with citation; licence not stated.
  Cite Alsaheel et al. (USENIX Security 2021) and Riddle, Westfall & Bates (arXiv:2401.01341). REAPr labels: https://bitbucket.org/sts-lab/reapr-ground-truth
* **Cyber Defense Benchmark sample** (`data/cdb_sample/sample.zip`): from https://github.com/simbianai/cyber_defense_benchmark (MIT-licensed repo). Chona et al., 2026.
* **SigmaHQ rules** (`data/sigma/`): Detection Rule License 1.1 (attribution required). See `data/sigma/SIGMA_VERSION.md`.

---

# EVICTGuard + RISKSTOP — Phase 1

Phase 1 provides dataset acquisition, inspection, SQLite ingestion, reproducible experimental copies, episode sampling, and tests. It does not implement the EVICTGuard reservoir or RISKSTOP policy.

## Dataset selection

The first real-data target is OTRF's **Empire Invoke DCOM ShellWindows** host archive. Its documented scenario page describes simulated Empire DCOM activity and links the host ZIP at:

`https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_dcom_shellwindows_stager.zip`

OTRF documents the archive as JSON Lines and demonstrates loading it as JSONL. Download size is checked at runtime (100 MB default), and archive validity and member names are verified. The manifest records the URL, time, size, and label limitations. Scenario context is useful provenance, but it does not establish that every row is malicious or give event-level ground truth.

## Setup (Windows PowerShell)

From this directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use `\.venv\Scripts\python.exe` in place of `python` for each command.

## Workflow

```powershell
python -m src.download_dataset
python -m src.inspect_dataset data/raw/empire_dcom_shellwindows_stager.zip
python -m src.ingest data/raw/empire_dcom_shellwindows_stager.zip --database database/evictguard.sqlite
python -m src.episode --database database/evictguard.sqlite --size 100 --seed 17 --time-ordered --output data/episodes/episode.csv
python -m src.noise data/episodes/episode.csv --noise-type duplicate-flooding --proportion 0.05 --seed 17 --output data/generated/episode_duplicate_5pct.csv
pytest -q
python -m src.demo
```

The demo uses the downloaded archive when present. With no archive it creates a clearly identified, deterministic 20-event fixture; pass `--download` to fetch real data automatically. The demo produces three noise variants, manifests, and `results/demo_record_counts.png`.

Supported formats for inspection/ingestion: ZIP containing JSON/JSONL/CSV, JSON, JSONL/NDJSON, and CSV. ZIP handling selects the first supported member in lexical order; confirm the report when using a multi-file archive. Original source archives are retained as downloaded. Re-ingestion of a file is refused unless `--allow-reingest` is specified; that option replaces prior records from that same absolute source path. Duplicate records remain stored by default; `--deduplicate` removes exact duplicates within that source.

## Troubleshooting

- **Download/network error:** rerun `python -m src.download_dataset`; the error includes the documented scenario page for manual retrieval. Place the original ZIP at `data/raw/empire_dcom_shellwindows_stager.zip` and do not extract over it.
- **Unsupported file:** use JSON, JSONL/NDJSON, CSV, or a ZIP containing one of those; malformed JSONL rows are logged and counted as rejected.
- **Already ingested:** use `--allow-reingest` only when intentionally refreshing that source; otherwise use the existing database.
- **SQLite locked:** close other processes using the database and retry.
- **PowerShell activation policy:** invoke `.venv\Scripts\python.exe` directly as above.

## Research limitations

Synthetic background rows have no genuine benign label. Duplicate flooding retains the source link. Missing-evidence manifests record removed record IDs. Noise acts on CSV/dataframe copies only; it never edits a database. Labels from source, inferred labels, and synthetic labels remain separate. Transform seed and settings are stored with each experiment.

## Phase 2: Evidence ledger

The ledger is stored in the existing `database/evictguard.sqlite`; it adds `evidence_ledger` and `evidence_status_history` tables and does not copy source event payloads. Original ledger rows point to `events.record_id`, where all original source fields remain in `original_json`. Synthetic and derived records keep a canonical JSON payload in the ledger. A matching content hash does not merge records. The status `evicted` means excluded from an active investigation set; it never deletes the source row. Every registration and status transition is timestamped and status transitions include a reason.

```powershell
python -m src.ledger --database database/evictguard.sqlite --episode data/episodes/demo_episode.csv --output results/evidence_ledger_report.json
python -m pytest -q
```

The demonstration registers five episode events, a synthetic event and a derived copy linked to its parent, verifies hashes, records a status transition, exports JSON, and compares the Phase 1 event count before/after. CSV export is also supported by passing an output ending in `.csv`. Ledger filtering and status changes are available through the `src.ledger` Python functions.

## Phase 3: EVICTGuard selection and baselines

Run a comparison against the existing episode. The evaluation creates a deterministic noise-injected copy (duplicate flooding by default), then gives the exact same candidates and capacity to EVICTGuard, FIFO and random retention:

```powershell
python -m src.evaluate --database database/evictguard.sqlite --episode data/episodes/demo_episode.csv --capacity 8 --seed 17 --noise-type duplicate-flooding --noise-proportion 0.20 --output results/phase3_comparison.json
```

The script writes the noisy candidate CSV and its manifest next to the JSON report. The report includes selected count, capacity utilization, duplicate-flooding reduction (only for synthetic copies linked to matching in-input parents), host/event/source diversity for all selected rows and separately for non-synthetic source rows, synthetic selected count, selection runtime and the unavailable ground-truth note. Equal content hashes alone do not cause separate source events to be treated as duplicates. Since this OTRF archive has no verified event-level labels, critical-evidence retention is `null` unless a future caller supplies a trustworthy label source. Scenario membership is not treated as a positive label. Synthetic events do not corroborate one another; the benign-looking noise manifest calls generated timestamps and reused hosts experimental placeholders.

EVICTGuard uses three normalized features and a weighted sum in `[0, 1]`:

| Feature | Definition | Default weight |
| --- | --- | ---: |
| Rarity | `1 - log(category_frequency) / log(max_category_frequency)`, where category frequencies count distinct content hashes; a sole category gets 1.0. | 0.45 |
| Corroboration | Capped `log1p(distinct other content hashes on the same known host) / log1p(5)`. Exact duplicate floods do not increase this value. | 0.35 |
| Non-redundancy | `1 / exact-content-group_size`. | 0.20 |

Weights must be non-negative and sum to 1. Asset sensitivity and attack-stage relevance are explicitly reported unavailable because the present dataset does not support them. Labels are not read by feature extraction or scoring. Exact-content groups retain one representative, preferring an original over a synthetic copy, then the higher score and stable record ID. Top-ranked records up to `ceil(capacity * protected_fraction)` are marked protected; the rest of capacity is filled round-robin across available host/event strata. Remaining exact duplicates are marked redundant and unique records outside capacity evicted in the Phase 2 ledger. These statuses never delete Phase 1 events. FIFO retains newest timestamps; random selects without replacement using the configured seed.

Weights, protection fraction, capacity and seed can be adjusted from Python or through CLI flags:

```powershell
python -m src.evaluate --capacity 8 --seed 17 --weight-rarity 0.45 --weight-corroboration 0.35 --weight-non-redundancy 0.20
python -m pytest -q
```

This is a reproducible prototype, not a validated production policy. The OTRF episode is small, categories and host identifiers are simple proxies for diversity, corroboration only measures distinct events sharing a host, and the weights are research defaults rather than empirically tuned values. Full experimental evaluation and RISKSTOP remain future phases.

## Phase 4: Labelled dataset, episodes and benchmark

The single unlabelled OTRF recording has been replaced by a labelled hybrid dataset. See **`docs/DATASET.md`** for the full design and rationale.

```bash
python -m src.otrf_corpus --include-compound   # 110 OTRF Windows host recordings + metadata (~115 MB)
python -m src.label --review-sample 5          # Sigma + causal-expansion event labels -> data/labels/
python -m src.compose_episodes --background otrf   # 300 ATTACK/BENIGN episodes, leakage-safe splits
python -m src.run_benchmark --split val        # EVICTGuard vs FIFO vs Random -> results/benchmark/
# after downloading ATLASv2 sysmon + msft-security folders into data/atlasv2/raw/:
python -m src.atlas_adapter --fetch-reapr && python -m src.atlas_adapter
python -m src.compose_episodes --background atlasv2
```
