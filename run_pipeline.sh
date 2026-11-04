#!/usr/bin/env bash
# End-to-end EVICTGuard data pipeline. Every step is idempotent and can be re-run.
#   ./run_pipeline.sh            interim run (OTRF background)
#   ./run_pipeline.sh atlasv2    final run (ATLASv2 benign background; streams ~12 GB once, keeps ~200 MB)
# Requirements: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pyyaml pyarrow
set -euo pipefail
cd "$(dirname "$0")"
PY="${PY:-.venv/bin/python}"
BACKGROUND="${1:-otrf}"
SIGMA_TAG="r2026-04-01"   # newer releases use renumbered ATT&CK IDs that do not match OTRF metadata

echo "== 1/6 OTRF corpus (~115 MB)"
[ -f data/otrf/index.csv ] || "$PY" -m src.otrf_corpus --include-compound

echo "== 2/6 SigmaHQ Windows rules @ $SIGMA_TAG"
if [ ! -d data/sigma/sigmahq ]; then
  git clone -q --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git data/sigma/sigmahq
  (cd data/sigma/sigmahq && git sparse-checkout set rules/windows && git fetch -q --depth 1 origin tag "$SIGMA_TAG" && git checkout -q "$SIGMA_TAG")
fi

echo "== 3/6 Event-level labels (resumable; ~35 min first time)"
[ -f data/labels/recording_summary.csv ] || "$PY" -W ignore -m src.label --review-sample 5

if [ "$BACKGROUND" = "atlasv2" ]; then
  echo "== 4/6 ATLASv2 benign background (streamed, raw XML never stored)"
  [ -d data/atlasv2/reapr ] || "$PY" -m src.atlas_adapter --fetch-reapr
  ls data/atlasv2/standardized/benign/*.parquet >/dev/null 2>&1 || "$PY" -W ignore -m src.atlas_adapter --stream
  # all 16 native attack scenarios (out-of-distribution test; attack section is at the start of the archive)
  [ "$(ls data/atlasv2/standardized/attack/*.parquet 2>/dev/null | wc -l)" -ge 16 ] || "$PY" -W ignore -m src.atlas_adapter --stream-attacks
else
  echo "== 4/6 skipped (interim OTRF background)"
fi

echo "== 5/6 Episodes ($BACKGROUND background)"
rm -rf data/benchmark
if [ "$BACKGROUND" = "atlasv2" ]; then
  "$PY" -W ignore -m src.compose_episodes --background atlasv2 --harmonize
else
  "$PY" -W ignore -m src.compose_episodes --background otrf
fi

echo "== 6/6 Benchmark on validation split (tune here; run --split test once at the end)"
"$PY" -W ignore -m src.run_benchmark --split val
if [ "$BACKGROUND" = "atlasv2" ]; then
  echo "== Out-of-distribution: native ATLASv2 attacks (no splicing) - the realistic number"
  "$PY" -W ignore -m src.run_benchmark --split ood --capacity 256 512 1024
fi
