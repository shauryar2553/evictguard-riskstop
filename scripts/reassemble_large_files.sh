#!/usr/bin/env bash
# Rebuild files that were split into 15 MB parts for upload (run once after cloning).
cd "$(dirname "$0")/.."
for parts0 in $(find . -name "*.part-aa" -not -path "./.git/*"); do
  f="${parts0%.part-aa}"
  [ -f "$f" ] && { echo "exists: $f"; continue; }
  cat "$f".part-* > "$f"
  if [ -f "$f.sha256" ] && [ "$(shasum -a 256 "$f" | awk '{print $1}')" = "$(cat "$f.sha256")" ]; then echo "rebuilt OK: $f"; else echo "CHECKSUM MISMATCH: $f"; fi
done
