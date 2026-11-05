#!/bin/zsh
# Free local-LLM RISKSTOP run (Qwen2.5-7B via Ollama): VAL+TEST alerts, all noise conditions, EVICTGuard memory, budget 12.
# Safe to re-run any time: every LLM answer already obtained is cached in data/llm_cache, so finished work is reused for free.
cd "$(dirname "$0")/.." || exit 1
pkill -f "src.run_alert_riskstop collect" 2>/dev/null
pgrep -f "ollama serve" >/dev/null || (OLLAMA_NUM_PARALLEL=2 nohup ollama serve > data/logs/ollama.log 2>&1 &) ; sleep 3
unset ANTHROPIC_API_KEY
nohup caffeinate -i zsh -c '
  .venv_mac/bin/python -u -W ignore -m src.run_alert_riskstop collect --investigator llm --budget 12 --workers 2 --memories evictguard --splits val test > data/logs/qwen_full.log 2>&1
  .venv_mac/bin/python -W ignore -m src.run_alert_riskstop evaluate --investigator llm --train-from heuristic_b12 > data/logs/qwen_eval.log 2>&1
' > /dev/null 2>&1 &
echo "started; progress: tail -f data/logs/qwen_full.log   (results at the end: data/logs/qwen_eval.log)"
