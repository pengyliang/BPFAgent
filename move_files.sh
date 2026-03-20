SAVE_PATH=$1
python3 scripts/collect_agent_mode_reports.py \
  --out-dir "experiments/不同LLM对比/glm" \
  --versions 4.19 5.4 5.15 6.6