#!/bin/sh
# Final AgentDojo run: address-book variant on the sending tasks, then all 40 user tasks
# against the in-scope injections, under one shared $1.40 budget with the probe runs.
# Needs OPENROUTER_API_KEY exported in this shell. Re-run with RESUME=--resume to continue.
set -e
cd "$(dirname "$0")/.."

: "${OPENROUTER_API_KEY:?export OPENROUTER_API_KEY first}"
MODEL="${BOUNCER_MODEL:-openai/gpt-4o-mini}"
RESUME="${RESUME:-}"
SHARED="probe-deepseek,probe-gpt4omini,probe-llama33,probe-mistralsmall"
TASKS="user_task_0,user_task_1,user_task_2,user_task_3,user_task_4,user_task_5,user_task_6,user_task_7,user_task_8,user_task_9,user_task_10,user_task_11,user_task_12,user_task_13,user_task_14,user_task_15,user_task_16,user_task_17,user_task_18,user_task_19,user_task_20,user_task_21,user_task_22,user_task_23,user_task_24,user_task_25,user_task_26,user_task_27,user_task_28,user_task_29,user_task_30,user_task_31,user_task_32,user_task_33,user_task_34,user_task_35,user_task_36,user_task_37,user_task_38,user_task_39"
INJECTIONS="injection_task_0,injection_task_3,injection_task_4,injection_task_6,injection_task_10,injection_task_7,injection_task_11,injection_task_5,injection_task_8,injection_task_9,injection_task_12"

export BOUNCER_LLM=openrouter BOUNCER_MODEL="$MODEL"
# keep a Mac awake for the run when caffeinate exists
KEEP=""
command -v caffeinate >/dev/null 2>&1 && KEEP="caffeinate -dis"

$KEEP uv run --extra benchmark python -m benchmark.run_agentdojo \
  --run-id ab-final $RESUME \
  --policy benchmark/agentdojo_workspace_address_book.yaml \
  --conditions bouncer,benign-bouncer \
  --user-tasks user_task_13,user_task_19,user_task_25,user_task_32,user_task_33,user_task_37 \
  --injection-tasks injection_task_0 \
  --max-cost-usd 0.17 --shared-budget-runs "$SHARED"

$KEEP uv run --extra benchmark python -m benchmark.run_agentdojo \
  --run-id final $RESUME \
  --user-tasks "$TASKS" --injection-tasks "$INJECTIONS" \
  --max-cost-usd 1.40 --shared-budget-runs "$SHARED,ab-final"
