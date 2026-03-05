# Aegis - Agent Guardrail Runtime

<p align="center" style="Background-Color = #ffffff">
  <img src="logo.png" alt="Aegis Logo" width="220"/>
</p>

Aegis is a policy-driven runtime guardrail layer for agentic systems. It enforces controls across user input, tool execution, tool output, and final model response.

## What Is New

- Strict policy schema validation and startup fail-hard if policies are invalid/empty.
- Guardrail profiles: `strict`, `balanced`, `assist`.
- Rate-limit backends: `memory`, `sqlite`, and `redis`.
- External evaluation suite expanded (public datasets + large-corpus builder).
- Local classifier path supports both NB JSON and TF-IDF + Logistic Regression (`.joblib`).
- Benchmark drift/trend reporting script and CI quality workflow.
- Stateful trajectory-risk control plane with quarantine mode.
- Action-centric tool risk fusion and OOD-driven dynamic thresholds.
- Tamper-evident audit chain (`prev_event_hash` -> `event_hash`) for each event.
- Replay endpoint for safety regression under new policy/model versions.
- Cost-risk metrics endpoint with risk-weighted error.

## Core Features

- Pre-LLM firewall: injection/jailbreak/exfiltration/network checks.
- Tool guardrails: allow/deny + environment and path controls.
- Post-LLM checks: secrets/PII/policy outputs.
- API key + JWT auth.
- Event/audit timeline via DB-backed sessions.
- Optional local llama.cpp classification (Qwen GGUF).

## Quick Start

```powershell
python -m uvicorn aegis.api.main:app --port 8000
```

Dashboard: 

```text
http://127.0.0.1:8000/v1/dashboard
```

## LLM Startup (GPU)

```powershell
.\llama.cpp\llama-server.exe -m models\qwen2.5-3b-instruct-q4_k_m.gguf --port 8080 --n-gpu-layers 35 --ctx-size 2048
$env:AEGIS_LLM_ENABLED="true"
$env:AEGIS_LLM_ENDPOINT="http://127.0.0.1:8080/v1/chat/completions"
$env:AEGIS_MODEL_ENABLED="true"
$env:AEGIS_MODEL_ENDPOINT="http://127.0.0.1:8080/v1/chat/completions"
python -m uvicorn aegis.api.main:app --port 8000
```

## Important Config

```env
AEGIS_GUARDRAIL_PROFILE=balanced
AEGIS_STRICT_POLICY_LOAD=true
AEGIS_RATE_LIMIT_BACKEND=sqlite
AEGIS_RATE_LIMIT_SQLITE_PATH=aegis_rate_limit.db
# or:
# AEGIS_RATE_LIMIT_BACKEND=redis
# AEGIS_RATE_LIMIT_REDIS_URL=redis://127.0.0.1:6379/0

AEGIS_LOCAL_CLASSIFIER_ENABLED=true
AEGIS_LOCAL_CLASSIFIER_PATH=models/guardrail_lr.joblib
AEGIS_LOCAL_BLOCK_THRESHOLD=0.78
AEGIS_LOCAL_WARN_THRESHOLD=0.64
AEGIS_LOCAL_APPEAL_LLM_ENABLED=false
AEGIS_LOCAL_APPEAL_CONF_THRESHOLD=0.62
AEGIS_QUARANTINE_THRESHOLD=0.95
AEGIS_OOD_WARN_THRESHOLD=0.72
AEGIS_ACTION_RISK_APPROVAL_THRESHOLD=0.75
AEGIS_ACTION_RISK_BLOCK_THRESHOLD=1.1
AEGIS_STAGE_DISAGREEMENT_THRESHOLD=2
AEGIS_POLICY_VERSION=v1
AEGIS_DETECTOR_VERSION=v1
AEGIS_MODEL_HASH=unknown
AEGIS_MODEL_ENABLED=true
AEGIS_MODEL_ENDPOINT=http://127.0.0.1:8080/v1/chat/completions
AEGIS_MODEL_NAME=qwen2.5-3b-instruct
AEGIS_MODEL_TIMEOUT=30
```

## External Agent Mode

For real agent wiring where your agent controls model/tool orchestration:

- `POST /v1/sessions/{id}/guard/input`
- `POST /v1/sessions/{id}/tools/execute`
- `POST /v1/sessions/{id}/guard/output`

Reference runner (free local model endpoint compatible, e.g. Ollama):

```powershell
python scripts/lightweight_agent_runner.py
```

## OpenClaw Direct Stack

One-command local stack (Aegis + OpenClaw gateway + Aegis OpenClaw plugin config):

```powershell
.\scripts\run_aegis_openclaw_stack.ps1 -AegisApiKey "<your-key>" -OpenDashboard
```

Free local stack (llama.cpp + Aegis + OpenClaw, no paid API keys):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_aegis_openclaw_free.ps1 -AegisApiKey "<your-key>" -OpenDashboard
```

Smoke test:

```powershell
.\scripts\test_aegis_openclaw.ps1 -AegisApiKey "<your-key>"
```

## Dataset and Benchmark Scripts

- Generate large local clean set (default 9000):  
  `python scripts/generate_clean_payloads.py`
- Build external holdout (default 1000 balanced):  
  `python scripts/build_external_eval_set.py`
- Build large external corpus (target 25k, public-source mix):  
  `python scripts/build_external_large_corpus.py`
- API end-to-end benchmark:  
  `python scripts/benchmark_guardrail_api_e2e.py ...`
- Benchmark trend/drift report:  
  `python scripts/benchmark_trend_report.py --glob "research/benchmark_*.json"`
- Generate adversarial payloads (continuous red-team corpus):  
  `python scripts/generate_adversarial_payloads.py --n 5000`

## Classifier Training

- Train NB: `python scripts/train_local_guardrail_nb.py ...`
- Train TF-IDF + Logistic Regression:  
  `python scripts/train_local_guardrail_lr.py --dataset research/aegis_payloads_clean_9000.txt --model-out models/guardrail_lr.joblib`
- Optional stack (LR scores + heuristics -> LightGBM):  
  `python scripts/train_local_guardrail_stack.py --dataset research/aegis_payloads_clean_9000.txt --lr-model models/guardrail_lr.joblib --model-out models/guardrail_stack_lgbm.joblib`
- Evaluate LR:  
  `python scripts/eval_local_guardrail_lr.py --model models/guardrail_lr.joblib --dataset research/external_eval_holdout_1000.jsonl`
- Threshold calibration:  
  `python scripts/calibrate_local_thresholds.py --model models/guardrail_lr.joblib --dataset research/external_eval_holdout_1000.jsonl`

## Policy Validation

Validate policy file before running:

```powershell
python scripts/validate_policies.py --path config/policies.example.yaml
```

## Control Plane APIs

- Session risk state: `GET /v1/sessions/{session_id}/risk`
- Session replay: `POST /v1/replay/session/{session_id}`
- Cost-risk metrics: `GET /v1/metrics/cost-risk`

## Tests

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

## CI

- Guardrail regression: `.github/workflows/guardrail-regression.yml`
- Quality + policy validation + trend artifact: `.github/workflows/guardrail-quality.yml`

## Docs

- `SYSTEM_ARCHITECTURE.md`
- `AGENT_INTEGRATION_README.md`
- `SECURITY.md`
- `research/aegis_project_guardrails_research_20260302_v2.pdf`
- `PRESENTATION_PLAYBOOK.md`
