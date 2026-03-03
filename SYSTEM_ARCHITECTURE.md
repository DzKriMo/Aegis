# Aegis — System Architecture (Detailed)

This document explains the Aegis guardrail runtime in precise, boring detail.

---

## 1. High‑Level Flow

Each agent interaction passes through four enforced stages:

1. **Pre‑LLM input guard** (user → agent)
2. **Tool guard** (agent → tools)
3. **Tool result guard** (tools → agent)
4. **Post‑LLM output guard** (agent → user)

At each stage, **policies** are evaluated against **detectors**. The result is a decision: allow, block, redact, warn, or require approval.

---

## 2. Core Components

### 2.1 Policy Engine (`src/aegis/policies/engine.py`)
- Loads policy rules from YAML or DB.
- Each rule contains:
  - `stage` (prellm, postllm, tool_pre, tool_post)
  - `match` conditions (detectors, regex, labels, role, env)
  - `action` (block, redact, warn, approve, modify)
  - `risk` score
- Rule matching uses OR semantics across `match.any`.

### 2.2 Detectors
Detectors return boolean signals used by the policy engine.

#### a) Regex + heuristics (`src/aegis/detectors/simple.py`)
- Prompt injection
- Jailbreak
- Secrets / PII
- Exfiltration

#### b) Semantic (optional)
- Small embedding model for similarity matching

#### c) LLM classifier (`src/aegis/detectors/llm_client.py`)
- Uses local llama.cpp server to classify content
- Returns structured JSON flags
- Results are logged as `llm_classification` events

### 2.3 Runtime (`src/aegis/runtime/runner.py`)
The runtime is the orchestrator.

Steps for a user message:
1. Normalize input
2. Run LLM classifier (if enabled) and log
3. Evaluate policies (`prellm`)
4. Generate model output (placeholder for demo)
5. Evaluate policies (`postllm`)
6. Apply redaction / approval / blocking

Steps for a tool call:
1. Evaluate policies (`tool_pre`)
2. Run tool sandbox wrappers
3. Evaluate policies (`tool_post`)

### 2.4 Tool Guard (`src/aegis/runtime/tool_router.py`)
- Applies allow/deny list
- Blocks dangerous shell commands
- Restricts filesystem access to a root path
- Enforces per‑tool policies

### 2.5 Storage

Two stores exist:
- **InMemoryStore**: for fast demo
- **DbStore**: SQLite/Postgres persistence

Each event is stored with:
- `stage`
- content/tool data
- decision output
- timestamp

### 2.6 Auth (`src/aegis/auth/`)
- API key required for all endpoints
- Optional JWT issuance:
  - `POST /v1/auth/token`
  - token valid for configured TTL

### 2.7 Telemetry (`src/aegis/telemetry/`)
- Each event is emitted in structured JSON
- Optional OpenTelemetry exporter

---

## 3. Database Schema (SQLite/Postgres)

Tables:
- `aegis_sessions` — session IDs
- `aegis_events` — event logs per session
- `aegis_policies` — policy rules
- `aegis_tool_policies` — tool policy metadata
- `aegis_api_keys` / `aegis_tenants` — auth metadata

---

## 4. Web Dashboard

Dashboard is a static HTML page that:
1. Reads API key from user input
2. Calls `GET /v1/sessions` to populate list
3. Calls `GET /v1/sessions/{id}` for event timeline
4. Shows LLM classification summary

---

## 5. Failure Modes

- **LLM disabled**: classifier returns `llm_disabled`
- **LLM parse errors**: classifier returns `__error__` and raw output
- **Missing DB**: falls back to in‑memory or YAML
- **Policy mismatch**: default is allow unless a rule blocks

---

## 6. Extending the System

To add new detectors:
1. Create detector function
2. Register it in `DetectorRegistry`
3. Reference it in policy YAML

To add new tools:
1. Define tool policy in `tool_registry.py`
2. Implement execution in `tool_router.py`
3. Add tool guard rules in YAML

---

## 7. Security Notes

This is **demo-grade**. For production you would add:
- Full sandboxing for code execution
- Hardened secrets management
- Redis-backed rate limits
- TLS termination

---

## 8. Configuration

See `.env` for:
- LLM enablement
- DB URL
- Auth secrets
- Telemetry output

---

## 9. Deployability Hardening (New)

- **Strict policy load**: startup now validates policy schema and fails fast if policies are invalid or empty.
- **Guardrail profiles**:
  - `strict`: lower thresholds, fail-closed, semantic enabled
  - `balanced`: default
  - `assist`: higher thresholds to reduce user friction
- **Rate-limit backends**:
  - `memory` (dev)
  - `sqlite` (single-node deploy)
  - `redis` (distributed production)
- **Benchmark drift tooling**: generate trend reports from benchmark JSON files and surface regression alerts.
- **External corpus tooling**: builders for balanced external holdouts and larger public-source corpora.

---

## 10. Control Plane Safety (Level 2)

- **Trajectory risk state** per session:
  - `cumulative_risk_score`
  - `goal_drift_score`
  - `injection_attempt_count`
  - `sensitive_tool_attempts`
- **Quarantine mode**:
  - auto-enabled when trajectory risk crosses threshold
  - sensitive tools are blocked
  - tool calls are forced into approval flow
- **OOD-aware thresholds**:
  - local classifier entropy/distance builds an OOD score
  - warn/block thresholds are lowered dynamically under uncertainty
- **Action-centric risk fusion**:
  - tool risk modifier is fused with text/policy risk before execution
  - high combined risk can force approval or block
- **Tool output sanitizer**:
  - scans tool outputs for prompt-injection patterns
  - wraps post-tool policy evaluation with `<UNTRUSTED_TOOL_DATA>`
- **Tamper-evident audit chain**:
  - each event includes `prev_event_hash` and `event_hash`
  - hash chain makes session event logs tamper-evident

---

End of document.
