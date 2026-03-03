# Security Policy

## Supported Versions
This repository is for coursework/demo use. Security fixes are best-effort.

## Reporting a Vulnerability
If you find a security issue, open a private issue or contact the maintainer directly.

## Scope
- Demo-grade guardrails.
- Not fully hardened as a production perimeter by itself.

## Current Security Controls
- Stateful trajectory-risk tracking and quarantine mode.
- Action-centric tool risk fusion before execution.
- OOD-triggered dynamic thresholds to reduce over-allow under shift.
- Tool-output prompt-injection sanitizer and untrusted-data wrapping.
- Tamper-evident audit chain (`prev_event_hash`/`event_hash`).
- Cross-stage consistency anomaly escalation.

## Operational Controls
- Use `AEGIS_ENV=prod`, strong `AEGIS_API_KEY`, and strong `AEGIS_JWT_SECRET`.
- Keep `AEGIS_FAIL_CLOSED=true` and `AEGIS_STRICT_POLICY_LOAD=true` in production.
- Set and track `AEGIS_POLICY_VERSION`, `AEGIS_DETECTOR_VERSION`, and `AEGIS_MODEL_HASH`.
- Use replay endpoint (`POST /v1/replay/session/{id}`) before promoting policy/model changes.
