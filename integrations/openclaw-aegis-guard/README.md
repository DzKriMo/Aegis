# OpenClaw Aegis Guard Plugin

This local plugin wires OpenClaw hooks to Aegis endpoints:

- `llm_input` -> `/guard/input` (observability for model input in direct/webchat runs)
- `llm_output` -> `/guard/output` (observability for model output in direct/webchat runs)
- `before_tool_call` -> `/guard/tool-pre`
- `after_tool_call` -> `/guard/tool-post`
- `message_sending` -> `/guard/output`

## Install

```powershell
openclaw plugins install -l integrations/openclaw-aegis-guard
openclaw plugins enable aegis-guard
openclaw config set plugins.entries.aegis-guard.config.aegisUrl "http://127.0.0.1:8000/v1"
openclaw config set plugins.entries.aegis-guard.config.apiKeyEnv "AEGIS_API_KEY"
openclaw config set plugins.entries.aegis-guard.config.environment "dev"
```

Restart OpenClaw gateway after config updates.