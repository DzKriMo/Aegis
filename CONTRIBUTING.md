# Contributing

Thanks for your interest in improving Aegis.

## Setup
- Install Python 3.10+
- Create a virtual environment
- Install dependencies from `requirements.txt`
- For full local experimentation, also install `requirements-ml.txt`

## Development
- Keep changes small and focused
- Add tests if you change core logic
- Run the demo script to validate behavior
- For safety-control changes, run replay against at least one historical session

## Style
- Prefer clear, explicit code over clever abstractions
- Keep security decisions easy to read

## Pull Requests
- Describe what you changed and why
- Include screenshots for UI changes

## Required Checks
- `python -m unittest discover -s tests -p "test_*.py" -v`
- `python scripts/validate_policies.py --path config/policies.example.yaml`
- If changed runtime/policies, include replay output from:
  - `POST /v1/replay/session/{session_id}`

## CI Notes
GitHub workflow tests use deterministic env flags:
- `AEGIS_LLM_ENABLED=false`
- `AEGIS_DB_ENABLED=false`
- `AEGIS_SEMANTIC_ENABLED=false`
- `HF_HUB_OFFLINE=1`
