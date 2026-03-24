from __future__ import annotations

import os


AEGIS_BASE = os.getenv("AEGIS_BASE_URL", "http://127.0.0.1:8000/v1")
AEGIS_API_KEY = os.getenv("AEGIS_API_KEY", "changeme")
MODEL_ENDPOINT = os.getenv("AGENT_MODEL_ENDPOINT", "http://127.0.0.1:11434/v1/chat/completions")
MODEL_NAME = os.getenv("AGENT_MODEL_NAME", "qwen2.5:7b-instruct")
MODEL_TEMPERATURE = float(os.getenv("AGENT_MODEL_TEMPERATURE", "0.1"))
MODEL_MAX_TOKENS = int(os.getenv("AGENT_MODEL_MAX_TOKENS", "400"))
MODEL_STREAM_ENABLED = os.getenv("AGENT_MODEL_STREAM", "true").lower() in {"1", "true", "yes", "on"}
AGENT_ENV = os.getenv("AEGIS_AGENT_ENV", "dev")
FILESYSTEM_ROOT = os.getenv("AEGIS_AGENT_FILESYSTEM_ROOT", os.getcwd())
AGENT_NAME = "KriMo AI"
AGENT_BANNER = r"""
██╗  ██╗██████╗ ██╗███╗   ███╗ ██████╗      █████╗ ██╗
██║ ██╔╝██╔══██╗██║████╗ ████║██╔═══██╗    ██╔══██╗██║
█████╔╝ ██████╔╝██║██╔████╔██║██║   ██║    ███████║██║
██╔═██╗ ██╔══██╗██║██║╚██╔╝██║██║   ██║    ██╔══██║██║
██║  ██╗██║  ██║██║██║ ╚═╝ ██║╚██████╔╝    ██║  ██║██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝ ╚═════╝     ╚═╝  ╚═╝╚═╝
""".strip("\n")
