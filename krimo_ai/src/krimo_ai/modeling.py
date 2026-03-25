from __future__ import annotations

import json
from typing import Optional

import requests

from .config import MODEL_ENDPOINT, MODEL_MAX_TOKENS, MODEL_NAME, MODEL_TEMPERATURE


MODEL_SESSION = requests.Session()


def model_chat(messages: list[dict[str, str]], stream: bool = False, stream_label: Optional[str] = None) -> str:
    payload = {
        "model": MODEL_NAME,
        "temperature": MODEL_TEMPERATURE,
        "max_tokens": MODEL_MAX_TOKENS,
        "messages": messages,
    }
    if stream:
        payload["stream"] = True
        resp = MODEL_SESSION.post(MODEL_ENDPOINT, json=payload, timeout=90, stream=True)
        resp.raise_for_status()
        parts: list[str] = []
        announced = False
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw:
                continue
            line = raw.strip()
            if line == "data: [DONE]":
                break
            if not line.startswith("data: "):
                continue
            try:
                chunk = json.loads(line[6:])
            except Exception:
                continue
            delta = (((chunk.get("choices") or [{}])[0].get("delta") or {}).get("content")) or ""
            if delta:
                parts.append(delta)
                if stream_label and not announced:
                    print(f"[stream] {stream_label}")
                    announced = True
        return "".join(parts).strip()
    resp = MODEL_SESSION.post(MODEL_ENDPOINT, json=payload, timeout=90)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def force_plain_answer(user_text: str) -> str:
    return model_chat(
        [
            {"role": "system", "content": "Reply with plain text only. Do not return JSON. Answer the user directly."},
            {"role": "user", "content": user_text},
        ]
    )


def add_line_references(text: str, max_lines: int = 80) -> str:
    lines = text.splitlines()
    rendered = [f"{idx + 1}: {line}" for idx, line in enumerate(lines[:max_lines])]
    if len(lines) > max_lines:
        rendered.append(f"... truncated after {max_lines} lines")
    return "\n".join(rendered)
