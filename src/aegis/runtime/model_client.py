from __future__ import annotations

from typing import Any, Dict

import httpx

from ..config import settings


def _extract_content(resp_json: Dict[str, Any]) -> str:
    choices = resp_json.get("choices") or []
    if not choices:
        return ""
    message = (choices[0] or {}).get("message") or {}
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts).strip()
    return ""


def generate_text(prompt_text: str, model_name: str | None = None) -> str:
    payload: Dict[str, Any] = {
        "model": model_name or settings.aegis_model_name,
        "temperature": 0.1,
        "max_tokens": settings.aegis_model_max_tokens,
        "messages": [
            {"role": "system", "content": settings.aegis_model_system_prompt},
            {"role": "user", "content": prompt_text},
        ],
    }
    timeout = httpx.Timeout(connect=5.0, read=float(settings.aegis_model_timeout), write=30.0, pool=5.0)
    with httpx.Client(timeout=timeout) as client:
        last_exc: Exception | None = None
        for _attempt in range(2):
            try:
                resp = client.post(settings.aegis_model_endpoint, json=payload)
                resp.raise_for_status()
                text = _extract_content(resp.json()).strip()
                if text:
                    return text
                raise RuntimeError("Model returned empty content")
            except httpx.ReadTimeout as exc:
                last_exc = exc
                continue
        raise last_exc or RuntimeError("Model generation timed out")
