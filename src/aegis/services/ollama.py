from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx

from ..config import settings


def _base_url_from_endpoint(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    if not parsed.scheme or not parsed.netloc:
        return settings.aegis_ollama_base_url
    return f"{parsed.scheme}://{parsed.netloc}"


def ollama_base_url() -> str:
    return settings.aegis_ollama_base_url or _base_url_from_endpoint(settings.aegis_model_endpoint)


def list_ollama_models() -> List[Dict[str, Any]]:
    url = f"{ollama_base_url()}/api/tags"
    with httpx.Client(timeout=10) as client:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.json()

    models: List[Dict[str, Any]] = []
    for item in data.get("models") or []:
        if not isinstance(item, dict):
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        models.append(
            {
                "name": str(item.get("name") or item.get("model") or ""),
                "model": str(item.get("model") or item.get("name") or ""),
                "size": item.get("size"),
                "modified_at": item.get("modified_at"),
                "family": details.get("family"),
                "parameter_size": details.get("parameter_size"),
                "quantization_level": details.get("quantization_level"),
            }
        )
    return models
