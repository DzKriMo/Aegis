from __future__ import annotations

import json
import time
from typing import Dict, Any

from ..config import settings


def emit(event: Dict[str, Any]):
    if not settings.aegis_telemetry_enabled:
        return
    payload = {
        "ts": time.time(),
        "event": event,
    }
    line = json.dumps(payload, ensure_ascii=True)
    if settings.aegis_telemetry_path:
        with open(settings.aegis_telemetry_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    else:
        try:
            print(line)
        except UnicodeEncodeError:
            print(line.encode("ascii", errors="backslashreplace").decode("ascii"))
