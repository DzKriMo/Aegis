from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import time
import json

from .api.routes import router
from .api.dashboard_ui import router as dashboard_router
from .api.health import router as health_router
from .api.auth import router as auth_router
from fastapi.staticfiles import StaticFiles
from .config import settings
from .storage.db import init_db
from .telemetry.otel import init_otel
from .security import validate_startup_settings

app = FastAPI(title="Aegis", version="0.1.0")
STATIC_PATH = Path(__file__).resolve().parent / "static"

# CORS (configurable; production rejects wildcard via startup validation)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.aegis_cors_origins,
    allow_credentials=True,
    allow_methods=["*"] ,
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    validate_startup_settings()
    init_db()
    init_otel()

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    print(json.dumps({
        "ts": time.time(),
        "path": request.url.path,
        "method": request.method,
        "status": response.status_code,
        "duration_ms": int(duration * 1000),
    }))
    return response

app.include_router(router, prefix="/v1")
app.include_router(dashboard_router, prefix="/v1")
app.include_router(health_router, prefix="/v1")
app.include_router(auth_router, prefix="/v1")
app.mount("/static", StaticFiles(directory=STATIC_PATH), name="static")
