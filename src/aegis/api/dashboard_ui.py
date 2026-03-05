from pathlib import Path

from fastapi import APIRouter, Response
from fastapi.responses import FileResponse

router = APIRouter()

ROOT_PATH = Path(__file__).resolve().parents[3]
LOGO_PATH = ROOT_PATH / "logo.png"
TEMPLATES_PATH = Path(__file__).resolve().parents[1] / "templates"
DASHBOARD_HTML_PATH = TEMPLATES_PATH / "dashboard.html"


@router.get("/dashboard/logo.png")
def dashboard_logo():
    if not LOGO_PATH.exists():
        return Response(status_code=404)
    return FileResponse(LOGO_PATH, media_type="image/png")


@router.get("/dashboard")
def dashboard():
    if not DASHBOARD_HTML_PATH.exists():
        return Response(status_code=404)
    return FileResponse(DASHBOARD_HTML_PATH, media_type="text/html")
