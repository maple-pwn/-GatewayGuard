"""UI route serving the bundled Android frontend."""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse


router = APIRouter(tags=["ui"])
STATIC_UI_DIR = Path(__file__).resolve().parent.parent / "static" / "ui"
INDEX_FILE = STATIC_UI_DIR / "index.html"


@router.get("/ui/")
async def ui_index():
    if INDEX_FILE.exists():
        return FileResponse(INDEX_FILE)
    return HTMLResponse(
        "<!doctype html><title>GatewayGuard</title>"
        "<body>GatewayGuard Android UI files are missing.</body>",
        status_code=500,
    )
