"""GET /scan — form page (SSE scan handled by /api/scan + /api/scan/{id}/stream)."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/scan", response_class=HTMLResponse)
async def scan_form(request: Request):
    return request.app.state.templates.TemplateResponse(
        request,
        "scan.html",
        {"active": "scan"},
    )
