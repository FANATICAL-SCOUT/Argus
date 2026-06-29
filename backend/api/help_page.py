"""Help page route."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/help", response_class=HTMLResponse)
async def help_page(request: Request):
    return request.app.state.templates.TemplateResponse(
        request,
        "help.html",
        {"active": "help"},
    )
