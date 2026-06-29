"""History routes: list · detail · delete · JSON export."""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from backend.database.db import delete_scan, get_all_scans_with_vuln_count, get_scan

router = APIRouter()


@router.get("/history", response_class=HTMLResponse)
async def history(request: Request, new: int = 0, deleted: int = 0):
    """History page — Tabulator.js loads data via /api/history/data."""
    return request.app.state.templates.TemplateResponse(
        request,
        "history.html",
        {
            "active": "history",
            "new_id": new,
            "deleted": bool(deleted),
        },
    )


@router.get("/api/history/data")
async def history_data():
    """JSON endpoint consumed by Tabulator for client-side sort/filter/export."""
    scans = get_all_scans_with_vuln_count()
    return JSONResponse(scans)


@router.get("/history/{scan_id}", response_class=HTMLResponse)
async def scan_detail(scan_id: int, request: Request):
    scan = get_scan(scan_id)
    if scan is None:
        return request.app.state.templates.TemplateResponse(
            request, "errors/404.html", status_code=404
        )
    return request.app.state.templates.TemplateResponse(
        request,
        "scan_detail.html",
        {"active": "history", "scan": scan},
    )


@router.post("/history/{scan_id}/delete")
async def delete(scan_id: int, request: Request):
    delete_scan(scan_id)
    return RedirectResponse(url="/history?deleted=1", status_code=303)
