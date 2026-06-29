"""GET / — dashboard overview."""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from backend.database.db import (
    get_all_scans_with_vuln_count,
    get_dashboard_stats,
    get_service_distribution,
)

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    stats = get_dashboard_stats()
    recent = get_all_scans_with_vuln_count()[:5]
    svc_dist = get_service_distribution()

    svc_labels = json.dumps([r["service"] for r in svc_dist])
    svc_data = json.dumps([r["count"] for r in svc_dist])

    risk_counts = {"None": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for scan in get_all_scans_with_vuln_count():
        vc = scan.get("vuln_count", 0)
        if vc == 0:
            risk_counts["None"] += 1
        elif vc <= 2:
            risk_counts["Low"] += 1
        elif vc <= 5:
            risk_counts["Medium"] += 1
        elif vc <= 10:
            risk_counts["High"] += 1
        else:
            risk_counts["Critical"] += 1

    risk_labels = json.dumps(list(risk_counts.keys()))
    risk_data = json.dumps(list(risk_counts.values()))

    return request.app.state.templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "active": "dashboard",
            "stats": stats,
            "recent_scans": recent,
            "svc_labels": svc_labels,
            "svc_data": svc_data,
            "risk_labels": risk_labels,
            "risk_data": risk_data,
        },
    )
