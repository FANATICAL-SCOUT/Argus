"""SDN Controller Panel — GET /controller."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from backend.database.db import get_controller_data, get_dashboard_stats

router = APIRouter()

_RISKY_PORTS = {21, 23, 69, 135, 139, 445, 1433, 3389, 5900}
_METER_PORTS = {80, 8080, 8443, 3306, 5432, 27017}


def _priority(port: int) -> int:
    if port in _RISKY_PORTS: return 200
    if port < 1024:           return 100
    if port < 49152:          return 50
    return 10


def _action(port: int) -> tuple[str, str]:
    if port in _RISKY_PORTS: return "DROP",    "danger"
    if port in _METER_PORTS: return "METER",   "warning"
    return                           "FORWARD", "success"


def _fake_pkts(port: int, scan_id: int) -> int:
    return (port * 7 + scan_id * 13) % 9_000 + 500


def _fmt_bytes(pkts: int, port: int) -> str:
    total = pkts * (port % 50 + 10)
    if total >= 1_048_576: return f"{total / 1_048_576:.1f} MB"
    if total >= 1_024:     return f"{total / 1_024:.1f} KB"
    return f"{total} B"


def _uptime(first_scan_time: str | None) -> str:
    if not first_scan_time:
        return "N/A"
    try:
        start = datetime.fromisoformat(first_scan_time)
        delta = datetime.now() - start
        d, h = delta.days, delta.seconds // 3600
        m = (delta.seconds % 3600) // 60
        if d:  return f"{d}d {h}h {m}m"
        if h:  return f"{h}h {m}m"
        return f"{m}m"
    except Exception:
        return "N/A"


def _node_id(ip: str, idx: int) -> str:
    parts = ip.split(".")
    return f"node-{idx + 1:03d}" if len(parts) != 4 else f"sw-{parts[2]}-{parts[3]}"


@router.get("/controller", response_class=HTMLResponse)
async def controller_panel(request: Request):
    data  = get_controller_data()
    stats = get_dashboard_stats()

    flows = []
    for i, f in enumerate(data["flows"][:200]):
        port = f["port"]
        pkts = _fake_pkts(port, f.get("scan_id", i))
        action, action_cls = _action(port)
        flows.append({
            **f,
            "flow_id":    i + 1,
            "priority":   _priority(port),
            "action":     action,
            "action_cls": action_cls,
            "packets":    f"{pkts:,}",
            "bytes_str":  _fmt_bytes(pkts, port),
            "service":    f.get("service") or "unknown",
            "protocol":   (f.get("protocol") or "TCP").upper(),
        })

    nodes = [
        {**n, "node_id": _node_id(n["ip"], i), "idx": i}
        for i, n in enumerate(data["nodes"])
    ]

    total_pkts = sum(_fake_pkts(f["port"], f.get("scan_id", 0)) for f in data["flows"])
    net_load   = min(92, max(5, (data["total_flows"] * 3) % 75 + 15))

    return request.app.state.templates.TemplateResponse(
        request,
        "controller.html",
        {
            "active":       "controller",
            "nodes":        nodes,
            "flows":        flows,
            "total_nodes":  data["total_nodes"],
            "total_flows":  data["total_flows"],
            "total_scans":  stats["total_scans"],
            "uptime":       _uptime(data["first_scan_time"]),
            "total_pkts":   f"{total_pkts:,}",
            "net_load":     net_load,
        },
    )
