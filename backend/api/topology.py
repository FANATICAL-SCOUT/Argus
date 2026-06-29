"""Network topology discovery routes."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import queue
import threading

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from backend.core.network import (
    discover_network, get_local_subnet,
    can_arp_scan, get_discovery_mode,
)
from backend.topology_tasks import create_topology_task, get_topology_task

router = APIRouter()


@router.get("/topology", response_class=HTMLResponse)
async def topology_page(request: Request):
    local_ip, subnet = get_local_subnet()
    return request.app.state.templates.TemplateResponse(
        request,
        "topology.html",
        {"active": "topology", "local_ip": local_ip, "subnet": subnet},
    )


@router.get("/api/topology/capabilities")
async def topology_capabilities():
    """Tell the frontend what discovery modes are available."""
    arp_ok = can_arp_scan()
    mode   = get_discovery_mode()
    return JSONResponse({
        "arp_scapy":   arp_ok,
        "arp_table":   True,          # always attempted
        "mode":        mode,
        "description": (
            "Full ARP scan — finds every device regardless of firewall"
            if arp_ok
            else "ARP table + ping/TCP sweep — restart as Administrator for full ARP discovery"
        ),
    })


@router.post("/api/topology/discover")
async def start_discovery(request: Request):
    body   = await request.json()
    subnet = body.get("subnet") or None
    if not subnet:
        _, subnet = get_local_subnet()

    task = create_topology_task(subnet)

    def _run() -> None:
        def on_progress(phase: str, completed: int, total: int,
                        ip: str, alive: bool) -> None:
            try:
                task.events.put_nowait(("progress", {
                    "phase": phase, "completed": completed,
                    "total": total, "ip": ip, "alive": alive,
                }))
            except queue.Full:
                pass

        try:
            hosts, ui_mode = discover_network(
                subnet=task.subnet, on_progress=on_progress
            )

            network    = ipaddress.IPv4Network(task.subnet, strict=False)
            gateway_ip = str(list(network.hosts())[0])
            alive_ips  = {h.ip for h in hosts}

            nodes = [
                {
                    "id":               h.ip,
                    "label":            h.device_name or (h.hostname.split(".")[0] if h.hostname else h.ip),
                    "ip":               h.ip,
                    "hostname":         h.hostname,
                    "mac":              h.mac,
                    "vendor":           h.vendor,
                    "device_type":      h.device_type,
                    "risk_level":       h.risk_level,
                    "open_ports":       h.open_ports,
                    "latency_ms":       h.latency_ms,
                    "is_gateway":       h.is_gateway,
                    "is_self":          h.is_self,
                    "os_hint":          h.os_hint,
                    "discovery_method": h.discovery_method,
                    "device_name":      h.device_name,
                }
                for h in hosts
            ]
            edges = [
                {"source": gateway_ip, "target": h.ip}
                for h in hosts
                if not h.is_gateway and gateway_ip in alive_ips
            ]
            sdn_controllers = [h.ip for h in hosts if h.device_type == "sdn_controller"]
            stats = {
                "total":  len(hosts),
                "risky":  sum(1 for h in hosts if h.risk_level in ("medium", "high")),
                "ports":  sum(len(h.open_ports) for h in hosts),
                "subnet": task.subnet,
                "mode":   ui_mode,
                "by_method": {
                    "arp_scapy": sum(1 for h in hosts if h.discovery_method == "arp_scapy"),
                    "arp_table": sum(1 for h in hosts if h.discovery_method == "arp_table"),
                    "ping":      sum(1 for h in hosts if h.discovery_method == "ping"),
                    "tcp":       sum(1 for h in hosts if h.discovery_method == "tcp"),
                },
                "sdn_info": {
                    "controllers": sdn_controllers,
                    "detected":    bool(sdn_controllers),
                },
            }
            task.events.put(("done", {"nodes": nodes, "edges": edges, "stats": stats}))
        except Exception as exc:
            task.events.put(("error", {"message": str(exc)}))
        finally:
            task.done = True

    threading.Thread(target=_run, daemon=True).start()
    return {"task_id": task.task_id, "subnet": task.subnet}


@router.get("/api/topology/stream/{task_id}")
async def topology_stream(task_id: str):
    task = get_topology_task(task_id)
    if task is None:
        async def _err():
            yield f"event: error\ndata: {json.dumps({'message': 'Task not found'})}\n\n"
        return StreamingResponse(_err(), media_type="text/event-stream")

    async def _generate():
        while True:
            try:
                event_type, data = await asyncio.to_thread(task.events.get, True, 1.0)
                yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
                if event_type in ("done", "error"):
                    break
            except queue.Empty:
                if task.done:
                    break
                yield "event: ping\ndata: {}\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
