"""Async API: POST /api/scan (start) + GET /api/scan/{id}/stream (SSE)."""
from __future__ import annotations

import asyncio
import json
import queue
import threading
import time
from datetime import datetime

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, StreamingResponse

from backend.cli.output import save_scan_txt
from backend.core import scanner as core_scanner
from backend.core.scanner import ping_host, fingerprint_os
from backend.core.models import ScanMeta, ScanResult
from backend.database.db import save_scan
from backend.scan_tasks import ScanTask, create_task, get_task

router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# Background scan thread
# ---------------------------------------------------------------------------

def _run_scan(
    task: ScanTask,
    timeout: float,
    threads: int,
    probe_delay: float = 0.0,
    run_vulns: bool = True,
    do_ping_check: bool = False,
) -> None:
    start_ts = time.time()
    open_ports = []

    # ── Optional ping/liveness check ──────────────────────────────────────
    if do_ping_check:
        alive, latency_ms = ping_host(task.target, timeout=2.0)
        _put(task, {"type": "ping_result", "alive": alive, "latency_ms": latency_ms})
        if not alive:
            _put(task, {
                "type": "error",
                "message": (
                    f"Host {task.target!r} did not respond to ping or TCP probe. "
                    "It may be offline or blocking ICMP. Disable 'Host alive check' to force-scan anyway."
                ),
            })
            task.done = True
            return

    def _on_progress(completed: int, total: int) -> None:
        elapsed = round(time.time() - start_ts, 1)
        pct = round(completed / total * 100, 1) if total else 100.0
        _put(task, {"type": "progress", "scanned": completed, "total": total,
                    "pct": pct, "elapsed": elapsed})

    try:
        for pr in core_scanner.scan_iter(
            task.target, task.start_port, task.end_port,
            timeout, threads, on_progress=_on_progress,
            probe_delay=probe_delay, run_vulns=run_vulns,
        ):
            open_ports.append(pr)
            _put(task, {
                "type": "open_port",
                "port": pr.port,
                "service": pr.service or "unknown",
                "banner": (pr.banner or "")[:80],
                "vuln_count": len(pr.vulnerabilities),
                "elapsed": round(time.time() - start_ts, 1),
            })

        # ── OS fingerprint from found ports ───────────────────────────────
        os_hint = fingerprint_os(open_ports)

        # Persist result
        end_dt = datetime.now()
        duration = time.time() - start_ts
        meta = ScanMeta(
            target=task.target,
            start_port=task.start_port,
            end_port=task.end_port,
            start_time=datetime.fromtimestamp(start_ts),
            end_time=end_dt,
            duration=round(duration, 2),
            total_ports=task.end_port - task.start_port + 1,
            open_count=len(open_ports),
        )
        result = ScanResult(
            meta=meta,
            ports=sorted(open_ports, key=lambda p: p.port),
        )
        db_id = save_scan(result)
        save_scan_txt(result)
        task.db_id = db_id

        # ── SDN policy recommendations for high-risk findings ─────────────
        sdn_rules = _generate_sdn_recommendations(task.target, open_ports)

        _put(task, {
            "type": "done",
            "db_id": db_id,
            "open_count": len(open_ports),
            "duration": round(duration, 1),
            "os_hint": os_hint,
            "sdn_rules": sdn_rules,
        })

    except Exception as exc:
        _put(task, {"type": "error", "message": str(exc)})
    finally:
        task.done = True


# High-risk ports that warrant SDN DROP rules
_HIGH_RISK = {
    21: "FTP (plaintext auth)",
    23: "Telnet (plaintext)",
    135: "MS-RPC/EPMAP",
    139: "NetBIOS Session",
    445: "SMB (EternalBlue target)",
    1433: "MS SQL Server",
    3306: "MySQL (unauthenticated risk)",
    3389: "RDP (BlueKeep target)",
    5900: "VNC (often no auth)",
    6379: "Redis (no auth by default)",
    27017: "MongoDB (no auth by default)",
}


def _generate_sdn_recommendations(target: str, open_ports: list) -> list[dict]:
    """Generate OpenFlow-style DROP rule recommendations for high-risk open ports."""
    rules = []
    for pr in open_ports:
        reason = _HIGH_RISK.get(pr.port)
        if reason:
            rules.append({
                "port": pr.port,
                "service": pr.service,
                "reason": reason,
                "rule": f'in_port=any, nw_dst={target}, tp_dst={pr.port}, nw_proto=TCP → DROP',
                "openflow_json": {
                    "priority": 300,
                    "match": {"nw_dst": target, "tp_dst": pr.port, "nw_proto": 6},
                    "actions": [],
                    "reason": reason,
                },
            })
    return rules


def _put(task: ScanTask, event: dict) -> None:
    try:
        task.events.put_nowait(event)
    except queue.Full:
        pass  # client disconnected or too slow — drop event silently


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/scan")
async def api_start_scan(
    target: str = Form(...),
    port_range: str = Form("1-1024"),
    timeout: float = Form(1.0),
    threads: int = Form(100),
    probe_delay: float = Form(0.0),
    run_vulns: str = Form("on"),
    ping_check: str = Form("off"),
):
    target = target.strip()
    if not target:
        return JSONResponse({"error": "Target is required"}, status_code=422)

    try:
        start_str, _, end_str = port_range.partition("-")
        start_port = int(start_str.strip())
        end_port = int(end_str.strip()) if end_str.strip() else start_port
        start_port, end_port = min(start_port, end_port), max(start_port, end_port)
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid port range (e.g. 1-1024)"}, status_code=422)

    threads = max(1, min(int(threads), 500))
    timeout = max(0.1, min(float(timeout), 10.0))
    probe_delay = max(0.0, min(float(probe_delay), 5.0))
    vuln_scan_enabled = run_vulns == "on"
    do_ping_check = ping_check == "on"

    task = create_task(target, start_port, end_port)
    threading.Thread(
        target=_run_scan,
        args=(task, timeout, threads, probe_delay, vuln_scan_enabled, do_ping_check),
        daemon=True,
    ).start()

    return JSONResponse({"task_id": task.task_id})


@router.get("/scan/{task_id}/stream")
async def api_scan_stream(task_id: str, request: Request):
    task = get_task(task_id)
    if task is None:
        return JSONResponse({"error": "Task not found"}, status_code=404)

    async def _generate():
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.to_thread(task.events.get, True, 1.0)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ("done", "error"):
                    break
            except queue.Empty:
                if task.done and task.events.empty():
                    break
                yield 'data: {"type":"ping"}\n\n'

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
