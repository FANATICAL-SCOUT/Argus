"""Core port-scanning engine.

Exports
-------
scan_iter        — yields PortResult objects as each open port is found (SSE)
scan             — full scan returning ScanResult
ping_host        — ICMP/TCP ping to check host liveness
fingerprint_os   — rough OS guess from open port list
"""
from __future__ import annotations

import platform
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Iterator, Optional

from backend.core.models import PortResult, ScanMeta, ScanResult
from backend.core.services import get_service_name
from backend.core.vuln import check_vulnerabilities

_IS_WIN = platform.system().lower() == "windows"


# ---------------------------------------------------------------------------
# Host liveness check
# ---------------------------------------------------------------------------

def ping_host(target: str, timeout: float = 2.0) -> tuple[bool, float]:
    """ICMP ping the target. Returns (is_alive, latency_ms).
    Falls back to TCP connect on port 80/443 if ping is blocked.
    """
    cmd = (
        ["ping", "-n", "1", "-w", str(int(timeout * 1000)), target]
        if _IS_WIN
        else ["ping", "-c", "1", "-W", str(int(timeout)), target]
    )
    try:
        t0 = time.monotonic()
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        ms = round((time.monotonic() - t0) * 1000, 1)
        if r.returncode == 0:
            return True, ms
    except Exception:
        pass

    # Fallback: TCP connect to port 80 or 443
    for port in (80, 443, 22, 8080):
        try:
            t0 = time.monotonic()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                s.close()
                return True, round((time.monotonic() - t0) * 1000, 1)
            s.close()
        except Exception:
            pass

    return False, 0.0


# ---------------------------------------------------------------------------
# OS fingerprinting (port-based heuristic)
# ---------------------------------------------------------------------------

def fingerprint_os(open_ports: list) -> str:
    """Rough OS guess from the set of open ports. Returns a string hint or ''."""
    p = {pr.port for pr in open_ports}

    if 3389 in p or (135 in p and 445 in p) or 139 in p:
        return "Windows"
    if 22 in p and (80 in p or 443 in p) and 3389 not in p:
        return "Linux/Unix"
    if 22 in p and 548 in p:
        return "macOS"
    if 631 in p or 9100 in p or 515 in p:
        return "Printer/Embedded"
    if 1433 in p or 3306 in p or 5432 in p:
        return "Database Server"
    if 80 in p or 443 in p or 8080 in p:
        return "Web Server"
    if 22 in p:
        return "Linux/Unix"
    return ""


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

def _grab_banner(target: str, sock: socket.socket, port: int, service: str) -> str:
    """Attempt to grab a service banner. Returns empty string on any failure."""
    try:
        if service in ("http", "https") or port in (80, 443, 8080, 8443):
            if service == "https" or port in (443, 8443):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock)
                except Exception:
                    pass
            try:
                sock.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % target.encode())
                return sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""

        if service == "ftp" or port == 21:
            try:
                return sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""

        if service == "ssh" or port == 22:
            try:
                return sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""

        # Generic probe
        try:
            sock.send(b"\r\n")
            return sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Single-port probe
# ---------------------------------------------------------------------------

def _scan_port(
    target: str,
    port: int,
    timeout: float,
    probe_delay: float = 0.0,
    run_vulns: bool = True,
) -> Optional[PortResult]:
    """Connect-scan one port. Returns PortResult if open, None if closed/error."""
    if probe_delay > 0:
        time.sleep(probe_delay)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((target, port)) == 0:
            service = get_service_name(port)
            banner = _grab_banner(target, s, port, service)
            s.close()
            vulns = check_vulnerabilities(service, port, banner) if run_vulns else []
            return PortResult(
                port=port,
                protocol="tcp",
                state="open",
                service=service,
                banner=banner,
                vulnerabilities=vulns,
            )
        s.close()
    except (socket.error, socket.timeout):
        pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_iter(
    target: str,
    start_port: int = 1,
    end_port: int = 1024,
    timeout: float = 1.0,
    threads: int = 100,
    on_progress: Optional[Callable[[int, int], None]] = None,
    probe_delay: float = 0.0,
    run_vulns: bool = True,
) -> Iterator[PortResult]:
    """Yield PortResult for each open port as it is discovered (completion order).

    on_progress(completed, total) is called at most ~5/s so SSE clients get
    smooth progress without being flooded.
    """
    ports = list(range(start_port, end_port + 1))
    total = len(ports)
    completed = 0
    _INTERVAL = 0.2  # seconds between progress calls
    _last_progress = time.monotonic() - _INTERVAL  # fire immediately on first call

    with ThreadPoolExecutor(max_workers=min(threads, total or 1)) as executor:
        futures = {
            executor.submit(_scan_port, target, port, timeout, probe_delay, run_vulns): port
            for port in ports
        }
        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                if result is not None:
                    yield result
            except Exception:
                pass
            if on_progress is not None:
                now = time.monotonic()
                if now - _last_progress >= _INTERVAL or completed == total:
                    _last_progress = now
                    on_progress(completed, total)


def scan(
    target: str,
    start_port: int = 1,
    end_port: int = 1024,
    timeout: float = 1.0,
    threads: int = 100,
) -> ScanResult:
    """Run a full port scan and return a structured ScanResult (ports sorted by number)."""
    start_time = datetime.now()
    meta = ScanMeta(
        target=target,
        start_port=start_port,
        end_port=end_port,
        start_time=start_time,
        total_ports=end_port - start_port + 1,
    )

    open_ports = sorted(
        scan_iter(target, start_port, end_port, timeout, threads),
        key=lambda p: p.port,
    )

    end_time = datetime.now()
    meta.end_time = end_time
    meta.duration = (end_time - start_time).total_seconds()
    meta.open_count = len(open_ports)

    return ScanResult(meta=meta, ports=open_ports)
