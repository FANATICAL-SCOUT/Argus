"""CLI command implementations — in-process dispatch (no subprocess calls).

Each cmd_* function maps to one CLI subcommand/mode.
"""
from __future__ import annotations

import sys
import time
from argparse import Namespace
from datetime import datetime

from backend.core import scanner as core_scanner
from backend.cli.output import print_scan_results, print_scan_json, save_scan_txt
from backend.utils.validators import validate_ip, resolve_hostname, parse_port_range


# ---------------------------------------------------------------------------
# pscan gui
# ---------------------------------------------------------------------------

def cmd_gui() -> None:
    """Launch the web dashboard and open it in the default browser."""
    try:
        import uvicorn
    except ImportError:
        print("[!] Web dashboard requires optional dependencies.")
        print("[!] Install them with:  pip install pscan[web]")
        print("[!] Or:                 pip install fastapi uvicorn[standard] jinja2 python-multipart")
        return

    from backend.config.settings import Settings

    host = Settings.WEB_HOST
    port = Settings.WEB_PORT
    url = f"http://{host}:{port}"

    print(f"[*] Starting pscan dashboard at {url}")
    print("[*] Press Ctrl+C to stop\n")

    import threading
    import time
    import webbrowser

    def _open():
        time.sleep(1.5)
        webbrowser.open(url)

    threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(
        "backend.app:app",
        host=host,
        port=port,
        reload=False,
        log_level="warning",
    )


# ---------------------------------------------------------------------------
# pscan <target> [options]
# ---------------------------------------------------------------------------

def cmd_scan(args: Namespace) -> None:
    """Run a port scan (regular or decoy) with optional MAC spoofing and vuln scan."""
    target = _resolve_target(args.target)

    try:
        start_port, end_port = parse_port_range(args.ports)
    except ValueError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    # ---- MAC spoofing (optional) ----------------------------------------
    spoofed, original_mac, interface = False, None, None
    if getattr(args, "mac", None):
        spoofed, original_mac, interface = _apply_mac_spoof(args.mac)

    # ---- Decoy scan -------------------------------------------------------
    if getattr(args, "decoy", None) is not None:
        _run_decoy(target, args.ports, args.decoy, args.threads, args.timeout)
    else:
        _run_regular(target, start_port, end_port, args)

    # ---- Restore MAC ------------------------------------------------------
    if spoofed and original_mac and interface and getattr(args, "restore_mac", False):
        _restore_mac(interface, original_mac)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_target(raw: str) -> str:
    if validate_ip(raw):
        return raw
    print(f"[*] Resolving hostname {raw}...")
    ip = resolve_hostname(raw)
    if not ip:
        print(f"[!] Could not resolve hostname {raw}")
        sys.exit(1)
    print(f"[*] Hostname resolved to {ip}")
    return ip


def _run_regular(target: str, start_port: int, end_port: int, args: Namespace) -> None:
    # Aggressive preset overrides timeout/threads
    timeout   = 0.3  if getattr(args, "aggressive", False) else getattr(args, "timeout",  1.0)
    threads   = 300  if getattr(args, "aggressive", False) else getattr(args, "threads",  100)
    delay     = getattr(args, "delay",      0.0)
    run_vulns = not getattr(args, "no_vulns", False)
    do_ping   = getattr(args, "ping_check", False)
    json_mode = getattr(args, "json",       False)

    def log(msg: str) -> None:
        if not json_mode:
            print(msg)

    if getattr(args, "aggressive", False):
        log("[!] Aggressive mode: timeout=0.3s, threads=300")

    # Optional host liveness check
    if do_ping:
        log(f"[*] Pinging {target}...")
        alive, latency = core_scanner.ping_host(target, timeout=2.0)
        if alive:
            log(f"[+] Host is reachable ({latency} ms)")
        else:
            if not json_mode:
                print(f"[!] Host did not respond to ping. Use without --ping-check to force-scan.")
            sys.exit(1)

    log(f"[*] Starting port scan on {target}")
    log(f"[*] Scanning ports {start_port}-{end_port}")
    log(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if not run_vulns:
        log("[*] Vulnerability detection disabled")

    result = core_scanner.scan(
        target,
        start_port,
        end_port,
        timeout=timeout,
        threads=threads,
    )

    # OS fingerprint
    os_hint = core_scanner.fingerprint_os(result.ports)
    if os_hint:
        log(f"[*] OS fingerprint (heuristic): {os_hint}")

    if json_mode:
        print_scan_json(result)
    else:
        print_scan_results(result)
        save_scan_txt(result)

    # Persist to SQLite (non-fatal if DB unavailable)
    try:
        from backend.database.db import save_scan
        scan_id = save_scan(result)
        log(f"[*] Scan persisted to database (id={scan_id})")
    except Exception as exc:
        log(f"[!] Warning: could not persist to database: {exc}")

    # Optional vuln report (skip in json mode — vulns are already embedded in JSON)
    if getattr(args, "vuln_scan", False) and not json_mode:
        from backend.core.vuln import generate_vuln_report
        report = generate_vuln_report(result, getattr(args, "output", None))
        print("\n" + report)


def _run_decoy(target: str, ports: str, num_decoys: int, threads: int, timeout: float) -> None:
    try:
        from backend.core.decoy import run_decoy_scan
        run_decoy_scan(target, ports, num_decoys, threads, timeout)
    except Exception as exc:
        print(f"[!] Decoy scan error: {exc}")
        sys.exit(1)


def _apply_mac_spoof(mac_arg: str):
    """Attempt MAC spoofing; returns (spoofed, original_mac, interface)."""
    try:
        from backend.core.mac import get_interface_name, spoof_mac
        interface = get_interface_name()
        vendor = None if mac_arg == "random" else mac_arg
        if interface:
            spoofed, original = spoof_mac(interface, vendor=vendor)
            return spoofed, original, interface
        print("[!] Could not determine network interface for MAC spoofing")
    except Exception as exc:
        print(f"[!] MAC spoofing error: {exc}")
    return False, None, None


def _restore_mac(interface: str, original_mac: str) -> None:
    try:
        from backend.core.mac import restore_mac
        print(f"[*] Restoring original MAC address {original_mac}...")
        restore_mac(interface, original_mac)
        print("[+] MAC address restored")
    except Exception as exc:
        print(f"[!] Could not restore MAC: {exc}")
