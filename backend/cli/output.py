"""Console rendering and .txt file persistence for scan results.

Produces byte-for-byte identical output to v1 print_results() and the
records/*.txt format, so existing users see no change.
"""
from __future__ import annotations

import json
from pathlib import Path

from backend.config.settings import Settings
from backend.core.models import ScanResult


# ---------------------------------------------------------------------------
# JSON output (machine-readable / pipe-friendly)
# ---------------------------------------------------------------------------

def print_scan_json(result: ScanResult) -> None:
    """Dump ScanResult to stdout as JSON. Only output — no progress noise."""
    meta = result.meta
    data = {
        "target": meta.target,
        "start_time": meta.start_time.isoformat(),
        "duration_seconds": round(meta.duration, 3),
        "ports_scanned": meta.total_ports,
        "open_count": meta.open_count,
        "open_ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service,
                "banner": p.banner if p.banner not in ("", "No banner retrieved") else None,
                "vulnerabilities": [
                    {
                        "name": v.name,
                        "cve": v.cve,
                        "description": v.description,
                        "confirmed": v.confirmed,
                    }
                    for v in p.vulnerabilities
                ],
            }
            for p in result.open_ports
        ],
    }
    print(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Console output (identical format to v1)
# ---------------------------------------------------------------------------

def print_scan_results(result: ScanResult) -> None:
    """Print a ScanResult to stdout in the same format as v1."""
    meta = result.meta
    print("\n" + "=" * 60)
    print(f"SCAN RESULTS FOR {meta.target}")
    print("=" * 60)
    print(f"Scan completed in {meta.duration:.2f} seconds")
    print(f"Open ports: {meta.open_count}/{meta.total_ports}")
    print("-" * 60)

    if not result.open_ports:
        print("No open ports found.")
    else:
        for pr in result.open_ports:
            print(f"PORT {pr.port}/tcp\tOPEN\t{pr.service}")
            if pr.banner and pr.banner != "No banner retrieved":
                truncated = pr.banner[:100] + ("..." if len(pr.banner) > 100 else "")
                print(f"  Banner: {truncated}")
            if pr.vulnerabilities:
                print("  POTENTIAL VULNERABILITIES:")
                for vuln in pr.vulnerabilities:
                    print(f"    - {vuln.name} ({vuln.cve})")
            print()

    print("=" * 60)


# ---------------------------------------------------------------------------
# File persistence (identical format to v1 records/)
# ---------------------------------------------------------------------------

def save_scan_txt(result: ScanResult) -> Path:
    """Write scan results to data/records/<filename>.txt. Returns the path."""
    Settings.ensure_dirs()
    ts = result.meta.start_time.strftime("%Y%m%d_%H%M%S")
    filepath = Settings.RECORDS_DIR / f"scan_{result.meta.target}_{ts}.txt"

    meta = result.meta
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"SCAN RESULTS FOR {meta.target}\n")
        f.write(f"Scan date: {meta.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Ports scanned: {meta.start_port}-{meta.end_port}\n")
        f.write(f"Scan duration: {meta.duration:.2f} seconds\n")
        f.write(f"Open ports: {meta.open_count}/{meta.total_ports}\n")
        f.write("-" * 60 + "\n\n")

        if not result.open_ports:
            f.write("No open ports found.\n")
        else:
            for pr in result.open_ports:
                f.write(f"PORT {pr.port}/tcp\tOPEN\t{pr.service}\n")
                if pr.banner and pr.banner != "No banner retrieved":
                    short = pr.banner[:100] + ("..." if len(pr.banner) > 100 else "")
                    f.write(f"  Banner: {short}\n")
                if pr.vulnerabilities:
                    f.write("  POTENTIAL VULNERABILITIES:\n")
                    for vuln in pr.vulnerabilities:
                        f.write(f"    - {vuln.name} ({vuln.cve})\n")
                f.write("\n")

    print(f"[*] Results saved to {filepath.absolute()}")
    return filepath
