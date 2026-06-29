"""Decoy scanning — wrapper that exposes the DecoyScanner as a callable function.

The underlying Scapy logic is unchanged from v1; only module location changes.
The root-level decoy_scanner.py becomes a backward-compatibility shim.
"""
from __future__ import annotations

from typing import List, Optional


def run_decoy_scan(
    target: str,
    ports: str,
    num_decoys: int = 5,
    threads: int = 100,
    timeout: float = 1.0,
) -> List[int]:
    """Run a decoy scan and return a list of open port numbers.

    Delegates to the DecoyScanner class; preserves all Scapy + fallback logic.
    """
    # Import locally so the rest of the package can load without Scapy installed
    from backend.core._decoy_impl import DecoyScanner

    scanner = DecoyScanner(target, ports, num_decoys, timeout, threads)
    return scanner.scan()
