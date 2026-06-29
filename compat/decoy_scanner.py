"""Backward-compat shim — run with: python compat/decoy_scanner.py <target> <ports>"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.core._decoy_impl import DecoyScanner  # noqa: F401


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target> <ports> [num_decoys] [threads] [timeout]")
        sys.exit(1)

    target     = sys.argv[1]
    ports      = sys.argv[2]
    num_decoys = int(sys.argv[3])   if len(sys.argv) > 3 else 5
    threads    = int(sys.argv[4])   if len(sys.argv) > 4 else 100
    timeout    = float(sys.argv[5]) if len(sys.argv) > 5 else 1.0

    DecoyScanner(target, ports, num_decoys, timeout, threads).scan()
