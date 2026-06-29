"""Backward-compat shim — run with: python compat/scanner.py <target>"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.core.scanner import scan, scan_iter  # noqa: F401
from backend.core.models import PortResult, ScanResult, ScanMeta  # noqa: F401
from backend.utils.validators import validate_ip, resolve_hostname  # noqa: F401


class PortScanner:
    """Deprecated wrapper — use backend.core.scanner directly."""
    def __init__(self, target, start_port=1, end_port=1024, timeout=1, threads=100):
        self.target    = target
        self.start_port = start_port
        self.end_port  = end_port
        self.timeout   = timeout
        self.threads   = threads

    def run_scan(self, run_vuln_scan=False):
        import argparse
        from backend.cli.commands import cmd_scan
        args = argparse.Namespace(
            target=self.target,
            ports=f"{self.start_port}-{self.end_port}",
            timeout=self.timeout,
            threads=self.threads,
            decoy=None, mac=None, restore_mac=False,
            vuln_scan=run_vuln_scan, output=None,
        )
        cmd_scan(args)


def main():
    from backend.cli.main import main as _main
    _main()


if __name__ == "__main__":
    main()
