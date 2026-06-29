"""Backward-compat shim — run with: python compat/vuln_scanner.py"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.core.vuln import check_vulnerabilities, generate_vuln_report  # noqa: F401
from backend.core.models import Vulnerability                               # noqa: F401


class VulnerabilityScanner:
    """Deprecated wrapper — use backend.core.vuln directly."""
    def __init__(self, target, open_ports, banner_info):
        self.target = target
        self.open_ports = open_ports
        self.banner_info = banner_info

    def generate_report(self, output_file=None):
        print("[!] VulnerabilityScanner is deprecated. Use backend.core.vuln.generate_vuln_report().")


def main():
    from backend.cli.main import main as _main
    _main()


if __name__ == "__main__":
    main()
