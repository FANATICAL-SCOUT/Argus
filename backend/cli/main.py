"""pscan CLI entry point.

Same flags as v1 backend.py; adds `pscan gui` subcommand.
No subprocess calls — all dispatch is in-process via backend.cli.commands.
"""
from __future__ import annotations

import sys
import argparse

from backend.cli.commands import cmd_scan, cmd_gui


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus — SDN-aware Network Scanner & Security Dashboard",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Scanning Options
    parser.add_argument("target", nargs="?", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range to scan (e.g. 1-1024 or 80,443,8080)  [default: 1-1024]",
    )

    scan_grp = parser.add_argument_group("Scanning Options")
    scan_grp.add_argument("-t", "--timeout", type=float, default=1.0,
                          help="Connection timeout in seconds  [default: 1.0]")
    scan_grp.add_argument("-T", "--threads", type=int, default=100,
                          help="Number of threads  [default: 100]")
    scan_grp.add_argument("--delay", type=float, default=0.0, metavar="SECS",
                          help="Probe delay per thread in seconds — slows scan, reduces IDS noise  [default: 0]")
    scan_grp.add_argument("--ping-check", action="store_true",
                          help="Ping host before scanning; abort if unreachable")
    scan_grp.add_argument("--aggressive", action="store_true",
                          help="Aggressive preset: timeout=0.3s, threads=300 (noisy, fast)")
    scan_grp.add_argument("-D", "--decoy", nargs="?", type=int, const=5, metavar="NUM",
                          help="Decoy scan — optional number of decoys  [default: 5]")

    mac_grp = parser.add_argument_group("MAC Spoofing Options")
    mac_grp.add_argument("-m", "--mac", nargs="?", const="random", metavar="VENDOR",
                         help="Spoof MAC (optional: Apple, Cisco, Dell … — omit for random)")
    mac_grp.add_argument("-r", "--restore-mac", action="store_true",
                         help="Restore original MAC address after scan")

    vuln_grp = parser.add_argument_group("Vulnerability Scanning Options")
    vuln_grp.add_argument("-v", "--vuln-scan", action="store_true",
                          help="Generate vulnerability report for open ports")
    vuln_grp.add_argument("--no-vulns", action="store_true",
                          help="Disable per-port vulnerability matching (faster scans)")
    vuln_grp.add_argument("-o", "--output", metavar="FILE",
                          help="Custom output path for vulnerability report")

    return parser


def main() -> None:
    # Handle `pscan gui` before argparse to avoid positional-arg collision
    if len(sys.argv) > 1 and sys.argv[1] == "gui":
        cmd_gui()
        return

    parser = _build_parser()
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    cmd_scan(args)


if __name__ == "__main__":
    main()
