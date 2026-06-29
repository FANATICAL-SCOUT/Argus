"""Input validation helpers — lifted from v1 scanner.py."""
from __future__ import annotations

import re
import socket
from typing import Optional


def validate_ip(ip: str) -> bool:
    """Return True if *ip* is a syntactically valid IPv4 address."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve *hostname* to an IPv4 string, or return None on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def parse_port_range(ports_str: str) -> tuple[int, int]:
    """Parse a port string like '1-1024' or '80,443' into (start, end).

    For comma-separated lists, returns (min_port, max_port).
    Raises ValueError on invalid input.
    """
    ports_str = ports_str.strip()
    if "-" in ports_str:
        parts = ports_str.split("-", 1)
        start, end = int(parts[0]), int(parts[1])
    elif "," in ports_str:
        port_list = [int(p.strip()) for p in ports_str.split(",")]
        start, end = min(port_list), max(port_list)
    else:
        start = end = int(ports_str)

    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        raise ValueError(f"Invalid port range: {ports_str}")
    return start, end
