"""Network discovery: ARP scan, ARP table, ping sweep, device fingerprinting.

Discovery tiers (best → fallback):
  1. Scapy ARP   — admin + Scapy/Npcap installed → finds ALL devices
  2. ARP table   — no admin, reads OS cache + broadcast ping → finds recently-seen devices
  3. ICMP ping   — always available, misses firewalled/sleeping devices
All three run together; results are merged and deduplicated by IP.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

FINGERPRINT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 515, 631, 902, 993, 995, 1433, 3306, 3389,
    5555, 5900, 6633, 6653, 8080, 8181, 8443, 9100, 62078,
]

# Extra TCP ports tried during liveness check (not full fingerprint)
_LIVENESS_PORTS = [80, 443, 22, 445, 8080, 21, 23, 3389, 8443, 8888, 8008, 7547]

_IS_WIN = platform.system().lower() == "windows"


# ---------------------------------------------------------------------------
# OUI vendor lookup (built from mac.py's MAC_PREFIXES table)
# ---------------------------------------------------------------------------

def _build_oui_lookup() -> dict[str, str]:
    try:
        from backend.core.mac import MAC_PREFIXES
        lookup: dict[str, str] = {}
        for vendor, prefixes in MAC_PREFIXES.items():
            for prefix in prefixes:
                key = prefix.lower().replace("-", ":")
                lookup[key] = vendor
        return lookup
    except Exception:
        return {}

_OUI_LOOKUP: dict[str, str] = _build_oui_lookup()


def _oui_vendor(mac: str) -> str:
    """Return vendor name for a MAC address, or '' if unknown."""
    if not mac or not _OUI_LOOKUP:
        return ""
    normalized = mac.lower().replace("-", ":")
    parts = normalized.split(":")
    if len(parts) < 3:
        return ""
    prefix = ":".join(parts[:3])
    return _OUI_LOOKUP.get(prefix, "")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredHost:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    latency_ms: float = 0.0
    open_ports: list = field(default_factory=list)
    device_type: str = "host"
    os_hint: str = ""
    risk_level: str = "none"
    is_gateway: bool = False
    is_self: bool = False
    discovery_method: str = "ping"  # "arp_scapy" | "arp_table" | "ping" | "tcp"
    device_name: str = ""           # best human-readable name (NetBIOS / UPnP / hostname)


# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------

def can_arp_scan() -> bool:
    """True if Scapy ARP scan is available (admin/root + Scapy + Npcap on Windows)."""
    try:
        if _IS_WIN:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return False
        else:
            import os
            if os.geteuid() != 0:
                return False
        from scapy.all import ARP, Ether, srp  # noqa: F401
        return True
    except Exception:
        return False


def get_discovery_mode() -> str:
    """Return the best available discovery mode label."""
    if can_arp_scan():
        return "arp_scapy"
    return "arp_table"   # We always do ARP table + ping together


# ---------------------------------------------------------------------------
# Local network info
# ---------------------------------------------------------------------------

def get_local_subnet() -> tuple[str, str]:
    """Return (local_ip, subnet_cidr) e.g. ('192.168.1.5', '192.168.1.0/24')."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return local_ip, str(network)


# ---------------------------------------------------------------------------
# Tier 1: Scapy ARP scan
# ---------------------------------------------------------------------------

def _arp_scan_scapy(subnet: str) -> list[tuple[str, str, float]]:
    """ARP broadcast scan via Scapy. Returns [(ip, mac, latency_ms)].
    Only works when running as admin/root with Scapy + Npcap installed.
    """
    try:
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
        conf.verb = 0
        t0 = time.monotonic()
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=3,
        )
        results = []
        for _, received in ans:
            ms = round((time.monotonic() - t0) * 1000, 1)
            results.append((received.psrc, received.hwsrc, ms))
        return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Tier 2: OS ARP table read (no admin needed)
# ---------------------------------------------------------------------------

def _arp_table_read(subnet: str) -> list[tuple[str, str]]:
    """Read the OS ARP cache. No admin required.
    First pings the broadcast address to refresh the cache, then parses arp -a.
    Returns [(ip, mac)].
    """
    network = ipaddress.IPv4Network(subnet, strict=False)
    broadcast = str(network.broadcast_address)

    # Refresh the ARP cache by pinging broadcast
    try:
        cmd = (
            ["ping", "-n", "3", "-w", "500", broadcast]
            if _IS_WIN
            else ["ping", "-c", "3", "-W", "1", broadcast]
        )
        subprocess.run(cmd, capture_output=True, timeout=8)
    except Exception:
        pass

    results = []
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            ip_m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if not ip_m:
                continue
            ip = ip_m.group(1)
            try:
                addr = ipaddress.IPv4Address(ip)
                if addr not in network:
                    continue
                if addr in (network.network_address, network.broadcast_address):
                    continue
            except Exception:
                continue
            mac_m = re.search(r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}', line)
            mac = mac_m.group(0) if mac_m else ""
            if mac.lower() in ("ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff"):
                continue
            results.append((ip, mac))
    except Exception:
        pass

    return results


# ---------------------------------------------------------------------------
# Tier 3: ICMP ping + TCP liveness probe
# ---------------------------------------------------------------------------

def _ping(ip: str, timeout_ms: int = 800) -> tuple[bool, float, int]:
    """Returns (alive, latency_ms, ttl). TTL is 0 if unavailable."""
    cmd = (
        ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        if _IS_WIN
        else ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    )
    try:
        t0 = time.monotonic()
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        ms = (time.monotonic() - t0) * 1000
        alive = r.returncode == 0
        ttl = 0
        if alive:
            ttl_m = re.search(r'[Tt][Tt][Ll]=(\d+)', r.stdout)
            if ttl_m:
                ttl = int(ttl_m.group(1))
        return alive, round(ms, 1), ttl
    except Exception:
        return False, 0.0, 0


_APPLE_VENDORS   = ('apple',)
_ANDROID_VENDORS = (
    'samsung', 'xiaomi', 'huawei', 'oneplus', 'oppo', 'vivo',
    'realme', 'motorola', 'google', 'asus mobile', 'lenovo mobile',
    'lg electronics', 'nothing tech', 'tecno', 'infinix', 'wiko',
)


def _detect_os(ports: list, ttl: int, vendor: str) -> str:
    """Improved OS detection using open ports, TTL, and MAC vendor."""
    p = set(ports)
    v = (vendor or "").lower()

    if any(k in v for k in _APPLE_VENDORS):
        return "macOS" if (22 in p or (80 in p and 443 in p)) else "iOS"
    if any(k in v for k in _ANDROID_VENDORS):
        return "Android"

    if 62078 in p:                          # iTunes Wi-Fi sync → iPhone
        return "iOS"
    if 5555 in p:                           # Android Debug Bridge
        return "Android"
    if {135, 445} & p or 3389 in p:
        return "Windows"
    if 22 in p and (80 in p or 443 in p):
        return "Linux"
    if 22 in p:
        return "Linux / macOS"

    if ttl <= 0:
        return ""
    if ttl > 200:
        return "Network Device"
    if ttl > 100:
        return "Windows"
    return "Linux / Android / macOS"


def _netbios_name(ip: str) -> str:
    """Query NetBIOS computer name via nbtstat (Windows-only)."""
    if not _IS_WIN:
        return ""
    try:
        r = subprocess.run(
            ['nbtstat', '-A', ip],
            capture_output=True, text=True, timeout=3,
        )
        for line in r.stdout.splitlines():
            line = line.strip()
            if '<00>' in line and 'UNIQUE' in line:
                name = line.split('<')[0].strip()
                if name:
                    return name
    except Exception:
        pass
    return ""


def _upnp_name(ip: str) -> str:
    """Fetch UPnP friendlyName from router / smart device description XML."""
    import urllib.request
    import re as _re
    for port, path in [(49000, '/rootDesc.xml'), (5000, '/rootDesc.xml'),
                       (80, '/rootDesc.xml'), (80, '/description.xml')]:
        try:
            req = urllib.request.Request(
                f'http://{ip}:{port}{path}',
                headers={'User-Agent': 'pscan/2.0'},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                xml = resp.read(8192).decode('utf-8', errors='ignore')
            m = _re.search(r'<friendlyName>([^<]+)</friendlyName>', xml, _re.IGNORECASE)
            if m:
                return m.group(1).strip()
        except Exception:
            continue
    return ""


def _get_device_name(ip: str, hostname: str, vendor: str,
                     open_ports: list, is_gateway: bool) -> str:
    """Best-effort human-readable device name from all available sources."""
    nb = _netbios_name(ip)
    if nb:
        return nb
    if hostname:
        short = hostname.split('.')[0]
        if short and short != ip:
            return short
    if is_gateway or any(p in open_ports for p in (80, 8080, 49000)):
        upnp = _upnp_name(ip)
        if upnp:
            return upnp
    return ""


def _tcp_liveness(ip: str) -> tuple[bool, float]:
    """Try TCP connect on common ports. Returns (alive, latency_ms)."""
    for port in _LIVENESS_PORTS:
        try:
            t0 = time.monotonic()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return True, round((time.monotonic() - t0) * 1000, 1)
            s.close()
        except Exception:
            pass
    return False, 0.0


def _probe_host(ip: str) -> tuple[bool, float, str, int]:
    """Check if a host is alive via ICMP or TCP. Returns (alive, latency_ms, method, ttl)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        ping_fut = ex.submit(_ping, ip)
        tcp_fut  = ex.submit(_tcp_liveness, ip)
        ping_ok, ping_ms, ttl = ping_fut.result()
        tcp_ok, tcp_ms        = tcp_fut.result()

    if ping_ok:
        return True, ping_ms, "ping", ttl
    if tcp_ok:
        return True, tcp_ms, "tcp", 0
    return False, 0.0, "none", 0


# ---------------------------------------------------------------------------
# Port scan + fingerprint
# ---------------------------------------------------------------------------

def _quick_scan(ip: str) -> list[int]:
    open_ports: list[int] = []

    def _chk(port: int) -> Optional[int]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            ok = s.connect_ex((ip, port)) == 0
            s.close()
            return port if ok else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(_chk, p): p for p in FINGERPRINT_PORTS}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            if r is not None:
                open_ports.append(r)
    return sorted(open_ports)


def _fingerprint(
    ports: list[int],
    is_gateway: bool,
    vendor: str = "",
) -> tuple[str, str, str]:
    """Return (device_type, os_hint, risk_level).

    Uses port patterns + MAC vendor hint for improved classification.
    """
    p = set(ports)
    v = vendor.lower()

    # SDN controller — OpenFlow (6633/6653) or ONOS/ODL REST (8181)
    if 6633 in p or 6653 in p or 8181 in p:
        risk = "medium" if (21 in p or 23 in p or 22 in p) else "low"
        return "sdn_controller", "Linux", risk

    # Router/gateway — by role or Cisco/Huawei vendor OUI
    if is_gateway or "cisco" in v or "huawei" in v:
        risk = "medium" if (23 in p or 21 in p) else "low"
        return "router", "", risk

    if 631 in p or 9100 in p or 515 in p:
        return "printer", "", "low"

    # VMware ESXi
    if 902 in p:
        return "linux_server", "VMware ESXi", "medium"

    if 3389 in p or (135 in p and 445 in p) or 139 in p:
        risk = "high" if (23 in p or 21 in p) else "medium" if 445 in p else "low"
        return "windows_pc", "Windows", risk

    if 1433 in p or 3306 in p:
        return "database", "", "high"

    if 22 in p and (80 in p or 443 in p or 8080 in p):
        risk = "medium" if (21 in p or 23 in p) else "low"
        return "linux_server", "Linux", risk

    if 22 in p:
        return "linux_host", "Linux", "low"

    if 80 in p or 443 in p or 8080 in p:
        return "web_server", "", "medium"

    return "host", "", "none" if not ports else "low"


def _get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Main discovery: merges all tiers
# ---------------------------------------------------------------------------

def discover_network(
    subnet: str | None = None,
    on_progress: Callable | None = None,
) -> tuple[list[DiscoveredHost], str]:
    """Discover all hosts on the subnet using all available methods.

    Returns (hosts, discovery_mode) where discovery_mode is one of:
      'arp_scapy'  — full ARP scan (admin + Scapy)
      'arp_table'  — OS ARP cache + ping sweep
      'ping'       — ICMP + TCP only
    """
    local_ip, auto_subnet = get_local_subnet()
    if subnet is None:
        subnet = auto_subnet

    network    = ipaddress.IPv4Network(subnet, strict=False)
    all_hosts  = list(network.hosts())
    gateway_ip = str(all_hosts[0])
    all_ips    = [str(ip) for ip in all_hosts]
    total      = len(all_ips)

    # alive_map: ip → (latency_ms, mac, method, ttl)
    alive_map: dict[str, tuple[float, str, str, int]] = {}
    mode = get_discovery_mode()

    # ── Tier 1: Scapy ARP ────────────────────────────────────────────────
    if mode == "arp_scapy":
        if on_progress:
            on_progress("arp", 0, total, "starting ARP scan…", True)
        arp_results = _arp_scan_scapy(subnet)
        for ip, mac, ms in arp_results:
            alive_map[ip] = (ms, mac, "arp_scapy", 0)
        if on_progress:
            on_progress("arp", total, total, f"ARP found {len(arp_results)} hosts", True)

    # ── Tier 2: ARP table (always run, catches extra devices) ────────────
    if on_progress:
        on_progress("arp_table", 0, total, "reading ARP cache…", True)
    arp_table = _arp_table_read(subnet)
    for ip, mac in arp_table:
        if ip not in alive_map:
            alive_map[ip] = (0.0, mac, "arp_table", 0)
    if on_progress:
        on_progress("arp_table", total, total,
                    f"ARP table found {len(arp_table)} entries", True)

    # ── Tier 3: Concurrent ICMP + TCP sweep ──────────────────────────────
    def _probe_and_report(ip: str, idx: int) -> None:
        alive, ms, method, ttl = _probe_host(ip)
        if on_progress:
            on_progress("ping", idx, total, ip, alive or ip in alive_map)
        if alive and ip not in alive_map:
            alive_map[ip] = (ms, "", method, ttl)
        elif ip in alive_map:
            old_ms, mac, old_method, old_ttl = alive_map[ip]
            new_ms  = ms  if old_ms  == 0.0 else old_ms
            new_ttl = ttl if old_ttl == 0   else old_ttl
            alive_map[ip] = (new_ms, mac, old_method, new_ttl)

    done_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=150) as ex:
        futs = {ex.submit(_probe_and_report, ip, i): ip
                for i, ip in enumerate(all_ips)}
        for fut in concurrent.futures.as_completed(futs):
            done_count += 1
            fut.result()

    # ── Phase 2: port scan + fingerprint all alive hosts ─────────────────
    results: list[DiscoveredHost] = []
    alive_items = list(alive_map.items())
    for idx, (ip, (ms, mac, disc_method, ttl)) in enumerate(alive_items):
        if on_progress:
            on_progress("scan", idx, len(alive_items), ip, True)

        vendor  = _oui_vendor(mac)
        is_gw   = (ip == gateway_ip)
        is_self = (ip == local_ip)

        # Run port scan, hostname, NetBIOS in parallel per host
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            ports_fut    = ex.submit(_quick_scan, ip)
            hostname_fut = ex.submit(_get_hostname, ip)
            netbios_fut  = ex.submit(_netbios_name, ip)
            open_ports = ports_fut.result()
            hostname   = hostname_fut.result()
            netbios    = netbios_fut.result()

        dtype, os_hint, risk = _fingerprint(open_ports, is_gw, vendor)
        os_hint = _detect_os(open_ports, ttl, vendor) or os_hint

        # Device name: NetBIOS > short hostname > UPnP > vendor
        device_name = netbios or ""
        if not device_name and hostname:
            device_name = hostname.split('.')[0]
        if not device_name and (is_gw or any(p in open_ports for p in (80, 8080, 49000))):
            device_name = _upnp_name(ip)

        results.append(DiscoveredHost(
            ip=ip, hostname=hostname, mac=mac, vendor=vendor,
            latency_ms=ms, open_ports=open_ports,
            device_type=dtype, os_hint=os_hint,
            risk_level=risk, is_gateway=is_gw,
            is_self=is_self, discovery_method=disc_method,
            device_name=device_name,
        ))

    # Determine overall mode label for the UI
    if mode == "arp_scapy":
        ui_mode = "arp_scapy"
    elif arp_table:
        ui_mode = "arp_table"
    else:
        ui_mode = "ping"

    return results, ui_mode
