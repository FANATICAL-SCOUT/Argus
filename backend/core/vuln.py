"""Vulnerability matching — checks banners against the CVE database.

Fixes from v1:
- `port` parameter is now explicit (fixes NameError in old scanner.py)
- Duplicate vuln-check in scanner.py removed; this is the single source
- CVE database loads from data/vuln_database.json with built-in fallback
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from backend.core.models import Vulnerability


# ---------------------------------------------------------------------------
# Database loading
# ---------------------------------------------------------------------------

def _builtin_db() -> dict:
    return {
        "ftp": [
            {
                "name": "vsftpd Backdoor",
                "versions": ["vsftpd 2.3.4"],
                "cve": "CVE-2011-2523",
                "description": "Backdoor that allows unauthorized access",
            },
            {
                "name": "ProFTPD Arbitrary File Copy",
                "versions": ["ProFTPD 1.3.5"],
                "cve": "CVE-2015-3306",
                "description": "Remote command execution via mod_copy module",
            },
        ],
        "ssh": [
            {
                "name": "OpenSSH User Enumeration",
                "versions": ["OpenSSH 7.2p2", "OpenSSH 7.1p1"],
                "cve": "CVE-2016-6210",
                "description": "User enumeration via timing attack",
            },
            {
                "name": "OpenSSH Username Enumeration",
                "versions": ["OpenSSH 5.9p1", "OpenSSH 7.7"],
                "cve": "CVE-2018-15473",
                "description": "Username enumeration via crafted packets",
            },
        ],
        "http": [
            {
                "name": "Apache Struts RCE",
                "versions": ["Struts 2.3.5", "Struts 2.3.31"],
                "cve": "CVE-2017-5638",
                "description": "Remote Code Execution via Content-Type header",
            },
            {
                "name": "Apache HTTP Server Path Traversal",
                "versions": ["Apache 2.4.49"],
                "cve": "CVE-2021-41773",
                "description": "Path traversal and file disclosure vulnerability",
            },
        ],
        "https": [
            {
                "name": "Heartbleed",
                "versions": ["OpenSSL 1.0.1", "OpenSSL 1.0.1f"],
                "cve": "CVE-2014-0160",
                "description": "Memory disclosure vulnerability in OpenSSL",
            },
            {
                "name": "POODLE",
                "versions": ["SSLv3"],
                "cve": "CVE-2014-3566",
                "description": "Padding Oracle On Downgraded Legacy Encryption",
            },
        ],
        "smb": [
            {
                "name": "EternalBlue",
                "versions": ["SMBv1"],
                "cve": "CVE-2017-0144",
                "description": "Remote code execution vulnerability in SMBv1",
            },
            {
                "name": "SambaCry",
                "versions": ["Samba 3.5.0", "Samba 4.5.9"],
                "cve": "CVE-2017-7494",
                "description": "Remote code execution vulnerability in Samba",
            },
        ],
        "mysql": [
            {
                "name": "MySQL Auth Bypass",
                "versions": ["MySQL 5.5.", "MySQL 5.6."],
                "cve": "CVE-2012-2122",
                "description": "Authentication bypass via timing attack",
            },
            {
                "name": "MySQL Remote Code Execution",
                "versions": ["MySQL 5.5.", "MySQL 5.6.", "MySQL 5.7."],
                "cve": "CVE-2016-6662",
                "description": "Remote code execution via malicious configuration",
            },
        ],
    }


def _load_db() -> dict:
    """Load CVE database from data/vuln_database.json; fall back to built-in."""
    from backend.config.settings import Settings

    db_path: Path = Settings.VULN_DB_PATH
    if db_path.exists():
        try:
            return json.loads(db_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return _builtin_db()


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

# Port-based risk flags — flagged regardless of banner content.
# These are real security findings: having these ports exposed is a risk.
_PORT_RISKS: List[dict] = [
    {
        "ports": [23],
        "name": "Telnet Service Exposed",
        "cve": "CWE-319",
        "description": "Telnet transmits credentials and data in plaintext. Replace with SSH immediately.",
        "confirmed": True,
    },
    {
        "ports": [21],
        "name": "FTP Service Exposed",
        "cve": "CWE-319",
        "description": "FTP transmits credentials in plaintext. Use SFTP or FTPS instead.",
        "confirmed": True,
    },
    {
        "ports": [445, 139],
        "name": "SMB Port Exposed",
        "cve": "CVE-2017-0144",
        "description": "SMB exposed to network. Vulnerable to EternalBlue-class attacks if unpatched.",
        "confirmed": False,
    },
    {
        "ports": [3389],
        "name": "RDP Accessible",
        "cve": "CVE-2019-0708",
        "description": "Remote Desktop exposed. Susceptible to brute-force and BlueKeep if unpatched.",
        "confirmed": False,
    },
    {
        "ports": [3306],
        "name": "MySQL Database Exposed",
        "cve": "CWE-284",
        "description": "MySQL port accessible from network. Database should not be publicly reachable.",
        "confirmed": True,
    },
    {
        "ports": [1433],
        "name": "MSSQL Database Exposed",
        "cve": "CWE-284",
        "description": "MSSQL port accessible from network. Database should not be publicly reachable.",
        "confirmed": True,
    },
    {
        "ports": [5900],
        "name": "VNC Remote Access Exposed",
        "cve": "CWE-284",
        "description": "VNC port accessible. Often weakly authenticated and unencrypted.",
        "confirmed": True,
    },
    {
        "ports": [80, 8080, 8008],
        "name": "Unencrypted HTTP Service",
        "cve": "CWE-319",
        "description": "Web service running on plain HTTP. Traffic is unencrypted and can be intercepted.",
        "confirmed": True,
    },
    {
        "ports": [25],
        "name": "SMTP Port Exposed",
        "cve": "CWE-284",
        "description": "SMTP accessible. May be used for email spoofing or relay abuse.",
        "confirmed": False,
    },
    {
        "ports": [161],
        "name": "SNMP Service Exposed",
        "cve": "CVE-2002-0013",
        "description": "SNMP exposes device configuration and network info. Default community strings often guessable.",
        "confirmed": False,
    },
]


def _port_risk_flags(port: int) -> List[Vulnerability]:
    """Return risk-based Vulnerability objects for a port, regardless of banner."""
    found = []
    for rule in _PORT_RISKS:
        if port in rule["ports"]:
            found.append(Vulnerability(
                name=rule["name"],
                cve=rule["cve"],
                description=rule["description"],
                confirmed=rule["confirmed"],
            ))
    return found


def check_vulnerabilities(service: str, port: int, banner: str) -> List[Vulnerability]:
    """Return a list of Vulnerability objects matching the service/port/banner.

    Parameters
    ----------
    service : str
        Service name from socket.getservbyport (e.g. 'http', 'ssh').
    port : int
        TCP port number — needed for well-known port heuristics.
    banner : str
        Raw banner string grabbed from the port.
    """
    # Always run port-based risk flags (no banner needed)
    found: List[Vulnerability] = _port_risk_flags(port)

    # Banner-based version-specific CVE matching (requires a banner)
    if not banner:
        return found

    db = _load_db()

    categories: List[str] = []
    if service == "http" or port in (80, 8080):
        categories.append("http")
    if service == "https" or port in (443, 8443):
        categories.append("https")
    if service == "ftp" or port == 21:
        categories.append("ftp")
    if service == "ssh" or port == 22:
        categories.append("ssh")
    if service == "mysql" or port == 3306:
        categories.append("mysql")
    if service in ("netbios-ssn", "microsoft-ds") or port in (139, 445):
        categories.append("smb")

    # Banner-based inference when service name isn't mapped
    if not categories:
        lower = banner.lower()
        if "ssh" in lower:
            categories.append("ssh")
        elif "ftp" in lower:
            categories.append("ftp")
        elif "http" in lower:
            categories.append("http")

    for category in categories:
        for entry in db.get(category, []):
            for version in entry.get("versions", []):
                if version.lower() in banner.lower():
                    found.append(
                        Vulnerability(
                            name=entry["name"],
                            cve=entry.get("cve", "Unknown"),
                            description=entry.get("description", ""),
                            confirmed=False,
                        )
                    )
                    break

    return found


def generate_vuln_report(result: "ScanResult", output_file: str | None = None) -> str:  # noqa: F821
    """Generate a formatted vulnerability report from a ScanResult.

    Replaces VulnerabilityScanner.generate_report() from v1.
    """
    from datetime import datetime
    from backend.config.settings import Settings

    lines = [
        "=" * 70,
        f"VULNERABILITY SCAN REPORT FOR {result.meta.target}",
        "=" * 70,
        f"Scan date: {result.meta.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
    ]

    total_vulns = sum(len(p.vulnerabilities) for p in result.ports)
    lines.append(f"Total vulnerabilities detected: {total_vulns}")
    lines.append("-" * 70)
    lines.append("")

    for port_result in sorted(result.ports, key=lambda p: p.port):
        if not port_result.vulnerabilities:
            continue
        lines.append(f"PORT {port_result.port}/{port_result.service.upper()}")
        lines.append("-" * 50)
        for vuln in port_result.vulnerabilities:
            lines.append(f"  {vuln.name}")
            lines.append(f"    CVE: {vuln.cve}")
            if vuln.description:
                lines.append(f"    Description: {vuln.description}")
            lines.append(f"    Confidence: {'High' if vuln.confirmed else 'Medium'}")
            lines.append("")
        lines.append("")

    report = "\n".join(lines)

    if output_file:
        Path(output_file).write_text(report, encoding="utf-8")
    else:
        Settings.ensure_dirs()
        ts = result.meta.start_time.strftime("%Y%m%d_%H%M%S")
        path = Settings.RECORDS_DIR / f"vuln_scan_{result.meta.target}_{ts}.txt"
        path.write_text(report, encoding="utf-8")
        print(f"[*] Vulnerability report saved to {path.absolute()}")

    return report
