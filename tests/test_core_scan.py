"""Tests for backend.core.scanner and domain models."""
import pytest
from backend.core.models import PortResult, ScanResult, ScanMeta, Vulnerability
from backend.core.services import get_service_name
from backend.core.vuln import check_vulnerabilities
from backend.utils.validators import validate_ip, resolve_hostname, parse_port_range


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------

class TestModels:
    def test_scan_result_open_ports_filter(self, sample_scan):
        assert len(sample_scan.open_ports) == 1
        assert sample_scan.open_ports[0].port == 80

    def test_port_result_defaults(self):
        pr = PortResult(port=22)
        assert pr.protocol == "tcp"
        assert pr.state == "open"
        assert pr.service == "unknown"
        assert pr.vulnerabilities == []


# ---------------------------------------------------------------------------
# Service lookup
# ---------------------------------------------------------------------------

class TestServices:
    def test_known_port(self):
        assert get_service_name(80) == "http"
        assert get_service_name(22) == "ssh"
        assert get_service_name(21) == "ftp"

    def test_unknown_port(self):
        assert get_service_name(59999) == "unknown"


# ---------------------------------------------------------------------------
# Vulnerability matching
# ---------------------------------------------------------------------------

class TestVulnCheck:
    def test_no_banner_returns_empty(self):
        assert check_vulnerabilities("http", 80, "") == []

    def test_vsftpd_match(self):
        vulns = check_vulnerabilities("ftp", 21, "220 (vsFTPd 2.3.4)")
        assert len(vulns) == 1
        assert vulns[0].cve == "CVE-2011-2523"

    def test_apache_match(self):
        vulns = check_vulnerabilities("http", 80, "Apache 2.4.49")
        assert any(v.cve == "CVE-2021-41773" for v in vulns)

    def test_no_match(self):
        vulns = check_vulnerabilities("http", 80, "nginx/1.22.0")
        assert vulns == []

    def test_port_not_undefined(self):
        """Regression: port NameError from v1 scanner.py check_vulnerabilities."""
        # SMB port path — port must be accessible (was undefined in v1)
        result = check_vulnerabilities("microsoft-ds", 445, "SMBv1 server")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

class TestValidators:
    def test_valid_ips(self):
        assert validate_ip("192.168.1.1")
        assert validate_ip("10.0.0.1")
        assert validate_ip("255.255.255.255")

    def test_invalid_ips(self):
        assert not validate_ip("256.0.0.1")
        assert not validate_ip("hostname.local")
        assert not validate_ip("192.168.1")

    def test_parse_range(self):
        assert parse_port_range("1-1024") == (1, 1024)
        assert parse_port_range("80") == (80, 80)

    def test_parse_comma(self):
        start, end = parse_port_range("80,443,8080")
        assert start == 80 and end == 8080

    def test_parse_invalid(self):
        with pytest.raises(ValueError):
            parse_port_range("0-65536")


# ---------------------------------------------------------------------------
# Scan (lightweight — scans only 1 port on loopback, no network dep)
# ---------------------------------------------------------------------------

class TestScan:
    def test_scan_returns_scan_result(self):
        from backend.core.scanner import scan
        result = scan("127.0.0.1", start_port=65530, end_port=65535, timeout=0.2, threads=6)
        assert isinstance(result, ScanResult)
        assert result.meta.target == "127.0.0.1"
        assert result.meta.total_ports == 6
        assert isinstance(result.ports, list)

    def test_scan_iter_yields_port_results(self):
        from backend.core.scanner import scan_iter
        results = list(scan_iter("127.0.0.1", start_port=65530, end_port=65532, timeout=0.2, threads=3))
        assert all(isinstance(r, PortResult) for r in results)
