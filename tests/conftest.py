"""Shared pytest fixtures."""
import pytest
from datetime import datetime
from backend.core.models import ScanResult, ScanMeta, PortResult, Vulnerability


@pytest.fixture
def sample_vuln():
    return Vulnerability(name="Test Vuln", cve="CVE-2024-0001", description="Test", confirmed=False)


@pytest.fixture
def sample_port(sample_vuln):
    return PortResult(port=80, service="http", banner="Apache/2.4.49", vulnerabilities=[sample_vuln])


@pytest.fixture
def sample_scan(sample_port):
    meta = ScanMeta(
        target="127.0.0.1",
        start_port=1,
        end_port=100,
        start_time=datetime(2024, 1, 1, 12, 0, 0),
        end_time=datetime(2024, 1, 1, 12, 0, 5),
        duration=5.0,
        total_ports=100,
        open_count=1,
    )
    return ScanResult(meta=meta, ports=[sample_port])


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Point the database at a temp directory for isolation."""
    from backend.config import settings as s
    monkeypatch.setattr(s.Settings, "DB_DIR", tmp_path)
    monkeypatch.setattr(s.Settings, "DB_PATH", tmp_path / "test_backend.db")
    monkeypatch.setattr(s.Settings, "RECORDS_DIR", tmp_path / "records")
    monkeypatch.setattr(s.Settings, "EXPORTS_DIR", tmp_path / "exports")
    monkeypatch.setattr(s.Settings, "LOGS_DIR", tmp_path / "logs")
    return tmp_path
