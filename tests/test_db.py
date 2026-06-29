"""Tests for backend.database.db — SQLite persistence layer."""
import pytest
from backend.database.db import save_scan, get_scan, get_all_scans, delete_scan


class TestDatabase:
    def test_save_and_retrieve(self, tmp_db, sample_scan):
        scan_id = save_scan(sample_scan)
        assert isinstance(scan_id, int)
        assert scan_id > 0

        result = get_scan(scan_id)
        assert result is not None
        assert result["target"] == "127.0.0.1"
        assert result["open_count"] == 1
        assert len(result["ports"]) == 1

    def test_ports_and_vulns_persisted(self, tmp_db, sample_scan):
        scan_id = save_scan(sample_scan)
        result = get_scan(scan_id)

        port = result["ports"][0]
        assert port["port"] == 80
        assert port["service"] == "http"
        assert len(port["vulnerabilities"]) == 1
        assert port["vulnerabilities"][0]["cve"] == "CVE-2024-0001"

    def test_get_all_scans(self, tmp_db, sample_scan):
        save_scan(sample_scan)
        save_scan(sample_scan)
        scans = get_all_scans()
        assert len(scans) == 2

    def test_delete_scan(self, tmp_db, sample_scan):
        scan_id = save_scan(sample_scan)
        assert delete_scan(scan_id) is True
        assert get_scan(scan_id) is None

    def test_delete_nonexistent(self, tmp_db):
        assert delete_scan(99999) is False

    def test_get_nonexistent(self, tmp_db):
        assert get_scan(99999) is None
