"""SQLite persistence layer for backend.

Public API
----------
save_scan(result)     -> int          persist a ScanResult; return row id
get_scan(scan_id)     -> dict | None  full scan data with ports + vulns
get_all_scans()       -> list[dict]   all scan metadata (no ports)
delete_scan(scan_id)  -> bool         delete a scan and its children
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Optional

from backend.config.settings import Settings
from backend.core.models import ScanResult


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    """Yield a sqlite3 connection with foreign keys enabled; auto-commit or rollback."""
    Settings.ensure_dirs()
    con = sqlite3.connect(str(Settings.DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create tables if they do not exist (idempotent)."""
    schema_path: Path = Path(__file__).parent / "schema.sql"
    with _conn() as con:
        con.executescript(schema_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------

def save_scan(result: ScanResult) -> int:
    """Persist *result* to SQLite. Returns the new scan row id."""
    init_db()
    meta = result.meta

    with _conn() as con:
        cur = con.execute(
            """
            INSERT INTO scans
                (target, start_port, end_port, start_time, end_time,
                 duration, total_ports, open_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                meta.target,
                meta.start_port,
                meta.end_port,
                meta.start_time.isoformat(),
                meta.end_time.isoformat() if meta.end_time else None,
                meta.duration,
                meta.total_ports,
                meta.open_count,
            ),
        )
        scan_id: int = cur.lastrowid  # type: ignore[assignment]

        for pr in result.ports:
            cur2 = con.execute(
                """
                INSERT INTO ports (scan_id, port, protocol, state, service, banner)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, pr.port, pr.protocol, pr.state, pr.service, pr.banner),
            )
            port_id: int = cur2.lastrowid  # type: ignore[assignment]

            for vuln in pr.vulnerabilities:
                con.execute(
                    """
                    INSERT INTO vulnerabilities
                        (port_id, name, cve, description, confirmed)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (port_id, vuln.name, vuln.cve, vuln.description, int(vuln.confirmed)),
                )

    return scan_id


def delete_scan(scan_id: int) -> bool:
    """Delete scan *scan_id* and its child rows. Returns True if a row was deleted."""
    init_db()
    with _conn() as con:
        cur = con.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------

def get_all_scans() -> List[dict]:
    """Return all scan metadata rows, newest first."""
    init_db()
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM scans ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_dashboard_stats() -> dict:
    """Aggregate stats for the dashboard overview cards."""
    init_db()
    with _conn() as con:
        total_scans = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        total_open = con.execute("SELECT COALESCE(SUM(open_count), 0) FROM scans").fetchone()[0]
        total_vulns = con.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        last_row = con.execute(
            "SELECT created_at, target FROM scans ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    return {
        "total_scans": total_scans,
        "total_open_ports": total_open,
        "total_vulnerabilities": total_vulns,
        "last_scan_time": dict(last_row)["created_at"] if last_row else None,
        "last_scan_target": dict(last_row)["target"] if last_row else None,
    }


def get_service_distribution(limit: int = 8) -> List[dict]:
    """Return top N services by open port count (for bar chart)."""
    init_db()
    with _conn() as con:
        rows = con.execute(
            """SELECT COALESCE(NULLIF(service,''), 'unknown') as service,
                      COUNT(*) as count
               FROM ports WHERE state = 'open'
               GROUP BY service ORDER BY count DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_all_scans_with_vuln_count() -> List[dict]:
    """Return all scan rows with an extra vuln_count column, newest first."""
    init_db()
    with _conn() as con:
        rows = con.execute(
            """SELECT s.*,
                      COUNT(v.id) AS vuln_count
               FROM scans s
               LEFT JOIN ports p ON p.scan_id = s.id
               LEFT JOIN vulnerabilities v ON v.port_id = p.id
               GROUP BY s.id
               ORDER BY s.created_at DESC"""
        ).fetchall()
    return [dict(r) for r in rows]


def get_controller_data() -> dict:
    """Return all data needed for the SDN controller panel."""
    init_db()
    with _conn() as con:
        nodes_rows = con.execute("""
            SELECT target AS ip,
                   COUNT(DISTINCT id)  AS scan_count,
                   MAX(created_at)     AS last_scan,
                   COALESCE(SUM(open_count), 0) AS total_open
            FROM scans
            GROUP BY target
            ORDER BY last_scan DESC
        """).fetchall()

        flows_rows = con.execute("""
            SELECT p.id, p.port, p.protocol, p.service, p.state,
                   s.target, s.id AS scan_id, s.created_at
            FROM ports p
            JOIN scans s ON s.id = p.scan_id
            WHERE p.state = 'open'
            ORDER BY s.created_at DESC, p.port
            LIMIT 500
        """).fetchall()

        total_flows = con.execute(
            "SELECT COUNT(*) FROM ports WHERE state = 'open'"
        ).fetchone()[0]

        first_scan = con.execute(
            "SELECT MIN(created_at) FROM scans"
        ).fetchone()[0]

    return {
        "nodes":           [dict(r) for r in nodes_rows],
        "flows":           [dict(r) for r in flows_rows],
        "total_nodes":     len(nodes_rows),
        "total_flows":     total_flows,
        "first_scan_time": first_scan,
    }


def get_scan(scan_id: int) -> Optional[dict]:
    """Return a scan with nested ports and vulnerabilities, or None if not found."""
    init_db()
    with _conn() as con:
        row = con.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        scan = dict(row)

        ports_rows = con.execute(
            "SELECT * FROM ports WHERE scan_id = ? ORDER BY port", (scan_id,)
        ).fetchall()

        ports = []
        for pr in ports_rows:
            port_dict = dict(pr)
            vuln_rows = con.execute(
                "SELECT * FROM vulnerabilities WHERE port_id = ?", (pr["id"],)
            ).fetchall()
            port_dict["vulnerabilities"] = [dict(v) for v in vuln_rows]
            ports.append(port_dict)

        scan["ports"] = ports
    return scan
