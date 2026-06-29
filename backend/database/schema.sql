-- pscan SQLite schema
-- Version: 1.0.0

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    start_port  INTEGER NOT NULL,
    end_port    INTEGER NOT NULL,
    start_time  TEXT    NOT NULL,
    end_time    TEXT,
    duration    REAL,
    total_ports INTEGER,
    open_count  INTEGER,
    created_at  TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ports (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  INTEGER NOT NULL,
    port     INTEGER NOT NULL,
    protocol TEXT    DEFAULT 'tcp',
    state    TEXT    DEFAULT 'open',
    service  TEXT,
    banner   TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id     INTEGER NOT NULL,
    name        TEXT    NOT NULL,
    cve         TEXT,
    description TEXT,
    confirmed   INTEGER DEFAULT 0,
    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
);
