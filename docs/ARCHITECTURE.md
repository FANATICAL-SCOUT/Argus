# Argus — Architecture

This document describes the **original** v1 architecture of the `argus` CLI scanner and
the **implemented** architecture for the v2 Network Discovery & Security Analysis Dashboard.
It is the reference for all refactoring decisions. No code is changed by this document.

---

## 1. Original Architecture (v1.0.0)

`argus` (then called `pscan`) was a flat collection of five Python scripts coordinated by **subprocess calls**.

| Module | Responsibility |
|---|---|
| `pscan.py` | `argparse` CLI front door. Builds command strings and **shells out** to the other scripts via `subprocess.run()`. Adds the `gui`/decoy/mac/vuln dispatch. |
| `scanner.py` | Core engine: `PortScanner` (threaded TCP connect-scan, banner grab, service names). Imports `mac_spoofer` and `vuln_scanner`. |
| `vuln_scanner.py` | `VulnerabilityScanner`: hardcoded CVE DB (optionally `vuln_database.json`), banner→version matching, text report. |
| `mac_spoofer.py` | OS-specific MAC address changes (Windows registry/PowerShell, Linux `ip`, macOS `ifconfig`). 19 vendor OUI tables. |
| `decoy_scanner.py` | `DecoyScanner`: Scapy-based decoy SYN scanning, falls back to TCP connect when Scapy is absent. |

### Data Flow (current)

```
user ─▶ pscan.py ──subprocess──▶ scanner.py ──import──▶ mac_spoofer.py
            │                         │        ──import──▶ vuln_scanner.py
            │                         └─ prints to stdout
            │                         └─ writes records/scan_*.txt
            ├──subprocess──▶ decoy_scanner.py ─▶ records/decoy_*.txt
            └──subprocess──▶ vuln_scanner.py  ─▶ records/vuln_*.txt
```

**Key fact:** the system communicates by **side effects** — `print()`, timestamped
`.txt` files in `records/`, and subprocess exit codes. **No function returns structured
results.** This is the central obstacle for a GUI, which needs live, structured data.

---

## 2. Module Disposition

| Module / area | Decision | Rationale |
|---|---|---|
| `mac_spoofer.py` OS logic | **Untouched — wrap only** | Fragile, privilege- and platform-sensitive; works today. |
| `decoy_scanner.py` SYN/Scapy core | **Untouched — wrap I/O only** | Hard to test; refactor only its printing/persistence. |
| `PortScanner.scan_port` / `grab_banner` | **Preserve logic, extract** | Sound engine; lift into shared core and return data instead of printing. |
| `vuln_scanner.py` DB + matching | **Refactor lightly** | Keep CVE DB; separate matching from report writing; externalize DB to JSON. |
| `pscan.py` | **Refactor** | Replace subprocess dispatch with in-process core calls; add `pscan gui`. |
| `print_results` / file writers | **Refactor** | Split *produce data* / *render text* / *persist*. |

### Known technical debt
- `scanner.py check_vulnerabilities()` references an undefined `port` (would raise
  `NameError` if that branch executes) and duplicates `vuln_scanner.py` logic.
- No structured persistence — history is free-text `.txt`, so "compare scans" is impractical.
- Logic and I/O are interleaved inside scan methods.

---

## 3. Implemented Architecture (v2)

A single **shared core** consumed by both the CLI and the web dashboard.
**One backend, no duplicated business logic.**

```
argus/
  backend/                  # Python package — all server-side logic
    core/                   #   engine: returns structured data (dataclasses), no I/O
    cli/                    #   argparse adapter — renders core data to text
    api/                    #   FastAPI route handlers (HTTP pages + SSE streams)
    database/               #   SQLite layer (db.py + schema.sql)
    config/                 #   settings, constants
    utils/                  #   validators, helpers, logger
    app.py                  #   FastAPI factory
    scan_tasks.py           #   SSE task registry (scanning)
    topology_tasks.py       #   SSE task registry (discovery)

  frontend/                 # All browser-facing assets
    static/                 #   CSS, JS, self-hosted vendor libs (Bootstrap, Cytoscape, fonts)
    templates/              #   Jinja2 HTML templates (one per page)
```

### Data Flow

```
              ┌──────────── backend/core (returns ScanResult objects) ────────────┐
              │                                                                     │
   CLI  ──────┤  scan(target, opts) -> yields PortResult                           │
              │                                                                     │
   Web  ──────┤  POST /api/scan -> task_id                                         │
   (FastAPI)  │  GET  /api/scan/{id}/stream  (SSE) -> open_port / progress / done  │
              └──────────────────────────┬──────────────────────────────────────-─┘
                                         ▼
                              backend/database/ (SQLite)  ← history, reports, controller
                                         ▼
                              frontend/templates/ (Jinja2) ← rendered HTML to browser
                                         +
                              frontend/static/             ← CSS/JS/vendor downloaded by browser
```

### Design principles
- **Shared core is the only place business logic lives.** CLI and web are thin adapters.
- **Core returns data; adapters render.** No `print()` inside `core/`.
- **CLI behaviour is preserved** — verified by test suite each phase.
- **Wrap, don't rewrite** fragile modules (`mac`, `decoy`).
- **All vendor assets self-hosted** — no CDN, works fully offline.
- **Tech stack:** FastAPI + SSE, Bootstrap 5.3, Chart.js, Tabulator.js, Cytoscape.js, SQLite.

---

## 4. Implementation Phases

See `TODO.md` for the live task list and `CHANGELOG.md` for completed changes.

| Phase | Scope | Status |
|---|---|---|
| 0 | Analysis, docs, structure proposal | ✅ |
| 1 | Shared `core` + SQLite + CLI adapter + 27 tests | ✅ |
| 2 | FastAPI shell — dashboard, scan form, history, stubs | ✅ |
| 3 | Live scanning via SSE (`scan_iter` → `EventSource` → real-time table) | ✅ |
| 4 | Tabulator.js tables · scan detail page · CSV/JSON export | ✅ |
| 5 | Report viewer (sectioned report + print-to-PDF) | ✅ |
| 6 | Network topology (ping sweep → fingerprint → Cytoscape.js graph) | ✅ |
| 7 | SDN Controller Panel (OpenFlow-style view derived from scan history) | ✅ |
| 8 | UI polish · self-hosted assets · mobile sidebar · `?target=` autofill | ✅ |

Every phase leaves the project in a fully working state (CLI + dashboard).
