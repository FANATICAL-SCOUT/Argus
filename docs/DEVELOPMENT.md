# Argus — Development Guide

## Quick start

```bash
git clone https://github.com/FANATICAL-SCOUT/Argus.git
cd Argus
pip install -e ".[dev,web]"
```

## Running the dashboard

```bash
argus gui                                  # opens http://127.0.0.1:8000 in browser
uvicorn backend.app:app --reload           # dev mode with auto-reload
```

## CLI usage

```bash
argus 192.168.1.1                          # basic scan (ports 1-1024)
argus 192.168.1.1 -p 22,80,443 -v         # specific ports + vuln report
argus 192.168.1.1 -D 5 -m Apple -r        # decoy scan + MAC spoof
python -m backend 192.168.1.1             # alternative invocation
```

## Tests

```bash
pytest                    # all 27 tests
pytest tests/test_db.py  # single module
pytest -v --tb=short     # verbose
```

---

## Project layout

```
argus/                          ← project root
│
├── backend/                    ← Python package (all server-side code)
│   ├── __init__.py             version = "2.0.0"
│   ├── __main__.py             python -m backend entry
│   ├── app.py                  FastAPI factory; mounts frontend/static + frontend/templates
│   ├── scan_tasks.py           ScanTask registry + bounded SSE queue
│   ├── topology_tasks.py       TopologyTask registry + bounded SSE queue
│   │
│   ├── api/                    ← route handlers (HTTP + SSE)
│   │   ├── dashboard.py        GET /
│   │   ├── scan.py             GET /scan  (form page)
│   │   ├── scan_api.py         POST /api/scan · GET /api/scan/{id}/stream (SSE)
│   │   ├── history.py          GET /history · GET /history/{id} · POST /history/{id}/delete
│   │   │                       GET /api/history/data  (Tabulator JSON)
│   │   ├── reports.py          GET /reports · GET /reports/{id}
│   │   ├── topology.py         GET /topology · POST /api/topology/discover
│   │   │                       GET /api/topology/stream/{id} (SSE)
│   │   ├── controller.py       GET /controller
│   │   └── stubs.py            empty router (all stubs promoted to real routes)
│   │
│   ├── core/                   ← pure engine — no I/O, no print
│   │   ├── models.py           ScanResult · ScanMeta · PortResult · Vulnerability
│   │   ├── scanner.py          scan() · scan_iter(on_progress=)  SSE-ready generator
│   │   ├── vuln.py             check_vulnerabilities() · generate_vuln_report()
│   │   ├── services.py         get_service_name(port)
│   │   ├── network.py          discover_network() · get_local_subnet() · DiscoveredHost
│   │   ├── mac.py              MAC spoofing (OS-specific)
│   │   ├── decoy.py            run_decoy_scan() wrapper
│   │   └── _decoy_impl.py      Scapy DecoyScanner (verbatim v1 logic)
│   │
│   ├── database/
│   │   ├── db.py               save_scan · get_scan · get_all_scans · delete_scan
│   │   │                       get_dashboard_stats · get_service_distribution
│   │   │                       get_all_scans_with_vuln_count · get_controller_data
│   │   └── schema.sql          scans · ports · vulnerabilities (FK cascade delete)
│   │
│   ├── cli/                    ← argparse adapter
│   │   ├── main.py             entry point; argus gui dispatched before argparse
│   │   ├── commands.py         cmd_gui() · cmd_scan() · _apply_mac_spoof()
│   │   └── output.py           print_scan_results() · save_scan_txt()
│   │
│   ├── config/
│   │   ├── settings.py         Settings class — all runtime paths resolved from __file__
│   │   └── constants.py        shared constants
│   │
│   └── utils/
│       ├── validators.py       validate_ip · resolve_hostname · parse_port_range
│       ├── logger.py
│       └── helpers.py
│
├── frontend/                   ← all browser-facing assets
│   ├── static/
│   │   ├── css/app.css         full design system (tokens, sidebar, cards, badges,
│   │   │                       topology, controller, animations, responsive)
│   │   ├── js/app.js           sidebar collapse · mobile backdrop · toasts · rel-time
│   │   └── vendor/             self-hosted: Bootstrap 5.3.3 · Bootstrap Icons 1.11.3
│   │                           Cytoscape 3.28.1 · Inter · JetBrains Mono fonts
│   │
│   └── templates/
│       ├── base.html           sidebar nav · topbar · vendor CSS/JS · toast container
│       ├── dashboard.html      stat cards · Chart.js bar/donut · recent scans table
│       ├── scan.html           live SSE scan form → real-time results table
│       ├── history.html        Tabulator.js: sort/filter/export/delete
│       ├── scan_detail.html    per-scan breakdown: ports · vulns · metadata
│       ├── reports_index.html  scan list with risk badges + report links
│       ├── report.html         sectioned report: overview·ports·services·vulns·recommendations
│       ├── topology.html       Cytoscape.js topology + discovery controls + detail panel
│       ├── controller.html     SDN controller panel: metric cards · flow table · nodes
│       ├── stub.html           reusable placeholder page
│       └── errors/404.html · errors/500.html
│
├── data/                       ← runtime data (gitignored except .gitkeep + vuln_database.json)
│   ├── vuln_database.json      CVE signatures (ftp/ssh/http/https/smb/mysql/rdp)
│   ├── records/                .txt scan reports written by CLI
│   ├── database/argus.db       SQLite (scan history)
│   ├── exports/                reserved for future CSV/PDF exports
│   └── logs/
│
├── docs/
│   ├── ARCHITECTURE.md         design rationale · module disposition · phases
│   ├── UI_GUIDELINES.md        design system — colours · type · components · states
│   ├── API.md                  full endpoint reference
│   └── DEVELOPMENT.md          ← this file
│
├── tests/
│   ├── conftest.py             fixtures: sample_vuln · sample_port · sample_scan · tmp_db
│   ├── test_core_scan.py       models · services · vuln matching · validators · scan_iter
│   ├── test_db.py              SQLite save/retrieve/delete roundtrip
│   └── test_cli_regression.py  --help · no-args · gui-import · short-scan pipeline
│
├── compat/                     ← v1 backward-compat shims (python scanner.py still works)
│   ├── scanner.py              → backend.core.scanner
│   ├── vuln_scanner.py         → backend.core.vuln
│   ├── mac_spoofer.py          → backend.core.mac
│   ├── decoy_scanner.py        → backend.core._decoy_impl
│   └── pscan.py                → backend.cli.main  (legacy shim)
│
├── scripts/pscan.bat           Legacy Windows launcher (compat shim)
├── pyproject.toml              PEP 621; entry: argus = "backend.cli.main:main"
├── requirements.txt
├── setup.py                    3-line shim (pyproject.toml is authoritative)
├── README.md · CHANGELOG.md · TODO.md · LICENSE
└── .gitignore
```

---

## Architecture decisions

See `docs/ARCHITECTURE.md` for full design rationale and module disposition.

## Design system

See `docs/UI_GUIDELINES.md` — all CSS tokens, colours, typography, component specs.

## API reference

See `docs/API.md` — complete endpoint list with request/response shapes.

## Adding vulnerability signatures

Edit `data/vuln_database.json`:

```json
{
  "<service>": [
    {
      "name": "Human-readable name",
      "versions": ["version substring to match in banner"],
      "cve": "CVE-YYYY-NNNN",
      "description": "Short description"
    }
  ]
}
```

## SSE event protocol

### Scan stream  `GET /api/scan/{id}/stream`

| Event | Payload fields |
|---|---|
| `progress` | `scanned`, `total`, `pct`, `elapsed` |
| `open_port` | `port`, `service`, `banner`, `vuln_count`, `elapsed` |
| `done` | `db_id`, `open_count`, `duration` |
| `error` | `message` |
| `ping` | *(keepalive, no fields)* |

### Topology stream  `GET /api/topology/stream/{id}`

| Event | Payload fields |
|---|---|
| `progress` | `phase`, `message`, `found` |
| `done` | `hosts` (array of DiscoveredHost) |
| `error` | `message` |

## Implementation phases

| Phase | Status | Description |
|---|---|---|
| 0 | ✅ | Architecture, planning, docs |
| 1 | ✅ | Shared core, SQLite, CLI adapter, 27 tests |
| 2 | ✅ | FastAPI dashboard shell (dashboard, scan form, history) |
| 3 | ✅ | Live scanning via SSE (scan_iter → EventSource → real-time table) |
| 4 | ✅ | Tabulator.js tables · scan detail page · CSV/JSON export |
| 5 | ✅ | Report viewer (sectioned report + print-to-PDF) |
| 6 | ✅ | Network topology (ping sweep → fingerprint → Cytoscape.js) |
| 7 | ✅ | SDN Controller Panel (OpenFlow-style view from scan history) |
| 8 | ✅ | UI polish · self-hosted assets · mobile sidebar · ?target= autofill |
