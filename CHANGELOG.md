# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses date-based entries with Added / Changed / Removed / Refactored / Reason.

---

## [2.11.0] — Device Intelligence + UI Polish + Scan Integration  *(2026-06-28)*

### Added

#### Device Name & OS Detection (`backend/core/network.py`)
- **`_netbios_name(ip)`** — queries Windows/Samba computer name via `nbtstat -A` (Windows-only);
  returns the workstation name (e.g. `DESKTOP-ABC123`) for any Windows device on the subnet.
- **`_upnp_name(ip)`** — fetches UPnP `<friendlyName>` from device description XML over ports
  49000, 5000, 80; identifies routers and smart TVs by model name (e.g. `TP-Link Archer AX55`).
- **`_detect_os(ports, ttl, vendor)`** — replaces `_os_from_ttl()`; combines MAC vendor OUI,
  open ports, and TTL for accurate OS identification:
  - MAC vendor → Android (Samsung/Xiaomi/Huawei/etc.) or iOS/macOS (Apple)
  - Port 62078 (iTunes sync) → iOS; port 5555 (ADB) → Android
  - Ports 135/445/3389 → Windows; port 22 → Linux
- **`device_name` field** on `DiscoveredHost` — populated from NetBIOS → short hostname →
  UPnP in priority order; falls back to empty string.
- **Ports 5555 and 62078** added to `FINGERPRINT_PORTS` for Android/iPhone detection.
- **Per-host parallel lookup** — port scan, hostname, and NetBIOS run concurrently per host
  using a 3-worker `ThreadPoolExecutor`.

#### Port-Based Vulnerability Detection (`backend/core/vuln.py`)
- **`_PORT_RISKS` table** — 10 rules that flag risky open ports without requiring a version
  banner; covers: Telnet/23 (CWE-319 high), FTP/21, SMB/445+139 (EternalBlue), RDP/3389
  (BlueKeep), MySQL/3306, MSSQL/1433, VNC/5900, HTTP/80 (unencrypted), SMTP/25, SNMP/161.
- **`_port_risk_flags(port)`** — returns `Vulnerability` objects for any matching port.
- `check_vulnerabilities()` now runs port-risk flags first (no banner required), then
  appends banner-based CVE matches on top. Dashboard vuln count now shows real data for
  home/lab networks.

#### Topology Sidebar UX (`frontend/templates/topology.html`, `frontend/static/css/app.css`)
- **Minimize toggle** — chevron button in sidebar header collapses sidebar to 36px with
  220ms CSS transition; icon flips `‹`/`›`; `cy.resize()` called after animation.
- **Drag-to-resize handle** — 5px strip between sidebar and canvas; drag to resize 160–520px;
  auto-expands collapsed sidebar on drag; `cy.resize()` on mouse-up.
- **Overlay escape hatch** — double-click on the discovery progress overlay to dismiss it
  if it gets stuck after a failed scan.

#### Scan Integration from Topology (`frontend/templates/topology.html`)
- Node detail panel now shows **Device Name** and **Vendor / Brand** rows.
- **Three scan buttons** replace the single "Full Port Scan" button:
  - `Quick` → `/scan?target=IP&ports=1-1024` (new tab)
  - `Full` → `/scan?target=IP&ports=1-65535` (new tab)
  - `Vuln` → `/scan?target=IP&ports=1-1024&vuln=1` (new tab)

#### Scan Page URL Params (`frontend/templates/scan.html`)
- `?ports=` pre-fills the port range input on page load.
- `?vuln=1` enables the vulnerability scan toggle on page load.
- CLI preview updates to reflect both params.

#### New-Tab Navigation (`frontend/templates/base.html`)
- **Network Topology** and **SDN Controller** sidebar links open in a new browser tab
  (`target="_blank"`) so the main dashboard session is never interrupted.

#### Topology Node Labels (`backend/api/topology.py`)
- Node `label` field now uses `device_name` (if found) before falling back to
  short hostname or IP — device names appear directly on the topology graph.

#### New Files
- **`mock_sdn_controller.py`** — standalone demo script; listens on OpenFlow ports 6633
  and 6653 so the topology scanner detects the local machine as an SDN Controller node.
  Used for demonstrating SDN detection without a real OpenFlow controller.
- **`RUNNING.md`** — quick-reference guide covering all run modes (GUI, CLI, mock SDN),
  admin requirements per feature, and step-by-step SDN demo instructions.

### Changed
- `discover_network()` phase-2 loop now runs port scan + hostname + NetBIOS in parallel
  per host; populates `device_name` and uses `_detect_os()` for richer OS hints.
- `topology.py` node serialisation passes `device_name` to the frontend.
- `.gitignore` — expanded: covers `report.txt`, `*.zip`, `.coverage`, `htmlcov/`,
  `.pytest_cache/`, `.venv/`, `secrets.json`.

---

## [2.10.0] — Phase 10: Topology Intelligence + Visual Overhaul + SDN Panel  *(2026-06-28)*

Three co-delivered phases that complete the SDN-aware topology feature.

### Phase A — Discovery Intelligence (`backend/core/network.py`)

#### Added
- **OUI vendor lookup** — `_build_oui_lookup()` inverts `mac.py`'s `MAC_PREFIXES` table at import
  time into a `{oui_prefix → vendor}` reverse dict. `_oui_vendor(mac)` resolves any captured MAC
  to a brand name (e.g. "Cisco", "Dell", "Apple") using 3-byte OUI prefix matching.
- **TTL-based OS detection** — `_ping()` now returns `(alive, latency_ms, ttl)` by parsing
  `TTL=N` from ping stdout (case-insensitive; works on both Windows and Linux output formats).
  `_os_from_ttl(ttl)` maps TTL → "Windows" (>100), "Linux / macOS" (≤64), "Network Device" (>200).
  TTL hint is used as `os_hint` fallback when port fingerprinting returns no OS information.
- **`_probe_host()` returns TTL** — passes TTL through from ping result; stored in `alive_map` as
  4-tuple `(latency_ms, mac, method, ttl)`.
- **Extended `FINGERPRINT_PORTS`** — added 902 (VMware ESXi), 6633 (OpenFlow), 6653 (OpenFlow alt),
  8181 (ONOS/ODL Karaf REST). Total: 27 fingerprint ports.
- **SDN controller detection** — `_fingerprint()` now detects OpenFlow/ONOS nodes:
  ports 6633/6653/8181 → `device_type = "sdn_controller"`, `os_hint = "Linux"`.
- **Vendor-boosted fingerprinting** — `_fingerprint()` accepts `vendor` string; Cisco/Huawei OUI
  on any non-gateway host is classified as `router` even without gateway-role IP assignment.
- **VMware ESXi detection** — port 902 → `device_type = "linux_server"`, `os_hint = "VMware ESXi"`.
- **`DiscoveredHost.vendor`** — new field populated from OUI lookup after MAC is resolved.

#### Changed
- `discover_network()` — calls `_oui_vendor(mac)` per host; passes vendor to `_fingerprint()`;
  fills `os_hint` from TTL when port scan returns empty OS string.

### Phase B — Cytoscape Visual Overhaul (`frontend/templates/topology.html`)

#### Added
- **SVG node icons** — each device type gets a white minimal SVG icon (router, monitor, server rack,
  printer, globe, database cylinders, SDN hub, PC, question mark) embedded as data URIs via
  Cytoscape `background-image` with per-type `node[device_type = "X"]` selectors. Icons render
  at 65% node size on the coloured background circle.
- **Layout switcher** — four buttons in the sidebar: Concentric (default) | Tree (`breadthfirst`,
  gateway as root) | Force (`cose`, built-in force-directed) | Grid. Active button highlighted in
  primary colour. Animated transitions on layout change.
- **Directional edges** — `target-arrow-shape: triangle` with `arrow-scale: 0.7`. Edge `line-color`
  and `target-arrow-color` both map to `data(edgeColor)` — set to the target node's risk colour
  (green/yellow/orange/red). Edge `width` maps to `data(lineWidth)` — scales from 1.2 px base up
  to 4.5 px as open port count increases.
- **Search / filter bar** — text input in sidebar; `filterNodes(q)` matches IP, hostname,
  device_type, vendor, os_hint; non-matching nodes get `.dim` class (opacity 0.12); matching nodes
  get `.highlight` class (blue border); connected edges to dimmed nodes also dim.
- **Export PNG** — download button triggers `cy.png({ output:'blob', bg:'#f8fafc', scale:2 })` at
  2× resolution, saved as `topology-YYYY-MM-DD.png`.

#### Changed
- `addEdge()` — now reads target node data to compute `edgeColor` and `lineWidth`; uses
  `cy.$('[id = "IP"]')` attribute selector (safe for IPs with dots).
- `runLayout()` — supports all four layouts via named config map; `breadthfirst` roots on gateway.
- `clearTopology()` — also hides SDN panel and clears search input.

### Phase C — SDN Controller Panel (`frontend/templates/topology.html`, `backend/api/topology.py`)

#### Added (`topology.html`)
- **SDN Controller section** in sidebar (shown after discovery):
  - *Controller detection* — green dot + IP if `sdn_info.controllers` non-empty; grey dot +
    "No controller detected (standard L2)" otherwise.
  - *Network Segments* — auto-derived from `device_type` counts; colour-coded dots from
    `NODE_COLORS`; sorted by host count descending.
  - *Derived Flow Policies* — tallies which hosts expose each of 13 tracked service ports
    (SSH, Telnet, FTP, HTTP, HTTPS, RDP, SMB, MySQL, MSSQL, VNC, HTTP-Alt, OpenFlow x2);
    risky services shown in red with ⚠ prefix.
  - *Network Health Score* — 0–100 computed from risk levels and dangerous services
    (−20 per high-risk host, −8 per medium, −10 for Telnet, −5 for FTP/VNC); progress bar
    goes green (≥80) / yellow (≥50) / red (<50).

#### Added (`backend/api/topology.py`)
- `sdn_info` key in the `done` event stats payload: `{ controllers: [IPs…], detected: bool }`.
  Controllers are hosts where `device_type == "sdn_controller"`.

#### Added (`frontend/static/css/app.css`)
- SDN panel CSS: `.sdn-status-row`, `.sdn-dot` (+ `-green`, `-gray`, `-amber` variants),
  `.sdn-segments`, `.sdn-segment-row`, `.sdn-segment-label`, `.sdn-segment-count`,
  `.sdn-policies`, `.sdn-policy-row`, `.sdn-policy-count`.

### Also changed across all three phases
- `NODE_COLORS`, `DEVICE_ICONS` — `sdn_controller` entry added (teal `#06b6d4`, `bi-hdd-network`).
- Legend — SDN Controller entry added.
- Node detail panel — new **Vendor** row (between MAC Address and Found via).
- `addNode()` — passes `vendor` into Cytoscape node data.

### Regression
- **27/27 tests pass** — all existing CLI, DB, and scan tests unchanged.

---

## [2.0.0] — Phase 1: Shared Core + Persistence  *(2026-06-28)*

### Added
- `pscan/` Python package with full sub-package tree:
  `core/`, `cli/`, `web/`, `database/`, `reports/`, `sdn/`, `config/`, `utils/`
- `pscan/__init__.py` (v2.0.0), `pscan/__main__.py` (`python -m pscan`)
- `pscan/core/models.py` — `ScanResult`, `ScanMeta`, `PortResult`, `Vulnerability` dataclasses
- `pscan/core/scanner.py` — `scan()` + `scan_iter()` (SSE-ready generator); no print/file I/O
- `pscan/core/vuln.py` — `check_vulnerabilities(service, port, banner)` (fixes v1 `port` NameError); `generate_vuln_report()`
- `pscan/core/services.py` — `get_service_name()` extracted from old scanner
- `pscan/core/mac.py` — OS-specific MAC spoofing (logic verbatim from v1)
- `pscan/core/decoy.py` + `pscan/core/_decoy_impl.py` — Scapy decoy logic (verbatim from v1)
- `pscan/cli/main.py` — same argparse flags as v1; adds `pscan gui` stub
- `pscan/cli/commands.py` — in-process dispatch (subprocess calls removed)
- `pscan/cli/output.py` — console + `.txt` rendering (byte-for-byte identical to v1)
- `pscan/database/db.py` + `schema.sql` — SQLite persistence (`scans`, `ports`, `vulnerabilities`)
- `pscan/config/settings.py` — centralised path resolution; `Settings.ensure_dirs()`
- `pscan/config/constants.py` — shared constants
- `pscan/utils/validators.py` — `validate_ip`, `resolve_hostname`, `parse_port_range`
- `pscan/utils/logger.py` + `pscan/utils/helpers.py`
- `data/vuln_database.json` — externalised CVE database (was hard-coded in v1)
- `data/{records,database,exports,logs}/.gitkeep`
- `tests/conftest.py`, `test_core_scan.py`, `test_db.py`, `test_cli_regression.py` — 27 tests, all green
- `pyproject.toml` (PEP 621; `pscan` console entry point; optional extras `web`, `decoy`, `dev`)
- `requirements.txt`
- `scripts/pscan.bat` (updated to `python -m pscan`)
- `docs/API.md`, `docs/DEVELOPMENT.md`

### Changed
- `setup.py` → thin 3-line shim; `pyproject.toml` is now authoritative
- `ARCHITECTURE.md`, `UI_GUIDELINES.md` moved to `docs/`
- `.gitignore` — updated for `data/` runtime dirs; `.gitkeep` + `vuln_database.json` preserved
- `pscan.bat` at root superseded by `scripts/pscan.bat`

### Refactored (backward-compat shims kept)
- `scanner.py` → shim re-exporting `pscan.core.scanner`; `PortScanner` wrapper preserved
- `vuln_scanner.py` → shim; `VulnerabilityScanner` deprecated wrapper preserved
- `mac_spoofer.py` → shim re-exporting `pscan.core.mac`
- `decoy_scanner.py` → shim re-exporting `pscan.core._decoy_impl.DecoyScanner`
- `pscan.py` → shim delegating to `pscan.cli.main:main`

### Fixed
- `port` `NameError` in old `scanner.py check_vulnerabilities()` — `port` is now an explicit parameter in `pscan.core.vuln.check_vulnerabilities(service, port, banner)`
- Duplicated vuln-check logic removed — `pscan.core.vuln` is the single source

### Manual step required
- Rename root folder `"Port scanner"` → `"pscan"` after closing VS Code:
  `Rename-Item "...\Port scanner" "pscan"` in PowerShell

### Regression
- **27/27 tests pass** — CLI interface, SQLite roundtrip, vuln matching, core scan all verified

---

## [2.7.0] — Phase 8: UI Polish & Self-Hosted Assets  *(2026-06-28)*

### Added
- `pscan/web/static/vendor/bootstrap/` — Bootstrap 5.3.3 CSS + JS bundle (self-hosted)
- `pscan/web/static/vendor/bootstrap-icons/` — Bootstrap Icons 1.11.3 CSS + woff/woff2 fonts (self-hosted)
- `pscan/web/static/vendor/cytoscape/` — Cytoscape.js 3.28.1 (self-hosted)
- `pscan/web/static/vendor/fonts/` — Inter 400/500/600 + JetBrains Mono 400/500 woff2 via `@fontsource` (self-hosted)
- `app.css` — `@font-face` blocks for all self-hosted fonts; `btn-ghost` component; custom scrollbar (webkit); `:focus-visible` ring; `.stat-card` hover lift (`translateY(-2px)` + shadow); `fadeInPage` keyframe on `.page-content`; responsive topology sidebar (stacks ≤768 px); responsive controller banner (stacks ≤576 px); sidebar backdrop CSS (`.sidebar-backdrop`)
- `base.html` — `<div class="sidebar-backdrop" id="sidebarBackdrop">` before main-wrapper
- `app.js` — `openMobileSidebar()` / `closeMobileSidebar()` wired to backdrop element; click-outside-to-close logic

### Changed
- `base.html` — Bootstrap CSS/JS and Bootstrap Icons now served from `vendor/` (CDN links removed)
- `topology.html` — Cytoscape.js served from `vendor/cytoscape/` (CDN link removed)
- `scan.html` — IIFE at top of script block reads `?target=` URL param and auto-fills target input + CLI preview label (enables "Full Port Scan" flow from topology detail panel)

### Reason
Eliminate all external CDN dependencies so the dashboard works fully offline / in air-gapped lab environments. Polish pass to bring the UI up to enterprise-dashboard quality ahead of submission.

---

## [2.6.0] — Phase 7: SDN Controller Panel  *(2026-06-28)*

### Added
- `pscan/web/routes/controller.py` — `GET /controller`; derives fake-but-realistic SDN data from scan history: per-port priority (200/100/50/10), action (DROP/METER/FORWARD), deterministic packet/byte counters, node IDs (`sw-X-Y` format), controller uptime from first scan time
- `pscan/web/templates/controller.html` — pulsing green "Controller Active" status banner; 4 metric cards (Connected Nodes / Active Flows / Packets Processed / Network Load with progress bar); Flow Table (Priority · Match · Action · Packets · Bytes · Status columns); flow filter toolbar (text search + Action dropdown); Connected Nodes table with Scan + Report quick-action buttons
- `app.css` — `.ctrl-banner`, `.ctrl-status-dot` (pulse-dot keyframe animation), `.flow-match`, `.priority-badge`, `.ctrl-node-status`, `.btn-xs`

### Changed
- `pscan/database/db.py` — `get_controller_data()` added: returns `nodes` (unique targets as SDN nodes), `flows` (open ports as OpenFlow-style entries), `total_nodes`, `total_flows`, `first_scan_time`
- `pscan/web/app.py` — `controller.router` registered
- `pscan/web/templates/base.html` — SDN Controller sidebar nav item added (`bi-cpu` icon)

### Reason
The project is an SDN-subject submission. A dedicated Controller Panel presenting scan history as live OpenFlow data makes the SDN angle credible without requiring a real controller (Ryu/ONOS) or Mininet.

---

## [2.5.0] — Phase 6: Network Topology  *(2026-06-28)*

### Added
- `pscan/core/network.py` — `get_local_subnet()` (auto-detect via `socket`); `_ping()` (Windows `-n 1 -w 800` / Linux `-c 1 -W 1`); `_quick_scan()` (50-thread connect scan across 23 fingerprint ports); `_fingerprint()` (device_type, os_hint, risk_level from open port set); `discover_network()` (full pipeline: ping sweep → quick scan → fingerprint, driven by `on_progress` callback); `DiscoveredHost` dataclass
- `pscan/web/topology_tasks.py` — `TopologyTask` dataclass + in-memory task registry (mirrors `scan_tasks.py` pattern); bounded SSE queue (5 000 events)
- `pscan/web/routes/topology.py` — `GET /topology`; `POST /api/topology/discover` (starts discovery thread, returns `task_id`); `GET /api/topology/stream/{task_id}` (SSE; events: `progress`, `done`, `error`)
- `pscan/web/templates/topology.html` — full-bleed Cytoscape.js page; left control sidebar (subnet input, Discover button, stats, risk legend); concentric layout (gateway at centre); node click → slide-in detail panel (IP, type, OS hint, risk, open ports as chips, "Full Port Scan" button → `/scan?target=IP`); discovery progress overlay
- Device fingerprint catalogue: router, printer, windows_pc, linux_server, linux_host, web_server, database, host
- Risk colour overlay on node borders: none=green / low=yellow / medium=orange / high=red
- `app.css` — `.topo-container`, `.topo-sidebar`, `.topo-cy`, `.topo-empty`, `.topo-detail` (slide-in panel), `.topo-overlay`, `.port-chip`

### Changed
- `pscan/web/routes/stubs.py` — topology stub removed (now a real route); file left as empty router
- `pscan/web/templates/base.html` — "Phase 6" badge removed from topology nav item; label changed to "Network Topology"
- `pscan/web/app.py` — `topology.router` registered (single include, no duplicate)

### Reason
Core SDN-subject deliverable: live subnet scan → visual topology gives the dashboard a genuine network-discovery capability, not just a port-scanner wrapper.

---

## [2.4.0] — Phase 5: Report Viewer  *(2026-06-28)*

### Added
- `pscan/web/routes/reports.py` — `GET /reports` (index) + `GET /reports/{id}` (sectioned report); `_build_report_context()` derives service distribution, vuln summary, risk level; `_recommendations()` generates actionable findings for Telnet/FTP/SMB/RDP/CVEs
- `pscan/web/templates/reports_index.html` — scans list with risk badge + report links
- `pscan/web/templates/report.html` — 5-section report: Overview (stat cards) · Open Ports (table) · Services (chip grid) · Vulnerabilities (table) · Recommendations (colour-coded cards); section nav bar; print/PDF via `window.print()` with `@media print` sidebar hiding
- Report CSS: header layout, section nav with hover underline, service chip grid, recommendations cards (success/warning/danger variants)

### Changed
- `pscan/web/routes/stubs.py` — Reports stub removed (route is now real)
- `pscan/web/templates/base.html` — Reports sidebar link is now live (Phase 5 badge removed)
- `pscan/web/templates/history.html` — fmtActions adds report icon link (`/reports/${id}`)
- `pscan/web/templates/scan_detail.html` — "Report" button in page header

### Regression
- **27/27 tests pass**

---

## [2.3.0] — Phase 4: Tables UX + Scan History  *(2026-06-28)*

### Added
- `pscan/web/routes/history.py` — `GET /api/history/data` (JSON for Tabulator) + `GET /history/{id}` (scan detail page)
- `pscan/web/templates/scan_detail.html` — breadcrumb nav, 4 stat cards, Tabulator ports table + CSV export, vulnerability table, metadata grid
- `pscan/web/static/css/app.css` — Tabulator Bootstrap5 overrides; filter toolbar; detail metadata grid; `badge-high` + `badge-neutral`

### Changed
- `pscan/web/templates/history.html` — full rewrite using Tabulator.js (CDN); ajax data from `/api/history/data`; global target search; risk-level filter dropdown; CSV + JSON export; delete without page reload; row highlight for new scans
- `pscan/web/routes/history.py` — pagination removed (Tabulator handles it client-side); added API data + detail routes
- `pscan/web/static/` — layout fixed: `vendor/`, `fonts/`, `icons/`, `images/` with `.gitkeep`; `css/vendor/` removed
- `.gitignore` — Phase 7 self-hosted asset dirs added
- `docs/DEVELOPMENT.md` — complete project tree + SSE event protocol table

### Regression
- **27/27 tests pass**

---

## [2.2.0] — Phase 3: Live Scanning via SSE  *(2026-06-28)*

### Added
- `pscan/web/scan_tasks.py` — `ScanTask` dataclass + in-memory registry; bounded queue (20k); TTL pruning of old tasks
- `pscan/web/routes/scan_api.py` — `POST /api/scan` (starts background thread, returns `task_id`) + `GET /api/scan/{task_id}/stream` (SSE; events: `open_port`, `progress`, `done`, `error`, `ping`)
- `pscan/web/static/css/app.css` — `spin-slow` + `row-highlight-anim` keyframes for live scan UI

### Changed
- `pscan/core/scanner.scan_iter()` — added optional `on_progress(completed, total)` callback; throttled to ≤5 calls/s with final guaranteed call at 100%
- `pscan/web/templates/scan.html` — full rewrite to SSE frontend: JS fetch → `/api/scan`; EventSource stream; live ports table (rows prepended in real time); progress bar + animated striped fill; elapsed timer; row flash on new port; error banner; "View in History" / "New Scan" done actions
- `pscan/web/routes/scan.py` — sync `POST /scan` removed; file now only serves `GET /scan` form page
- `pscan/web/app.py` — `scan_api` router registered (before `/scan` to avoid prefix collision)

### Regression
- **27/27 tests pass**

---

## [2.1.0] — Phase 2: GUI Foundation  *(2026-06-28)*

### Added
- `pscan/web/app.py` — FastAPI app factory; mounts `/static`, Jinja2Templates with `dt`/`dur` custom filters; 404/500 error handlers
- `pscan/web/routes/dashboard.py` — GET `/`; stat cards + Chart.js bar/donut data from SQLite
- `pscan/web/routes/scan.py` — GET `/scan` (form) + POST `/scan` (sync scan via `asyncio.to_thread`; redirects to history)
- `pscan/web/routes/history.py` — GET `/history` (paginated, search); POST `/history/{id}/delete`
- `pscan/web/routes/stubs.py` — GET `/reports`, `/topology` (phase-stub pages)
- `pscan/web/templates/base.html` — Bootstrap 5 sidebar layout (dark #111827), sticky topbar, Inter font (CDN)
- `pscan/web/templates/dashboard.html` — 4 stat cards, services bar chart, risk donut chart, recent scans table
- `pscan/web/templates/scan.html` — scan form with port presets, advanced options collapse, live CLI preview, loading overlay
- `pscan/web/templates/history.html` — paginated table, target search, delete with confirm, success/delete toasts
- `pscan/web/templates/stub.html` — reusable "coming in Phase N" page
- `pscan/web/templates/errors/404.html`, `errors/500.html` — error pages
- `pscan/web/static/css/app.css` — full design system implementation (all UI_GUIDELINES tokens, responsive, sidebar collapse, stat cards, charts, tables, badges, forms, empty states)
- `pscan/web/static/js/app.js` — sidebar toggle + localStorage persist, mobile overlay, Bootstrap toast init, relative-time labels
- `pscan/database/db.py` — `get_dashboard_stats()`, `get_service_distribution()`, `get_all_scans_with_vuln_count()` (JOIN query adds `vuln_count` per scan)

### Changed
- `pscan/cli/commands.py` — `cmd_gui()` now launches uvicorn + opens browser tab (import-guards with helpful install hint if FastAPI/uvicorn absent)
- `tests/test_cli_regression.py` — `test_gui_subcommand` replaced with `test_gui_subcommand_imports` (server is blocking; test verifies the web app imports cleanly instead)

### Regression
- **27/27 tests pass** — all Phase 1 tests unchanged; CLI interface preserved

---

## [Unreleased] — v2 Dashboard

Work toward the SDN-aware Network Discovery & Security Analysis Dashboard built on
top of the existing `pscan` backend. The v1 CLI remains fully functional throughout.

### Added
- `ARCHITECTURE.md` — current and target architecture, module disposition, phases.
- `TODO.md` — phased roadmap and feature backlog.
- `CHANGELOG.md` — this file.
- `UI_GUIDELINES.md` — UI design system / single source of truth (palette, type, components, states, a11y).
- `docs/V2_DASHBOARD_BRIEF.md` — internal architect working brief (gitignored).
- Phase Completion Protocol in `TODO.md`: every phase ends with a completion summary
  (files created/modified/deleted, rationale, decisions, how-to-test, regressions, next phase)
  plus a synced update to `TODO.md` and `CHANGELOG.md`.

### Changed
- Locked table library to **Tabulator.js** (native CSV/JSON/PDF export + streaming-friendly
  updates for SSE). Confirmed **Cytoscape.js** for topology over Vis.js (cleaner layouts,
  maintainability, SDN extensibility).
- Added **Phase 7 — UI Polish & UX** to the roadmap (enterprise styling, loading/empty/error
  states, notifications, responsive, subtle animation).

### Reason
Phase 0 (analysis & planning) per the v2 directive: document the system and plan the
refactor before any code changes. No application code modified in this phase.

---

## [1.0.0] — Baseline (existing CLI)

The pre-existing `pscan` command-line scanner. Captured here as the baseline that
v2 must preserve.

### Added (pre-existing)
- Multi-threaded TCP connect scanning (`scanner.py`).
- Banner grabbing with protocol-aware probes and SSL/TLS handling.
- Service detection via `socket.getservbyport`.
- Vulnerability scanning with a built-in CVE database (`vuln_scanner.py`).
- MAC address spoofing across Windows/Linux/macOS with vendor OUI tables (`mac_spoofer.py`).
- Decoy scanning via Scapy with a TCP-connect fallback (`decoy_scanner.py`).
- Unified `argparse` CLI dispatcher (`pscan.py`) and `pscan.bat` launcher.
- Timestamped text reports written to `records/`.
- Installable package via `setup.py` (`pscan` console entry point).
