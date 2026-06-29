# TODO — Argus Dashboard

Living task list. Updated after every phase. See `ARCHITECTURE.md` for the design
and `CHANGELOG.md` for completed changes.

Legend: `[ ]` pending · `[~]` in progress · `[x]` done · `[!]` deferred · `[-]` rejected

---

## Phase Completion Protocol (applies to every phase)

At the **end of every implementation phase**, automatically provide a completion summary:
- Files created
- Files modified
- Files deleted (if any)
- Why each change was made
- Architectural decisions taken
- How to test the completed phase
- Any regressions detected (verify the CLI still works)
- Next recommended phase

Then update **TODO.md** and **CHANGELOG.md** to match the actual implementation, mark
completed tasks, and leave the project in a fully working state.

---

## Phase 0 — Analysis & Planning  `[x]`
- [x] Read and understand all five modules
- [x] Document current architecture & data flow (`docs/ARCHITECTURE.md`)
- [x] Module disposition: untouched / wrap / refactor
- [x] Choose tech stack (FastAPI+SSE, Bootstrap+Chart.js, SQLite, Cytoscape.js, Tabulator.js)
- [x] Propose target package structure (Option B — approved)
- [x] Create `ARCHITECTURE.md`, `CHANGELOG.md`, `TODO.md`
- [x] Create `UI_GUIDELINES.md` (design system / single source of truth for UI)
- [x] Detailed per-feature roadmap

## Phase 1 — Shared Core + Persistence  `[x]`
- [x] `pscan/core/models.py` — `ScanResult`, `PortResult`, `Vulnerability`, `ScanMeta`
- [x] `pscan/core/scanner.py` — `scan()` + `scan_iter()` (SSE-ready); no print/file I/O
- [x] `pscan/core/vuln.py` — fixes `port` NameError; deduped; loads `data/vuln_database.json`
- [x] `pscan/core/mac.py`, `pscan/core/decoy.py` — wrappers (OS logic verbatim)
- [x] `pscan/database/db.py` + `schema.sql` — SQLite: `scans`, `ports`, `vulnerabilities`
- [x] `pscan/cli/` — in-process dispatch; same console+file output as v1; `pscan gui` stub
- [x] `data/vuln_database.json` — externalised CVE database
- [x] Root shims: `scanner.py`, `vuln_scanner.py`, `mac_spoofer.py`, `decoy_scanner.py`, `pscan.py`
- [x] `pyproject.toml` (PEP 621), `requirements.txt`, `setup.py` shim
- [x] `tests/` — 27/27 green (core scan, DB roundtrip, CLI regression)
- [x] `docs/` reorganised: `ARCHITECTURE.md`, `UI_GUIDELINES.md`, `API.md`, `DEVELOPMENT.md`
- [ ] **Manual step:** rename `"Port scanner"` → `"pscan"` folder after closing VS Code

## Phase 2 — GUI Foundation  `[x]`
- [x] FastAPI app factory (`pscan/web/app.py`); Jinja2 + static files mounted
- [x] `pscan gui` command launches uvicorn + opens browser tab
- [x] Dashboard: stat cards, bar chart (services), donut chart (risk), recent scans table
- [x] New Scan page: target form, port presets, advanced options collapse, loading overlay, live CLI preview
- [x] History page: paginated table, search/filter, delete, toast notifications
- [x] Stub pages for Reports (Phase 5) and SDN Topology (Phase 6)
- [x] 404 / 500 error pages
- [x] `pscan/web/static/css/app.css` — full design system from UI_GUIDELINES (tokens, sidebar, topbar, stat cards, charts, tables, badges, empty states, forms)
- [x] `pscan/web/static/js/app.js` — sidebar collapse/persist, mobile overlay, toasts, relative-time labels
- [x] `pscan/database/db.py` — added `get_dashboard_stats()`, `get_service_distribution()`, `get_all_scans_with_vuln_count()`
- [x] 27/27 tests passing; `test_gui_subcommand` updated to import-test (server blocks subprocess)

## Phase 3 — Live Scanning (SSE)  `[x]`
- [x] `pscan/core/scanner.scan_iter()` — added `on_progress(completed, total)` callback (throttled to ~5/s)
- [x] `pscan/web/scan_tasks.py` — in-memory `ScanTask` registry; thread-safe bounded queue (20k events); TTL pruning
- [x] `POST /api/scan` — starts scan in daemon thread, returns `{task_id}`
- [x] `GET /api/scan/{task_id}/stream` — SSE stream (`open_port`, `progress`, `done`, `error`, `ping` events)
- [x] `scan.html` — JS fetch replaces form submit; EventSource live results table; progress bar; elapsed timer; row flash animation; error banner; done actions
- [x] `pscan/web/routes/scan.py` — sync POST /scan removed (replaced by /api/scan)
- [x] 27/27 tests passing

## Phase 4 — Tables UX + Scan History  `[x]`
- [x] `history.html` — Tabulator.js replaces plain table: client-side sort/filter/pagination/export
- [x] Global search (target IP), risk-level filter dropdown, clear filters button
- [x] Export CSV + JSON from filtered table view
- [x] `GET /api/history/data` — JSON endpoint for Tabulator ajax source
- [x] `GET /history/{id}` — scan detail page: stat cards, ports Tabulator, vuln table, metadata grid
- [x] `scan_detail.html` — breadcrumb, 4 stat cards, Tabulator ports table with CSV export, vuln table, metadata
- [x] `badge-high`, `badge-neutral` added to design system
- [x] Tabulator Bootstrap5 theme overrides in `app.css`
- [x] Filter toolbar styles + detail metadata grid styles
- [x] Folder structure cleaned: static dir layout fixed, `.gitkeep` in placeholder dirs, `.gitignore` updated
- [x] `docs/DEVELOPMENT.md` — complete tree + SSE protocol table
- [x] 27/27 tests passing

## Phase 5 — Report Viewer  `[x]`
- [x] `GET /reports` — reports index listing all scans with risk badge + "View report" link
- [x] `GET /reports/{id}` — full sectioned report: Overview / Open Ports / Services / Vulnerabilities / Recommendations
- [x] Risk-level computation (Clean/Low/Medium/High) from vuln count
- [x] Auto-generated recommendations engine (Telnet, FTP, SMB, RDP, CVE patching)
- [x] Print/PDF via `window.print()` with `@media print` CSS (sidebar hidden, clean layout)
- [x] Report section nav (anchor links)
- [x] `pscan/web/routes/reports.py` — index + detail routes + `_build_report_context()` + `_recommendations()`
- [x] `reports_index.html`, `report.html` templates
- [x] Reports sidebar link now live (Phase 5 badge removed)
- [x] History + scan_detail — "View Report" links wired to `/reports/{id}`
- [x] Report CSS: header, section nav, service chips, recommendations cards
- [x] 27/27 tests passing

## Phase 6 — Network Topology  `[x]`
- [x] `pscan/core/network.py` — subnet auto-detection, concurrent ping sweep, quick port scan, device fingerprinting
- [x] `pscan/web/topology_tasks.py` — SSE task registry for discovery jobs (mirrors `scan_tasks.py` pattern)
- [x] `POST /api/topology/discover` + `GET /api/topology/stream/{id}` — SSE-streamed discovery (ping → scan → fingerprint)
- [x] `GET /topology` — full-bleed Cytoscape.js topology page; left control panel, node detail slide-in, progress overlay
- [x] Device fingerprinting: router, windows_pc, linux_server, linux_host, printer, web_server, database, host
- [x] Risk overlay on node borders (green/yellow/orange/red)
- [x] "Full Port Scan" button on node detail → navigates to `/scan?target=IP`
- [x] Topology stub replaced with real route; "Phase 6" nav badge removed
- [x] Self-hosted Cytoscape.js (vendor/cytoscape/)

## Phase 7 — SDN Controller Panel  `[x]`
- [x] `pscan/web/routes/controller.py` — fake-but-realistic SDN controller data derived from scan history
- [x] `pscan/database/db.py` — `get_controller_data()` returns nodes + flow entries + uptime
- [x] `GET /controller` — dedicated full page with pulsing green status banner
- [x] Metric cards: Connected Nodes, Active Flows, Packets Processed, Network Load
- [x] Flow Table: every open port from scan history as an OpenFlow-style entry (Priority · Match · Action · Packets · Bytes · Status)
- [x] Flow filter toolbar: search by IP/port + filter by Action (FORWARD / METER / DROP)
- [x] Connected Nodes table: every scanned target presented as an SDN node with scan/report quick-actions
- [x] SDN Controller added to sidebar nav (`bi-cpu` icon)

## Phase 9 — Topology Multi-Tier Discovery  `[x]`
- [x] `network.py` — Scapy ARP scan (Tier 1, admin + Npcap); OS ARP table read `arp -a` (Tier 2); ICMP + TCP liveness probe in parallel (Tier 3)
- [x] `DiscoveredHost.mac` + `DiscoveredHost.discovery_method` fields
- [x] `can_arp_scan()` + `get_discovery_mode()` capability detection
- [x] `GET /api/topology/capabilities` endpoint — tells frontend which mode is active
- [x] `discover_network()` returns `(hosts, ui_mode)` tuple; `topology.py` passes `mode` + `by_method` stats in `done` event
- [x] `topology.html` — mode banner (green ARP / blue ARP-table / yellow ping-only); 4-phase progress handler (arp / arp_table / ping / scan); MAC + discovery_method in node detail panel; `addNode()` passes `mac` and `discovery_method` into Cytoscape data

## Phase 8 — UI Polish & Self-Hosted Assets  `[x]`
- [x] Self-hosted Bootstrap 5.3.3 CSS + JS bundle (vendor/bootstrap/)
- [x] Self-hosted Bootstrap Icons 1.11.3 + woff/woff2 fonts (vendor/bootstrap-icons/)
- [x] Self-hosted Cytoscape 3.28.1 (vendor/cytoscape/)
- [x] Self-hosted Inter (400/500/600) + JetBrains Mono (400/500) via @fontsource woff2 (vendor/fonts/)
- [x] `@font-face` declarations in app.css replace Google Fonts CDN
- [x] `/scan?target=` URL param auto-fills target input (topology "Full Port Scan" flow now end-to-end)
- [x] Mobile sidebar: slide-in + backdrop overlay + close on backdrop tap
- [x] `btn-ghost` component added to design system
- [x] Custom scrollbar polish (webkit)
- [x] Focus ring using CSS `focus-visible`
- [x] Stat card hover lift animation
- [x] Fade-in page transition (`fadeInPage` keyframe)
- [x] Responsive controller banner (stacks on narrow screens)
- [x] Responsive topology sidebar (stacks on mobile)

## Phase 10 — Topology Intelligence + Visual Overhaul + SDN Panel  `[x]`

### Phase A — Discovery Intelligence
- [x] OUI vendor lookup: `_build_oui_lookup()` inverts `mac.py`'s `MAC_PREFIXES`; `_oui_vendor(mac)` → "Cisco", "Dell", etc.
- [x] TTL-based OS detection: `_ping()` returns TTL; `_os_from_ttl()` maps TTL → Windows / Linux / Network Device
- [x] Extended fingerprint ports: +902 (VMware), +6633/6653 (OpenFlow), +8181 (ONOS/ODL) — 27 total
- [x] SDN controller detection in `_fingerprint()`: ports 6633/6653/8181 → `device_type="sdn_controller"`
- [x] Vendor-boosted fingerprinting: Cisco/Huawei OUI on non-gateway → `router`
- [x] `DiscoveredHost.vendor` field; `topology.py` passes `vendor` in node payload

### Phase B — Cytoscape Visual Overhaul
- [x] SVG node icons: white minimal SVGs per device type via `background-image` data URIs; per-type `node[device_type="X"]` selectors
- [x] Layout switcher: Concentric / Tree (breadthfirst) / Force (cose) / Grid — animated transitions
- [x] Directional edges: triangle arrowhead; edge colour = target risk; edge width = open port count
- [x] Search/filter bar: `filterNodes(q)` dims non-matching nodes + edges; `.dim` / `.highlight` Cytoscape classes
- [x] Export PNG: `cy.png({ output:'blob', bg:'#f8fafc', scale:2 })` → download

### Phase C — SDN Controller Panel
- [x] SDN Controller sidebar section: controller detection dot, Network Segments, Derived Flow Policies, Health Score
- [x] `sdn_info` in topology `done` stats payload: `{ controllers: [...], detected: bool }`
- [x] SDN panel CSS: `.sdn-status-row`, `.sdn-dot`, `.sdn-segment-*`, `.sdn-policy-*`
- [x] `sdn_controller` device type in legend, NODE_COLORS, DEVICE_ICONS (teal `#06b6d4`)
- [x] Vendor row in node detail panel

### Regression
- [x] 27/27 tests passing

---

## Backlog / Future Phases

- [ ] **Phase 11 — Topology persistence** — save discovered topology to SQLite; load/compare previous scans
- [ ] **Phase 12 — Scheduled scans** — cron-style periodic discovery with change detection alerts
- [ ] **Phase 13 — Cytoscape compound nodes** — group hosts by segment/VLAN into visual parent nodes
- [ ] **Phase 14 — Minimap** — Cytoscape navigator extension for large networks (>50 nodes)

---

## Rejected / Deferred (with reason)
- [-] **Auth / multi-user** — local single-user tool; adds scope, no value.
- [-] **Live SDN flow programming** — out of scope; needs a controller + Mininet.
- [!] **Column resizing** — low payoff; brief marked it "if feasible."
- [!] **Heavy server-side PDF** — ship client-side print-to-PDF first.
