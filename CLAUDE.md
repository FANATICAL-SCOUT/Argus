# Argus — Claude Code Project Brief

> Read this entire file before doing anything. This is the single source of truth
> for every Claude session working on this project.

---

## What is this project?

**Argus** is an SDN-aware network scanner and security dashboard built in Python.
It was previously named **pscan / Portscanner-project** — you may see that name
in older git history, comments, or imports. They are the same project.

- CLI tool: `argus <target>` — scans ports, detects vulns, saves to DB
- Web dashboard: `argus gui` — full browser UI at `http://127.0.0.1:8000`
- Topology page: ARP/ping discovery → live Cytoscape.js network map
- SDN detection: identifies OpenFlow controllers (ports 6633/6653/8181)

---

## Project Structure

```
argus/                        ← git repo root (was "Pscan/")
├── backend/
│   ├── api/                  ← FastAPI route handlers
│   │   ├── topology.py       ← /topology + /api/topology/* routes
│   │   ├── scan_api.py       ← /api/scan/* SSE streaming
│   │   ├── dashboard.py      ← / dashboard route
│   │   ├── history.py        ← /history route
│   │   ├── reports.py        ← /reports route
│   │   └── controller.py     ← /controller SDN panel route
│   ├── core/
│   │   ├── network.py        ← ARP/ping/TCP discovery, device detection
│   │   ├── scanner.py        ← TCP port scanner
│   │   ├── vuln.py           ← CVE + port-risk vulnerability engine
│   │   ├── models.py         ← ScanResult, PortResult, Vulnerability dataclasses
│   │   ├── mac.py            ← MAC vendor OUI lookup + spoofing
│   │   └── decoy.py          ← Scapy decoy scan
│   ├── cli/
│   │   ├── main.py           ← argparse entry point (`argus` command)
│   │   └── commands.py       ← cmd_gui(), cmd_scan() implementations
│   ├── database/
│   │   ├── db.py             ← SQLite read/write (scans, ports, vulns)
│   │   └── schema.sql        ← table definitions
│   ├── config/
│   │   └── settings.py       ← paths, ports, DB location
│   └── app.py                ← FastAPI app factory
├── frontend/
│   ├── templates/
│   │   ├── base.html         ← sidebar nav, topbar, layout shell
│   │   ├── topology.html     ← network topology page (Cytoscape.js)
│   │   ├── dashboard.html    ← main dashboard
│   │   ├── scan.html         ← new scan form + SSE live results
│   │   ├── history.html      ← scan history table
│   │   ├── controller.html   ← SDN controller panel
│   │   └── report.html       ← single scan report
│   └── static/
│       ├── css/app.css       ← full design system
│       └── js/app.js         ← shared JS
├── tests/                    ← pytest suite (27 tests)
├── data/
│   ├── vuln_database.json    ← CVE database
│   └── {records,database,exports,logs}/.gitkeep
├── mock_sdn_controller.py    ← demo script: fake OpenFlow controller
├── RUNNING.md                ← command reference (READ THIS)
├── CHANGELOG.md              ← full history of all changes
└── pyproject.toml            ← package config (name=argus, version=2.11.0)
```

---

## How to Run

### One-time setup
```powershell
cd "E:\CYBERSEC PROJECTS\Argus\argus"
pip install -e .
```

### Daily commands
```powershell
argus gui                      # Launch web dashboard (admin PowerShell for full ARP scan)
argus 192.168.0.1              # CLI port scan
python mock_sdn_controller.py  # Demo SDN detection
```

### Admin requirement
- `argus gui` → admin = full ARP scan (more devices discovered)
- `argus gui` → non-admin = ping/TCP fallback (still works)
- CLI scan → no admin needed

---

## Key Technical Decisions

### Discovery (backend/core/network.py)
- Three-tier discovery: Scapy ARP (admin) → OS ARP table → ICMP/TCP ping
- Device name detection: NetBIOS (`nbtstat`) → hostname → UPnP friendlyName
- OS detection: MAC vendor OUI first (Samsung=Android, Apple=iOS), then ports, then TTL
- `DiscoveredHost` dataclass has `device_name` field (populated after discovery)

### Vulnerability Engine (backend/core/vuln.py)
- Two-layer detection:
  1. **Port-risk flags** — no banner needed; flags Telnet/FTP/SMB/RDP/MySQL/VNC/HTTP/etc.
  2. **Banner CVE matching** — exact version string match against vuln_database.json
- Port-risk layer ensures dashboard shows non-zero vulns for home networks

### Topology (frontend/templates/topology.html)
- Cytoscape.js graph with SVG node icons per device type
- Sidebar: collapsible (chevron toggle) + drag-to-resize handle
- Node detail panel: Device Name, OS, Risk, MAC, Vendor, open ports
- Three scan buttons per node: Quick / Full / Vuln — each opens new tab with IP pre-filled
- SDN panel: shows OpenFlow controllers, network segments, flow policies, health score
- Topology and SDN Controller nav links open in new browser tab

### Database (backend/database/db.py)
- SQLite at `data/database/argus.db`
- Tables: `scans` → `ports` → `vulnerabilities` (cascade on delete)
- Both CLI and GUI scans write to same DB — history is unified

---

## SDN Feature — How to Demo Without a Real SDN Network

```powershell
# Terminal 1 (normal user)
python mock_sdn_controller.py
# → Listens on ports 6633 and 6653

# Terminal 2 (admin)
argus gui
# → Open topology page → Discover Network
# → Your machine appears as cyan SDN Controller node
```

**How to explain SDN to someone:**
> SDN separates the network brain (controller) from the switches. All switches
> talk to one OpenFlow controller using ports 6633/6653. Argus detects this
> controller, groups devices into logical segments, and derives flow policies
> from open ports — the same view an SDN controller has of its network.

---

## Working Protocol (how Claude should approach this project)

1. **Read before writing** — always check the relevant file before editing
2. **Never break the CLI** — `argus <target>` must always work; it's the core feature
3. **Analyse first, then confirm** — for any feature that touches topology.html or
   network.py, explain the approach and wait for approval before implementing
4. **No unnecessary abstractions** — three similar lines beats a premature helper
5. **Test impact** — after editing network.py, check that 27 tests still pass:
   `cd argus && pytest`

---

## Current Version: 2.11.0

### What's built and working
- [x] Full CLI port scanner with vuln detection, MAC spoofing, decoy scans
- [x] Web dashboard with live SSE scanning
- [x] Scan history + reports with PDF export
- [x] Network topology with ARP discovery and Cytoscape.js visualization
- [x] SDN controller detection and panel
- [x] Device name detection (NetBIOS, UPnP, hostname)
- [x] OS fingerprinting (Android, iOS, Windows, Linux)
- [x] Port-based vulnerability flagging
- [x] Topology sidebar: minimize + drag-to-resize
- [x] Three scan modes from topology node (Quick/Full/Vuln → new tab)
- [x] Mock SDN controller for demo

### What's NOT done yet (future work)
- [ ] Real-time alerts / notification system
- [ ] Scheduled/automated scans
- [ ] User management (multi-user)
- [ ] Export topology as JSON/XML
- [ ] IPv6 support

---

## GitHub

- Repo: https://github.com/FANATICAL-SCOUT/Argus
- Push command: `git push origin main`
- This project was previously at: https://github.com/FANATICAL-SCOUT/Portscanner

---

## If Something Is Broken

### App won't start
```powershell
cd "E:\CYBERSEC PROJECTS\Argus\argus"
pip install -e ".[web]"
argus gui
```

### Database corrupted
```powershell
del data\database\argus.db   # delete and let it recreate
argus gui
```

### Topology shows nothing
- Make sure running as admin for ARP scan
- Check mode banner at top of topology page
- Try ping mode: any device that responds to ping will appear

### Port conflicts
Default port is 8000. If taken:
```powershell
# Edit backend/config/settings.py → WEB_PORT = 8001
argus gui
```
