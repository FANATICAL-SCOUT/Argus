# Argus — Network Discovery & Security Analysis Dashboard

A full-stack network security tool built on top of a battle-tested Python port scanner.
The **v2 dashboard** turns the CLI scanner into an SDN-aware web interface with live
scanning, interactive topology mapping, and an OpenFlow-style controller panel — all
running locally, no cloud or external controller required.

---

## Features

| Area | Capability |
|---|---|
| **Live Port Scanning** | SSE-streamed results; port presets; banner grab; CVE lookup |
| **Scan History** | Tabulator.js table with sort, filter, CSV/JSON export, delete |
| **Security Reports** | Sectioned report (Overview · Ports · Services · Vulns · Recommendations); print-to-PDF |
| **Network Topology** | ARP/ping/TCP discovery · OUI vendor ID · TTL OS detection · SDN controller detection · Cytoscape.js graph with icons, layout switcher, edge risk colouring, search/filter, PNG export |
| **SDN Controller Panel** | OpenFlow-style flow table derived from scan history; metric cards; node registry |
| **CLI** | Full CLI (`argus <target> [options]`); `argus gui` launches the dashboard |

All vendor assets (Bootstrap, Bootstrap Icons, Cytoscape.js, fonts) are **self-hosted** —
the dashboard works fully offline / in air-gapped environments.

---

## Quick Start

### 1. Install

```bash
# Clone
git clone https://github.com/FANATICAL-SCOUT/Argus.git
cd Argus

# Install with web dependencies
pip install -e ".[web]"
```

### 2. Launch the dashboard

```bash
argus gui
```

Opens `http://127.0.0.1:8000` in your default browser automatically.

### 3. CLI (unchanged from v1)

```bash
# Basic scan
argus 192.168.1.1

# Scan specific ports with vulnerability check
argus 192.168.1.1 -p 22,80,443 -v

# Full options
argus 192.168.1.1 -p 1-1024 -t 1.5 -T 200 -v -o results.txt

# Decoy scan with MAC spoofing (requires admin/root)
argus 192.168.1.1 -D 5 -m Apple -r
```

---

## Dashboard Pages

### Dashboard `/`
Overview of all scan activity: total scans, open ports, vulnerability counts, service
distribution bar chart, risk-level donut chart, and a recent scans table.

### New Scan `/scan`
Target input with port presets (Top 20 / Common / Full / Custom), advanced options
(timeout, threads, vulnerability scan), live CLI preview, and real-time results streamed
via Server-Sent Events. Supports `?target=<ip>` URL parameter for pre-filling the target
(used by the topology "Full Port Scan" button).

### Scan History `/history`
Interactive Tabulator.js table of all past scans. Columns: target, timestamp, open ports,
vulnerabilities, risk level. Supports full-text search, risk filter, CSV/JSON export,
and per-row delete.

### Reports `/reports` · `/reports/{id}`
Printable sectioned report for any saved scan. Sections: Overview (stat cards), Open Ports
(table), Services (chip grid), Vulnerabilities (CVE table), Recommendations (colour-coded
action cards). Uses browser print dialog for PDF export.

### Network Topology `/topology`
Discover all live hosts on the current subnet using a three-tier approach:

1. **ARP scan** (admin + Scapy/Npcap) — finds every device regardless of firewall rules
2. **ARP table read** — always runs; reads OS cache + broadcast ping refresh; captures MAC addresses
3. **Ping & TCP sweep** — ICMP + TCP liveness probe in parallel; fallback for hosts missing from ARP

After discovery, each host gets a quick port scan (27 fingerprint ports, 50 threads) and fingerprinting:

| Device type | Detection signals |
|---|---|
| Router | Gateway IP, or Cisco/Huawei OUI |
| Windows PC | RDP (3389), SMB (445/135) |
| Linux Server | SSH + HTTP/S |
| Web Server | HTTP/HTTPS only |
| Database | MySQL (3306) or MSSQL (1433) |
| Printer | IPP (631), JetDirect (9100) |
| VMware ESXi | Port 902 |
| **SDN Controller** | OpenFlow (6633/6653), ONOS/ODL (8181) |

**Graph features**: node icons (SVG per device type), risk-coloured directional edges (green→red),
layout switcher (Concentric / Tree / Force / Grid), search/filter bar, PNG export.

**Node detail panel**: IP, hostname, MAC address, **vendor** (OUI lookup), OS hint (port + TTL),
risk level, discovery method badge, open port chips, "Full Port Scan" button.

**SDN Controller sidebar panel** (appears after discovery):
- Controller detection status (OpenFlow/ONOS at detected IP, or "standard L2")
- Network Segments — host counts grouped by device type
- Derived Flow Policies — which services are exposed across how many hosts; risky services flagged
- Network Health Score — 0–100 composite score penalising high-risk hosts and dangerous services

### SDN Controller `/controller`
Presents scan history as a live SDN controller view:
- **Metric cards**: Connected Nodes, Active Flows, Packets Processed, Network Load
- **Flow Table**: every open port from scan history as an OpenFlow-style entry with
  Priority, Match (IP:port), Action (FORWARD / METER / DROP), packet/byte counters, status
- **Connected Nodes**: every scanned target listed as an SDN network node with quick
  Scan and Report actions

---

## CLI Options

| Flag | Description | Default |
|---|---|---|
| `-p`, `--ports` | Port range (`1-1024`, `80,443,8080`, `1-65535`) | `1-1024` |
| `-t`, `--timeout` | Connection timeout in seconds | `1.0` |
| `-T`, `--threads` | Number of scanner threads | `100` |
| `-v`, `--vuln-scan` | CVE lookup on open ports | off |
| `-o`, `--output` | Custom output file path | auto-named |
| `--aggressive` | Fast preset: 0.3s timeout, 300 threads (noisy) | off |
| `--delay` | Per-probe delay in seconds — reduces IDS noise | `0` |
| `--ping-check` | Ping host first; abort if unreachable | off |
| `--no-vulns` | Skip vulnerability matching (faster) | off |
| `-D`, `--decoy` | Decoy scan with N fake source IPs (requires Scapy + admin) | off |
| `-m`, `--mac` | Spoof MAC — optional vendor name (Apple/Cisco/Dell/…) or omit for random (requires admin) | off |
| `-r`, `--restore-mac` | Restore original MAC address after scan | off |
| `--json` | Output results as JSON to stdout — suppresses all other output (pipe-friendly) | off |

---

## Requirements

- Python 3.10+
- `fastapi`, `uvicorn`, `jinja2`, `aiofiles` — for the web dashboard (`pip install -e ".[web]"`)
- `scapy` — only for decoy scanning (`pip install -e ".[decoy]"`)
- Administrator / root — only for MAC spoofing and decoy scanning

---

## Project Structure

```
argus/
├── backend/
│   ├── api/          # FastAPI route handlers (dashboard, scan, history, topology, controller)
│   ├── core/         # scanner.py, vuln.py, network.py, models.py, mac.py, decoy.py
│   ├── database/     # db.py, schema.sql (SQLite)
│   ├── cli/          # argparse entry point (main.py, commands.py)
│   ├── config/       # settings.py, constants.py
│   └── app.py        # FastAPI factory
├── frontend/
│   ├── templates/    # Jinja2 HTML (base, dashboard, scan, history, topology, controller, report)
│   └── static/
│       ├── vendor/   # self-hosted Bootstrap, Icons, Cytoscape, fonts (offline capable)
│       ├── css/app.css
│       └── js/app.js
├── data/
│   ├── vuln_database.json
│   └── {records,database,exports,logs}/
├── docs/             # ARCHITECTURE.md, UI_GUIDELINES.md, API.md, DEVELOPMENT.md
├── tests/            # 27 pytest tests
├── mock_sdn_controller.py
├── CHANGELOG.md
└── TODO.md
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
