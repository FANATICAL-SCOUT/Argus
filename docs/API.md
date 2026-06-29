# Argus REST API Reference

All routes are served by the FastAPI app at `http://127.0.0.1:8000`.
Page routes return HTML (Jinja2 rendered). API routes return JSON or SSE.

---

## Page Routes (HTML)

| Method | Path | Template | Description |
|---|---|---|---|
| `GET` | `/` | `dashboard.html` | Dashboard — stat cards, charts, recent scans |
| `GET` | `/scan` | `scan.html` | New scan form |
| `GET` | `/history` | `history.html` | Scan history (Tabulator.js) |
| `GET` | `/history/{id}` | `scan_detail.html` | Single scan breakdown |
| `GET` | `/reports` | `reports_index.html` | All scan reports index |
| `GET` | `/reports/{id}` | `report.html` | Full sectioned security report |
| `GET` | `/topology` | `topology.html` | Network topology (Cytoscape.js) |
| `GET` | `/controller` | `controller.html` | SDN controller panel |

---

## Scan API

### Start a scan
```
POST /api/scan
Content-Type: application/x-www-form-urlencoded

target=192.168.1.1&ports=1-1024&timeout=1.0&threads=100&vuln_scan=on
```
**Response:**
```json
{ "task_id": "uuid4-string" }
```

### Stream scan results (SSE)
```
GET /api/scan/{task_id}/stream
Accept: text/event-stream
```
**Events:**

| Event | JSON payload |
|---|---|
| `progress` | `{ "scanned": 50, "total": 1024, "pct": 4, "elapsed": 1.2 }` |
| `open_port` | `{ "port": 80, "service": "http", "banner": "Apache...", "vuln_count": 0, "elapsed": 2.1 }` |
| `done` | `{ "db_id": 42, "open_count": 3, "duration": 18.4 }` |
| `error` | `{ "message": "Connection refused" }` |
| `ping` | *(empty keepalive, sent every 15s)* |

---

## History API

### Get all scans (Tabulator JSON source)
```
GET /api/history/data
```
**Response:**
```json
[
  {
    "id": 1,
    "target": "192.168.1.1",
    "scanned_at": "2026-06-28T12:00:00",
    "open_ports": 3,
    "vuln_count": 1,
    "risk_level": "medium",
    "duration": 18.4
  }
]
```

### Delete a scan
```
POST /history/{id}/delete
```
Redirects to `/history` with a success toast on completion.

---

## Topology API

### Start network discovery
```
POST /api/topology/discover
Content-Type: application/x-www-form-urlencoded

subnet=192.168.1.0/24
```
**Response:**
```json
{ "task_id": "uuid4-string" }
```

### Stream discovery progress (SSE)
```
GET /api/topology/stream/{task_id}
Accept: text/event-stream
```
**Events:**

| Event | JSON payload |
|---|---|
| `progress` | `{ "phase": "ping", "message": "Scanning 192.168.1.0/24...", "found": 3 }` |
| `done` | `{ "hosts": [ { "ip": "192.168.1.1", "device_type": "router", "os_hint": "Linux", "risk_level": "low", "open_ports": [80, 443], "is_gateway": true } ] }` |
| `error` | `{ "message": "Subnet unreachable" }` |

**Device types returned:** `router`, `windows_pc`, `linux_server`, `linux_host`, `printer`, `web_server`, `database`, `host`

**Risk levels:** `none`, `low`, `medium`, `high`

---

## Controller (read-only, derived from scan history)

```
GET /controller
```
Returns HTML page. No separate JSON endpoint — data is rendered server-side from `get_controller_data()`.

**Data derived:**
- Each scanned target → SDN node (`sw-X-Y` node ID)
- Each open port → OpenFlow-style flow entry (Priority / Match / Action / Packets / Bytes)
- Port priority: risky ports (23, 445, 3389...) → 200; metered (80, 8080...) → 100; others → 50/10
- Action: `DROP` for risky ports, `METER` for web/db ports, `FORWARD` for rest
