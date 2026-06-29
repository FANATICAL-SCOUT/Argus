# Running Argus — Quick Reference

## One-time setup (do this once)

Navigate to the argus folder and install the package:

```powershell
cd "E:\CYBERSEC PROJECTS\Argus\argus"
pip install -e .
```

After this, the `argus` command works from anywhere.

---

## Admin vs Normal — What needs what

| Mode | Admin Required? | Why |
|------|----------------|-----|
| GUI dashboard | Optional | Admin enables full ARP scan (finds more devices) |
| CLI scan | No | Basic TCP connect scan works as standard user |
| Mock SDN controller | No | Just opens two ports locally |
| Topology — ARP mode | Yes | Raw packet sending requires elevated privileges |
| Topology — Ping mode | No | Falls back automatically if not admin |

---

## Starting the GUI Dashboard

**With admin (recommended for topology / ARP scan):**

1. Open PowerShell as Administrator (Win+X → Terminal Admin)
2. Run:
```powershell
argus gui
```
Browser opens automatically at `http://127.0.0.1:8000`

**Without admin (CLI scan + basic topology still works):**
```powershell
argus gui
```

---

## CLI Scan Commands

No admin needed for basic scanning.

```powershell
# Basic scan (ports 1-1024)
argus 192.168.0.1

# Specific ports
argus 192.168.0.1 -p 80,443,22,3306

# Full port scan (all 65535 ports)
argus 192.168.0.1 -p 1-65535

# With vulnerability report
argus 192.168.0.1 -v

# Aggressive mode — timeout 0.3s, 300 threads (fast but noisy)
argus 192.168.0.1 --aggressive

# Slow/stealth mode — add delay between probes to reduce IDS noise
argus 192.168.0.1 --delay 0.5

# Ping check — abort if host is unreachable before scanning
argus 192.168.0.1 --ping-check

# Custom threads and timeout
argus 192.168.0.1 -T 200 -t 2.0

# Save vulnerability report to file
argus 192.168.0.1 -v -o report.txt

# Combine — aggressive full scan with vuln report saved to file
argus 192.168.0.1 -p 1-65535 --aggressive -v -o report.txt
```

---

## MAC Spoofing (requires admin PowerShell)

```powershell
# Spoof as a specific vendor
argus 192.168.0.1 -m Apple
argus 192.168.0.1 -m Cisco
argus 192.168.0.1 -m Dell

# Random vendor MAC
argus 192.168.0.1 -m

# Spoof + restore original MAC after scan
argus 192.168.0.1 -m Apple -r
```

Supported vendors: Apple, Cisco, Dell, Samsung, Intel, Huawei, TP-Link, Netgear, and more.

---

## Decoy Scan (requires Scapy + admin PowerShell)

Sends scan traffic from multiple fake IP addresses to obscure your real IP in target logs.

```powershell
# Default — 5 decoy IPs
argus 192.168.0.1 -D

# Custom number of decoys
argus 192.168.0.1 -D 10

# Combine with vuln scan
argus 192.168.0.1 -D 5 -v
```

---

## Demo: SDN Controller Detection

Used to prove the SDN detection feature works without a real SDN network.

**Step 1** — Open a normal PowerShell terminal and run:
```powershell
cd "E:\CYBERSEC PROJECTS\Argus\argus"
python mock_sdn_controller.py
```
Leave this running. You should see:
```
[Mock SDN] Listening on port 6633
[Mock SDN] Listening on port 6653
```

**Step 2** — Open a separate admin PowerShell and run the GUI:
```powershell
argus gui
```

**Step 3** — Go to topology page → click Discover Network

Your own machine will appear as a cyan SDN Controller node in the topology map.

Stop the mock controller with `Ctrl+C` when done.

---

## Summary — Three commands to know

```powershell
argus gui                        # Launch web dashboard
argus <target>                   # CLI scan a single host
python mock_sdn_controller.py    # Demo SDN detection
```
