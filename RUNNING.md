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

No admin needed for these.

```powershell
# Basic scan (ports 1-1024)
argus 192.168.0.1

# Specific ports
argus 192.168.0.1 -p 80,443,22,3306

# Port range
argus 192.168.0.1 -p 1-65535

# With vulnerability report
argus 192.168.0.1 -v

# Fast aggressive scan
argus 192.168.0.1 --aggressive

# Save report to file
argus 192.168.0.1 -v -o report.txt
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
