"""Report viewer: GET /reports (index) · GET /reports/{scan_id}."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from backend.database.db import get_all_scans_with_vuln_count, get_scan

router = APIRouter()


def _build_report_context(scan: dict) -> dict:
    """Derive all display-layer data from a full scan dict."""
    ports = scan.get("ports", [])

    # Service distribution
    service_counts: Counter = Counter()
    for p in ports:
        svc = p.get("service") or "unknown"
        service_counts[svc] += 1

    # Vulnerability summary
    all_vulns = []
    for p in ports:
        for v in p.get("vulnerabilities", []):
            all_vulns.append({**v, "port": p["port"], "service": p.get("service", "")})

    vuln_count = len(all_vulns)
    confirmed_count = sum(1 for v in all_vulns if v.get("confirmed"))

    # Risk level
    if vuln_count == 0:
        risk_level, risk_cls = "Clean", "success"
    elif vuln_count <= 2:
        risk_level, risk_cls = "Low", "warning"
    elif vuln_count <= 5:
        risk_level, risk_cls = "Medium", "high"
    else:
        risk_level, risk_cls = "High", "danger"

    # Recommendations
    recommendations = _recommendations(ports, all_vulns)

    return {
        "scan": scan,
        "ports": ports,
        "service_counts": dict(service_counts.most_common()),
        "all_vulns": all_vulns,
        "vuln_count": vuln_count,
        "confirmed_count": confirmed_count,
        "risk_level": risk_level,
        "risk_cls": risk_cls,
        "recommendations": recommendations,
    }


def _recommendations(ports: list, vulns: list) -> list[dict]:
    recs = []
    open_ports = {p["port"] for p in ports}
    services = {p.get("service", "") for p in ports}

    if 23 in open_ports:
        recs.append({"severity": "danger", "icon": "bi-x-circle",
                     "title": "Disable Telnet (port 23)",
                     "body": "Telnet transmits credentials in plaintext. Replace with SSH."})
    if 21 in open_ports:
        recs.append({"severity": "warning", "icon": "bi-exclamation-triangle",
                     "title": "Restrict FTP (port 21)",
                     "body": "FTP sends passwords unencrypted. Use SFTP or FTPS instead."})
    if 445 in open_ports:
        recs.append({"severity": "danger", "icon": "bi-x-circle",
                     "title": "Restrict SMB (port 445)",
                     "body": "SMB should not be exposed externally. Firewall this port if not required."})
    if 3389 in open_ports:
        recs.append({"severity": "warning", "icon": "bi-exclamation-triangle",
                     "title": "Secure RDP (port 3389)",
                     "body": "Restrict RDP access with a VPN or IP allowlist. Enable NLA."})
    if vulns:
        cves = [v["cve"] for v in vulns if v.get("cve")]
        if cves:
            recs.append({"severity": "danger", "icon": "bi-shield-exclamation",
                         "title": f"Patch {len(cves)} known CVE(s)",
                         "body": "Apply vendor patches for: " + ", ".join(sorted(set(cves)))})
    if not recs:
        recs.append({"severity": "success", "icon": "bi-check-circle",
                     "title": "No critical issues detected",
                     "body": "Continue to monitor this host regularly and keep services patched."})
    return recs


# ── Routes ────────────────────────────────────────────────────────────

@router.get("/reports", response_class=HTMLResponse)
async def reports_index(request: Request):
    scans = get_all_scans_with_vuln_count()
    return request.app.state.templates.TemplateResponse(
        request,
        "reports_index.html",
        {"active": "reports", "scans": scans},
    )


@router.get("/reports/{scan_id}", response_class=HTMLResponse)
async def report_detail(scan_id: int, request: Request):
    scan = get_scan(scan_id)
    if scan is None:
        return request.app.state.templates.TemplateResponse(
            request, "errors/404.html", status_code=404
        )
    ctx = _build_report_context(scan)
    ctx["active"] = "reports"
    return request.app.state.templates.TemplateResponse(request, "report.html", ctx)
