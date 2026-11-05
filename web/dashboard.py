#!/usr/bin/env python3
# web/dashboard.py — M7Hunter V7 Web Dashboard (stdlib only)
# MilkyWay Intelligence | Author: Sharlix

import os, json, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="30">
<title>M7Hunter V7 Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:20px}
.hdr{text-align:center;padding:20px 0;border-bottom:1px solid #30363d;margin-bottom:20px}
h1{color:#58a6ff;font-size:24px}
.sub{color:#8b949e;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}
.card .num{font-size:32px;font-weight:700}
.card .lbl{font-size:12px;color:#8b949e;margin-top:4px}
.crit{color:#dc3545} .high{color:#fd7e14} .med{color:#ffc107}
.low{color:#28a745}  .info{color:#17a2b8} .tot{color:#58a6ff}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:16px}
th{background:#161b22;padding:10px;text-align:left;border:1px solid #30363d;color:#8b949e}
td{padding:8px 10px;border:1px solid #21262d;vertical-align:top}
tr:hover td{background:#161b22}
.badge{padding:3px 8px;border-radius:4px;font-size:11px;font-weight:700;color:white}
.badge.critical{background:#dc3545} .badge.high{background:#fd7e14}
.badge.medium{background:#b8860b} .badge.low{background:#28a745}
.badge.info{background:#17a2b8}
.ftr{text-align:center;color:#8b949e;font-size:12px;margin-top:24px}
.refresh{color:#8b949e;font-size:11px}
</style>
</head>
<body>
<div class="hdr">
  <h1>M7Hunter V7 — Live Dashboard</h1>
  <div class="sub">MilkyWay Intelligence | <span class="refresh">Auto-refresh every 30s</span></div>
</div>
{STATS_SECTION}
{TABLE_SECTION}
<div class="ftr">M7Hunter V7.0 | Author: Sharlix | Only test authorized targets</div>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    results_dir = "results"

    def log_message(self, *args):
        pass  # suppress default access log

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/findings":
            self._serve_json()
        elif path == "/health":
            self._respond(200, "OK", "text/plain")
        else:
            self._serve_html()

    def _get_findings(self) -> list:
        all_findings = []
        try:
            rd = self.results_dir
            if not os.path.isdir(rd):
                return []
            for root, _, files in os.walk(rd):
                for fname in files:
                    if fname.endswith("_findings_v7.json") or fname.endswith("_findings_v6.json"):
                        path = os.path.join(root, fname)
                        try:
                            with open(path) as f:
                                data = json.load(f)
                                all_findings.extend(data.get("findings", []))
                        except Exception:
                            pass
        except Exception:
            pass
        return all_findings

    def _compute_stats(self, findings: list) -> dict:
        stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0,"total":0}
        for f in findings:
            sev = f.get("severity","info")
            stats[sev] = stats.get(sev,0) + 1
            stats["total"] += 1
        return stats

    def _serve_html(self):
        findings = self._get_findings()
        stats    = self._compute_stats(findings)

        stats_html = f"""
<div class="grid">
  <div class="card"><div class="num crit">{stats['critical']}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num high">{stats['high']}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num med">{stats['medium']}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num low">{stats['low']}</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num info">{stats['info']}</div><div class="lbl">Info</div></div>
  <div class="card"><div class="num tot">{stats['total']}</div><div class="lbl">Total</div></div>
</div>"""

        rows = ""
        sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        sorted_findings = sorted(findings,
            key=lambda f: sev_order.get(f.get("severity","info"),4))

        for f in sorted_findings[:100]:
            sev    = f.get("severity","info")
            vt     = f.get("vuln_type") or f.get("type","")
            url    = f.get("url","")[:80]
            detail = f.get("detail","")[:80]
            tool   = f.get("tool","")
            stat   = f.get("status","?")
            rows  += (f"<tr>"
                      f"<td><span class='badge {sev}'>{sev.upper()}</span></td>"
                      f"<td><strong>{vt}</strong></td>"
                      f"<td style='font-family:monospace;font-size:11px'>{url}</td>"
                      f"<td>{detail}</td>"
                      f"<td>{tool}</td>"
                      f"<td style='color:{'#3fb950' if stat=='confirmed' else '#e3b341'}'>{stat}</td>"
                      f"</tr>")

        if not rows:
            rows = "<tr><td colspan='6' style='text-align:center;color:#8b949e;padding:30px'>No findings yet — scan in progress...</td></tr>"

        table_html = f"""
<table>
  <tr><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Tool</th><th>Status</th></tr>
  {rows}
</table>"""

        html = HTML_TEMPLATE.replace("{STATS_SECTION}", stats_html)\
                             .replace("{TABLE_SECTION}", table_html)
        self._respond(200, html, "text/html")

    def _serve_json(self):
        findings = self._get_findings()
        self._respond(200, json.dumps({"findings": findings}, indent=2), "application/json")

    def _respond(self, status: int, body: str, ct: str = "text/html"):
        body_bytes = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{ct}; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


class Dashboard:
    def __init__(self, log=None, port: int = 8719, results_dir: str = "results"):
        self.log         = log
        self.port        = port
        self.results_dir = results_dir
        DashboardHandler.results_dir = results_dir
        self._server     = None

    def start(self, blocking: bool = True):
        self._server = HTTPServer(("0.0.0.0", self.port), DashboardHandler)
        if self.log:
            self.log.success(f"Dashboard: http://localhost:{self.port}")
        if blocking:
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                pass
        else:
            t = threading.Thread(target=self._server.serve_forever, daemon=True)
            t.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
