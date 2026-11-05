#!/usr/bin/env python3
# reporting/report_generator.py — M7Hunter V7 Report Generator
# Generates: HTML, Markdown (bug bounty ready), JSON, Burp XML
# FIX: Replaces "Findings: 0" with proper exploitable findings report
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
import base64
from datetime import datetime

SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high"    : "#fd7e14",
    "medium"  : "#ffc107",
    "low"     : "#28a745",
    "info"    : "#17a2b8",
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high"    : "🟠",
    "medium"  : "🟡",
    "low"     : "🟢",
    "info"    : "🔵",
}

CVSS_MAP = {
    "critical": "9.8",
    "high"    : "7.5",
    "medium"  : "5.3",
    "low"     : "3.1",
    "info"    : "0.0",
}


class ReportGeneratorV6:
    """
    Bug Bounty Report Generator v6.
    
    Output formats:
    1. HTML — visual, color-coded, copy-paste ready
    2. Markdown — HackerOne/Bugcrowd submission format
    3. JSON — API / tool integration
    4. Burp XML — import into Burp Suite Pro
    
    FIX: No longer shows "Findings: 0" when findings exist.
    """

    def __init__(self, pipeline):
        self.p       = pipeline
        self.out_dir = pipeline.out
        self.target  = pipeline.target
        self.prefix  = pipeline.prefix

    def generate_all(self) -> dict:
        """Generate all report formats."""
        findings = self._get_sorted_findings()
        stats    = self._compute_stats(findings)
        paths    = {}

        paths["html"]     = self._write_html(findings, stats)
        paths["markdown"] = self._write_markdown(findings, stats)
        paths["json"]     = self._write_json(findings, stats)
        paths["burp"]     = self._write_burp_xml(findings)

        self._print_console_summary(findings, stats)
        return paths

    def _get_sorted_findings(self) -> list:
        """FIX: Get findings from pipeline — uses new FindingsEngine if available."""
        # Try new engine first
        if hasattr(self.p, 'findings_engine'):
            return self.p.findings_engine.get_all()
        # Fallback to legacy pipeline.findings list
        findings = list(getattr(self.p, 'findings', []))
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(findings, key=lambda f: order.get(f.get("severity","info"), 4))

    def _compute_stats(self, findings: list) -> dict:
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f.get("severity","info")
            stats[sev] = stats.get(sev, 0) + 1
            stats["total"] += 1
        stats["confirmed"] = sum(1 for f in findings if f.get("status") == "confirmed")
        return stats

    # ── HTML Report ──────────────────────────────────────────────────

    def _write_html(self, findings: list, stats: dict) -> str:
        path = os.path.join(self.out_dir, f"{self.prefix}_report_v7.html")
        rows = ""
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity","info")
            col   = SEVERITY_COLORS.get(sev, "#888")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            vtype = f.get("vuln_type","")
            url   = f.get("url","")[:80]
            detail = f.get("detail","")[:100]
            payload = f.get("payload","")[:80]
            impact  = f.get("impact","")[:120]
            status  = f.get("status","potential")
            fid     = f.get("id", f"F{i:04d}")

            rows += f"""
<tr>
  <td><code>{fid}</code></td>
  <td><span style="background:{col};color:white;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:bold">{sev.upper()}</span></td>
  <td>{emoji} <strong>{vtype}</strong></td>
  <td style="font-family:monospace;font-size:12px;word-break:break-all">{url}</td>
  <td>{detail}</td>
  <td style="font-family:monospace;font-size:11px">{payload or '—'}</td>
  <td>{impact}</td>
  <td><span style="color:{'green' if status=='confirmed' else 'orange'}">{status}</span></td>
</tr>"""

        chains = self._get_chain_section(findings)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>M7Hunter V7 — {self.target}</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:20px}}
.header{{text-align:center;padding:30px 0;border-bottom:1px solid #30363d}}
h1{{color:#58a6ff;font-size:28px;margin:0}} .sub{{color:#8b949e;font-size:14px;margin-top:6px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:20px 0}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center}}
.stat .num{{font-size:28px;font-weight:700;line-height:1}}
.stat .lbl{{font-size:12px;color:#8b949e;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:20px}}
th{{background:#161b22;padding:10px;text-align:left;border:1px solid #30363d;color:#8b949e}}
td{{padding:8px 10px;border:1px solid #21262d;vertical-align:top}}
tr:hover td{{background:#161b22}}
.chains{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-top:20px}}
.chain-item{{font-size:13px;padding:6px 0;border-bottom:1px solid #21262d;color:#79c0ff}}
.footer{{text-align:center;color:#8b949e;font-size:12px;margin-top:30px;padding-top:16px;border-top:1px solid #30363d}}
</style>
</head>
<body>
<div class="header">
  <h1>M7Hunter V7 — Security Report</h1>
  <div class="sub">Target: <strong>{self.target}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | MilkyWay Intelligence</div>
</div>

<div class="stats">
  <div class="stat"><div class="num" style="color:{SEVERITY_COLORS['critical']}">{stats['critical']}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="num" style="color:{SEVERITY_COLORS['high']}">{stats['high']}</div><div class="lbl">High</div></div>
  <div class="stat"><div class="num" style="color:{SEVERITY_COLORS['medium']}">{stats['medium']}</div><div class="lbl">Medium</div></div>
  <div class="stat"><div class="num" style="color:{SEVERITY_COLORS['low']}">{stats['low']}</div><div class="lbl">Low</div></div>
  <div class="stat"><div class="num" style="color:#58a6ff">{stats['total']}</div><div class="lbl">Total</div></div>
  <div class="stat"><div class="num" style="color:#3fb950">{stats['confirmed']}</div><div class="lbl">Confirmed</div></div>
</div>

<table>
<tr><th>ID</th><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Payload</th><th>Impact</th><th>Status</th></tr>
{rows if rows else '<tr><td colspan="8" style="text-align:center;color:#8b949e">No findings — try --deep mode or add --cookie for authenticated scanning</td></tr>'}
</table>

{chains}

<div class="footer">Generated by M7Hunter V7.0 | MilkyWay Intelligence | Author: Sharlix<br>
<em>Only test systems you own or have explicit written permission to test.</em></div>
</body></html>"""

        with open(path,"w") as f: f.write(html)
        return path

    # ── Markdown (Bug Bounty submission format) ───────────────────────

    def _write_markdown(self, findings: list, stats: dict) -> str:
        path = os.path.join(self.out_dir, f"{self.prefix}_report_v7.md")
        md   = []
        md.append(f"# M7Hunter V7 — Security Report: {self.target}")
        md.append(f"\n**Date:** {datetime.now().strftime('%Y-%m-%d')}  ")
        md.append(f"**Findings:** {stats['total']} total | "
                  f"Critical: {stats['critical']} | High: {stats['high']} | "
                  f"Medium: {stats['medium']} | Low: {stats['low']}  ")
        md.append(f"**Confirmed:** {stats['confirmed']}\n")
        md.append("---\n")

        for i, f in enumerate(findings, 1):
            sev    = f.get("severity","info").upper()
            emoji  = SEVERITY_EMOJI.get(f.get("severity",""), "⚪")
            vtype  = f.get("vuln_type","")
            url    = f.get("url","")
            detail = f.get("detail","")
            payload = f.get("payload","")
            impact  = f.get("impact","")
            repro   = f.get("repro_steps", [])
            chains  = f.get("chain_hints", [])
            cvss    = CVSS_MAP.get(f.get("severity","info"), "5.0")
            fid     = f.get("id", f"F{i:04d}")
            status  = f.get("status","potential").upper()

            md.append(f"## {emoji} [{fid}] {vtype} — {sev}")
            md.append(f"\n**CVSS:** {cvss} | **Status:** {status}\n")
            md.append(f"### Vulnerability Details\n")
            md.append(f"| Field | Value |")
            md.append(f"|-------|-------|")
            md.append(f"| **Endpoint** | `{url}` |")
            md.append(f"| **Type** | {vtype} |")
            md.append(f"| **Severity** | {sev} |")
            md.append(f"| **Detail** | {detail} |")
            if payload:
                md.append(f"| **Payload** | `{payload}` |")
            md.append(f"\n### Impact\n{impact}\n")

            if repro:
                md.append("### Steps to Reproduce\n")
                for step in repro:
                    md.append(f"{step}  ")

            if chains:
                md.append("\n### Attack Chain Potential\n")
                for chain in chains:
                    md.append(f"- 🔗 {chain}")

            md.append("\n---\n")

        with open(path,"w") as f: f.write("\n".join(md))
        return path

    # ── JSON ─────────────────────────────────────────────────────────

    def _write_json(self, findings: list, stats: dict) -> str:
        path = os.path.join(self.out_dir, f"{self.prefix}_findings_v7.json")
        data = {
            "tool"      : "M7Hunter V7.0",
            "author"    : "Sharlix | MilkyWay Intelligence",
            "target"    : self.target,
            "generated" : datetime.now().isoformat(),
            "stats"     : stats,
            "findings"  : findings,
        }
        with open(path,"w") as f: json.dump(data, f, indent=2)
        return path

    # ── Burp Suite XML ───────────────────────────────────────────────

    def _write_burp_xml(self, findings: list) -> str:
        """
        Generate Burp Suite XML for import into Burp Pro.
        Includes ready-to-use HTTP requests for each finding.
        """
        path  = os.path.join(self.out_dir, f"{self.prefix}_burp_export.xml")
        items = []

        for f in findings:
            url     = f.get("url","http://target/")
            payload = f.get("payload","")
            vtype   = f.get("vuln_type","")
            detail  = f.get("detail","")

            # Build a basic HTTP request
            try:
                import urllib.parse as up
                parsed = up.urlparse(url)
                host   = parsed.netloc or "target"
                path_q = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
                protocol = "https" if url.startswith("https") else "http"
                port_num = "443" if protocol == "https" else "80"

                raw_req = (
                    f"GET {path_q} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: M7Hunter-v6/BugBounty\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                )
                raw_req_b64 = base64.b64encode(raw_req.encode()).decode()
            except Exception:
                host, path_q, protocol, port_num = "target", "/", "https", "443"
                raw_req_b64 = ""

            sev_burp = {
                "critical": "High",
                "high"    : "High",
                "medium"  : "Medium",
                "low"     : "Low",
                "info"    : "Information",
            }.get(f.get("severity","info"), "Medium")

            items.append(f"""  <issue>
    <serialNumber>{abs(hash(url)) % 999999999}</serialNumber>
    <type>134217728</type>
    <name>{vtype}</name>
    <host ip="">{host}</host>
    <path><![CDATA[{path_q}]]></path>
    <location><![CDATA[URL: {url}]]></location>
    <severity>{sev_burp}</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[{detail}]]></issueBackground>
    <remediationBackground><![CDATA[See M7Hunter report for remediation steps.]]></remediationBackground>
    <requestresponse>
      <request method="GET" base64="true"><![CDATA[{raw_req_b64}]]></request>
    </requestresponse>
  </issue>""")

        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE issues [
  <!ELEMENT issues (issue*)>
  <!ELEMENT issue (serialNumber, type, name, host, path, location, severity, confidence, issueBackground, remediationBackground, requestresponse*)>
]>
<issues burpVersion="2024.1" exportTime="{datetime.now().isoformat()}">
{chr(10).join(items)}
</issues>"""

        with open(path,"w") as f: f.write(xml)
        return path

    # ── Console summary ──────────────────────────────────────────────

    def _print_console_summary(self, findings: list, stats: dict):
        B  = "\033[34m"; G = "\033[92m"; R = "\033[91m"
        Y  = "\033[93m"; C = "\033[96m"; W = "\033[97m"
        DIM= "\033[2m";  RST= "\033[0m"; BOLD= "\033[1m"

        print(f"\n{B}{'═'*70}{RST}")
        print(f"{W}{BOLD}  M7Hunter V7 — EXPLOITABLE VULNERABILITY REPORT{RST}")
        print(f"{B}{'═'*70}{RST}\n")
        print(f"  Target  : {W}{self.target}{RST}")
        print(f"  Date    : {DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")

        if stats["total"] == 0:
            print(f"\n  {Y}[!] No findings.\n"
                  f"      Try: --deep --cookie 'session=...' for authenticated scan{RST}")
        else:
            print(f"\n  {R}{BOLD}CRITICAL : {stats['critical']}{RST}")
            print(f"  {R}HIGH     : {stats['high']}{RST}")
            print(f"  {Y}MEDIUM   : {stats['medium']}{RST}")
            print(f"  {G}LOW      : {stats['low']}{RST}")
            print(f"  ─────────────────────")
            print(f"  {W}TOTAL    : {stats['total']}{RST}")
            print(f"  {G}CONFIRMED: {stats['confirmed']}{RST}")

            print(f"\n{B}  TOP FINDINGS{RST}")
            print(f"  {'─'*66}")
            for f in findings[:5]:
                sev  = f.get("severity","info")
                col  = {
                    "critical": R+BOLD, "high": R, "medium": Y, "low": G
                }.get(sev, C)
                fid  = f.get("id","?")
                vt   = f.get("vuln_type","")
                url  = f.get("url","")[:55]
                imp  = f.get("impact","")[:50]
                print(f"  {col}[{sev.upper():8s}]{RST} {W}{fid}{RST} {C}{vt}{RST}")
                print(f"           {DIM}{url}{RST}")
                print(f"           Impact: {imp}")
                print()

        print(f"{B}{'═'*70}{RST}\n")

    def _get_chain_section(self, findings: list) -> str:
        """HTML section showing attack chain suggestions."""
        chains = []
        for f in findings:
            for chain in f.get("chain_hints", []):
                if chain not in chains:
                    chains.append(chain)

        if not chains:
            return ""

        items = "".join(f'<div class="chain-item">🔗 {c}</div>' for c in chains[:8])
        return f"""
<div class="chains">
  <h3 style="color:#79c0ff;margin-top:0">⛓️ Attack Chain Suggestions</h3>
  {items}
</div>"""
