import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.utils import get_prefix
#!/usr/bin/env python3
# reporting/executive_report.py — Executive Summary Report Generator
# Cycle 10: Professional executive report for non-technical stakeholders
# Source: Bug Hunter Methodology — reporting methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, json
from datetime import datetime

SEVERITY_COLOR = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#ffc107",
    "low":      "#28a745",
    "info":     "#17a2b8",
}

RISK_SCORE = {
    "critical": 10,
    "high":     7,
    "medium":   4,
    "low":      1,
    "info":     0,
}

REMEDIATION_PRIORITY = {
    "critical": "Immediate — within 24 hours",
    "high":     "Urgent — within 1 week",
    "medium":   "Scheduled — within 1 month",
    "low":      "Planned — within quarter",
    "info":     "Informational — review at convenience",
}


class ExecutiveReportGenerator:
    def __init__(self, pipeline=None, target: str = "", out_dir: str = ""):
        if pipeline:
            self.target  = pipeline.target
            self.out_dir = pipeline.out
            self.prefix  = pipeline.prefix
        else:
            self.target  = target
            self.out_dir = out_dir or "results"
            self.prefix  = get_prefix(target)

    def generate(self, findings: list) -> str:
        os.makedirs(self.out_dir, exist_ok=True)
        path = os.path.join(self.out_dir, f"{self.prefix}_executive_report.html")

        stats     = self._compute_stats(findings)
        risk      = self._compute_risk_score(findings)
        top_risks = self._get_top_risks(findings)
        timeline  = self._build_timeline(findings)

        html = self._render_html(stats, risk, top_risks, timeline, findings)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _compute_stats(self, findings: list) -> dict:
        s = {"critical":0,"high":0,"medium":0,"low":0,"info":0,"total":0,"confirmed":0}
        for f in findings:
            sev = f.get("severity","info")
            s[sev] = s.get(sev, 0) + 1
            s["total"] += 1
            if f.get("status") == "confirmed":
                s["confirmed"] += 1
        return s

    def _compute_risk_score(self, findings: list) -> dict:
        total = sum(RISK_SCORE.get(f.get("severity","info"),0) for f in findings)
        max_s = max(total, 1)
        pct   = min(100, int((total / (len(findings) * 10 + 1)) * 100)) if findings else 0

        if pct >= 75:   label, color = "CRITICAL RISK", "#dc3545"
        elif pct >= 50: label, color = "HIGH RISK",     "#fd7e14"
        elif pct >= 25: label, color = "MEDIUM RISK",   "#ffc107"
        elif pct > 0:   label, color = "LOW RISK",      "#28a745"
        else:           label, color = "MINIMAL RISK",  "#17a2b8"

        return {"score": pct, "label": label, "color": color, "raw": total}

    def _get_top_risks(self, findings: list) -> list:
        order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        sorted_f = sorted(findings,
                          key=lambda x: order.get(x.get("severity","info"), 4))
        return sorted_f[:5]

    def _build_timeline(self, findings: list) -> list:
        seen   = set()
        events = []
        for f in findings:
            vtype = f.get("vuln_type","")
            sev   = f.get("severity","info")
            if vtype not in seen:
                seen.add(vtype)
                events.append({
                    "type":  vtype,
                    "sev":   sev,
                    "color": SEVERITY_COLOR.get(sev,"#888"),
                    "url":   f.get("url","")[:60],
                })
        return events[:12]

    def _render_html(self, stats, risk, top_risks, timeline, all_findings) -> str:
        date = datetime.now().strftime("%B %d, %Y")

        # Severity bars
        bars = ""
        for sev, count in [("Critical",stats["critical"]),
                            ("High",    stats["high"]),
                            ("Medium",  stats["medium"]),
                            ("Low",     stats["low"])]:
            col = SEVERITY_COLOR.get(sev.lower(),"#888")
            pct = int((count / max(stats["total"],1)) * 100)
            bars += f"""
            <div class="bar-row">
              <div class="bar-label">{sev}</div>
              <div class="bar-track">
                <div class="bar-fill" style="width:{pct}%;background:{col}"></div>
              </div>
              <div class="bar-count">{count}</div>
            </div>"""

        # Top risks table
        top_rows = ""
        for f in top_risks:
            sev  = f.get("severity","info")
            col  = SEVERITY_COLOR.get(sev,"#888")
            vt   = f.get("vuln_type","")
            url  = f.get("url","")[:55]
            pri  = REMEDIATION_PRIORITY.get(sev,"Review")
            top_rows += f"""
            <tr>
              <td><span class="sev-badge" style="background:{col}">{sev.upper()}</span></td>
              <td>{vt}</td>
              <td class="url-cell">{url}</td>
              <td>{pri}</td>
            </tr>"""

        # Timeline
        tl_items = ""
        for ev in timeline:
            tl_items += f"""
            <div class="tl-item">
              <div class="tl-dot" style="background:{ev['color']}"></div>
              <div class="tl-content">
                <strong>{ev['type']}</strong>
                <span class="tl-url">{ev['url']}</span>
              </div>
            </div>"""

        # All findings summary
        all_rows = ""
        order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        for f in sorted(all_findings,
                        key=lambda x: order.get(x.get("severity","info"),4))[:20]:
            sev = f.get("severity","info")
            col = SEVERITY_COLOR.get(sev,"#888")
            all_rows += f"""
            <tr>
              <td><span class="sev-badge" style="background:{col}">{sev.upper()}</span></td>
              <td>{f.get('vuln_type','')}</td>
              <td class="url-cell">{f.get('url','')[:50]}</td>
              <td>{f.get('status','')}</td>
              <td>{f.get('detail','')[:60]}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>M7Hunter Executive Report — {self.target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:30px;max-width:1100px;margin:0 auto}}
.header{{text-align:center;margin-bottom:30px;padding:30px;background:#161b22;border-radius:12px;border:1px solid #30363d}}
.header h1{{color:#58a6ff;font-size:28px;margin-bottom:6px}}
.header .sub{{color:#8b949e;font-size:14px}}
.header .date{{color:#58a6ff;font-size:13px;margin-top:8px}}

/* Risk gauge */
.risk-section{{display:flex;gap:20px;margin-bottom:20px}}
.gauge-card{{flex:0 0 220px;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;text-align:center}}
.gauge-ring{{width:140px;height:140px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;border:12px solid {risk['color']};background:#0d1117}}
.gauge-score{{font-size:36px;font-weight:700;color:{risk['color']}}}
.gauge-label{{font-size:14px;font-weight:600;color:{risk['color']}}}

/* Stats */
.stats-card{{flex:1;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px}}
.stats-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}}
.stat-box{{background:#0d1117;border-radius:8px;padding:12px;text-align:center}}
.stat-num{{font-size:28px;font-weight:700}}
.stat-lbl{{font-size:11px;color:#8b949e;margin-top:2px}}
.bar-row{{display:flex;align-items:center;gap:10px;margin:6px 0}}
.bar-label{{width:65px;font-size:13px;color:#8b949e}}
.bar-track{{flex:1;height:10px;background:#21262d;border-radius:5px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:5px;transition:width .3s}}
.bar-count{{width:30px;text-align:right;font-size:13px;font-weight:600}}

/* Sections */
.section{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:16px}}
.section h2{{color:#58a6ff;font-size:16px;margin-bottom:14px;display:flex;align-items:center;gap:8px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#21262d;color:#8b949e;padding:8px 10px;text-align:left;font-size:12px;font-weight:600;border-bottom:1px solid #30363d}}
td{{padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:middle}}
.url-cell{{font-family:monospace;font-size:11px;color:#8b949e;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.sev-badge{{padding:2px 8px;border-radius:4px;color:white;font-size:10px;font-weight:700}}

/* Timeline */
.tl-item{{display:flex;align-items:flex-start;gap:12px;margin:8px 0}}
.tl-dot{{width:12px;height:12px;border-radius:50%;flex-shrink:0;margin-top:3px}}
.tl-content{{flex:1}}
.tl-content strong{{font-size:13px}}
.tl-url{{display:block;font-size:11px;color:#8b949e;font-family:monospace}}

/* Recommendations */
.rec-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}
.rec-card{{background:#0d1117;border-radius:8px;padding:14px;border-left:3px solid}}
.rec-title{{font-size:13px;font-weight:600;margin-bottom:4px}}
.rec-desc{{font-size:12px;color:#8b949e;line-height:1.5}}

.footer{{text-align:center;color:#8b949e;font-size:11px;margin-top:24px;padding-top:16px;border-top:1px solid #21262d}}
</style>
</head>
<body>

<div class="header">
  <h1>🎯 Security Assessment Executive Report</h1>
  <div class="sub">Target: <strong>{self.target}</strong></div>
  <div class="date">Generated: {date} | M7Hunter V7 | MilkyWay Intelligence</div>
</div>

<div class="risk-section">
  <div class="gauge-card">
    <div class="gauge-ring">
      <div class="gauge-score">{risk['score']}</div>
    </div>
    <div class="gauge-label">{risk['label']}</div>
    <div style="font-size:12px;color:#8b949e;margin-top:4px">Overall Risk Score</div>
  </div>

  <div class="stats-card">
    <div class="stats-grid">
      <div class="stat-box"><div class="stat-num" style="color:#dc3545">{stats['critical']}</div><div class="stat-lbl">Critical</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#fd7e14">{stats['high']}</div><div class="stat-lbl">High</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#ffc107">{stats['medium']}</div><div class="stat-lbl">Medium</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#28a745">{stats['low']}</div><div class="stat-lbl">Low</div></div>
    </div>
    {bars}
    <div style="font-size:12px;color:#8b949e;margin-top:10px">
      Total Findings: <strong>{stats['total']}</strong> &nbsp;|&nbsp;
      Confirmed: <strong style="color:#58a6ff">{stats['confirmed']}</strong>
    </div>
  </div>
</div>

<div class="section">
  <h2>🔴 Top Risk Findings</h2>
  <table>
    <tr><th>Severity</th><th>Vulnerability</th><th>Affected URL</th><th>Remediation Priority</th></tr>
    {top_rows}
  </table>
</div>

<div class="section">
  <h2>📋 Attack Timeline</h2>
  {tl_items}
</div>

<div class="section">
  <h2>📊 All Findings Summary</h2>
  <table>
    <tr><th>Severity</th><th>Type</th><th>URL</th><th>Status</th><th>Detail</th></tr>
    {all_rows}
  </table>
</div>

<div class="section">
  <h2>✅ Recommendations</h2>
  <div class="rec-grid">
    <div class="rec-card" style="border-color:#dc3545">
      <div class="rec-title" style="color:#dc3545">🔴 Immediate Actions</div>
      <div class="rec-desc">Patch critical vulnerabilities within 24 hours.
      Disable exposed admin panels, rotate compromised credentials,
      and apply emergency WAF rules for critical XSS/SQLi findings.</div>
    </div>
    <div class="rec-card" style="border-color:#fd7e14">
      <div class="rec-title" style="color:#fd7e14">🟠 Short Term (1 Week)</div>
      <div class="rec-desc">Fix high-severity issues including CORS
      misconfigurations, JWT vulnerabilities, and SSRF.
      Implement Content Security Policy headers site-wide.</div>
    </div>
    <div class="rec-card" style="border-color:#ffc107">
      <div class="rec-title" style="color:#ffc107">🟡 Medium Term (1 Month)</div>
      <div class="rec-desc">Address medium-severity findings: improve
      session management, add HttpOnly/Secure cookie flags,
      implement rate limiting, and fix CSRF tokens.</div>
    </div>
    <div class="rec-card" style="border-color:#28a745">
      <div class="rec-title" style="color:#28a745">🟢 Long Term (Quarter)</div>
      <div class="rec-desc">Security program improvements: regular
      penetration testing, developer security training, SAST/DAST
      integration in CI/CD, and bug bounty program launch.</div>
    </div>
  </div>
</div>

<div class="footer">
  M7Hunter V7 | MilkyWay Intelligence | Author: Sharlix<br>
  This report contains confidential security information — handle accordingly
</div>
</body></html>"""
