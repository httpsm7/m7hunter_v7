import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.utils import get_prefix
#!/usr/bin/env python3
# reporting/bug_bounty_report.py — Bug Bounty Submission Report Generator
# Based on: Bug Hunter's Methodology (Jason Haddix) + Bug Bounty Bootcamp (Vickie Li)
# Produces HackerOne/Bugcrowd-ready report format
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os
import json
from datetime import datetime

# ── REMEDIATION DATABASE (from Bug Bounty Bootcamp + CEH) ─────────────────────
REMEDIATION = {
    "XSS": {
        "summary": "Cross-Site Scripting (XSS)",
        "description": "The application reflects user-supplied input in the HTTP response without proper encoding, allowing attackers to inject malicious scripts that execute in victims' browsers.",
        "impact": [
            "Session hijacking via cookie theft",
            "Account takeover by stealing authentication tokens",
            "Keylogging and credential harvesting",
            "Phishing via malicious redirects",
            "Defacement of web pages for targeted users",
        ],
        "remediation": [
            "Encode all user-supplied data before rendering in HTML context (use &lt; &gt; &amp; etc.)",
            "Use Content Security Policy (CSP) headers: `Content-Security-Policy: default-src 'self'`",
            "Apply output encoding for the specific context (HTML/JS/URL/CSS)",
            "Avoid `innerHTML`, `document.write()` — use `textContent` or `createTextNode()` instead",
            "Set HttpOnly and Secure flags on session cookies",
            "Use a well-tested sanitization library (DOMPurify for client-side)",
            "Enable X-XSS-Protection header as defense-in-depth",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://portswigger.net/web-security/cross-site-scripting",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "cvss_base": "6.1 (Medium) — Scope: Changed, Auth: None",
    },
    "IDOR": {
        "summary": "Insecure Direct Object Reference (IDOR)",
        "description": "The application exposes direct references to internal objects (user IDs, account numbers) without proper authorization checks, allowing attackers to access other users' data by modifying these references.",
        "impact": [
            "Unauthorized access to other users' private data",
            "Account takeover by accessing profile/settings of other users",
            "Data exfiltration at scale by enumerating IDs",
            "Privilege escalation by accessing admin objects",
        ],
        "remediation": [
            "Implement server-side authorization checks for every object access request",
            "Use indirect references (UUIDs, hashed IDs) instead of sequential integers",
            "Validate that the authenticated user owns or has permission to access the requested object",
            "Log and alert on unusual access patterns (bulk enumeration)",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
        ],
        "cvss_base": "8.1 (High) — Auth: Required, Impact: High",
    },
    "SQLI": {
        "summary": "SQL Injection",
        "description": "User-supplied data is incorporated into database queries without proper sanitization, allowing attackers to manipulate SQL logic and extract, modify, or delete data.",
        "impact": [
            "Complete database exfiltration (usernames, passwords, PII)",
            "Authentication bypass",
            "Data modification or deletion",
            "Remote code execution via DB features (xp_cmdshell, INTO OUTFILE)",
        ],
        "remediation": [
            "Use parameterized queries (prepared statements) — NEVER concatenate user input into SQL",
            "Apply input validation and whitelisting",
            "Use an ORM that handles SQL safely",
            "Apply least-privilege DB accounts",
            "Disable detailed error messages in production",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "cvss_base": "9.8 (Critical) — Auth: None, Impact: Complete",
    },
    "SSRF": {
        "summary": "Server-Side Request Forgery (SSRF)",
        "description": "The application can be made to make requests to arbitrary URLs, including internal services and cloud metadata endpoints, bypassing network controls.",
        "impact": [
            "Access to cloud metadata (AWS credentials, GCP service accounts)",
            "Port scanning of internal network",
            "Access to internal admin services (Redis, Elasticsearch, etc.)",
            "Potential RCE via SSRF chains",
        ],
        "remediation": [
            "Whitelist allowed protocols (http/https only) and domains",
            "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)",
            "Use DNS rebinding protection",
            "Implement response validation (don't return raw internal responses to users)",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://portswigger.net/web-security/ssrf",
        ],
        "cvss_base": "9.8 (Critical) — when cloud credentials accessible",
    },
    "SSTI": {
        "summary": "Server-Side Template Injection (SSTI)",
        "description": "User input is passed directly into template engine expressions, allowing attackers to execute arbitrary code on the server.",
        "impact": [
            "Remote code execution on the server",
            "Full server compromise",
            "File read/write on the filesystem",
            "Lateral movement within internal network",
        ],
        "remediation": [
            "Never render user input directly in template expressions",
            "Use sandboxed template environments",
            "Apply input validation and reject template syntax characters",
            "Separate template logic from user-supplied data",
        ],
        "references": [
            "https://portswigger.net/research/server-side-template-injection",
        ],
        "cvss_base": "9.8 (Critical)",
    },
    "LFI": {
        "summary": "Local File Inclusion (LFI)",
        "description": "The application includes files based on user-supplied input without validation, allowing attackers to read arbitrary files from the server filesystem.",
        "impact": [
            "Read of /etc/passwd, application config files, credentials",
            "Source code disclosure",
            "Potential RCE via log poisoning",
        ],
        "remediation": [
            "Never use user-supplied data in file include operations",
            "Whitelist allowed files/directories",
            "Use realpath() and validate the resolved path is within allowed directory",
            "Disable allow_url_include in PHP",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
        ],
        "cvss_base": "7.5 (High)",
    },
    "CSRF": {
        "summary": "Cross-Site Request Forgery (CSRF)",
        "description": "The application does not validate the origin of state-changing requests, allowing attackers to trick authenticated users into performing unintended actions.",
        "impact": [
            "Account settings modification (email, password change)",
            "Unauthorized transactions or data operations",
            "Account takeover when combined with other vulnerabilities",
        ],
        "remediation": [
            "Implement synchronizer CSRF tokens for all state-changing requests",
            "Use SameSite=Strict or SameSite=Lax cookie attribute",
            "Verify the Origin/Referer header for cross-origin requests",
            "Require user interaction (re-authentication) for sensitive actions",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/csrf",
        ],
        "cvss_base": "6.5 (Medium) — Auth: Required",
    },
    "XXE": {
        "summary": "XML External Entity (XXE) Injection",
        "description": "The application processes XML input with external entity support enabled, allowing attackers to read local files, perform SSRF, or cause denial of service.",
        "impact": [
            "Read arbitrary files from the server",
            "Server-Side Request Forgery via external entities",
            "Denial of Service via billion laughs attack",
        ],
        "remediation": [
            "Disable external entity processing in XML parsers",
            "Use simpler data formats (JSON) where XML is not required",
            "Validate and sanitize XML input",
        ],
        "references": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        ],
        "cvss_base": "7.5 (High)",
    },
    "CORS": {
        "summary": "CORS Misconfiguration",
        "description": "The application returns overly permissive CORS headers, allowing arbitrary origins to make cross-origin requests and read the response.",
        "impact": [
            "Stealing authenticated user data from cross-origin JavaScript",
            "Reading API responses that contain sensitive data",
        ],
        "remediation": [
            "Only allow specific trusted origins in Access-Control-Allow-Origin",
            "Never reflect the Origin header directly without validation",
            "Do not allow credentials (Access-Control-Allow-Credentials: true) with wildcard origins",
        ],
        "references": [
            "https://portswigger.net/web-security/cors",
        ],
        "cvss_base": "5.4 (Medium)",
    },
    "DEFAULT": {
        "summary": "Security Vulnerability",
        "description": "A security vulnerability was identified that may allow unauthorized access or actions.",
        "impact": ["Unauthorized access or manipulation of application data"],
        "remediation": ["Apply the principle of least privilege and validate all user inputs"],
        "references": ["https://owasp.org/www-project-top-ten/"],
        "cvss_base": "5.0 (Medium)",
    }
}

# ── REPRODUCTION STEP TEMPLATES ────────────────────────────────────────────────
REPRO_TEMPLATES = {
    "XSS": """1. Navigate to: {url}
2. In the parameter `{param}`, insert payload: `{payload}`
3. Observe that the payload executes unencoded in the browser (alert popup or DOM execution)
4. The JavaScript context receives the payload without HTML entity encoding""",

    "IDOR": """1. Log in as User A (attacker) and capture your session cookie
2. Navigate to: {url}
3. Note the object ID in the request: `{param}`
4. Replace the ID with another user's ID (e.g., increment by 1)
5. Observe that User B's data is returned without authorization check""",

    "SQLI": """1. Navigate to: {url}
2. Insert payload into parameter `{param}`: `{payload}`
3. Observe database error or timing delay indicating SQL injection
4. Confirm by extracting database version or schema information""",

    "SSRF": """1. Navigate to: {url}
2. Insert internal URL into parameter `{param}`: `{payload}`
3. Observe that the server makes an outbound request to the specified URL
4. For cloud environments, test: `http://169.254.169.254/latest/meta-data/`""",

    "DEFAULT": """1. Navigate to: {url}
2. Insert test payload into parameter `{param}`: `{payload}`
3. Observe the vulnerability response
4. Confirm the finding is exploitable""",
}


class BugBountyReportGenerator:
    """
    Generates bug bounty-ready reports in HackerOne/Bugcrowd format.
    Based on Bug Hunter's Methodology and Bug Bounty Bootcamp templates.
    """

    def __init__(self, pipeline=None, target: str = "", out_dir: str = ""):
        if pipeline:
            self.target  = pipeline.target
            self.out_dir = pipeline.out
            self.prefix  = pipeline.prefix
        else:
            self.target  = target
            self.out_dir = out_dir or "results"
            self.prefix  = get_prefix(target)

    def generate_all(self, findings: list) -> dict:
        """Generate all bug bounty report formats."""
        os.makedirs(self.out_dir, exist_ok=True)
        paths = {}
        sorted_findings = self._sort_findings(findings)
        stats = self._compute_stats(sorted_findings)

        paths["markdown"] = self._write_markdown(sorted_findings, stats)
        paths["html"]     = self._write_html(sorted_findings, stats)
        paths["json"]     = self._write_json(sorted_findings, stats)

        return paths

    def _sort_findings(self, findings: list) -> list:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(findings, key=lambda f: order.get(f.get("severity", "info"), 4))

    def _compute_stats(self, findings: list) -> dict:
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f.get("severity", "info")
            stats[sev] = stats.get(sev, 0) + 1
            stats["total"] += 1
        stats["confirmed"] = sum(1 for f in findings if f.get("status") == "confirmed")
        return stats

    def _get_remediation(self, vuln_type: str) -> dict:
        key = vuln_type.upper().split("_")[0]
        return REMEDIATION.get(key, REMEDIATION["DEFAULT"])

    def _get_repro_steps(self, finding: dict) -> str:
        vtype  = finding.get("vuln_type", "").upper().split("_")[0]
        url    = finding.get("url", "")
        detail = finding.get("detail", "")
        payload = finding.get("payload", "N/A")

        # Extract param from detail or URL
        param = "parameter"
        if "param=" in detail:
            param = detail.split("param=")[-1].split(" ")[0].split(",")[0]
        elif "?" in url:
            try:
                import urllib.parse
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                if qs:
                    param = list(qs.keys())[0]
            except Exception:
                pass

        template = REPRO_TEMPLATES.get(vtype, REPRO_TEMPLATES["DEFAULT"])
        return template.format(url=url, param=param, payload=payload)

    def _write_markdown(self, findings: list, stats: dict) -> str:
        """Generate HackerOne/Bugcrowd-ready Markdown report."""
        path = os.path.join(self.out_dir, f"{self.prefix}_bug_bounty_report.md")

        lines = [
            f"# M7Hunter Bug Bounty Report — {self.target}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Tool:** M7Hunter V7 | MilkyWay Intelligence",
            f"**Target:** {self.target}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {stats['critical']} |",
            f"| 🟠 High | {stats['high']} |",
            f"| 🟡 Medium | {stats['medium']} |",
            f"| 🟢 Low | {stats['low']} |",
            f"| **Total** | **{stats['total']}** |",
            "",
            f"**Confirmed Findings:** {stats['confirmed']}",
            "",
            "---",
            "",
        ]

        for i, f in enumerate(findings, 1):
            vtype   = f.get("vuln_type", "UNKNOWN")
            sev     = f.get("severity", "medium")
            url     = f.get("url", "")
            payload = f.get("payload", "N/A")
            detail  = f.get("detail", "")
            status  = f.get("status", "potential")
            conf    = f.get("confidence", 0.0)

            rem  = self._get_remediation(vtype)
            repro = self._get_repro_steps(f)

            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev, "⚪")

            lines += [
                f"## Finding #{i:03d} — {sev_emoji} {vtype} [{sev.upper()}]",
                "",
                f"**Summary:** {rem['summary']}",
                f"**Status:** `{status}` | **Confidence:** `{conf:.0%}`",
                f"**CVSS Base Score:** {rem['cvss_base']}",
                "",
                "### Vulnerability Description",
                "",
                rem["description"],
                "",
                "### Affected URL",
                "",
                f"```",
                url,
                f"```",
                "",
                "### Evidence",
                "",
                f"```",
                detail,
                f"```",
            ]

            if payload and payload != "N/A":
                lines += [
                    "",
                    "### Payload Used",
                    "",
                    f"```",
                    payload,
                    f"```",
                ]

            lines += [
                "",
                "### Steps to Reproduce",
                "",
                repro,
                "",
                "### Impact",
                "",
            ]
            for imp in rem["impact"]:
                lines.append(f"- {imp}")

            lines += [
                "",
                "### Remediation",
                "",
            ]
            for fix in rem["remediation"]:
                lines.append(f"1. {fix}")

            lines += [
                "",
                "### References",
                "",
            ]
            for ref in rem["references"]:
                lines.append(f"- {ref}")

            lines += ["", "---", ""]

        with open(path, "w", encoding="utf-8") as fout:
            fout.write("\n".join(lines))
        return path

    def _write_html(self, findings: list, stats: dict) -> str:
        """Generate visual HTML report."""
        path = os.path.join(self.out_dir, f"{self.prefix}_bug_bounty_report.html")

        sev_colors = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107", "low": "#28a745", "info": "#17a2b8"
        }

        cards = ""
        for i, f in enumerate(findings, 1):
            vtype   = f.get("vuln_type", "UNKNOWN")
            sev     = f.get("severity", "medium")
            url     = f.get("url", "")[:100]
            payload = f.get("payload", "N/A")[:200]
            detail  = f.get("detail", "")[:200]
            status  = f.get("status", "potential")
            conf    = f.get("confidence", 0.0)
            col     = sev_colors.get(sev, "#888")
            rem     = self._get_remediation(vtype)
            repro   = self._get_repro_steps(f).replace("\n", "<br>")

            impact_html = "".join(f"<li>{imp}</li>" for imp in rem["impact"])
            remed_html  = "".join(f"<li>{fix}</li>" for fix in rem["remediation"])

            status_color = "green" if status == "confirmed" else "orange"

            cards += f"""
<div class="card">
  <div class="card-header" style="border-left:4px solid {col}">
    <span class="badge" style="background:{col}">#{i:03d} {sev.upper()}</span>
    <strong>{vtype}</strong>
    <span style="float:right;color:{status_color};font-size:13px">{status} ({conf:.0%})</span>
  </div>
  <div class="card-body">
    <div class="meta">CVSS: {rem['cvss_base']}</div>
    <p>{rem['description']}</p>
    <h4>📍 Affected URL</h4>
    <code class="url">{url}</code>
    <h4>🔍 Evidence</h4>
    <pre class="pre">{detail}</pre>
    {"<h4>💉 Payload</h4><pre class='pre'>" + payload + "</pre>" if payload != "N/A" else ""}
    <h4>📋 Steps to Reproduce</h4>
    <pre class="pre">{repro}</pre>
    <h4>💥 Impact</h4>
    <ul>{impact_html}</ul>
    <h4>🔧 Remediation</h4>
    <ol>{remed_html}</ol>
  </div>
</div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>M7Hunter Bug Bounty Report — {self.target}</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:20px;max-width:1200px;margin:0 auto}}
h1{{color:#58a6ff;text-align:center}} .subtitle{{text-align:center;color:#8b949e;margin-bottom:30px}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center}}
.stat .num{{font-size:28px;font-weight:700}} .stat .lbl{{font-size:12px;color:#8b949e}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin:16px 0;overflow:hidden}}
.card-header{{padding:12px 16px;background:#21262d;display:flex;align-items:center;gap:10px}}
.badge{{padding:3px 10px;border-radius:4px;color:white;font-size:12px;font-weight:bold}}
.card-body{{padding:16px}} h4{{color:#58a6ff;margin:12px 0 6px}}
.pre{{background:#0d1117;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
.url{{background:#0d1117;padding:6px 10px;border-radius:4px;font-size:12px;display:block;word-break:break-all}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:8px}} li{{margin:4px 0;font-size:14px}}
</style>
</head>
<body>
<h1>🎯 M7Hunter Bug Bounty Report</h1>
<div class="subtitle">Target: <strong>{self.target}</strong> | {datetime.now().strftime('%Y-%m-%d %H:%M')} | MilkyWay Intelligence</div>
<div class="stats">
  <div class="stat"><div class="num" style="color:#dc3545">{stats['critical']}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="num" style="color:#fd7e14">{stats['high']}</div><div class="lbl">High</div></div>
  <div class="stat"><div class="num" style="color:#ffc107">{stats['medium']}</div><div class="lbl">Medium</div></div>
  <div class="stat"><div class="num" style="color:#28a745">{stats['low']}</div><div class="lbl">Low</div></div>
  <div class="stat"><div class="num" style="color:#58a6ff">{stats['confirmed']}</div><div class="lbl">Confirmed</div></div>
</div>
{cards}
<div style="text-align:center;color:#8b949e;font-size:12px;margin-top:30px">M7Hunter V7 | MilkyWay Intelligence</div>
</body></html>"""

        with open(path, "w", encoding="utf-8") as fout:
            fout.write(html)
        return path

    def _write_json(self, findings: list, stats: dict) -> str:
        path = os.path.join(self.out_dir, f"{self.prefix}_bug_bounty_report.json")
        data = {
            "target":    self.target,
            "generated": datetime.now().isoformat(),
            "stats":     stats,
            "findings":  findings,
        }
        with open(path, "w") as fout:
            json.dump(data, fout, indent=2, default=str)
        return path


if __name__ == "__main__":
    # TEST: Generate a sample report
    test_findings = [
        {
            "vuln_type": "XSS",
            "severity":  "high",
            "url":       "https://example.com/search?q=test",
            "payload":   "<svg/onload=alert(1)>",
            "detail":    "XSS bypass=svg_basic param=q — unencoded reflection confirmed",
            "status":    "confirmed",
            "confidence": 0.92,
        },
        {
            "vuln_type": "IDOR",
            "severity":  "critical",
            "url":       "https://example.com/api/user/1337/profile",
            "payload":   "user_id=1338",
            "detail":    "User B's profile returned without authorization",
            "status":    "confirmed",
            "confidence": 0.95,
        },
    ]

    gen = BugBountyReportGenerator(target="example.com", out_dir="/tmp/m7test")
    paths = gen.generate_all(test_findings)
    print("Generated reports:")
    for fmt, path in paths.items():
        size = os.path.getsize(path)
        print(f"  {fmt}: {path} ({size} bytes)")
