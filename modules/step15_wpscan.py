#!/usr/bin/env python3
# modules/step15_wpscan.py — WordPress Security Scan (wpscan)
# MilkyWay Intelligence | Author: Sharlix

import re, os
from core.utils import safe_read, count_lines
from core.http_client import sync_get


class Step15Wpscan:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        live  = safe_read(p.files.get("fmt_url",""))[:20]
        found = 0

        if not live:
            p.log.warn("WPScan: no live hosts"); return

        token_flag = ""
        if getattr(p.args, "wpscan_token", None):
            token_flag = f"--api-token {p.args.wpscan_token}"

        cookie_flag = ""
        if getattr(p.args, "cookie", None):
            cookie_flag = f"--cookie '{p.args.cookie}'"

        # Detect WordPress first
        wp_hosts = []
        for host in live:
            if self._is_wordpress(host):
                wp_hosts.append(host)
                p.log.info(f"  WordPress detected: {host}")

        if not wp_hosts:
            p.log.info("WPScan: No WordPress sites found")
            return

        p.log.info(f"WPScan: scanning {len(wp_hosts)} WordPress sites")

        for host in wp_hosts[:5]:
            out = os.path.join(p.out, f"{p.prefix}_wpscan_{host.split('//')[1][:20]}.txt")
            result = p.shell(
                f"wpscan --url {host} "
                f"--enumerate u,vp,vt,cb,dbe "
                f"--detection-mode aggressive "
                f"--random-user-agent "
                f"--no-update "
                f"{token_flag} {cookie_flag} "
                f"--format cli 2>/dev/null",
                label=f"wpscan {host[:40]}",
                tool_name="wpscan",
                timeout=p.tmgr.get("default")
            )

            if result:
                with open(out, "w") as f:
                    f.write(result)
                self._parse_wpscan(result, host)
                found += 1

        p.log.success(f"WPScan: {found} sites scanned")

    def _is_wordpress(self, url: str) -> bool:
        resp = sync_get(url, timeout=6)
        if not resp:
            return False
        body    = resp.get("body","").lower()
        headers = str(resp.get("headers",{})).lower()
        return any(sig in body or sig in headers for sig in [
            "wp-content", "wp-includes", "wordpress",
            "wp-login", "xmlrpc.php",
        ])

    def _parse_wpscan(self, output: str, host: str):
        p = self.p
        # Vulnerabilities
        for m in re.finditer(
            r'\[!\]\s*(CVE-[\d-]+|VULNERABILITY[^\n]+)', output, re.IGNORECASE
        ):
            p.add_finding("high","WORDPRESS_VULN", host, m.group(1)[:80], "wpscan")

        # Admin users exposed
        if re.search(r'(admin|administrator)\s+\(Found\)', output, re.IGNORECASE):
            p.add_finding("medium","WORDPRESS_USER_ENUM", host,
                           "WordPress admin username enumerated", "wpscan")

        # xmlrpc enabled
        if "xmlrpc" in output.lower() and "enabled" in output.lower():
            p.add_finding("medium","WORDPRESS_XMLRPC", host + "/xmlrpc.php",
                           "XML-RPC enabled — brute force / SSRF possible", "wpscan")

        # Debug mode
        if "debug mode" in output.lower():
            p.add_finding("medium","WORDPRESS_DEBUG", host,
                           "WordPress debug mode enabled — info disclosure", "wpscan")
