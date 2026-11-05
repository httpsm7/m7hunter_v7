#!/usr/bin/env python3
# modules/step02_dns.py — DNS Resolution + Record Enumeration
# MilkyWay Intelligence | Author: Sharlix

import os
from core.utils import count_lines, FormatFixer, safe_read


class Step02Dns:
    def __init__(self, pipeline):
        self.p = pipeline

    def _python_dns_fallback(self, subs_file: str, resolved_file: str,
                              fmt_url_file: str):
        """
        Python DNS fallback when dnsx/massdns not installed.
        Resolves each subdomain via socket.getaddrinfo().
        Guarantees resolved.txt + fmt_url.txt are populated.
        """
        import socket, pathlib

        subs = []
        try:
            subs = [s.strip() for s in open(subs_file).read().splitlines()
                    if s.strip() and not s.startswith('#')]
        except Exception:
            pass

        if not subs:
            # At minimum resolve the base target
            domain = self.p.target.replace("https://","").replace("http://","").split("/")[0]
            subs   = [domain]

        resolved  = []
        fmt_urls  = []
        socket.setdefaulttimeout(3)

        for sub in subs[:100]:
            try:
                results = socket.getaddrinfo(sub, 80, socket.AF_INET)
                ip      = results[0][4][0] if results else ""
                if ip:
                    resolved.append(f"{sub} A {ip}")
                    # Build URL
                    scheme = "https" if "443" in str(results) else "http"
                    fmt_urls.append(f"{scheme}://{sub}")
            except Exception:
                pass

        if resolved:
            with open(resolved_file,"a") as f:
                f.write("\n".join(resolved) + "\n")
        if fmt_urls:
            with open(fmt_url_file,"a") as f:
                f.write("\n".join(fmt_urls) + "\n")

        self.p.log.info(
            f"  Python DNS fallback: {len(resolved)}/{len(subs)} resolved")
        return len(resolved)

    def run(self):
        p   = self.p
        src = p.files.get("subdomains","")
        fmt = p.files.get("fmt_domain","")
        out = p.files["resolved"]
        dns = p.files["dns_records"]
        t   = p.tmgr.get
        h   = p.bypass.headers()

        input_file = fmt if os.path.isfile(fmt) and count_lines(fmt) > 0 else src
        if not os.path.isfile(input_file) or count_lines(input_file) == 0:
            p.log.warn("DNS: no subdomains to resolve — skipping")
            return

        p.log.info(f"Resolving {count_lines(input_file)} subdomains")

        # dnsx - resolve A records
        p.shell(
            f"dnsx -l {input_file} -silent -a -resp -o {out} -t 100 2>/dev/null",
            label="dnsx resolve", tool_name="dnsx", timeout=t("dnsx")
        )

        # dnsx - all record types (for zone transfer / misconfig detection)
        p.shell(
            f"dnsx -l {input_file} -silent -a -aaaa -cname -mx -ns -txt "
            f"-resp -o {dns} -t 100 2>/dev/null",
            label="dnsx full records", tool_name="dnsx", timeout=t("dnsx")
        )

        # Check zone transfer
        tgt = p.target.replace("https://","").replace("http://","").split("/")[0]
        zone = p.shell(
            f"dig axfr {tgt} @$(dig NS {tgt} +short | head -1) 2>/dev/null | head -30",
            label="zone transfer check", timeout=20
        )
        if zone and ("IN" in zone or "SOA" in zone):
            p.add_finding("critical", "DNS_ZONE_TRANSFER", f"dns://{tgt}",
                           "Zone transfer allowed — all DNS records exposed",
                           tool="dig")

        n = count_lines(out)
        # Python DNS fallback when tools missing
        fmt_url = p.files.get("fmt_url", "")
        resolved_f = p.files.get("resolved","")
        if count_lines(resolved_f) == 0:
            p.log.warn("  step02: dnsx missing or no results — Python DNS fallback")
            self._python_dns_fallback(
                p.files.get("subdomains",""),
                resolved_f,
                fmt_url
            )

        p.log.success(f"Resolved: {n} hosts")
        FormatFixer.fix(out, p.files["fmt_domain"], 'domain')
