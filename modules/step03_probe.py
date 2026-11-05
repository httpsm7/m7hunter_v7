#!/usr/bin/env python3
# modules/step03_probe.py — HTTP Probe V7 (ARCHITECTURE FIXED)
# ROOT FIX: fmt_url.txt is GUARANTEED to have content after this step
# If httpx fails/missing → target URL written directly
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, shutil, urllib.request, urllib.error
from core.utils import count_lines, FormatFixer, safe_read


class Step03Probe:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p   = self.p
        fmt = p.files.get("fmt_domain","")
        res = p.files.get("resolved","")
        sub = p.files.get("subdomains","")
        out = p.files["live_hosts"]
        t   = p.tmgr.get

        # Determine target
        raw_target = p.target.strip()
        if not raw_target.startswith("http"):
            raw_target = "https://" + raw_target
        domain = raw_target.replace("https://","").replace("http://","").split("/")[0]

        # ── Pick best input file ──────────────────────────────────
        input_file = ""
        for f in [fmt, res, sub]:
            if f and os.path.isfile(f) and count_lines(f) > 0:
                input_file = f
                break

        # If no recon data → single-target mode
        if not input_file:
            p.log.warn("Probe: no recon data — single target mode")
            self._write_single_target(raw_target, out, p)
            return

        p.log.info(f"Probing {count_lines(input_file)} hosts via httpx")

        cookie_flag = ""
        auth_h = self._build_auth_header(p)
        if auth_h:
            cookie_flag = " ".join([f'-H "{k}: {v}"' for k,v in auth_h.items()])

        # ── httpx probe ───────────────────────────────────────────
        if shutil.which("httpx"):
            rate = getattr(p.args, "rate", 1000) or 1000
            p.shell(
                f"httpx -l {input_file} -silent -status-code "
                f"-title -tech-detect -follow-redirects "
                f"-threads 100 -rate-limit {rate} "
                f"{cookie_flag} -o {out} 2>/dev/null",
                label="httpx probe", tool_name="httpx", timeout=t("httpx")
            )
        else:
            p.log.warn("httpx not installed — using direct connectivity check")
            self._python_probe(input_file, out, auth_h)

        # ── CRITICAL: Guarantee output is never empty ─────────────
        if not os.path.isfile(out) or count_lines(out) == 0:
            p.log.warn("Probe: no live hosts from scan — adding target directly")
            self._write_single_target(raw_target, out, p)

        # ── Format outputs ────────────────────────────────────────
        n = FormatFixer.fix(out, p.files["fmt_url"],  "url")
        FormatFixer.fix(out, p.files["fmt_host"], "host")

        # CRITICAL: If fmt_url still empty (format issue) → force-write target
        if n == 0 or not os.path.isfile(p.files["fmt_url"]) or \
                count_lines(p.files["fmt_url"]) == 0:
            p.log.warn("fmt_url empty after format — force-writing target URL")
            with open(p.files["fmt_url"],"w") as f:
                f.write(raw_target + "\n")
            with open(p.files["fmt_host"],"w") as f:
                f.write(domain + "\n")
            n = 1

        # ── WAF detection ─────────────────────────────────────────
        if shutil.which("wafw00f"):
            waf = p.shell(
                f"wafw00f {raw_target} 2>/dev/null | head -5",
                label="WAF detect", timeout=30
            )
            if waf:
                p.log.info(f"  WAF: {waf.strip()[:80]}")
                for waf_name in ["Cloudflare","Akamai","Imperva","F5","Sucuri","Wordfence"]:
                    if waf_name.lower() in waf.lower():
                        p.ceo.set_waf_detected(waf_name)
                        break

        p.log.success(f"Live hosts: {n} | fmt_url ready ✅")
        if n == 1:
            p.log.info(f"  Target: {raw_target}")
        else:
            hosts = safe_read(p.files["fmt_url"])[:3]
            for h in hosts:
                p.log.info(f"  ↳ {h}")

    def _python_probe(self, input_file: str, out: str, auth_h: dict):
        """Pure Python fallback probe when httpx not available."""
        hosts = safe_read(input_file)[:200]
        live  = []
        for host in hosts:
            host = host.strip()
            if not host: continue
            for scheme in ["https","http"]:
                url = f"{scheme}://{host}" if not host.startswith("http") else host
                try:
                    req = urllib.request.Request(url, headers={
                        "User-Agent": "Mozilla/5.0",
                        **auth_h
                    })
                    resp = urllib.request.urlopen(req, timeout=8)
                    status = resp.status
                    live.append(f"{url} [{status}]")
                    break
                except urllib.error.HTTPError as e:
                    if e.code in (200,301,302,401,403,404):
                        live.append(f"{url} [{e.code}]")
                        break
                except Exception:
                    continue

        if live:
            with open(out,"w") as f:
                f.write("\n".join(live) + "\n")

    def _write_single_target(self, url: str, out: str, p):
        """Write target URL to all format files directly."""
        domain = url.replace("https://","").replace("http://","").split("/")[0]
        with open(out,"w") as f:
            f.write(url + "\n")
        with open(p.files["fmt_url"],"w") as f:
            f.write(url + "\n")
        with open(p.files["fmt_host"],"w") as f:
            f.write(domain + "\n")
        p.log.success(f"Probe: target set → {url}")

    def _build_auth_header(self, p) -> dict:
        hdrs = {}
        s = getattr(p.args,"session",None) or getattr(p.args,"cookie",None)
        if s:
            hdrs["Cookie"] = s
        a = getattr(p.args,"auth",None) or getattr(p.args,"authorization",None)
        if a:
            hdrs["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        j = getattr(p.args,"jwt",None)
        if j:
            hdrs["Authorization"] = f"Bearer {j}"
        return hdrs
