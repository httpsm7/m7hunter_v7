#!/usr/bin/env python3
# modules/step25_csrf.py — CSRF Testing Engine v6 (NEW)
# Tests: missing CSRF tokens, SameSite=None cookies, referer bypass
# High ROI — commonly missed by automated tools
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import time
import urllib.request
import urllib.parse
import urllib.error
from core.utils import safe_read, count_lines

# State-changing endpoints commonly vulnerable to CSRF
CSRF_SENSITIVE_PATHS = [
    "/api/user/update", "/api/account/update", "/api/profile/update",
    "/api/password/change", "/api/email/change",
    "/api/settings", "/settings/update",
    "/api/payment", "/api/order", "/api/transfer",
    "/account/delete", "/api/user/delete",
    "/api/admin", "/admin/user",
    "/api/follow", "/api/subscribe", "/api/unsubscribe",
    "/api/like", "/api/vote",
]

# Methods that should have CSRF protection
CSRF_METHODS = ["POST", "PUT", "PATCH", "DELETE"]



def _get_live_hosts(p, limit=100):
    """Returns live hosts - ALWAYS includes main target as fallback."""
    tgt = p.target.strip()
    if not tgt.startswith("http"):
        tgt = "https://" + tgt

    hosts = []
    seen  = set()

    for key in ("fmt_url", "live_hosts", "resolved"):
        src = p.files.get(key, "")
        if not src or not os.path.isfile(src):
            continue
        from core.utils import safe_read
        for line in safe_read(src):
            line = line.strip()
            if not line:
                continue
            if not line.startswith("http"):
                line = "https://" + line
            if line not in seen:
                seen.add(line)
                hosts.append(line)
        if hosts:
            break

    # GUARANTEED: always include main target
    if tgt not in seen:
        hosts.insert(0, tgt)

    return hosts[:limit]


class CSRFStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        live  = self.f["live_hosts"]
        urls  = self.f["urls"]
        out   = self.f["csrf_results"]
        found = 0

        hosts = safe_read(live)[:100]
        if not hosts:
            self.log.warn("CSRF: no live hosts"); return

        self.log.info(f"CSRF: testing {len(hosts)} hosts")

        for host in hosts:
            host = host.rstrip("/")

            # Test 1: Missing CSRF token on state-changing forms
            result = self._test_form_csrf(host, urls)
            if result:
                sev, detail, url = result
                with open(out,"a") as f:
                    f.write(f"CSRF_MISSING_TOKEN: {url} | {detail}\n")
                self.p.add_finding(sev, "CSRF_MISSING_TOKEN", url, detail, "csrf-engine")
                found += 1

            # Test 2: SameSite=None cookie without Secure flag
            result2 = self._test_cookie_samesite(host)
            if result2:
                sev, detail, url = result2
                with open(out,"a") as f:
                    f.write(f"CSRF_SAMESITE_NONE: {url} | {detail}\n")
                self.p.add_finding("medium", "CSRF_SAMESITE_NONE", url, detail, "csrf-engine")
                found += 1

            # Test 3: Referer header bypass
            result3 = self._test_referer_bypass(host, urls)
            if result3:
                sev, detail, url = result3
                with open(out,"a") as f:
                    f.write(f"CSRF_REFERER_BYPASS: {url} | {detail}\n")
                self.p.add_finding(sev, "CSRF_REFERER_BYPASS", url, detail, "csrf-engine")
                found += 1

            # Test 4: API endpoints without CSRF (common with JSON APIs)
            result4 = self._test_api_csrf(host)
            if result4:
                sev, detail, url = result4
                with open(out,"a") as f:
                    f.write(f"CSRF_API_NO_PROTECTION: {url} | {detail}\n")
                self.p.add_finding(sev, "CSRF_API_NO_PROTECTION", url, detail, "csrf-engine")
                found += 1

            self.p.bypass.jitter()

        self.log.success(f"CSRF: {found} findings → {os.path.basename(out)}")

    def _test_form_csrf(self, host: str, urls_file: str) -> tuple:
        """Test HTML forms for missing CSRF tokens."""
        all_urls = safe_read(urls_file)
        form_urls = [u for u in all_urls if host in u][:100]

        for url in form_urls:
            resp = self._fetch(url)
            if not resp or "html" not in resp.get("ct",""):
                continue

            body = resp.get("body","")

            # Find POST forms
            forms = re.findall(r'<form[^>]*method=["\']?post["\']?[^>]*>.*?</form>',
                               body, re.IGNORECASE | re.DOTALL)
            if not forms:
                continue

            for form_html in forms:
                # Check for CSRF token inputs
                has_csrf = bool(re.search(
                    r'<input[^>]*(?:name|id)=["\'](?:csrf|_token|authenticity_token|'
                    r'csrfmiddlewaretoken|_csrf_token|xsrf|__requestverificationtoken)["\']',
                    form_html, re.IGNORECASE))

                if not has_csrf:
                    # Check action URL to see if it's state-changing
                    action = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', form_html, re.I)
                    if action:
                        action_url = urllib.parse.urljoin(host, action.group(1))
                    else:
                        action_url = url

                    detail = f"POST form with no CSRF token at {action_url[:60]}"
                    return ("high", detail, url)

        return None

    def _test_cookie_samesite(self, host: str) -> tuple:
        """Check for SameSite=None cookies without Secure flag."""
        resp = self._fetch(host, get_headers=True)
        if not resp:
            return None

        cookies = resp.get("set_cookie","")
        if not cookies:
            return None

        for cookie in cookies.split("\n"):
            cookie_lower = cookie.lower()
            if "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                detail = f"SameSite=None without Secure: {cookie[:100]}"
                return ("medium", detail, host)

        return None

    def _test_referer_bypass(self, host: str, urls_file: str) -> tuple:
        """Test if CSRF protection can be bypassed by removing Referer header."""
        all_urls = safe_read(urls_file)
        api_urls = [u for u in all_urls if host in u and
                    any(p in u for p in ["/api/","/account","/user","/profile"])][:5]

        for url in api_urls:
            # Request without Referer
            resp_no_ref = self._fetch_post(url, referer=None)
            # Request with attacker Referer
            resp_evil   = self._fetch_post(url, referer="https://evil.com")

            if not resp_no_ref or not resp_evil:
                continue

            # If both return same status (not rejected) = bypass possible
            if (resp_no_ref.get("status") == resp_evil.get("status") and
                    resp_no_ref.get("status") not in (401,403,405)):
                detail = f"CSRF via referer removal accepted: {url[:60]}"
                return ("medium", detail, url)

        return None

    def _test_api_csrf(self, host: str) -> tuple:
        """Test JSON API endpoints for CSRF vulnerability."""
        # Common state-changing API patterns
        test_endpoints = [f"{host}{path}" for path in CSRF_SENSITIVE_PATHS[:5]]

        for url in test_endpoints:
            # Send cross-origin request (simulate CSRF)
            resp = self._fetch_post(
                url,
                body='{"test":1}',
                content_type="application/json",
                referer="https://attacker.evil.com",
                origin="https://attacker.evil.com"
            )
            if not resp:
                continue

            # If API accepts cross-origin JSON POST (not 403/401) = potential CSRF
            if resp.get("status") in (200, 201, 202, 400):
                # 400 = endpoint exists but bad data (still CSRF-able)
                body = resp.get("body","")
                if "not found" not in body.lower() and "404" not in body:
                    detail = f"API accepts cross-origin JSON POST (no CSRF check): {url[:60]}"
                    return ("high", detail, url)

        return None

    def _fetch(self, url: str, get_headers=False, timeout=8) -> dict:
        try:
            req  = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(30000).decode("utf-8", errors="ignore")
            ct   = resp.headers.get("Content-Type","")
            set_cookie = resp.headers.get("Set-Cookie","") if get_headers else ""
            return {"status": resp.status, "body": body, "ct": ct, "set_cookie": set_cookie}
        except Exception:
            return None

    def _fetch_post(self, url: str, body: str = "", content_type: str = "application/x-www-form-urlencoded",
                    referer: str = None, origin: str = None, timeout=8) -> dict:
        try:
            data = body.encode() if body else b""
            req  = urllib.request.Request(url, data=data, method="POST", headers={
                "User-Agent"  : "Mozilla/5.0",
                "Content-Type": content_type,
                "Content-Length": str(len(data)),
            })
            if referer:
                req.add_header("Referer", referer)
            if origin:
                req.add_header("Origin", origin)
            resp = urllib.request.urlopen(req, timeout=timeout)
            body_resp = resp.read(5000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body_resp}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None
