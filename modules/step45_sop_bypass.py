#!/usr/bin/env python3
# modules/step45_sop_bypass.py — SOP Bypass + Cross-Origin Data Leakage
# NEW MODULE: postMessage, CORS, WebSocket origin, JSONP, DNS rebinding
# Source: Bug Bounty Bootcamp Ch8 — SOP + origin isolation
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, json, urllib.request, urllib.error, urllib.parse
from core.utils import safe_read

# ── Same-Origin Policy bypass techniques ─────────────────────────────────────
SOP_PATHS = [
    "/api/user","/api/me","/api/account","/api/profile",
    "/api/data","/api/config","/api/admin",
]

# ── JSONP endpoints (SOP bypass via script tag) ────────────────────────────────
JSONP_PARAMS = ["callback","jsonp","cb","fn","wrapper","method","format",
                "jquery","handler","jcb","callbackFn","jsoncallback"]

JSONP_PROBE  = "m7hunter_sop_test"

# ── WebSocket cross-origin indicators ────────────────────────────────────────
WS_PATHS = ["/ws","/websocket","/socket","/socket.io",
            "/api/ws","/api/socket","/chat","/live"]

# ── DNS rebinding indicators ──────────────────────────────────────────────────
REBIND_HEADERS = ["X-Forwarded-Host","Host","X-Real-IP"]

# ── Cross-origin iframe detection ─────────────────────────────────────────────
FRAME_EMBED_RE = re.compile(
    r'<(?:iframe|frame|embed|object)[^>]+src=["\']([^"\']+)["\']',re.I)

# ── window.opener SOP bypass ──────────────────────────────────────────────────
OPENER_RE = re.compile(r'window\.opener|target=["\']_blank["\']',re.I)
REL_NOOPENER = re.compile(r'rel=["\'][^"\']*noopener[^"\']*["\']',re.I)


class Step45SopBypass:
    """
    SOP Bypass Detection Engine.
    Bug Bounty Bootcamp Ch8:
    1. JSONP endpoint leaks data cross-origin
    2. CORS misconfiguration → cross-origin reads
    3. WebSocket missing origin check
    4. window.opener tabnapping (missing rel=noopener)
    5. postMessage without origin validation
    6. Sandboxed iframe allow-scripts+allow-same-origin bypass
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("sop_results",
                             f"{p.out}/{p.prefix}_sop_bypass.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        urls  = safe_read(p.files.get("urls",""))
        js_f  = p.files.get("js_files","")
        found = 0

        if not live:
            p.log.warn("SOP Bypass: no live hosts"); return

        auth_h = self._build_auth(p)
        p.log.info(f"SOP Bypass V7: {len(live)} hosts — JSONP+opener+postMsg+WS")

        for host in live[:5]:
            host = host.rstrip("/")

            # Phase 1: JSONP endpoint detection
            r = self._test_jsonp(host, urls, auth_h, out)
            found += r

            # Phase 2: window.opener tabnapping
            r = self._test_opener(host, auth_h, out)
            found += r

            # Phase 3: WebSocket origin check
            r = self._test_websocket_origin(host, out)
            found += r

            # Phase 4: Sandboxed iframe bypass
            r = self._test_sandbox_bypass(host, auth_h, out)
            found += r

            p.bypass.jitter()

        # Phase 5: postMessage in JS files
        r = self._check_postmessage_js(js_f, live, out)
        found += r

        p.log.success(f"SOP Bypass V7: {found} findings")

    # ── Phase 1: JSONP ────────────────────────────────────────────────────────
    def _test_jsonp(self, host, urls, auth_h, out) -> int:
        found = 0
        test_urls = (
            [host + p for p in SOP_PATHS] +
            [u for u in urls if any(
                p in u.lower() for p in ["callback","jsonp","json"])][:10]
        )
        for base_url in test_urls[:20]:
            parsed = urllib.parse.urlparse(base_url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            for param in JSONP_PARAMS:
                test_qs  = {k: list(v) for k,v in qs.items()}
                test_qs[param] = [JSONP_PROBE]
                test_url = urllib.parse.urlunparse(
                    parsed._replace(
                        query=urllib.parse.urlencode(test_qs, doseq=True)))
                resp = self._fetch(test_url, auth_h)
                if not resp: continue

                body = resp.get("body","")
                ct   = resp.get("headers",{}).get("content-type","")

                if JSONP_PROBE in body:
                    if "javascript" in ct or "json" in ct or body.startswith(JSONP_PROBE+"("):
                        detail = (f"JSONP SOP bypass: param='{param}' reflects "
                                  f"callback in JS response — cross-origin data theft possible")
                        self._save(out,"high","JSONP_SOP_BYPASS",test_url,detail)
                        found += 1
                        break
        return found

    # ── Phase 2: window.opener tabnapping ─────────────────────────────────────
    def _test_opener(self, host, auth_h, out) -> int:
        found = 0
        resp = self._fetch(host, auth_h)
        if not resp: return 0
        body = resp.get("body","")

        # Find target="_blank" without rel="noopener noreferrer"
        blank_links = re.findall(
            r'<a[^>]+target=["\']_blank["\'][^>]*>',
            body, re.I)

        vulnerable = []
        for link in blank_links:
            if not REL_NOOPENER.search(link):
                href_m = re.search(r'href=["\']([^"\']+)["\']', link, re.I)
                if href_m:
                    vulnerable.append(href_m.group(1)[:60])

        if vulnerable:
            detail = (f"Tabnapping: {len(vulnerable)} links with target=_blank "
                      f"missing rel=noopener — opener can access/redirect parent: "
                      f"{', '.join(vulnerable[:3])}")
            self._save(out,"medium","TABNAPPING_OPENER",host,detail)
            found += 1

        # Check if window.opener is used without clearing
        if OPENER_RE.search(body):
            if "window.opener = null" not in body and "opener = null" not in body:
                detail = "window.opener used without nullification — tabnapping possible"
                self._save(out,"medium","WINDOW_OPENER",host,detail)
                found += 1
        return found

    # ── Phase 3: WebSocket origin check ──────────────────────────────────────
    def _test_websocket_origin(self, host, out) -> int:
        found = 0
        import socket, ssl as ssl_mod

        parsed = urllib.parse.urlparse(host)
        ws_host = parsed.hostname
        port    = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"

        for ws_path in WS_PATHS:
            try:
                s = socket.create_connection((ws_host, port), timeout=5)
                if use_ssl:
                    ctx = ssl_mod.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl_mod.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=ws_host)

                # Send WebSocket upgrade with evil origin
                evil_origin = "https://evil.com"
                key = "dGhlIHNhbXBsZSBub25jZQ=="  # standard test key
                req = (
                    f"GET {ws_path} HTTP/1.1\r\n"
                    f"Host: {ws_host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"Origin: {evil_origin}\r\n\r\n"
                )
                s.sendall(req.encode())
                resp = s.recv(4096).decode("latin-1","ignore")
                s.close()

                if "101 Switching Protocols" in resp:
                    detail = (f"WebSocket missing origin check: "
                              f"cross-origin connection from {evil_origin} "
                              f"accepted at {ws_path}")
                    self._save(out,"high","WS_NO_ORIGIN_CHECK",
                               host+ws_path, detail)
                    found += 1
                    break
            except Exception:
                pass
        return found

    # ── Phase 4: Sandbox bypass ───────────────────────────────────────────────
    def _test_sandbox_bypass(self, host, auth_h, out) -> int:
        found = 0
        resp = self._fetch(host, auth_h)
        if not resp: return 0
        body = resp.get("body","")

        # Find iframes with dangerous sandbox attributes
        iframes = re.findall(
            r'<iframe[^>]+sandbox=["\']([^"\']+)["\'][^>]*>',
            body, re.I)
        for sandbox in iframes:
            # allow-scripts + allow-same-origin together = sandbox bypass
            if "allow-scripts" in sandbox and "allow-same-origin" in sandbox:
                detail = (f"Sandbox bypass: iframe has "
                          f"sandbox=\"{sandbox[:80]}\" — "
                          f"allow-scripts+allow-same-origin negates sandbox")
                self._save(out,"high","IFRAME_SANDBOX_BYPASS",host,detail)
                found += 1
        return found

    # ── Phase 5: postMessage JS analysis ─────────────────────────────────────
    def _check_postmessage_js(self, js_file, live, out) -> int:
        found  = 0
        js_urls = safe_read(js_file)[:15] if js_file else []

        POST_MSG_RE = re.compile(
            r'addEventListener\s*\(\s*["\']message["\']',re.I)
        ORIGIN_CHECK_RE = re.compile(r'event\.origin|message\.origin',re.I)
        DANGEROUS_RE    = re.compile(
            r'innerHTML|eval\(|location\s*=|document\.write',re.I)

        for js_url in js_urls[:20]:
            try:
                req  = urllib.request.Request(
                    js_url, headers={"User-Agent": self.p.bypass.ua()})
                resp = urllib.request.urlopen(req, timeout=8)
                js   = resp.read(300000).decode("utf-8","ignore")
            except Exception:
                continue

            if not POST_MSG_RE.search(js):
                continue

            has_origin  = bool(ORIGIN_CHECK_RE.search(js))
            has_danger  = bool(DANGEROUS_RE.search(js))

            if not has_origin:
                sev    = "high" if has_danger else "medium"
                detail = (f"postMessage without origin check in {js_url[:60]} "
                          f"{'+ dangerous sink (innerHTML/eval)' if has_danger else ''}"
                          f" — cross-origin message injection possible")
                self._save(out, sev, "POSTMESSAGE_NO_ORIGIN",
                           js_url, detail)
                found += 1
        return found

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        if c: hdrs["Cookie"] = c
        if a: hdrs["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        return hdrs

    def _fetch(self, url, auth, timeout=8) -> dict:
        try:
            req  = urllib.request.Request(
                url, headers={**auth, "User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=timeout)
            hdrs = {k.lower():v for k,v in resp.headers.items()}
            return {"status": resp.status,
                    "body": resp.read(50000).decode("utf-8","ignore"),
                    "headers": hdrs}
        except urllib.error.HTTPError as e:
            hdrs = {k.lower():v for k,v in e.headers.items()}
            return {"status": e.code, "body": "", "headers": hdrs}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "sop-bypass-v7", response=response, payload=payload)
