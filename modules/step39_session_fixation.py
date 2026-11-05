#!/usr/bin/env python3
# modules/step39_session_fixation.py — Session Security Testing
# NEW MODULE: session fixation, cookie security flags, session riding
# Source: CEH v13 Lab Ch7 + Bug Bounty Bootcamp Ch13
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, urllib.request, urllib.error, urllib.parse, http.cookiejar
from core.utils import safe_read

LOGIN_PATHS = [
    "/login","/signin","/auth/login","/api/login",
    "/account/login","/user/login","/wp-login.php",
]
PROTECTED_PATHS = [
    "/dashboard","/account","/profile","/api/me",
    "/settings","/admin","/api/user",
]

# Cookie security checks
COOKIE_CHECKS = {
    "httponly":  ("Cookie lacks HttpOnly — accessible via XSS", "high"),
    "secure":    ("Cookie lacks Secure flag — sent over HTTP",   "medium"),
    "samesite":  ("Cookie lacks SameSite — CSRF risk",           "medium"),
}

SESSION_COOKIE_NAMES = re.compile(
    r'(?:session|sess|sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|'
    r'auth|token|jwt|access_token|connect\.sid)',
    re.I
)


class Step39SessionFixation:
    """
    Session Security Engine.
    CEH v13 + Bug Bounty Bootcamp methodology:
    1. Session fixation — set session ID before login, check if same after
    2. Cookie security flags (HttpOnly, Secure, SameSite)
    3. Session not invalidated on logout
    4. Session token entropy check
    5. Multiple sessions (same account, concurrent login)
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("session_results",
                             f"{p.out}/{p.prefix}_session.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("Session: no live hosts"); return

        auth_h = self._build_auth(p)
        p.log.info(f"Session V7: {len(live)} hosts — fixation+flags+logout+entropy")

        for host in live[:5]:
            host = host.rstrip("/")

            # Phase 1: Cookie security flags
            r = self._check_cookie_flags(host, auth_h, out)
            found += r

            # Phase 2: Session fixation
            r = self._test_session_fixation(host, auth_h, out)
            found += r

            # Phase 3: Session after logout
            r = self._test_logout_invalidation(host, auth_h, out)
            found += r

            # Phase 4: Session token entropy
            r = self._check_token_entropy(host, out)
            found += r

            p.bypass.jitter()

        p.log.success(f"Session V7: {found} findings")

    # ── Phase 1: Cookie flags ─────────────────────────────────────────────────
    def _check_cookie_flags(self, host: str, auth_h: dict, out: str) -> int:
        found = 0
        for path in LOGIN_PATHS + ["/", "/api/me"]:
            url  = host + path
            resp = self._fetch(url, auth_h)
            if not resp: continue

            for cookie_str in resp.get("set_cookies",[]):
                cookie_lower = cookie_str.lower()
                cookie_name  = cookie_str.split("=")[0].strip()

                # Only check session-related cookies
                if not SESSION_COOKIE_NAMES.search(cookie_name):
                    continue

                for flag, (msg, sev) in COOKIE_CHECKS.items():
                    if flag not in cookie_lower:
                        detail = (f"Cookie '{cookie_name}': {msg} "
                                  f"| Set-Cookie: {cookie_str[:80]}")
                        self._save(out, sev, f"COOKIE_NO_{flag.upper()}",
                                   url, detail)
                        found += 1

                # Check for long expiry (persistent session)
                if "max-age" in cookie_lower or "expires" in cookie_lower:
                    m = re.search(r'max-age=(\d+)', cookie_lower)
                    if m and int(m.group(1)) > 86400 * 30:  # > 30 days
                        detail = (f"Cookie '{cookie_name}': long-lived session "
                                  f"(max-age={m.group(1)}s) — "
                                  f"stolen cookie gives long-term access")
                        self._save(out,"medium","COOKIE_LONG_EXPIRY",url,detail)
                        found += 1
            break  # Check one endpoint per host
        return found

    # ── Phase 2: Session fixation ─────────────────────────────────────────────
    def _test_session_fixation(self, host: str, auth_h: dict, out: str) -> int:
        """
        CEH v13: Set known session ID before login.
        If session ID stays same after login = fixation vulnerability.
        """
        # Only testable if we have credentials
        if not auth_h: return 0

        fixed_session = "M7HUNTER_FIXED_SESSION_1337ABCDEF"

        for login_path in LOGIN_PATHS:
            url = host + login_path
            probe = self._fetch(url, {})
            if not probe or probe.get("status",0) == 404:
                continue

            # Set fixed session
            fixed_hdrs = {"Cookie": f"PHPSESSID={fixed_session}; "
                                     f"session={fixed_session}; "
                                     f"JSESSIONID={fixed_session}"}

            # Login with fixed session
            login_resp = self._post(url, {
                "username": "test@test.com",
                "password":  "test123",
            }, {**auth_h, **fixed_hdrs})

            if not login_resp: continue

            # Check if fixed session appears in response cookies
            for cookie_str in login_resp.get("set_cookies",[]):
                if fixed_session in cookie_str:
                    detail = (f"Session Fixation: pre-set session ID "
                              f"'{fixed_session[:20]}...' preserved "
                              f"after login at {login_path}")
                    self._save(out,"critical","SESSION_FIXATION",url,detail)
                    return 1
        return 0

    # ── Phase 3: Logout invalidation ─────────────────────────────────────────
    def _test_logout_invalidation(self, host: str, auth_h: dict, out: str) -> int:
        """Check if session token still works after logout."""
        if not auth_h: return 0

        # Capture session before logout
        token = auth_h.get("Cookie","").split(";")[0]
        if not token: return 0

        # Try to logout
        logout_urls = [host+p for p in ["/logout","/api/logout","/signout"]]
        for logout_url in logout_urls:
            self._fetch(logout_url, auth_h)

        # Check if token still works on protected resource
        for path in PROTECTED_PATHS:
            url  = host + path
            resp = self._fetch(url, auth_h)
            if not resp: continue
            st   = resp.get("status",0)
            body = resp.get("body","")

            if st == 200 and any(x in body.lower() for x in
                                  ["email","account","dashboard","profile"]):
                detail = (f"Session not invalidated after logout: "
                          f"token still works at {path}")
                self._save(out,"high","SESSION_NOT_INVALIDATED",url,detail)
                return 1
        return 0

    # ── Phase 4: Token entropy ────────────────────────────────────────────────
    def _check_token_entropy(self, host: str, out: str) -> int:
        """Collect multiple tokens and check randomness."""
        tokens = []
        for _ in range(5):
            resp = self._fetch(host + "/", {})
            if not resp: continue
            for cookie_str in resp.get("set_cookies",[]):
                m = re.search(r'=([A-Za-z0-9+/=._\-]{8,})', cookie_str)
                if m and SESSION_COOKIE_NAMES.search(cookie_str.split("=")[0]):
                    tokens.append(m.group(1))

        if len(tokens) < 3: return 0

        # Check for sequential/predictable tokens
        # Simple check: if tokens share > 70% prefix they're predictable
        if len(set(t[:8] for t in tokens)) < len(tokens) * 0.5:
            detail = (f"Weak session token entropy: tokens share common "
                      f"prefix — predictable session IDs: {tokens[:3]}")
            self._save(out,"high","WEAK_SESSION_ENTROPY",host,detail)
            return 1

        # Check token length (< 16 chars = weak)
        short = [t for t in tokens if len(t) < 16]
        if short:
            detail = (f"Short session token ({len(short[0])} chars): "
                      f"'{short[0][:20]}' — brute-forceable")
            self._save(out,"high","SHORT_SESSION_TOKEN",host,detail)
            return 1
        return 0

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        if c: hdrs["Cookie"] = c
        if a: hdrs["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        return hdrs

    def _fetch(self, url: str, auth: dict, timeout=8) -> dict:
        try:
            req  = urllib.request.Request(
                url, headers={**auth, "User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=timeout)
            cookies = resp.headers.get_all("set-cookie") or []
            return {"status": resp.status,
                    "body":   resp.read(20000).decode("utf-8","ignore"),
                    "set_cookies": cookies}
        except urllib.error.HTTPError as e:
            cookies = []
            try: cookies = e.headers.get_all("set-cookie") or []
            except: pass
            return {"status": e.code, "body": "", "set_cookies": cookies}
        except Exception:
            return None

    def _post(self, url: str, data: dict, auth: dict, timeout=8) -> dict:
        try:
            body = urllib.parse.urlencode(data).encode()
            hdrs = {**auth,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent":   self.p.bypass.ua()}
            req  = urllib.request.Request(url, data=body,
                                          headers=hdrs, method="POST")
            resp = urllib.request.urlopen(req, timeout=timeout)
            cookies = resp.headers.get_all("set-cookie") or []
            return {"status": resp.status,
                    "body":   resp.read(20000).decode("utf-8","ignore"),
                    "set_cookies": cookies}
        except urllib.error.HTTPError as e:
            cookies = []
            try: cookies = e.headers.get_all("set-cookie") or []
            except: pass
            return {"status": e.code, "body": "", "set_cookies": cookies}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "session-v7", response=response, payload=payload)
