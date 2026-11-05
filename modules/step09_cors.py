#!/usr/bin/env python3
# modules/step09_cors.py — CORS Misconfiguration Testing V7 (UPGRADED)
# Added: postMessage testing, JSONP detection, credentialed CORS
# Source: Bug Bounty Bootcamp Ch8 — CORS full methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, json, urllib.request, urllib.error, urllib.parse
from core.utils import safe_read
from core.http_client import sync_get

# Evil origins to test (Bug Bounty Bootcamp methodology)
EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",                          # null origin bypass
    "https://{target}.evil.com",     # subdomain of target (wildcard bypass)
    "https://evil{target}",          # prefix bypass
    "https://{target}evil.com",      # suffix bypass
]

CORS_ENDPOINTS = [
    "/api/user","/api/me","/api/profile","/api/account","/api/admin",
    "/api/v1/user","/api/v2/user","/api/v1/me","/graphql",
    "/api/settings","/api/orders","/api/data","/api/whoami",
    "/api/config","/api/keys","/api/internal","/api/secret",
]

# JSONP callback injection patterns
JSONP_PATTERNS = [
    re.compile(r'callback\s*=\s*\w+', re.I),
    re.compile(r'jsonp\s*=\s*\w+', re.I),
    re.compile(r'cb\s*=\s*\w+', re.I),
]
JSONP_ENDPOINTS = [
    "/api/user?callback=test","/api/me?callback=test",
    "/api/profile?cb=test","/api/data?jsonp=test",
]
JSONP_PAYLOAD = "m7hunter_xss_test"

# postMessage insecure patterns
POST_MSG_PATTERNS = [
    re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.I),
    re.compile(r'\.postMessage\s*\(', re.I),
    re.compile(r'event\.origin', re.I),
    re.compile(r'event\.data', re.I),
    re.compile(r'window\.on message', re.I),
]
POST_MSG_MISSING_ORIGIN_CHECK = re.compile(
    r'addEventListener\s*\(\s*["\']message["\'][^)]+\)[^{]*\{(?!.*event\.origin)',
    re.I | re.DOTALL
)


class Step09Cors:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["cors_results"]
        live  = p.files.get("fmt_url","")
        urls  = p.files.get("urls","")
        js_f  = p.files.get("js_files","")
        found = 0

        hosts = safe_read(live)[:20]
        if not hosts:
            p.log.warn("CORS: no live hosts"); return

        p.log.info(f"CORS V7: testing {len(hosts)} hosts — CORS + JSONP + postMessage")
        auth_h = {}
        c = getattr(p.args,'cookie',None) or getattr(p.args,'session',None)
        a = getattr(p.args,'authorization',None) or getattr(p.args,'auth',None)
        j = getattr(p.args,'jwt',None) or getattr(p.args,'_jwt_token',None)
        if c: auth_h["Cookie"] = c
        if a: auth_h["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        if j and "Authorization" not in auth_h:
            auth_h["Authorization"] = f"Bearer {j}" 

        for host in hosts:
            host    = host.rstrip("/")
            domain  = urllib.parse.urlparse(host).netloc.split(":")[0]

            # Build targeted evil origins for this host
            evil_origins = [
                "https://evil.com",
                "null",
                f"https://{domain}.evil.com",
                f"https://evil-{domain}.com",
                f"https://{domain}evil.com",
                f"https://not{domain}.com",
            ]

            test_urls = [host + ep for ep in CORS_ENDPOINTS]
            disc = [u for u in safe_read(urls) if domain in u][:8]
            test_urls.extend(disc)

            for url in test_urls[:20]:
                # ── Test 1: Basic CORS misconfiguration ─────────────────
                for origin in evil_origins:
                    result = self._test_cors(url, origin, auth_h)
                    if result:
                        sev, detail = result
                        with open(out,"a") as f:
                            f.write(f"CORS: {url} | {detail}\n")
                        p.add_finding(sev,"CORS_MISCONFIG",url,detail,"cors-engine-v7")
                        found += 1
                        break

                # ── Test 2: Credentialed CORS (most impactful) ──────────
                result = self._test_credentialed_cors(url, domain, auth_h)
                if result:
                    sev, detail = result
                    with open(out,"a") as f:
                        f.write(f"CORS_CRED: {url} | {detail}\n")
                    p.add_finding(sev,"CORS_CREDENTIALED",url,detail,"cors-engine-v7")
                    found += 1

            # ── Test 3: JSONP injection (Bug Bounty Bootcamp Ch8) ──────
            for ep in JSONP_ENDPOINTS:
                result = self._test_jsonp(host + ep)
                if result:
                    sev, detail = result
                    with open(out,"a") as f:
                        f.write(f"JSONP: {host+ep} | {detail}\n")
                    p.add_finding(sev,"JSONP_INJECTION",host+ep,detail,"cors-engine-v7")
                    found += 1
                    break

            # ── Test 4: postMessage without origin check (JS analysis) ─
            if js_f:
                result = self._test_postmessage(host, js_f)
                if result:
                    sev, detail = result
                    with open(out,"a") as f:
                        f.write(f"POSTMESSAGE: {host} | {detail}\n")
                    p.add_finding(sev,"POSTMESSAGE_NO_ORIGIN",host,detail,"cors-engine-v7")
                    found += 1

            p.bypass.jitter()

        p.log.success(f"CORS V7: {found} issues found")

    # ── Test 1: Basic CORS ────────────────────────────────────────────────────
    def _test_cors(self, url: str, origin: str, extra_headers: dict):
        hdrs = {"Origin": origin, "User-Agent": self.p.bypass.ua()}
        hdrs.update(extra_headers)
        resp = self._fetch(url, hdrs)
        if not resp: return None
        acao = resp.get("headers",{}).get("access-control-allow-origin","")
        acac = resp.get("headers",{}).get("access-control-allow-credentials","")
        if not acao: return None

        if acao == "*" and acac.lower() == "true":
            return ("high",
                f"CORS wildcard + credentials: ACAO=* with ACAC:true — "
                f"any origin can read authenticated responses")

        if acao == origin and origin not in ("", "null") and "evil" in origin:
            msg = (f"CORS reflects evil origin: ACAO={acao[:60]} | "
                   f"ACAC={acac} — attacker origin accepted")
            sev = "high" if acac.lower() == "true" else "medium"
            return (sev, msg)

        if acao == "null" or acao == "*":
            return ("medium",
                f"CORS permissive: ACAO={acao} — any sandboxed/cross-origin "
                f"request can read response")
        return None

    # ── Test 2: Credentialed CORS (highest impact) ────────────────────────────
    def _test_credentialed_cors(self, url: str, domain: str, extra_headers: dict):
        """
        Bug Bounty Bootcamp: CORS + credentials = account takeover.
        If ACAO reflects origin AND ACAC=true → attacker JS can read cookies.
        """
        evil = f"https://{domain}.attacker.com"
        hdrs = {
            "Origin": evil,
            "User-Agent": self.p.bypass.ua(),
        }
        hdrs.update(extra_headers)
        resp = self._fetch(url, hdrs)
        if not resp: return None

        acao = resp.get("headers",{}).get("access-control-allow-origin","")
        acac = resp.get("headers",{}).get("access-control-allow-credentials","").lower()
        vary = resp.get("headers",{}).get("vary","").lower()

        if acao == evil and acac == "true":
            return ("critical",
                f"CREDENTIALED CORS: ACAO reflects '{evil}' with ACAC=true — "
                f"attacker can steal authenticated user data (account takeover possible)")

        if acao and acac == "true" and "origin" not in vary:
            return ("high",
                f"CORS + credentials without Vary: Origin — cache poisoning possible: "
                f"ACAO={acao[:50]}, ACAC=true")
        return None

    # ── Test 3: JSONP injection ───────────────────────────────────────────────
    def _test_jsonp(self, url: str):
        """
        Bug Bounty Bootcamp Ch8: JSONP callback injection.
        If callback param is reflected in response → XSS or data theft.
        """
        # Replace test callback with XSS payload
        xss_cb  = f"m7hunter_alert_1"
        test_url = re.sub(r'(callback|jsonp|cb)=\w+',
                          f'\\1={xss_cb}', url, flags=re.I)
        resp = self._fetch(test_url, {"User-Agent": self.p.bypass.ua()})
        if not resp: return None

        body = resp.get("body","")
        ct   = resp.get("headers",{}).get("content-type","")

        if xss_cb in body:
            if "javascript" in ct or "json" in ct:
                return ("high",
                    f"JSONP injection: callback '{xss_cb}' reflected in "
                    f"JavaScript response — XSS or cross-domain data theft possible")
        return None

    # ── Test 4: postMessage analysis ─────────────────────────────────────────
    def _test_postmessage(self, host: str, js_file: str):
        """
        Bug Bounty Bootcamp Ch8: postMessage without origin check.
        JS reads event.data without checking event.origin → XSS from any origin.
        """
        js_urls = safe_read(js_file)[:10]
        for js_url in js_urls:
            if not host.split("//")[-1].split("/")[0] in js_url:
                continue
            try:
                req  = urllib.request.Request(
                    js_url, headers={"User-Agent": self.p.bypass.ua()})
                resp = urllib.request.urlopen(req, timeout=8)
                js   = resp.read(200000).decode("utf-8",errors="ignore")
            except Exception:
                continue

            has_listener = any(p.search(js) for p in POST_MSG_PATTERNS[:2])
            if not has_listener:
                continue

            has_origin_check = bool(re.search(r'event\.origin', js))
            has_data_use     = bool(re.search(
                r'(innerHTML|eval|document\.write|location)', js, re.I))

            if not has_origin_check and has_data_use:
                return ("high",
                    f"postMessage listener without event.origin check in {js_url[:80]} — "
                    f"attacker can send arbitrary messages from any origin → XSS")

            if not has_origin_check:
                return ("medium",
                    f"postMessage listener without event.origin check in {js_url[:80]} — "
                    f"no origin validation on incoming messages")
        return None

    def _fetch(self, url: str, headers: dict = None) -> dict:
        try:
            req  = urllib.request.Request(url, headers=headers or {})
            resp = urllib.request.urlopen(req, timeout=8)
            hdrs = {k.lower(): v for k,v in resp.headers.items()}
            body = resp.read(20000).decode("utf-8",errors="ignore")
            return {"status": resp.status, "body": body, "headers": hdrs}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": "",
                    "headers": {k.lower():v for k,v in e.headers.items()}}
        except Exception:
            return None
