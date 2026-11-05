#!/usr/bin/env python3
# modules/step31_deserialization.py — Insecure Deserialization V7
# NEW MODULE: PHP, Java, Python, Node.js deserialization attacks
# Source: Bug Bounty Bootcamp Ch13 — deserialization methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, base64, hashlib, urllib.request, urllib.error, urllib.parse
from core.utils import safe_read

# ── Deserialization signatures in cookies/headers ─────────────────────────────
DESER_SIGNATURES = [
    # PHP serialized objects
    (re.compile(r'^O:\d+:"'),                          "php",    "PHP object serialization"),
    (re.compile(r'^a:\d+:\{'),                         "php",    "PHP array serialization"),
    (re.compile(r's:\d+:"'),                           "php",    "PHP string serialization"),
    # Java serialized (magic bytes rO0AB in base64)
    (re.compile(r'^rO0AB'),                            "java",   "Java serialized object (base64)"),
    (re.compile(r'^\xac\xed\x00\x05'),                "java",   "Java serialized object (binary)"),
    (re.compile(r'^aced0005'),                         "java",   "Java serialized object (hex)"),
    # Python pickle (base64 encoded)
    (re.compile(r'gASV'),                              "python", "Python pickle (base64)"),
    # Ruby Marshal
    (re.compile(r'^\x04\x08'),                         "ruby",   "Ruby Marshal object"),
    # .NET ViewState
    (re.compile(r'^\/wE'),                             "dotnet", ".NET ViewState (base64)"),
    (re.compile(r'__VIEWSTATE'),                       "dotnet", ".NET ViewState parameter"),
    # Node.js serialized
    (re.compile(r'"_$\.func":true'),                  "nodejs", "node-serialize object"),
    # YAML deserialization
    (re.compile(r'!!python/object'),                   "yaml",   "Python YAML deserialization"),
    (re.compile(r'!!java\.lang'),                      "yaml",   "Java YAML deserialization"),
]

# ── PHP deserialization payloads ──────────────────────────────────────────────
PHP_PAYLOADS = [
    # Object with magic method __destruct or __wakeup
    'O:8:"stdClass":1:{s:4:"test";s:3:"m7h";}',
    'a:1:{s:7:"m7check";s:2:"ok";}',
    # Detect gadget chains via class names in cookies
    'O:4:"User":1:{s:8:"username";s:5:"admin";}',
]

# ── Java deserialization YSOSERIAL payloads (detection only) ─────────────────
# We detect the magic bytes and report — no actual exploitation
JAVA_MAGIC = b'\xac\xed\x00\x05'
JAVA_MAGIC_B64 = "rO0AB"

# ── Node.js serialize payload (code exec) ────────────────────────────────────
NODEJS_PAYLOAD = '{"rce":"_$$ND_FUNC$$_function(){return 1+1}()"}'

# ── Python pickle detection payload ──────────────────────────────────────────
PICKLE_MARKER = "gASVKAAAAAAAAACMCG0naHVudGVylIwHbTd0ZXN0lIaUhpSFlFKULg=="

# ── Endpoints likely to use deserialization ───────────────────────────────────
DESER_PATHS = [
    "/","/login","/api/session","/api/auth",
    "/api/user","/api/profile","/dashboard",
    "/api/v1/session","/cart","/api/cart",
    "/api/deserialize","/api/data","/api/object",
]

DESER_HEADERS = ["Cookie","X-Auth-Token","Authorization","X-Session","X-Data"]
DESER_PARAMS  = ["data","object","payload","token","session","state",
                 "viewstate","__VIEWSTATE","JSESSIONID"]

# ── Indicators of successful deserialization ──────────────────────────────────
SUCCESS_INDICATORS = [
    "unserialize()",
    "ClassNotFoundException",
    "java.io.ObjectInputStream",
    "pickle.loads",
    "Marshal.load",
    "yaml.load",
    "Deserialization",
    "500",  # Error = likely triggered deserialization
]


class Step31Deserialization:
    """
    Insecure Deserialization scanner.
    Bug Bounty Bootcamp Ch13:
    1. Detect serialized data in cookies/params/headers
    2. Identify the language/format
    3. Test for deserialization by sending modified objects
    4. Look for errors that confirm deserialization is happening
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("deser_results",
                             f"{p.out}/{p.prefix}_deserialization.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        urls  = safe_read(p.files.get("urls",""))
        found = 0

        if not live:
            p.log.warn("Deserialization: no live hosts"); return

        p.log.info(f"Deserialization V7: PHP + Java + Python + Node.js + .NET")
        auth_h = self._build_auth(p)

        # Phase 1: Detect serialized data in existing cookies/params
        found += self._detect_in_session(live, auth_h, out)

        # Phase 2: Test endpoints with serialized payloads
        for host in live[:5]:
            host = host.rstrip("/")
            found += self._probe_endpoints(host, auth_h, out)
            p.bypass.jitter()

        # Phase 3: Check crawled URLs for serialized params
        found += self._check_url_params(urls[:100], auth_h, out)

        p.log.success(f"Deserialization V7: {found} findings")

    # ── Phase 1: Detect in cookies ────────────────────────────────────────────
    def _detect_in_session(self, live: list, auth_h: dict, out: str) -> int:
        """
        BB Bootcamp Ch13: first check if cookies already contain
        serialized data — this is the most reliable detection method.
        """
        found = 0

        # Check existing cookie values
        cookie = auth_h.get("Cookie","")
        if cookie:
            for part in cookie.split(";"):
                if "=" in part:
                    name, val = part.strip().split("=",1)
                    lang, detail = self._identify_serialization(val.strip())
                    if lang:
                        detail_str = (f"Serialized {lang} object in cookie "
                                      f"'{name.strip()}' — {detail}")
                        self._save(out,"high","DESER_COOKIE_FOUND",
                                   live[0] if live else "", detail_str)
                        found += 1

        # Check each live host's Set-Cookie headers
        for host in live[:5]:
            try:
                req  = urllib.request.Request(
                    host, headers={"User-Agent": self.p.bypass.ua()})
                resp = urllib.request.urlopen(req, timeout=8)
                for key, val in resp.headers.items():
                    if "set-cookie" in key.lower():
                        for part in val.split(";"):
                            if "=" in part:
                                n, v = part.strip().split("=",1)
                                lang, det = self._identify_serialization(v.strip())
                                if lang:
                                    detail_str = (
                                        f"Serialized {lang} in Set-Cookie "
                                        f"'{n.strip()}' on {host} — {det}")
                                    self._save(out,"high","DESER_SETCOOKIE",
                                               host, detail_str)
                                    found += 1
            except Exception:
                pass
        return found

    # ── Phase 2: Probe endpoints ──────────────────────────────────────────────
    def _probe_endpoints(self, host: str, auth_h: dict, out: str) -> int:
        """Send serialized payloads to common endpoints, detect errors."""
        found = 0
        test_payloads = [
            ("php",    PHP_PAYLOADS[0], "application/x-php-serialized"),
            ("java",   JAVA_MAGIC_B64 + "AAAA", "application/x-java-serialized"),
            ("python", PICKLE_MARKER, "application/x-python-pickle"),
            ("nodejs", NODEJS_PAYLOAD, "application/json"),
        ]

        for path in DESER_PATHS[:8]:
            url = host + path

            # Baseline
            baseline = self._fetch(url, auth_h)
            if not baseline or baseline.get("status",0) == 404:
                continue

            for lang, payload, ct in test_payloads[:3]:
                # Try as POST body
                resp = self._post(url, payload, ct, auth_h)
                if not resp: continue

                body   = resp.get("body","")
                status = resp.get("status",0)

                # Errors in response = deserialization triggered
                if self._has_deser_error(body, status):
                    detail = (f"Deserialization triggered: lang={lang} "
                              f"path={path} status={status}")
                    self._save(out,"critical","DESER_TRIGGERED",url,detail)
                    found += 1

        return found

    # ── Phase 3: URL params ───────────────────────────────────────────────────
    def _check_url_params(self, urls: list, auth_h: dict, out: str) -> int:
        found = 0
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query)
                for param, values in qs.items():
                    if param.lower() not in DESER_PARAMS:
                        continue
                    for val in values:
                        lang, det = self._identify_serialization(val)
                        if lang:
                            detail = (f"Serialized {lang} in URL param "
                                      f"'{param}' — {det}")
                            self._save(out,"high","DESER_URL_PARAM",url,detail)
                            found += 1
            except Exception:
                pass
        return found

    # ── Identification ────────────────────────────────────────────────────────
    def _identify_serialization(self, value: str) -> tuple:
        """Return (language, description) or ("","") if not serialized."""
        # Try base64 decode first
        try:
            decoded = base64.b64decode(value + "==").decode("latin-1")
        except Exception:
            decoded = ""

        check_vals = [value, decoded]

        for check in check_vals:
            for pattern, lang, desc in DESER_SIGNATURES:
                if isinstance(pattern.pattern, str):
                    if pattern.search(check):
                        return lang, desc
        return "", ""

    def _has_deser_error(self, body: str, status: int) -> bool:
        if status in (500, 502, 503):
            if any(s in body for s in SUCCESS_INDICATORS):
                return True
        return any(s in body for s in [
            "unserialize failed",
            "java.lang.ClassCastException",
            "pickle.UnpicklingError",
            "invalid serialization",
        ])

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
                    "body": resp.read(20000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(2000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None

    def _post(self, url, payload, ct, auth, timeout=8) -> dict:
        try:
            data = payload.encode() if isinstance(payload, str) else payload
            hdrs = {**auth, "Content-Type": ct,
                    "User-Agent": self.p.bypass.ua()}
            req  = urllib.request.Request(url, data=data,
                                          headers=hdrs, method="POST")
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body": resp.read(20000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(2000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "deser-v7", response=response, payload=payload)
