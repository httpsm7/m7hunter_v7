#!/usr/bin/env python3
# modules/step28_clickjacking.py — Clickjacking & UI Redressing Detection
# Source: Bug Bounty Bootcamp Ch8, CEH Ch9 — Clickjacking methodology
# Completely new module — was missing from M7Hunter
# MilkyWay Intelligence | Author: Sharlix + M7AI

import urllib.request, urllib.error
from core.utils import safe_read

# Pages likely to be sensitive and clickjack-able (high-impact targets)
SENSITIVE_PATHS = [
    "/","/dashboard","/account","/settings","/profile",
    "/admin","/transfer","/payment","/checkout","/delete",
    "/api/user/delete","/password/change","/email/change",
    "/account/delete","/settings/privacy","/oauth/authorize",
    "/auth/login","/logout","/withdraw","/send","/confirm",
]

# X-Frame-Options bypass check values — some servers are misconfigured
XFO_BYPASS_VARIANTS = [
    "ALLOWALL",       # nonstandard — means allow all
    "allow-from *",   # allow-from is deprecated, browsers ignore it → still frameable
]

# CSP frame-ancestors overrides that are too permissive
PERMISSIVE_FRAME_ANCESTORS = [
    "*",
    "http:",
    "https:",
    "'unsafe-inline'",
]


class Step28Clickjacking:
    """
    Clickjacking detection engine.
    Bug Bounty Bootcamp methodology:
    1. Check X-Frame-Options header (DENY / SAMEORIGIN = protected)
    2. Check Content-Security-Policy frame-ancestors directive
    3. If neither present → VULNERABLE (can be framed by attacker)
    4. If allow-from is used → effectively vulnerable in modern browsers
    5. Build PoC iframe to confirm frameability
    """

    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log

    def run(self):
        p     = self.p
        out   = p.files.get("clickjacking_results",
                             f"{p.out}/{p.prefix}_clickjacking.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:20]
        found = 0

        if not live:
            self.log.warn("Clickjacking: no live hosts"); return

        self.log.info(f"Clickjacking: checking {len(live)} hosts × {len(SENSITIVE_PATHS)} paths")

        for host in live:
            host = host.rstrip("/")

            for path in SENSITIVE_PATHS[:12]:
                url    = host + path
                result = self._check_clickjacking(url)
                if not result:
                    continue

                sev, detail = result
                poc         = self._generate_poc(url)

                with open(out, "a") as f:
                    f.write(f"CLICKJACKING: {url} | {detail}\n")

                p.add_finding(
                    severity  = sev,
                    vuln_type = "CLICKJACKING",
                    url       = url,
                    detail    = detail,
                    tool      = "clickjacking-engine",
                    response  = poc,
                )
                found += 1
                break  # One finding per host (no need to report every path)

            p.bypass.jitter()

        self.log.success(f"Clickjacking: {found} vulnerable pages found")

    def _check_clickjacking(self, url: str):
        """
        Returns (severity, detail) if vulnerable, None if protected.
        Bug Bounty Bootcamp logic:
        - No XFO + No CSP frame-ancestors → VULNERABLE (high)
        - allow-from directive → vulnerable in modern browsers (medium)
        - CSP frame-ancestors * or http: → VULNERABLE (high)
        """
        try:
            req  = urllib.request.Request(url, headers={
                "User-Agent": self.p.bypass.ua(),
            })
            resp = urllib.request.urlopen(req, timeout=8)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            hdrs = {k.lower(): v for k, v in e.headers.items()}
            if e.code not in (200, 301, 302, 403):
                return None
        except Exception:
            return None

        xfo  = hdrs.get("x-frame-options","").strip().upper()
        csp  = hdrs.get("content-security-policy","").lower()

        # ── CSP frame-ancestors check ─────────────────────────────────────
        if "frame-ancestors" in csp:
            directive = ""
            for part in csp.split(";"):
                if "frame-ancestors" in part:
                    directive = part.strip()
                    break
            # Permissive frame-ancestors
            for bad in PERMISSIVE_FRAME_ANCESTORS:
                if bad in directive:
                    return ("high",
                        f"CSP frame-ancestors is permissive: '{directive}' — can be framed")
            # Safe frame-ancestors — protected
            if "'none'" in directive or "'self'" in directive:
                return None

        # ── X-Frame-Options check ─────────────────────────────────────────
        if xfo in ("DENY", "SAMEORIGIN"):
            return None  # Protected

        if xfo.startswith("ALLOW-FROM"):
            return ("medium",
                "X-Frame-Options: ALLOW-FROM is deprecated — modern browsers "
                "ignore it, page is still frameable (clickjacking possible)")

        # ── No protection at all ──────────────────────────────────────────
        if not xfo and "frame-ancestors" not in csp:
            return ("high",
                "No X-Frame-Options and no CSP frame-ancestors — "
                "page can be framed by any attacker site (clickjacking)")

        return None

    def _generate_poc(self, url: str) -> str:
        """
        Generate clickjacking PoC HTML.
        Bug Bounty Bootcamp format: minimal PoC that demonstrates framing.
        """
        return f"""<!-- M7Hunter Clickjacking PoC -->
<!-- Save as clickjacking_poc.html and open in browser to confirm -->
<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC - M7Hunter</title>
<style>
  iframe {{
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.5; z-index: 2;
  }}
  button {{
    position: absolute; top: 300px; left: 400px;
    z-index: 1; width: 200px; height: 40px;
    font-size: 16px; cursor: pointer;
  }}
</style>
</head>
<body>
  <button>Click to Win a Prize!</button>
  <iframe src="{url}" sandbox="allow-scripts allow-forms allow-same-origin"></iframe>
  <p style="margin-top:400px">If the target page loads above, it is vulnerable to Clickjacking.</p>
</body>
</html>"""
