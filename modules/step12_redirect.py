#!/usr/bin/env python3
# modules/step12_redirect.py — Open Redirect + CRLF Injection
# MilkyWay Intelligence | Author: Sharlix

import re, urllib.parse
from core.utils import safe_read, count_lines
from core.http_client import sync_get

REDIRECT_PARAMS = [
    "url","uri","link","next","goto","redirect","return","returnurl",
    "returnto","dest","destination","target","redir","r","u","ref",
    "referer","callback","forward","location","back","continue","path",
    "file","src","source","page","go","jump","out","view","site","host",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "///evil.com",
    "\\\\evil.com",
    "https://evil.com%2F@legit.com",
    "https://legit.com.evil.com",
    "javascript:alert(1)",
    "%0d%0aLocation:%20https://evil.com",
    "\r\nLocation: https://evil.com",
    "%0aLocation:%20https://evil.com",
]

CRLF_PAYLOADS = [
    "%0d%0aX-Injected: M7Hunter",
    "%0aX-Injected:%20M7Hunter",
    "\r\nX-Injected: M7Hunter",
    "%0d%0aSet-Cookie:%20m7=injected",
    "%0d%0a%0d%0a<script>alert(1)</script>",
]


class Step12Redirect:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["redirect_results"]
        urls  = safe_read(p.files.get("urls", ""))
        live  = safe_read(p.files.get("fmt_url", ""))[:10]
        found = 0

        if not live:
            p.log.warn("Redirect: no live hosts"); return

        p.log.info(f"Open Redirect + CRLF testing")
        auth_h = {}
        if getattr(p.args, "cookie", None):
            auth_h["Cookie"] = p.args.cookie

        # Test discovered URLs with redirect params
        redirect_urls = [u for u in urls if any(f"?{rp}=" in u.lower() or
                          f"&{rp}=" in u.lower() for rp in REDIRECT_PARAMS)][:30]

        for url in redirect_urls:
            for payload in REDIRECT_PAYLOADS[:6]:
                result = self._test_redirect(url, payload, auth_h)
                if result:
                    sev, detail = result
                    with open(out, "a") as f:
                        f.write(f"REDIRECT: {url} | {detail}\n")
                    p.add_finding(sev, "OPEN_REDIRECT", url, detail, "redirect-engine")
                    found += 1
                    break

        # Test common redirect paths on each host
        for host in live:
            host = host.rstrip("/")
            for path in ["/redirect", "/out", "/go", "/link", "/forward", "/exit"]:
                for param in REDIRECT_PARAMS[:5]:
                    url = f"{host}{path}?{param}=https://evil.com"
                    result = self._test_redirect(url, "https://evil.com", auth_h)
                    if result:
                        sev, detail = result
                        with open(out, "a") as f:
                            f.write(f"REDIRECT: {url} | {detail}\n")
                        p.add_finding(sev, "OPEN_REDIRECT", url, detail, "redirect-engine")
                        found += 1
                        break

            # CRLF injection test
            for crlf in CRLF_PAYLOADS[:4]:
                test_url = f"{host}/?x={crlf}"
                resp = sync_get(test_url, headers=auth_h, timeout=8, follow_redirects=False)
                if resp:
                    hdrs = str(resp.get("headers", {})).lower()
                    if "x-injected" in hdrs or "m7=injected" in hdrs:
                        detail = f"CRLF injection in response headers: {crlf[:40]}"
                        with open(out, "a") as f:
                            f.write(f"CRLF: {test_url} | {detail}\n")
                        p.add_finding("high", "CRLF_INJECTION", test_url, detail, "crlf-engine")
                        found += 1
                        break

        p.log.success(f"Redirect/CRLF: {found} findings")

    def _test_redirect(self, url: str, payload: str, auth_h: dict) -> tuple:
        try:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return None

        for param in list(qs.keys()):
            if param.lower() not in REDIRECT_PARAMS:
                continue
            qs_mod = dict(qs)
            qs_mod[param] = [payload]
            new_qs  = urllib.parse.urlencode(qs_mod, doseq=True)
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=new_qs))

            resp = sync_get(test_url, headers=auth_h, timeout=8, follow_redirects=False)
            if not resp:
                continue

            status   = resp.get("status", 0)
            location = resp.get("location", "") or resp.get("headers", {}).get("location", "")

            if status in (301, 302, 303, 307, 308) and location:
                if "evil.com" in location or payload in location:
                    detail = (f"Open redirect via param '{param}': "
                              f"redirects to {location[:60]}")
                    sev = "critical" if "javascript:" in payload else "medium"
                    return (sev, detail)

        return None
