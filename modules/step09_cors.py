import os
#!/usr/bin/env python3
# modules/step09_cors.py — CORS Misconfiguration (Fixed)
# Fix: [:20]→100 hosts, better origin detection, preflight test
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import re
from core.utils import safe_read, count_lines
from core.http_client import sync_get
from core.error_handler import get_handler

CORS_ENDPOINTS = [
    "/api/user", "/api/me", "/api/profile", "/api/account",
    "/api/v1/user", "/api/v2/user", "/graphql", "/api/settings",
    "/api/orders", "/api/data", "/api/config", "/api/admin",
    "/v1/user", "/v2/profile", "/api/token", "/api/key",
]



def _get_live_hosts(p, limit=100):
    """Returns live hosts - ALWAYS includes main target as fallback."""
    tgt = p.target.strip()
    if not tgt.startswith("http"):
        tgt = "https://" + tgt

    hosts = []
    seen  = set()

    for key in ("fmt_url", "live_hosts", "resolved"):
        src = p.files.get(key, "")
        if not src or not os.path.isfile(src):
            continue
        from core.utils import safe_read
        for line in safe_read(src):
            line = line.strip()
            if not line:
                continue
            if not line.startswith("http"):
                line = "https://" + line
            if line not in seen:
                seen.add(line)
                hosts.append(line)
        if hosts:
            break

    # GUARANTEED: always include main target
    if tgt not in seen:
        hosts.insert(0, tgt)

    return hosts[:limit]


class Step09Cors:
    def __init__(self, pipeline): self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("cors_results", "/tmp/m7_cors.txt")
        found = 0

        # Get live hosts with fallback chain
        hosts = []
        for key in ("fmt_url", "live_hosts", "resolved"):
            src = p.files.get(key, "")
            if src:
                hosts = safe_read(src)[:100]
            if hosts: break

        if not hosts:
            p.log.warn("CORS: no live hosts"); return

        p.log.info(f"CORS: testing {len(hosts)} hosts")
        auth_h = {}
        if getattr(p.args,"cookie",None): auth_h["Cookie"] = p.args.cookie
        if getattr(p.args,"authorization",None):
            auth_h["Authorization"] = p.args.authorization

        for host in hosts:
            host = host.strip().rstrip("/")
            if not host.startswith("http"):
                host = "https://" + host

            domain = host.split("//")[-1].split("/")[0]

            # Evil origins — static + domain-based
            evil_origins = [
                "https://evil.com",
                "https://attacker.com",
                f"https://evil.{domain}",
                f"https://{domain}.evil.com",
                f"https://not{domain}",
                "null",
                "https://m7.evil.com",
            ]

            # Test discovered URLs + common endpoints
            disc = [u for u in safe_read(p.files.get("urls",""))
                    if domain in u][:30]
            test_urls = list(set(
                [host + ep for ep in CORS_ENDPOINTS] + disc
            ))[:60]

            for url in test_urls:
                for origin in evil_origins:
                    try:
                        r = self._test_cors(url, origin, auth_h)
                        if r:
                            sev, detail = r
                            try:
                                with open(out,"a") as f:
                                    f.write(f"CORS: {url} | {detail}\n")
                            except Exception:
                                pass
                            p.add_finding(sev, "CORS_MISCONFIG", url,
                                         detail, "cors-engine")
                            found += 1
                    except Exception as e:
                        get_handler().capture("step09_cors", e, url)

        p.log.success(f"CORS: {found} findings")

    def _test_cors(self, url, origin, auth_h):
        try:
            h = dict(auth_h)
            h["Origin"] = origin

            r = sync_get(url, headers=h, timeout=8)
            if not r: return None

            hdrs   = r.get("headers", {}) or {}
            acao   = hdrs.get("access-control-allow-origin","") or \
                     hdrs.get("Access-Control-Allow-Origin","")
            acac   = hdrs.get("access-control-allow-credentials","") or \
                     hdrs.get("Access-Control-Allow-Credentials","")
            acam   = hdrs.get("access-control-allow-methods","") or \
                     hdrs.get("Access-Control-Allow-Methods","")

            creds  = "true" in acac.lower()

            # Wildcard CORS
            if acao == "*":
                return ("medium",
                        f"Wildcard CORS — ACAO=* (methods={acam})")

            # Origin reflected exactly
            if acao and origin.lower() in acao.lower():
                if creds:
                    return ("high",
                            f"CORS w/ credentials — Origin={origin} "
                            f"reflected, ACAC=true")
                return ("medium",
                        f"CORS reflection — Origin={origin} → "
                        f"ACAO={acao}")

            # Null origin accepted
            if origin == "null" and acao.lower() == "null":
                return ("high",
                        f"Null origin accepted with ACAO=null")

        except Exception as e:
            get_handler().capture("step09_cors", e, "_test_cors")
        return None
