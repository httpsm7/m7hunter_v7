#!/usr/bin/env python3
# modules/step21_host_header.py — Host Header + Origin Injection (Fixed)
# Fix: [:10]→100, strict indicators→flexible, add Origin injection
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import os, re
from core.utils import safe_read, count_lines
from core.http_client import sync_get
from core.error_handler import get_handler

EVIL_HOST = "m7evil.com"

HEADERS_TO_TEST = [
    "Host", "X-Forwarded-Host", "X-Host",
    "X-Forwarded-Server", "X-HTTP-Host-Override",
    "Forwarded", "X-Original-Host",
    "X-Rewrite-URL", "X-Override-URL",
]

ORIGIN_HEADERS = [
    "Origin", "Access-Control-Request-Headers",
    "X-Origin", "X-Forwarded-Origin",
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


class Step21HostHeader:
    def __init__(self, pipeline): self.p = pipeline

    def run(self):
        p      = self.p
        out    = p.files.get("host_header_results", "/tmp/m7_hh.txt")
        # fmt_url → live_hosts → resolved fallback
        for key in ("fmt_url", "live_hosts", "resolved"):
            src = p.files.get(key, "")
            if src and os.path.isfile(src) and count_lines(src) > 0:
                live = safe_read(src)[:100]
                break
        else:
            p.log.warn("Host Header: no live hosts found"); return

        p.log.info(f"Host Header + Origin Injection: {len(live)} hosts")
        found = 0
        auth_h = {}
        if getattr(p.args, "cookie", None):
            auth_h["Cookie"] = p.args.cookie
        if getattr(p.args, "authorization", None):
            auth_h["Authorization"] = p.args.authorization

        for host in live:
            host = host.strip().rstrip("/")
            if not host.startswith("http"):
                host = "https://" + host

            try:
                # Baseline request
                baseline = sync_get(host, headers=auth_h, timeout=8)
                if not baseline:
                    continue
                base_body   = baseline.get("body", "")
                base_status = baseline.get("status", 0)
                base_len    = len(base_body)
            except Exception as e:
                get_handler().capture("step21", e, f"baseline:{host}")
                continue

            # ── Host Header Injection ─────────────────────────────────
            for hdr in HEADERS_TO_TEST:
                try:
                    h = dict(auth_h); h[hdr] = EVIL_HOST
                    r = sync_get(host, headers=h, timeout=8,
                                 follow_redirects=True)
                    if not r: continue
                    body   = r.get("body", "")
                    status = r.get("status", 0)
                    loc    = (r.get("location","") or
                              r.get("headers",{}).get("location",""))
                    combined = (body + loc).lower()

                    # Multiple detection signals
                    if EVIL_HOST.lower() in combined:
                        finding = (f"Host Header Injection via '{hdr}: {EVIL_HOST}' "
                                   f"reflected in response (status={status})")
                        self._add(out, p, "high", "HOST_HEADER_INJECTION",
                                  host, finding)
                        found += 1; break

                    # Response anomaly: big length diff
                    if abs(len(body) - base_len) > 500 and status != base_status:
                        finding = (f"Possible HHI via '{hdr}' — "
                                   f"status {base_status}→{status}, "
                                   f"len diff {abs(len(body)-base_len)}")
                        self._add(out, p, "medium", "HOST_HEADER_ANOMALY",
                                  host, finding)
                        found += 1; break
                except Exception as e:
                    get_handler().capture("step21", e, f"hh:{host}")

            # ── Origin Injection / CORS ───────────────────────────────
            for hdr in ORIGIN_HEADERS:
                for origin in [
                    f"https://{EVIL_HOST}",
                    f"https://evil.{host.split('//')[1].split('/')[0]}",
                    "null",
                ]:
                    try:
                        h = dict(auth_h); h[hdr] = origin
                        r = sync_get(host, headers=h, timeout=8)
                        if not r: continue
                        acao = (r.get("headers", {})
                                .get("access-control-allow-origin", ""))
                        acac = (r.get("headers", {})
                                .get("access-control-allow-credentials", ""))
                        if acao in (origin, "*") or EVIL_HOST in acao:
                            finding = (f"CORS/Origin Injection: "
                                       f"{hdr}={origin} → "
                                       f"ACAO={acao} ACAC={acac}")
                            sev = ("high" if "true" in acac.lower()
                                   else "medium")
                            self._add(out, p, sev, "ORIGIN_INJECTION",
                                      host, finding)
                            found += 1; break
                    except Exception as e:
                        get_handler().capture("step21", e, f"origin:{host}")

            # ── Password Reset Poisoning ─────────────────────────────
            for path in ["/forgot-password", "/reset-password",
                          "/password/reset", "/api/password/reset",
                          "/auth/forgot", "/account/forgot-password"]:
                url = host.rstrip("/") + path
                try:
                    r0 = sync_get(url, timeout=6)
                    if not r0 or r0.get("status", 0) not in (200, 302):
                        continue
                    h = dict(auth_h)
                    h["X-Forwarded-Host"] = EVIL_HOST
                    r1 = sync_get(url, headers=h, timeout=6)
                    if r1 and EVIL_HOST in r1.get("body", ""):
                        finding = (f"Password Reset Poisoning at {path} — "
                                   f"X-Forwarded-Host reflected in reset email")
                        self._add(out, p, "critical",
                                  "PASSWORD_RESET_POISONING", url, finding)
                        found += 1
                except Exception as e:
                    get_handler().capture("step21", e, f"reset:{url}")

        p.log.success(f"Host Header + Origin: {found} findings")

    @staticmethod
    def _add(out, p, sev, vtype, url, detail):
        try:
            with open(out, "a") as f:
                f.write(f"{vtype}: {url} | {detail}\n")
        except Exception:
            pass
        p.add_finding(sev, vtype, url, detail, "host-header")
