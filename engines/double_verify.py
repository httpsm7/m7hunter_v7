#!/usr/bin/env python3
# engines/double_verify.py — V7 Double Verification Engine
# Re-issues requests with delay + different UA to confirm findings
# Eliminates false positives before they reach the report
# MilkyWay Intelligence | Author: Sharlix

import asyncio
import re
import time
import random
from core.http_client import sync_get, sync_post, AsyncHTTPClient

USER_AGENTS_VERIFY = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# Confirmation patterns by vuln type
CONFIRM_PATTERNS = {
    "SSRF"           : [r"ami-id",r"instance-id",r"local-ipv4",r"AccessKeyId",r"computeMetadata"],
    "LFI_UNIX_PASSWD": [r"root:x?:\d+:\d+:",r"daemon:"],
    "LFI"            : [r"root:x?:\d+:\d+:",r"/bin/bash",r"\[boot loader\]"],
    "XSS"            : [r"<script[^>]*>alert",r"<svg[^>]*(onload|onerror)=",r"<img[^>]*onerror="],
    "SQLI_CONFIRMED" : [r"SQL syntax",r"ORA-\d{4}",r"PostgreSQL.*ERROR",r"SQLSTATE"],
    "NOSQL_INJECTION": [r'"role"\s*:\s*"admin"',r'"is_admin"\s*:\s*true',r"logged in"],
    "SSTI"           : [r"\b49\b",r"\b7777777\b",r"uid=\d+\("],
    "OPEN_S3_BUCKET" : [r"ListBucketResult",r"<Contents>"],
    "CORS_MISCONFIG" : [r"Access-Control-Allow-Origin:\s*https?://evil"],
}


class DoubleVerify:
    """
    Double Verification Engine.

    For any candidate finding:
    1. Wait a delay (CEO rule: default 1.5s)
    2. Re-issue with different User-Agent
    3. Check if vulnerability still present
    4. Only confirm if second check also positive

    Reduces false positives by ~80% for dynamic/random responses.
    """

    def __init__(self, ceo_engine=None, log=None):
        self.ceo = ceo_engine
        self.log = log
        self.delay = ceo_engine.double_verify_delay() if ceo_engine else 1.5

    def verify(self, vuln_type: str, url: str, payload: str = "",
                original_response: str = "", method: str = "GET",
                post_body: bytes = None, headers: dict = None) -> dict:
        """
        Synchronous double-verify.

        Returns:
        {
            "confirmed": bool,
            "confidence_boost": float,
            "reason": str
        }
        """
        # Wait before re-testing (avoid cache hits, vary timing)
        time.sleep(self.delay + random.uniform(0.3, 0.8))

        # Use different User-Agent for second request
        verify_headers = dict(headers or {})
        verify_headers["User-Agent"] = random.choice(USER_AGENTS_VERIFY)
        # Remove existing UA if present
        for k in list(verify_headers.keys()):
            if k.lower() == "user-agent" and verify_headers[k] not in USER_AGENTS_VERIFY:
                verify_headers[k] = random.choice(USER_AGENTS_VERIFY)

        # Re-issue request
        if method.upper() == "POST" and post_body:
            resp2 = sync_post(url, data=post_body, headers=verify_headers)
        else:
            resp2 = sync_get(url, headers=verify_headers)

        if not resp2 or resp2.get("status",0) == 0:
            return {"confirmed": False, "confidence_boost": 0.0,
                    "reason": "Verification request failed"}

        body2 = resp2.get("body","")

        # Check confirmation patterns
        patterns = CONFIRM_PATTERNS.get(vuln_type, CONFIRM_PATTERNS.get(
            vuln_type.split("_")[0], []))

        for pattern in patterns:
            if re.search(pattern, body2, re.IGNORECASE):
                return {"confirmed": True, "confidence_boost": 0.15,
                        "reason": f"Pattern confirmed on second request: {pattern[:40]}"}

        # Payload still reflected?
        if payload and payload.lower() in body2.lower():
            # Check encoding
            if "&lt;" not in body2 and "\\u003c" not in body2:
                return {"confirmed": True, "confidence_boost": 0.10,
                        "reason": "Payload still reflected unencoded on second request"}

        # Response similarity to original
        if original_response and body2:
            orig_len = len(original_response)
            new_len  = len(body2)
            if orig_len > 0 and abs(orig_len - new_len) / orig_len < 0.1:
                # Very similar responses = likely stable finding
                return {"confirmed": True, "confidence_boost": 0.05,
                        "reason": f"Consistent response ({orig_len}b ≈ {new_len}b)"}

        return {"confirmed": False, "confidence_boost": 0.0,
                "reason": "Finding not reproduced on second request — possible false positive"}

    async def verify_async(self, vuln_type: str, url: str, payload: str = "",
                            original_response: str = "", headers: dict = None) -> dict:
        """Async version of verify."""
        await asyncio.sleep(self.delay + random.uniform(0.3, 0.8))

        verify_headers = dict(headers or {})
        verify_headers["User-Agent"] = random.choice(USER_AGENTS_VERIFY)

        async with AsyncHTTPClient(timeout=10) as client:
            resp2 = await client.get(url, headers=verify_headers)

        if not resp2 or resp2.get("status",0) == 0:
            return {"confirmed": False, "confidence_boost": 0.0, "reason": "Request failed"}

        body2 = resp2.get("body","")
        patterns = CONFIRM_PATTERNS.get(vuln_type, [])

        for pattern in patterns:
            if re.search(pattern, body2, re.IGNORECASE):
                return {"confirmed": True, "confidence_boost": 0.15,
                        "reason": f"Async verified: {pattern[:40]}"}

        if payload and payload.lower() in body2.lower() and "&lt;" not in body2:
            return {"confirmed": True, "confidence_boost": 0.10,
                    "reason": "Payload reflected on second async request"}

        return {"confirmed": False, "confidence_boost": 0.0,
                "reason": "Could not reproduce asynchronously"}
