#!/usr/bin/env python3
# core/http_client.py — M7Hunter V7 Async HTTP Client
# HTTP/2 support via httpx, connection pooling, WAF evasion built-in
# MilkyWay Intelligence | Author: Sharlix

import asyncio
import random
import time
from typing import Optional, Dict, Any

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

import urllib.request
import urllib.parse
import urllib.error

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


class AsyncHTTPClient:
    """
    V7 Async HTTP client with HTTP/2, connection pooling, WAF evasion.
    Falls back to urllib if httpx not available.
    """

    def __init__(self, timeout: int = 10, max_connections: int = 50,
                 proxy: str = None, verify_ssl: bool = False,
                 http2: bool = True):
        self.timeout         = timeout
        self.max_connections = max_connections
        self.proxy           = proxy
        self.verify_ssl      = verify_ssl
        self.http2           = http2 and HTTPX_AVAILABLE
        self._client: Optional[Any] = None
        self._semaphore      = None

    async def __aenter__(self):
        if HTTPX_AVAILABLE:
            limits  = httpx.Limits(max_connections=self.max_connections,
                                   max_keepalive_connections=20)
            proxies = {"all://": self.proxy} if self.proxy else None
            client_kwargs = dict(
                http2        = self.http2,
                verify       = self.verify_ssl,
                limits       = limits,
                timeout      = httpx.Timeout(self.timeout),
                follow_redirects = False,
            )
            if proxies:
                try:
                    client_kwargs['proxies'] = proxies
                except Exception:
                    try:
                        client_kwargs['mounts'] = {'all://': httpx.AsyncHTTPTransport(proxy=self.proxy)}
                    except Exception as _e:
                        from core.error_handler import get_handler
                    get_handler().capture("http_client", _e)
            self._client = httpx.AsyncClient(**client_kwargs)
        self._semaphore = asyncio.Semaphore(self.max_connections)
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    def _evasion_headers(self, extra: dict = None) -> dict:
        """Generate WAF evasion headers."""
        ip  = ".".join(str(random.randint(1, 254)) for _ in range(4))
        hdrs = {
            "User-Agent"     : random.choice(USER_AGENTS),
            "X-Forwarded-For": ip,
            "X-Real-IP"      : ip,
            "Accept"         : "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control"  : "no-cache",
        }
        if extra:
            hdrs.update(extra)
        return hdrs

    async def get(self, url: str, headers: dict = None,
                  follow_redirects: bool = False, timeout: int = None) -> dict:
        """Async GET with evasion headers."""
        async with self._semaphore:
            hdrs = self._evasion_headers(headers)
            t    = timeout or self.timeout
            try:
                if self._client:
                    r = await self._client.get(url, headers=hdrs,
                                               follow_redirects=follow_redirects,
                                               timeout=t)
                    return {
                        "status"  : r.status_code,
                        "body"    : r.text,
                        "headers" : dict(r.headers),
                        "url"     : str(r.url),
                        "http2"   : r.http_version == "HTTP/2",
                        "ok"      : r.status_code < 400,
                    }
                else:
                    return await asyncio.get_running_loop().run_in_executor(
                        None, self._sync_get, url, hdrs, t)
            except Exception as e:
                return {"status": 0, "body": "", "headers": {}, "error": str(e), "ok": False}

    async def post(self, url: str, data: Any = None, json: Any = None,
                   headers: dict = None, timeout: int = None) -> dict:
        """Async POST."""
        async with self._semaphore:
            hdrs = self._evasion_headers(headers)
            t    = timeout or self.timeout
            try:
                if self._client:
                    r = await self._client.post(url, content=data, json=json,
                                                headers=hdrs, timeout=t)
                    return {"status": r.status_code, "body": r.text,
                            "headers": dict(r.headers), "ok": r.status_code < 400}
                else:
                    return await asyncio.get_running_loop().run_in_executor(
                        None, self._sync_post, url, data, hdrs, t)
            except Exception as e:
                return {"status": 0, "body": "", "headers": {}, "error": str(e), "ok": False}

    async def flood(self, url: str, method: str = "POST", data: bytes = b"",
                    headers: dict = None, count: int = 15) -> list:
        """
        Flood attack for race condition testing.
        Sends `count` requests simultaneously using HTTP/2 multiplexing.
        """
        hdrs = self._evasion_headers(headers)
        tasks = [self._single_flood(url, method, data, hdrs) for _ in range(count)]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def _single_flood(self, url, method, data, headers) -> dict:
        try:
            if self._client:
                if method == "POST":
                    r = await self._client.post(url, content=data, headers=headers, timeout=10)
                else:
                    r = await self._client.get(url, headers=headers, timeout=10)
                return {"status": r.status_code, "body": r.text[:500], "ok": r.status_code < 400}
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e), "ok": False}
        return {"status": 0, "body": "", "ok": False}

    def _sync_get(self, url, headers, timeout):
        try:
            req  = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(50000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body, "headers": dict(resp.headers),
                    "url": url, "http2": False, "ok": True}
        except urllib.error.HTTPError as e:
            try: body = e.read(5000).decode("utf-8", errors="ignore")
            except: body = ""
            return {"status": e.code, "body": body, "headers": {}, "ok": False}
        except Exception as e:
            return {"status": 0, "body": "", "headers": {}, "error": str(e), "ok": False}

    def _sync_post(self, url, data, headers, timeout):
        try:
            if isinstance(data, str): data = data.encode()
            if isinstance(data, dict):
                import json
                data = json.dumps(data).encode()
                headers["Content-Type"] = "application/json"
            req  = urllib.request.Request(url, data=data or b"", headers=headers, method="POST")
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(10000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body, "headers": dict(resp.headers), "ok": True}
        except urllib.error.HTTPError as e:
            try: body = e.read(2000).decode("utf-8", errors="ignore")
            except: body = ""
            return {"status": e.code, "body": body, "headers": {}, "ok": False}
        except Exception as e:
            return {"status": 0, "body": "", "headers": {}, "error": str(e), "ok": False}


def sync_get(url: str, headers: dict = None, timeout: int = 10,
             follow_redirects: bool = True) -> dict:
    """Synchronous GET wrapper for non-async contexts."""
    ip  = ".".join(str(random.randint(1, 254)) for _ in range(4))
    hdrs = {
        "User-Agent"     : random.choice(USER_AGENTS),
        "X-Forwarded-For": ip,
        "Accept"         : "*/*",
    }
    if headers: hdrs.update(headers)
    try:
        if follow_redirects:
            req  = urllib.request.Request(url, headers=hdrs)
            resp = urllib.request.urlopen(req, timeout=timeout)
        else:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw): return None
            opener = urllib.request.build_opener(NoRedirect())
            req    = urllib.request.Request(url, headers=hdrs)
            try:    resp = opener.open(req, timeout=timeout)
            except urllib.error.HTTPError as e: resp = e
        body     = resp.read(50000).decode("utf-8", errors="ignore")
        location = resp.headers.get("Location","") if hasattr(resp,"headers") else ""
        status   = resp.status if hasattr(resp,"status") else resp.code
        return {"status": status, "body": body,
                "headers": dict(resp.headers) if hasattr(resp,"headers") else {},
                "location": location, "ok": status < 400}
    except urllib.error.HTTPError as e:
        try:    body = e.read(5000).decode("utf-8", errors="ignore")
        except: body = ""
        location = e.headers.get("Location","") if hasattr(e,"headers") else ""
        return {"status": e.code, "body": body, "headers": {}, "location": location, "ok": False}
    except Exception as e:
        return {"status": 0, "body": "", "headers": {}, "location": "", "error": str(e), "ok": False}


def sync_post(url: str, data: Any = None, json_data: dict = None,
              headers: dict = None, timeout: int = 10) -> dict:
    """Synchronous POST wrapper."""
    import json as _json
    ip   = ".".join(str(random.randint(1, 254)) for _ in range(4))
    hdrs = {"User-Agent": random.choice(USER_AGENTS), "X-Forwarded-For": ip}
    if headers: hdrs.update(headers)
    body_bytes = b""
    if json_data is not None:
        body_bytes = _json.dumps(json_data).encode()
        hdrs["Content-Type"] = "application/json"
    elif data is not None:
        body_bytes = data if isinstance(data, bytes) else str(data).encode()
        hdrs.setdefault("Content-Type","application/x-www-form-urlencoded")
    try:
        req  = urllib.request.Request(url, data=body_bytes, headers=hdrs, method="POST")
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read(10000).decode("utf-8", errors="ignore")
        return {"status": resp.status, "body": body, "headers": dict(resp.headers), "ok": True}
    except urllib.error.HTTPError as e:
        try:    b = e.read(2000).decode("utf-8", errors="ignore")
        except: b = ""
        return {"status": e.code, "body": b, "headers": {}, "ok": False}
    except Exception as e:
        return {"status": 0, "body": "", "headers": {}, "error": str(e), "ok": False}
