#!/usr/bin/env python3
# core/proxy_manager.py — Proxy Lifecycle Manager
# Blueprint 5.6: Rotation, cooldown, failure scoring, geo routing, retry logic
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import time, threading, random
from dataclasses import dataclass, field
from typing import Optional
from core.error_handler import get_handler

@dataclass
class ProxyRecord:
    url          : str
    geo          : str   = "any"
    failures     : int   = 0
    successes    : int   = 0
    last_used    : float = 0.0
    last_failure : float = 0.0
    banned_until : float = 0.0
    latency_ms   : float = 0.0

    @property
    def score(self) -> float:
        total = self.successes + self.failures
        if total == 0: return 0.5
        sr = self.successes / total
        latency_penalty = min(self.latency_ms / 5000.0, 0.5)
        return round(max(0.0, sr - latency_penalty), 3)

    @property
    def is_available(self) -> bool:
        return time.time() >= self.banned_until


class ProxyManager:
    """
    Blueprint 5.6: Proxy Manager with rotation, cooldown, failure scoring.

    Features:
    - Score-based selection (success rate - latency penalty)
    - Failure cooldown (exponential backoff per proxy)
    - Geo-routing support
    - Thread-safe
    - No external dependencies
    """

    COOLDOWN_BASE   = 60      # seconds base cooldown
    COOLDOWN_MAX    = 3600    # 1 hour max ban
    FAILURE_LIMIT   = 5       # failures before hard ban
    MIN_COOLDOWN    = 15      # minimum cooldown after any failure

    def __init__(self, proxies: list[str] = None, log=None):
        self.log     = log
        self._lock   = threading.Lock()
        self._proxies: dict[str, ProxyRecord] = {}
        self._direct_mode = True  # fallback when no proxies

        for p in (proxies or []):
            self._add(p)

    def _add(self, proxy_url: str, geo: str = "any"):
        self._proxies[proxy_url] = ProxyRecord(url=proxy_url, geo=geo)
        self._direct_mode = False

    def add_proxy(self, url: str, geo: str = "any"):
        with self._lock:
            self._add(url, geo)

    def load_from_file(self, path: str):
        """Load proxies from file — one per line, optional :geo suffix."""
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    url = parts[0]
                    geo = parts[1] if len(parts) > 1 else "any"
                    self.add_proxy(url, geo)
            if self.log:
                self.log.info(f"[ProxyManager] Loaded {len(self._proxies)} proxies")
        except Exception as e:
            get_handler().capture("proxy_manager", e, "load_from_file")

    def get(self, geo: str = "any") -> Optional[str]:
        """
        Return best available proxy by score.
        Returns None if no proxies available (direct connection).
        """
        if self._direct_mode:
            return None

        with self._lock:
            candidates = [
                p for p in self._proxies.values()
                if p.is_available and (geo == "any" or p.geo in (geo, "any"))
            ]
            if not candidates:
                if self.log:
                    self.log.warn("[ProxyManager] No proxies available — using direct")
                return None
            best = sorted(candidates, key=lambda p: p.score, reverse=True)
            chosen = best[0]
            # Small randomization among top tier to avoid overuse
            top_tier = [p for p in best[:3] if p.score >= chosen.score - 0.1]
            chosen = random.choice(top_tier)
            chosen.last_used = time.time()
            return chosen.url

    def get_httpx_proxy(self, geo: str = "any") -> Optional[dict]:
        """Return proxy in httpx format."""
        url = self.get(geo)
        if not url:
            return None
        return {"http://": url, "https://": url}

    def report_success(self, proxy_url: str, latency_ms: float = 0.0):
        with self._lock:
            if proxy_url not in self._proxies:
                return
            p = self._proxies[proxy_url]
            p.successes += 1
            if latency_ms > 0:
                p.latency_ms = (p.latency_ms * 0.8 + latency_ms * 0.2)

    def report_failure(self, proxy_url: str, hard_fail: bool = False):
        with self._lock:
            if proxy_url not in self._proxies:
                return
            p = self._proxies[proxy_url]
            p.failures += 1
            p.last_failure = time.time()

            if hard_fail or p.failures >= self.FAILURE_LIMIT:
                cooldown = min(self.COOLDOWN_BASE * (2 ** p.failures), self.COOLDOWN_MAX)
            else:
                cooldown = self.MIN_COOLDOWN * p.failures

            p.banned_until = time.time() + cooldown
            if self.log:
                self.log.warn(f"[ProxyManager] {proxy_url[:40]} cooldown {cooldown}s "
                              f"(failures={p.failures})")

    def rotate_all(self):
        """Force rotate all proxies — reset cooldowns."""
        with self._lock:
            for p in self._proxies.values():
                p.banned_until = 0.0

    def status(self) -> dict:
        with self._lock:
            total     = len(self._proxies)
            available = sum(1 for p in self._proxies.values() if p.is_available)
            return {
                "total"    : total,
                "available": available,
                "banned"   : total - available,
                "direct"   : self._direct_mode,
                "proxies"  : [
                    {"url": p.url[:40], "score": p.score,
                     "ok": p.is_available, "geo": p.geo}
                    for p in self._proxies.values()
                ],
            }
