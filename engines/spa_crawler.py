#!/usr/bin/env python3
# engines/spa_crawler.py — V7 SPA Detection + Headless Browser Crawler
# Detects React/Vue/Angular/Next.js apps and uses Playwright for JS rendering
# Falls back to static crawl if Playwright not available
# MilkyWay Intelligence | Author: Sharlix

import asyncio
import re
import subprocess
import shutil
from typing import List, Set

# SPA framework signatures
SPA_SIGNATURES = {
    "nextjs"   : ["__NEXT_DATA__", "_next/static", "next/dist"],
    "react"    : ["ReactDOM", "react-root", "data-reactroot", "__react_fiber"],
    "vue"      : ["__vue__", "ng-version" ,"data-v-app", "vue.runtime"],
    "angular"  : ["ng-version", "ng-app", "angular.module", "platformBrowserDynamic"],
    "nuxt"     : ["__NUXT__", "_nuxt/", "nuxt.config"],
    "gatsby"   : ["___gatsby", "gatsby-focus-wrapper"],
    "svelte"   : ["__svelte", "svelte-kit"],
    "ember"    : ["Ember.Application", "ember-application"],
}

# JS-heavy endpoint patterns
JS_ENDPOINT_PATTERNS = [
    r'fetch\s*\(\s*["\']([^"\']+)',
    r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)',
    r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)',
    r'XMLHttpRequest.*open\s*\(\s*["\'][^"\']+["\'],\s*["\']([^"\']+)',
    r'href\s*=\s*["\']([^"\']*api[^"\']*)',
    r'action\s*=\s*["\']([^"\']+)',
]


class SPACrawler:
    """
    V7 SPA-aware crawler.

    Detection:
    - Scans page source for SPA framework signatures
    - Extracts JS-referenced endpoints from source

    Headless mode (Playwright):
    - Launches Chromium if SPA detected
    - Captures all network requests during page load
    - Returns post-render DOM endpoints

    Fallback:
    - Static HTML extraction if no Playwright
    """

    def __init__(self, log=None, timeout: int = 30):
        self.log              = log
        self.timeout          = timeout
        self.playwright_ok    = self._check_playwright()
        self._discovered_urls : Set[str] = set()

    def _check_playwright(self) -> bool:
        try:
            from playwright.async_api import async_playwright
            return True
        except ImportError:
            return False

    def detect_spa(self, html: str) -> dict:
        """
        Detect if page is an SPA and which framework.
        Returns {"is_spa": bool, "framework": str, "confidence": float}
        """
        html_lower = html.lower()
        scores     = {}

        for framework, sigs in SPA_SIGNATURES.items():
            matched = sum(1 for s in sigs if s.lower() in html_lower)
            if matched:
                scores[framework] = matched / len(sigs)

        if not scores:
            return {"is_spa": False, "framework": "none", "confidence": 0.0}

        best = max(scores, key=scores.get)
        return {
            "is_spa"    : True,
            "framework" : best,
            "confidence": round(scores[best], 2),
            "all_scores": scores,
        }

    def extract_js_endpoints(self, html: str, base_url: str = "") -> List[str]:
        """Extract API endpoints referenced in JavaScript."""
        endpoints = set()
        for pattern in JS_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for m in matches:
                url = m[-1] if isinstance(m, tuple) else m
                url = url.strip().strip("'\"")
                if url.startswith("/") and base_url:
                    from urllib.parse import urlparse
                    parsed = urlparse(base_url)
                    url    = f"{parsed.scheme}://{parsed.netloc}{url}"
                if url.startswith("http"):
                    endpoints.add(url)
        return list(endpoints)

    async def crawl(self, url: str, depth: int = 2) -> List[str]:
        """
        Main crawl entry point.
        Uses Playwright if SPA detected, else static extraction.
        """
        from core.http_client import AsyncHTTPClient
        urls_found = set()

        async with AsyncHTTPClient(timeout=self.timeout) as client:
            resp = await client.get(url)
            if not resp or not resp.get("body"):
                return []

            html = resp.get("body","")

            # SPA detection
            spa_info = self.detect_spa(html)
            if spa_info["is_spa"] and self.playwright_ok:
                if self.log:
                    self.log.info(f"  SPA detected: {spa_info['framework']} — using headless crawler")
                headless_urls = await self._playwright_crawl(url, depth)
                urls_found.update(headless_urls)
            else:
                if spa_info["is_spa"] and self.log:
                    self.log.warn(f"  SPA detected ({spa_info['framework']}) but Playwright not installed — static crawl only")
                    self.log.warn("  Install: pip3 install playwright && playwright install chromium")

            # Always extract JS endpoints from source
            js_endpoints = self.extract_js_endpoints(html, base_url=url)
            urls_found.update(js_endpoints)

            # Static HTML link extraction
            static_links = self._extract_static_links(html, base_url=url)
            urls_found.update(static_links)

        return list(urls_found)

    async def _playwright_crawl(self, url: str, depth: int = 2) -> List[str]:
        """
        Headless browser crawl using Playwright.
        Intercepts all network requests to find API endpoints.
        """
        captured_requests = set()
        captured_urls     = set()

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless = True,
                    args     = [
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-extensions",
                        "--disable-gpu",
                    ]
                )
                context = await browser.new_context(
                    user_agent       = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
                    ignore_https_errors = True,
                )
                page = await context.new_page()

                # Intercept all requests
                async def on_request(request):
                    req_url = request.url
                    if any(ext in req_url for ext in [".css",".png",".jpg",".gif",".woff",".ico"]):
                        return
                    captured_requests.add(req_url)

                page.on("request", on_request)

                # Navigate and wait for network idle
                try:
                    await asyncio.wait_for(
                        page.goto(url, wait_until="networkidle"),
                        timeout=self.timeout
                    )
                except asyncio.TimeoutError:
                    pass

                # Extract links from rendered DOM
                try:
                    links = await page.eval_on_selector_all(
                        "a[href]",
                        "els => els.map(e => e.href)"
                    )
                    captured_urls.update(links)
                except Exception:
                    pass

                # Extract form actions
                try:
                    actions = await page.eval_on_selector_all(
                        "form[action]",
                        "els => els.map(e => e.action)"
                    )
                    captured_urls.update(actions)
                except Exception:
                    pass

                await browser.close()

        except Exception as e:
            if self.log:
                self.log.warn(f"  Playwright error: {e}")

        all_found = captured_requests | captured_urls
        return [u for u in all_found if u.startswith("http")]

    def _extract_static_links(self, html: str, base_url: str = "") -> List[str]:
        """Extract href and src links from static HTML."""
        from urllib.parse import urljoin, urlparse
        links = set()
        base_parsed = urlparse(base_url)
        base_domain = base_parsed.netloc

        for pattern in [r'href=["\']([^"\']+)', r'action=["\']([^"\']+)',
                         r'src=["\']([^"\']*api[^"\']*)', r'src=["\']([^"\']*\.js[^"\']*)']: 
            for match in re.findall(pattern, html, re.IGNORECASE):
                url = match.strip()
                if url.startswith(("/","http","https")):
                    full = urljoin(base_url, url) if url.startswith("/") else url
                    # Scope check
                    if urlparse(full).netloc == base_domain or url.startswith("/"):
                        links.add(full)
        return list(links)
