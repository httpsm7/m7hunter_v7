#!/usr/bin/env python3
# core/browser_pool.py — Shared Browser Pool (Blueprint: one shared browser pool)
# RAM-aware, demand-only, auto-release after stage
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import asyncio, threading, time
from core.error_handler import get_handler

class BrowserPool:
    """
    Blueprint: One shared browser pool.
    - Playwright only on demand
    - Paused when RAM > 70%
    - Max pool size controlled by ResourceController
    - Each consumer checks out a page, returns it when done
    """

    def __init__(self, max_size: int = 3, resource_ctrl=None, log=None):
        self.max_size   = max_size
        self.rctrl      = resource_ctrl
        self.log        = log
        self._lock      = asyncio.Lock()
        self._tlock     = threading.Lock()
        self._pages     = []       # available (browser, context, page) tuples
        self._in_use    = 0
        self._playwright= None
        self._browser   = None
        self._ready     = False
        self._loop      = None

    # ── Sync wrappers (for non-async modules) ─────────────────────────
    def get_page_sync(self, timeout: int = 30):
        """Blocking page checkout for sync modules."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.get_page(timeout=timeout))
        finally:
            pass  # keep loop — page.close must run on same loop

    def release_page_sync(self, page):
        """Release a page back to the pool (sync)."""
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(self.release_page(page))
        finally:
            loop.close()

    # ── Async API ─────────────────────────────────────────────────────
    async def get_page(self, timeout: int = 30):
        """
        Check out a page from pool.
        Blocks until a page is available or timeout.
        Returns None if RAM gate blocks.
        """
        if self.rctrl and not self.rctrl.playwright_allowed():
            if self.log:
                self.log.warn("[BrowserPool] RAM gate: Playwright blocked")
            return None

        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._tlock:
                if self._pages:
                    _, _, page = self._pages.pop()
                    self._in_use += 1
                    return page
                if self._in_use < self._pool_limit():
                    page = await self._create_page()
                    if page:
                        self._in_use += 1
                        return page
            await asyncio.sleep(0.5)

        if self.log:
            self.log.warn("[BrowserPool] Timeout waiting for page")
        return None

    async def release_page(self, page):
        """Return page to pool or close it if pool is full."""
        try:
            if page is None:
                return
            with self._tlock:
                if len(self._pages) < self.max_size:
                    # Reset page state and return to pool
                    try:
                        await page.goto("about:blank", timeout=5000)
                        self._pages.append((None, None, page))
                    except Exception:
                        await self._close_page(page)
                else:
                    await self._close_page(page)
                self._in_use = max(0, self._in_use - 1)
        except Exception as e:
            get_handler().capture("browser_pool", e, "release_page")

    async def close_all(self):
        """Shutdown entire pool — call at end of scan."""
        try:
            with self._tlock:
                pages = list(self._pages)
                self._pages.clear()
            for _, _, page in pages:
                await self._close_page(page)
            if self._browser:
                await self._browser.close()
                self._browser = None
            if self._playwright:
                await self._playwright.__aexit__(None, None, None)
                self._playwright = None
            self._ready = False
            if self.log:
                self.log.info("[BrowserPool] Closed all browsers")
        except Exception as e:
            get_handler().capture("browser_pool", e, "close_all")

    # ── Internal ──────────────────────────────────────────────────────
    async def _ensure_browser(self):
        if self._ready and self._browser:
            return True
        try:
            from playwright.async_api import async_playwright
            from core.stealth import STEALTH_JS
            self._playwright = await async_playwright().__aenter__()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox","--disable-dev-shm-usage",
                      "--disable-blink-features=AutomationControlled"]
            )
            self._ready = True
            return True
        except ImportError:
            if self.log:
                self.log.warn("[BrowserPool] Playwright not installed")
            return False
        except Exception as e:
            get_handler().capture("browser_pool", e, "_ensure_browser")
            return False

    async def _create_page(self):
        if not await self._ensure_browser():
            return None
        try:
            from core.stealth import STEALTH_JS, PROFILES
            import random
            profile = random.choice(PROFILES)
            ctx = await self._browser.new_context(
                user_agent=profile["ua"],
                locale=profile["lang"],
                timezone_id=profile["tz"],
                viewport={"width": profile["w"], "height": profile["h"]},
            )
            await ctx.add_init_script(STEALTH_JS)
            page = await ctx.new_page()
            return page
        except Exception as e:
            get_handler().capture("browser_pool", e, "_create_page")
            return None

    async def _close_page(self, page):
        try:
            if page:
                await page.close()
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("browser_pool", _e)

    def _pool_limit(self) -> int:
        if self.rctrl:
            return max(1, self.rctrl.get_concurrency_limit(self.max_size))
        return self.max_size

    @property
    def status(self) -> dict:
        return {
            "pool_size"  : len(self._pages),
            "in_use"     : self._in_use,
            "max_size"   : self.max_size,
            "ready"      : self._ready,
            "limit"      : self._pool_limit(),
        }


# Module-level singleton
_pool: BrowserPool | None = None

def get_browser_pool(max_size: int = 3, resource_ctrl=None, log=None) -> BrowserPool:
    global _pool
    if _pool is None:
        _pool = BrowserPool(max_size=max_size, resource_ctrl=resource_ctrl, log=log)
    return _pool

def close_browser_pool():
    global _pool
    if _pool:
        import asyncio
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(_pool.close_all())
            loop.close()
        except Exception as e:
            get_handler().capture("browser_pool", e, "close_browser_pool")
        _pool = None
