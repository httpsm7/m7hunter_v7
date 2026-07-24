#!/usr/bin/env python3
# core/stealth_manager.py — Unified Stealth Browser Manager
# Blueprint 5.6: Single shared browser + isolated contexts, aggressive cleanup
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import asyncio, random, time, threading
from dataclasses import dataclass
from core.error_handler import get_handler

FINGERPRINTS = [
    {"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
     "platform": "Win32", "lang": "en-US", "tz": "America/New_York", "w": 1920, "h": 1080},
    {"ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Version/17.4.1 Safari/605.1.15",
     "platform": "MacIntel", "lang": "en-GB", "tz": "Europe/London", "w": 2560, "h": 1600},
    {"ua": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
     "platform": "Linux x86_64", "lang": "en-US", "tz": "America/Los_Angeles", "w": 1366, "h": 768},
]

STEALTH_SCRIPT = """
Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
if(!window.chrome){window.chrome={runtime:{},loadTimes:()=>{},csi:()=>{},app:{}};}
const _oq=navigator.permissions.query.bind(navigator.permissions);
navigator.permissions.query=p=>p.name==='notifications'?Promise.resolve({state:Notification.permission}):_oq(p);
Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});
Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});
delete window.__nightmare; delete window._phantom; delete window.callPhantom;
"""

@dataclass
class StealthContext:
    context_id : str
    page       : object
    context    : object
    created_at : float
    fingerprint: dict


class StealthManager:
    """
    Blueprint 5.6: Single shared browser + per-task isolated contexts.

    Lifecycle per task:
      acquire_context() → use page → release_context()

    On release:
      - close page
      - destroy context
      - clear cookies
      - clear memory references
      - release handles

    Never creates multiple independent Chromium instances.
    """

    MAX_CONTEXT_AGE = 300   # seconds before forced context rotation
    MAX_CONTEXTS    = 4     # max simultaneous contexts

    def __init__(self, resource_ctrl=None, proxy_manager=None, log=None):
        self.rctrl   = resource_ctrl
        self.proxies = proxy_manager
        self.log     = log
        self._lock   = asyncio.Lock()
        self._tlock  = threading.Lock()
        self._browser   = None
        self._playwright = None
        self._active_contexts: dict[str, StealthContext] = {}
        self._ready  = False
        self._launch_lock = asyncio.Lock()

    async def acquire_context(self, proxy: str = None) -> StealthContext | None:
        """Get an isolated context for one task."""
        if self.rctrl and not self.rctrl.playwright_allowed():
            if self.log:
                self.log.warn("[StealthMgr] RAM gate: browser blocked")
            return None

        async with (self._launch_lock or asyncio.Lock()):
            if not self._ready:
                await self._launch_browser()

        if not self._ready:
            return None

        fp = random.choice(FINGERPRINTS)
        proxy_url = proxy or (self.proxies.get() if self.proxies else None)

        try:
            ctx_opts = {
                "user_agent"  : fp["ua"],
                "locale"      : fp["lang"],
                "timezone_id" : fp["tz"],
                "viewport"    : {"width": fp["w"], "height": fp["h"]},
            }
            if proxy_url:
                ctx_opts["proxy"] = {"server": proxy_url}

            ctx  = await self._browser.new_context(**ctx_opts)
            await ctx.add_init_script(STEALTH_SCRIPT)
            page = await ctx.new_page()

            sc = StealthContext(
                context_id = f"ctx_{int(time.time()*1000)}_{random.randint(100,999)}",
                page       = page,
                context    = ctx,
                created_at = time.time(),
                fingerprint= fp,
            )
            with self._tlock:
                self._active_contexts[sc.context_id] = sc
            return sc

        except Exception as e:
            get_handler().capture("stealth_manager", e, "acquire_context")
            return None

    async def release_context(self, sc: StealthContext):
        """
        Blueprint: After task completion — full cleanup.
        close page → destroy context → clear cookies → clear refs → release handles
        """
        if sc is None:
            return
        try:
            # 1. Close page
            try:
                if sc.page and not sc.page.is_closed():
                    await sc.page.close()
            except Exception as e:
                get_handler().capture("stealth_manager", e, "close_page")

            # 2. Clear cookies
            try:
                if sc.context:
                    await sc.context.clear_cookies()
            except Exception as e:
                get_handler().capture("stealth_manager", e, "clear_cookies")

            # 3. Destroy context
            try:
                if sc.context:
                    await sc.context.close()
            except Exception as e:
                get_handler().capture("stealth_manager", e, "close_context")

            # 4. Clear memory references
            sc.page    = None
            sc.context = None

            # 5. Remove from registry
            with self._tlock:
                self._active_contexts.pop(sc.context_id, None)

        except Exception as e:
            get_handler().capture("stealth_manager", e, "release_context")

    async def navigate(self, url: str, wait: str = "networkidle",
                       timeout: int = 30000, proxy: str = None) -> dict:
        """One-shot navigate: acquire → load → release."""
        sc = await self.acquire_context(proxy=proxy)
        if sc is None:
            return {"status": 0, "body": "", "title": "", "url": url}
        try:
            resp = await sc.page.goto(url, timeout=timeout, wait_until=wait)
            body = await sc.page.content()
            return {
                "status" : resp.status if resp else 0,
                "body"   : body,
                "title"  : await sc.page.title(),
                "url"    : sc.page.url,
                "headers": dict(resp.headers) if resp else {},
            }
        except Exception as e:
            get_handler().capture("stealth_manager", e, f"navigate:{url[:60]}")
            return {"status": 0, "body": "", "title": "", "url": url}
        finally:
            await self.release_context(sc)

    async def screenshot(self, url: str, out_path: str,
                         proxy: str = None) -> bool:
        """Capture screenshot and release immediately."""
        sc = await self.acquire_context(proxy=proxy)
        if sc is None:
            return False
        try:
            await sc.page.goto(url, timeout=20000, wait_until="domcontentloaded")
            await sc.page.screenshot(path=out_path, full_page=True)
            return True
        except Exception as e:
            get_handler().capture("stealth_manager", e, f"screenshot:{url[:60]}")
            return False
        finally:
            await self.release_context(sc)

    async def close_all(self):
        """Shutdown entire browser — call at scan end."""
        try:
            with self._tlock:
                contexts = list(self._active_contexts.values())
            for sc in contexts:
                await self.release_context(sc)
            if self._browser:
                await self._browser.close()
                self._browser = None
            if self._playwright:
                await self._playwright.__aexit__(None, None, None)
                self._playwright = None
            self._ready = False
            if self.log:
                self.log.info("[StealthMgr] Browser closed cleanly")
        except Exception as e:
            get_handler().capture("stealth_manager", e, "close_all")

    async def _launch_browser(self):
        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().__aenter__()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--memory-pressure-off",
                    "--max_old_space_size=512",
                ],
            )
            self._ready = True
            if self.log:
                self.log.info("[StealthMgr] Browser launched (shared instance)")
        except ImportError:
            if self.log:
                self.log.warn("[StealthMgr] Playwright not installed")
        except Exception as e:
            get_handler().capture("stealth_manager", e, "_launch_browser")

    @property
    def active_context_count(self) -> int:
        with self._tlock:
            return len(self._active_contexts)

    def status(self) -> dict:
        return {
            "ready"          : self._ready,
            "active_contexts": self.active_context_count,
            "max_contexts"   : self.MAX_CONTEXTS,
        }
