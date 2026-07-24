#!/usr/bin/env python3
# core/stealth.py — Playwright Stealth Browser + WAF Evasion
# Blueprint Fix: Real browser fingerprints, proxy rotation, header randomization
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import random
from core.error_handler import get_handler

PROFILES = [
    {"ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
     "platform":"Win32","vendor":"Google Inc.","lang":"en-US","tz":"America/New_York","w":1920,"h":1080},
    {"ua":"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Version/17.4.1 Safari/605.1.15",
     "platform":"MacIntel","vendor":"Apple Computer, Inc.","lang":"en-GB","tz":"Europe/London","w":2560,"h":1600},
    {"ua":"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
     "platform":"Linux x86_64","vendor":"","lang":"en-US","tz":"America/Los_Angeles","w":1366,"h":768},
    {"ua":"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
     "platform":"Linux armv8l","vendor":"Google Inc.","lang":"en-US","tz":"America/Chicago","w":393,"h":851},
]

STEALTH_JS = """
Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
if(!window.chrome){window.chrome={runtime:{},loadTimes:()=>{},csi:()=>{},app:{}};}
const _oq=window.navigator.permissions.query.bind(navigator.permissions);
window.navigator.permissions.query=(p)=>p.name==='notifications'?
  Promise.resolve({state:Notification.permission}):_oq(p);
Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});
Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});
delete window.__nightmare; delete window._phantom; delete window.callPhantom;
"""

class StealthBrowser:
    def __init__(self, args=None, log=None, proxy=None):
        self.args    = args
        self.log     = log
        self._proxy  = proxy or (getattr(args,'proxy',None) if args else None)
        self._profile= random.choice(PROFILES)
        self._browser= None; self._ctx = None; self._page = None; self._pw = None

    async def __aenter__(self):
        await self._launch(); return self

    async def __aexit__(self, *a):
        await self._close()

    async def _launch(self):
        try:
            from playwright.async_api import async_playwright
            self._pw = await async_playwright().__aenter__()
            opts = {"headless":True,"args":["--no-sandbox","--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled"]}
            if self._proxy: opts["proxy"] = {"server": self._proxy}
            self._browser = await self._pw.chromium.launch(**opts)
            ctx_opts = {"user_agent":self._profile["ua"],"locale":self._profile["lang"],
                        "timezone_id":self._profile["tz"],
                        "viewport":{"width":self._profile["w"],"height":self._profile["h"]}}
            if self._proxy: ctx_opts["proxy"] = {"server":self._proxy}
            self._ctx = await self._browser.new_context(**ctx_opts)
            await self._ctx.add_init_script(STEALTH_JS)
            await self._ctx.set_extra_http_headers({"Accept-Language":self._profile["lang"],
                "Accept-Encoding":"gzip, deflate, br"})
            self._page = await self._ctx.new_page()
        except ImportError:
            if self.log: self.log.warn("[Stealth] playwright not installed — stealth unavailable")
        except Exception as e:
            get_handler().capture("stealth", e, "_launch")

    async def get(self, url, timeout=30000):
        if not self._page: return {"status":0,"body":"","title":"","headers":{}}
        try:
            r = await self._page.goto(url, timeout=timeout, wait_until="networkidle")
            return {"status":r.status if r else 0,"body":await self._page.content(),
                    "title":await self._page.title(),"headers":dict(r.headers) if r else {}}
        except Exception as e:
            get_handler().capture("stealth", e, f"get:{url}")
            return {"status":0,"body":"","title":"","headers":{}}

    async def screenshot(self, path):
        if self._page:
            try: await self._page.screenshot(path=path, full_page=True)
            except Exception as e: get_handler().capture("stealth", e, "screenshot")

    async def _close(self):
        try:
            if self._browser: await self._browser.close()
            if self._pw: await self._pw.__aexit__(None,None,None)
        except Exception as e: get_handler().capture("stealth", e, "_close")

    @staticmethod
    def random_ua(): return random.choice(PROFILES)["ua"]
