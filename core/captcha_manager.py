#!/usr/bin/env python3
# core/captcha_manager.py — CAPTCHA Provider Abstraction Layer
# Buildmap 7: Provider abstraction — 2Captcha, AntiCaptcha, CapMonster (optional)
# All integrations are OPTIONAL. No provider is bundled.
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import time, json
from abc import ABC, abstractmethod
from typing import Optional
from core.error_handler import get_handler


class CaptchaProvider(ABC):
    """Abstract base for all CAPTCHA providers."""

    @abstractmethod
    def solve_image(self, image_b64: str) -> Optional[str]:
        """Solve an image CAPTCHA. Returns solution string or None."""

    @abstractmethod
    def solve_recaptcha_v2(self, site_key: str, page_url: str) -> Optional[str]:
        """Solve reCAPTCHA v2. Returns g-recaptcha-response token."""

    @abstractmethod
    def solve_hcaptcha(self, site_key: str, page_url: str) -> Optional[str]:
        """Solve hCaptcha. Returns h-captcha-response token."""

    @abstractmethod
    def get_balance(self) -> float:
        """Check remaining API balance."""


class TwoCaptchaProvider(CaptchaProvider):
    """2Captcha integration — requires API key."""

    def __init__(self, api_key: str, timeout: int = 120):
        self._key     = api_key
        self._timeout = timeout
        self._base    = "http://2captcha.com"

    def solve_image(self, image_b64: str) -> Optional[str]:
        try:
            import urllib.request, urllib.parse
            data = urllib.parse.urlencode({
                "key": self._key, "method": "base64",
                "body": image_b64, "json": 1
            }).encode()
            r = urllib.request.urlopen(f"{self._base}/in.php", data, timeout=15)
            resp = json.loads(r.read())
            if resp.get("status") != 1:
                return None
            task_id = resp["request"]
            return self._poll(task_id)
        except Exception as e:
            get_handler().capture("captcha_2captcha", e, "solve_image")
            return None

    def solve_recaptcha_v2(self, site_key: str, page_url: str) -> Optional[str]:
        try:
            import urllib.request, urllib.parse
            data = urllib.parse.urlencode({
                "key": self._key, "method": "userrecaptcha",
                "googlekey": site_key, "pageurl": page_url, "json": 1
            }).encode()
            r = urllib.request.urlopen(f"{self._base}/in.php", data, timeout=15)
            resp = json.loads(r.read())
            if resp.get("status") != 1:
                return None
            return self._poll(resp["request"])
        except Exception as e:
            get_handler().capture("captcha_2captcha", e, "solve_recaptcha_v2")
            return None

    def solve_hcaptcha(self, site_key: str, page_url: str) -> Optional[str]:
        try:
            import urllib.request, urllib.parse
            data = urllib.parse.urlencode({
                "key": self._key, "method": "hcaptcha",
                "sitekey": site_key, "pageurl": page_url, "json": 1
            }).encode()
            r = urllib.request.urlopen(f"{self._base}/in.php", data, timeout=15)
            resp = json.loads(r.read())
            if resp.get("status") != 1:
                return None
            return self._poll(resp["request"])
        except Exception as e:
            get_handler().capture("captcha_2captcha", e, "solve_hcaptcha")
            return None

    def get_balance(self) -> float:
        try:
            import urllib.request
            url = f"{self._base}/res.php?key={self._key}&action=getbalance&json=1"
            r   = urllib.request.urlopen(url, timeout=10)
            return float(json.loads(r.read()).get("request", 0))
        except Exception:
            return -1.0

    def _poll(self, task_id: str, interval: int = 5) -> Optional[str]:
        import urllib.request
        deadline = time.time() + self._timeout
        while time.time() < deadline:
            time.sleep(interval)
            try:
                url  = f"{self._base}/res.php?key={self._key}&action=get&id={task_id}&json=1"
                r    = urllib.request.urlopen(url, timeout=10)
                resp = json.loads(r.read())
                if resp.get("status") == 1:
                    return resp["request"]
                if resp.get("request") == "ERROR_CAPTCHA_UNSOLVABLE":
                    return None
            except Exception as e:
                get_handler().capture("captcha_2captcha", e, "_poll")
        return None


class AntiCaptchaProvider(CaptchaProvider):
    """AntiCaptcha integration — requires API key."""

    def __init__(self, api_key: str, timeout: int = 120):
        self._key  = api_key
        self._timeout = timeout
        self._base = "https://api.anti-captcha.com"

    def _create_task(self, task: dict) -> Optional[str]:
        try:
            import urllib.request
            payload = json.dumps({"clientKey": self._key, "task": task}).encode()
            req  = urllib.request.Request(f"{self._base}/createTask",
                   data=payload, headers={"Content-Type": "application/json"})
            r    = urllib.request.urlopen(req, timeout=15)
            resp = json.loads(r.read())
            if resp.get("errorId") != 0:
                return None
            return str(resp["taskId"])
        except Exception as e:
            get_handler().capture("captcha_anticaptcha", e, "_create_task")
            return None

    def _get_result(self, task_id: str) -> Optional[str]:
        import urllib.request
        deadline = time.time() + self._timeout
        while time.time() < deadline:
            time.sleep(5)
            try:
                payload = json.dumps({"clientKey": self._key, "taskId": int(task_id)}).encode()
                req  = urllib.request.Request(f"{self._base}/getTaskResult",
                       data=payload, headers={"Content-Type": "application/json"})
                r    = urllib.request.urlopen(req, timeout=10)
                resp = json.loads(r.read())
                if resp.get("status") == "ready":
                    sol  = resp.get("solution", {})
                    return sol.get("gRecaptchaResponse") or sol.get("text")
            except Exception as e:
                get_handler().capture("captcha_anticaptcha", e, "_get_result")
        return None

    def solve_image(self, image_b64: str) -> Optional[str]:
        tid = self._create_task({"type": "ImageToTextTask", "body": image_b64})
        return self._get_result(tid) if tid else None

    def solve_recaptcha_v2(self, site_key: str, page_url: str) -> Optional[str]:
        tid = self._create_task({"type":"NoCaptchaTaskProxyless",
                                  "websiteURL": page_url,"websiteKey": site_key})
        return self._get_result(tid) if tid else None

    def solve_hcaptcha(self, site_key: str, page_url: str) -> Optional[str]:
        tid = self._create_task({"type":"HCaptchaTaskProxyless",
                                  "websiteURL": page_url,"websiteKey": site_key})
        return self._get_result(tid) if tid else None

    def get_balance(self) -> float:
        try:
            import urllib.request
            payload = json.dumps({"clientKey": self._key}).encode()
            req  = urllib.request.Request(f"{self._base}/getBalance",
                   data=payload, headers={"Content-Type": "application/json"})
            r    = urllib.request.urlopen(req, timeout=10)
            return float(json.loads(r.read()).get("balance", -1))
        except Exception:
            return -1.0


class CaptchaManager:
    """
    Provider abstraction layer — routes to active provider.
    All providers optional. No provider configured = skip CAPTCHA.
    """

    def __init__(self, provider: CaptchaProvider = None, log=None):
        self._provider = provider
        self.log       = log
        self._enabled  = provider is not None
        self._solved   = 0
        self._failed   = 0

    @classmethod
    def from_config(cls, config: dict, log=None) -> "CaptchaManager":
        """Build from config dict — provider auto-selected."""
        if not config or not config.get("enabled"):
            return cls(provider=None, log=log)
        provider_name = config.get("provider", "").lower()
        api_key       = config.get("api_key", "")
        if not api_key:
            if log: log.warn("[CaptchaMgr] No API key — CAPTCHA solving disabled")
            return cls(provider=None, log=log)
        if provider_name == "2captcha":
            return cls(TwoCaptchaProvider(api_key), log=log)
        if provider_name == "anticaptcha":
            return cls(AntiCaptchaProvider(api_key), log=log)
        if log: log.warn(f"[CaptchaMgr] Unknown provider: {provider_name}")
        return cls(provider=None, log=log)

    def solve_recaptcha(self, site_key: str, page_url: str) -> Optional[str]:
        if not self._enabled:
            return None
        try:
            result = self._provider.solve_recaptcha_v2(site_key, page_url)
            if result: self._solved += 1
            else:      self._failed += 1
            return result
        except Exception as e:
            get_handler().capture("captcha_manager", e, "solve_recaptcha")
            self._failed += 1
            return None

    def solve_hcaptcha(self, site_key: str, page_url: str) -> Optional[str]:
        if not self._enabled:
            return None
        try:
            result = self._provider.solve_hcaptcha(site_key, page_url)
            if result: self._solved += 1
            else:      self._failed += 1
            return result
        except Exception as e:
            get_handler().capture("captcha_manager", e, "solve_hcaptcha")
            return None

    def status(self) -> dict:
        return {
            "enabled" : self._enabled,
            "provider": type(self._provider).__name__ if self._provider else "none",
            "solved"  : self._solved,
            "failed"  : self._failed,
        }

    @property
    def enabled(self) -> bool:
        return self._enabled
