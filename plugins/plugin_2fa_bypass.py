#!/usr/bin/env python3
# plugins/plugin_2fa_bypass.py — 2FA Bypass Detection (requires --lab)
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY
import re, time, random
from core.base_step import BasePlugin
from core.http_client import sync_get, sync_post
from core.error_handler import get_handler

CODES    = ["000000","123456","111111","999999","123123","000001","888888"]
OTP_KW   = [r"otp",r"totp",r"verification.?code",r"2fa",r"two.?factor",r"authenticator"]
OTP_PATHS= ["/2fa","/otp","/verify","/mfa","/auth/otp","/login/verify","/account/2fa","/api/2fa/verify"]

class Plugin2FABypass(BasePlugin):
    PLUGIN_NAME="2fa_bypass"; PLUGIN_VERSION="1.0"
    name="plugin_2fa_bypass"; description="2FA bypass detection"
    requires_lab=True

    def run(self):
        self.log.info("[2FA] Starting 2FA bypass detection")
        endpoints = self._find_endpoints()
        if not endpoints:
            self.log.info("[2FA] No 2FA endpoints detected"); return
        for ep in endpoints[:5]:
            try: self._test_default_codes(ep)
            except Exception as e: get_handler().capture("2fa_bypass",e,f"default_codes:{ep}")
            try: self._test_rate_limit(ep)
            except Exception as e: get_handler().capture("2fa_bypass",e,f"rate_limit:{ep}")
            try: self._test_step_skip()
            except Exception as e: get_handler().capture("2fa_bypass",e,"step_skip")

    def _find_endpoints(self):
        found=[]; base=f"https://{self.target}"
        h={"User-Agent":"Mozilla/5.0","Accept":"*/*"}
        for path in OTP_PATHS:
            try:
                r=sync_get(f"{base}{path}",headers=h,timeout=6)
                if r and r.get("status") in (200,302,400,405,422):
                    if any(re.search(kw,r.get("body",""),re.I) for kw in OTP_KW):
                        found.append(f"{base}{path}")
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("plugin_2fa_bypass", _e)
        return found

    def _test_default_codes(self, endpoint):
        h={"User-Agent":"Mozilla/5.0","Content-Type":"application/json"}
        if getattr(self.args,"cookie",None): h["Cookie"]=self.args.cookie
        for code in CODES:
            try:
                r=sync_post(endpoint,json={"otp":code,"code":code,"token":code},headers=h,timeout=8)
                if r and self._is_success(r.get("body",""),r.get("status",0)):
                    self.add_finding("2FA_BYPASS_DEFAULT_CODE",endpoint,
                        f"Code '{code}' accepted|status={r.get('status')}",0.92,"high")
                    self.log.warn(f"[2FA] Default code accepted: {code}"); return
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("plugin_2fa_bypass", _e)

    def _test_rate_limit(self, endpoint):
        h={"User-Agent":"Mozilla/5.0","Content-Type":"application/json"}
        blocked=False
        for _ in range(15):
            try:
                r=sync_post(endpoint,json={"otp":str(random.randint(100000,999999))},headers=h,timeout=5)
                if r and r.get("status") in (429,423,403): blocked=True; break
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("plugin_2fa_bypass", _e)
            time.sleep(0.1)
        if not blocked:
            self.add_finding("2FA_RATE_LIMIT_BYPASS",endpoint,"15 attempts without lockout",0.80,"medium")

    def _test_step_skip(self):
        h={"User-Agent":"Mozilla/5.0"}
        if getattr(self.args,"cookie",None): h["Cookie"]=self.args.cookie
        for path in ["/dashboard","/home","/account","/profile","/settings"]:
            try:
                r=sync_get(f"https://{self.target}{path}",headers=h,timeout=7)
                if r and r.get("status")==200 and any(re.search(p,r.get("body",""),re.I)
                   for p in [r"dashboard",r"welcome",r"logout",r"profile"]):
                    self.add_finding("2FA_STEP_SKIP",f"https://{self.target}{path}",
                        "Post-auth page accessible without 2FA",0.75,"high")
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("plugin_2fa_bypass", _e)

    def _is_success(self, body, status):
        if status in (302,303): return True
        return any(re.search(p,body,re.I) for p in
            [r'"success"\s*:\s*true',r'"authenticated"\s*:\s*true',r"dashboard",r"Set-Cookie.*session="])
