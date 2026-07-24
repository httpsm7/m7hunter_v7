#!/usr/bin/env python3
# core/rate_bypass.py — WAF/Rate-Limit Bypass Helpers
# MilkyWay Intelligence | Author: Sharlix

import random, time

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/8.7.1",
    "python-requests/2.31.0",
]

TOOL_TIMEOUTS = {
    "subfinder"   : {"default": 120, "min": 60,  "max": 300},
    "amass"       : {"default": 300, "min": 120, "max": 600},
    "dnsx"        : {"default": 120, "min": 60,  "max": 240},
    "httpx"       : {"default": 120, "min": 60,  "max": 300},
    "gau"         : {"default": 120, "min": 60,  "max": 240},
    "waybackurls" : {"default": 120, "min": 60,  "max": 240},
    "katana"      : {"default": 300, "min": 120, "max": 600},
    "hakrawler"   : {"default": 180, "min": 90,  "max": 360},
    "arjun"       : {"default": 240, "min": 120, "max": 480},
    "naabu"       : {"default": 300, "min": 120, "max": 600},
    "nmap"        : {"default": 300, "min": 120, "max": 900},
    "nuclei"      : {"default": 1800,"min": 600, "max": 3600},
    "dalfox"      : {"default": 300, "min": 120, "max": 600},
    "sqlmap"      : {"default": 600, "min": 300, "max": 1200},
    "ffuf"        : {"default": 300, "min": 120, "max": 600},
    "subzy"       : {"default": 120, "min": 60,  "max": 240},
    "gowitness"   : {"default": 300, "min": 120, "max": 600},
    "default"     : {"default": 300, "min": 120, "max": 600},
}


class RateBypass:
    def __init__(self, min_delay: float = 0.3, max_delay: float = 1.5):
        self.min_d = min_delay
        self.max_d = max_delay

    def ua(self) -> str:
        return random.choice(USER_AGENTS)

    def fake_ip(self) -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def headers(self) -> dict:
        ip = self.fake_ip()
        return {
            "User-Agent"     : self.ua(),
            "X-Forwarded-For": ip,
            "X-Real-IP"      : ip,
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control"  : "no-cache",
        }

    def jitter(self):
        time.sleep(random.uniform(self.min_d, self.max_d))

    def curl_flags(self) -> str:
        h = self.headers()
        return " ".join(f'-H "{k}: {v}"' for k, v in list(h.items())[:2])


class TimeoutManager:
    def __init__(self, base_multiplier: float = 1.0):
        self.multiplier = base_multiplier
        self._history   = {}

    def get(self, tool_name: str) -> int:
        cfg      = TOOL_TIMEOUTS.get(tool_name, TOOL_TIMEOUTS["default"])
        base     = cfg["default"]
        adjusted = int(base * self.multiplier)
        hist     = self._history.get(tool_name, [])
        if len(hist) >= 2:
            timeout_rate = sum(1 for _, to in hist if to) / len(hist)
            if timeout_rate >= 0.5:
                adjusted = min(int(adjusted * 1.5), cfg["max"])
        return adjusted

    def record(self, tool_name: str, elapsed: float, timed_out: bool):
        self._history.setdefault(tool_name, [])
        self._history[tool_name].append((elapsed, timed_out))
        self._history[tool_name] = self._history[tool_name][-5:]

    def set_stealth(self): self.multiplier = 2.0
    def set_fast(self):    self.multiplier = 0.7
