#!/usr/bin/env python3
# engines/interactsh.py — OOB Blind Detection Client
# MilkyWay Intelligence | Author: Sharlix

import urllib.request, json, threading, time, random, string

PUBLIC_SERVERS = [
    "oast.pro", "oast.live", "oast.site", "oast.fun", "oast.me", "interact.sh"
]


class InteractshClient:
    def __init__(self, custom_url: str = None, log=None):
        self.log       = log
        self.server    = custom_url or random.choice(PUBLIC_SERVERS)
        self._callbacks: dict = {}
        self._lock     = threading.Lock()
        self._running  = False

    def _gen_token(self) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))

    def start(self):
        self._running = True
        threading.Thread(target=self._poll_loop, daemon=True).start()
        if self.log:
            self.log.info(f"OOB server: {self.server}")

    def stop(self):
        self._running = False

    def get_payload(self, vuln_type: str = "ssrf", context_url: str = "") -> str:
        token     = self._gen_token()
        subdomain = f"m7{token}.{self.server}"
        with self._lock:
            self._callbacks[token] = {
                "vuln_type"  : vuln_type,
                "context_url": context_url,
                "time"       : time.time(),
                "triggered"  : False,
            }
        return f"http://{subdomain}"

    def _poll_loop(self):
        while self._running:
            try:
                self._poll_once()
            except Exception:
                pass
            time.sleep(5)

    def _poll_once(self):
        if not self._callbacks:
            return
        try:
            url = f"https://{self.server}/poll"
            req  = urllib.request.Request(url, headers={"User-Agent": "M7Hunter/7.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read().decode())
            for interaction in data.get("data", []):
                full_id = interaction.get("full-id", "")
                for token in list(self._callbacks.keys()):
                    if token in full_id:
                        with self._lock:
                            self._callbacks[token]["triggered"]   = True
                            self._callbacks[token]["interaction"] = interaction
                        if self.log:
                            cb = self._callbacks[token]
                            self.log.finding(
                                "high",
                                f"BLIND_{cb['vuln_type'].upper()}_OOB",
                                cb["context_url"],
                                f"OOB callback from "
                                f"{interaction.get('remote-address', '?')}",
                            )
        except Exception:
            pass

    def get_triggered(self) -> dict:
        with self._lock:
            return {t: cb for t, cb in self._callbacks.items() if cb["triggered"]}

    def is_available(self) -> bool:
        try:
            urllib.request.urlopen(f"https://{self.server}", timeout=5)
            return True
        except Exception:
            return False
