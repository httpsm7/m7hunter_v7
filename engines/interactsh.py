#!/usr/bin/env python3
# engines/interactsh.py — OOB Blind Detection Client V7
# Blueprint Fix: Added self-hosted HTTP callback server + unified get_all_callbacks()
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import urllib.request, json, threading, time, random, string
from core.error_handler import get_handler

PUBLIC_SERVERS = ["oast.pro","oast.live","oast.site","oast.fun","oast.me","interact.sh"]

class InteractshClient:
    def __init__(self, custom_url=None, log=None):
        self.log    = log
        self.server = custom_url or random.choice(PUBLIC_SERVERS)
        self._callbacks: dict = {}
        self._lock  = threading.Lock()
        self._running = False
        self._local_callbacks = []
        self._http_server = None
        self._http_port   = None
        self._public_ip   = None

    def _gen_token(self):
        return "".join(random.choices(string.ascii_lowercase+string.digits, k=10))

    def start(self):
        self._running = True
        threading.Thread(target=self._poll_loop, daemon=True).start()
        if self.log: self.log.info(f"OOB server: {self.server}")

    def stop(self): self._running = False

    def get_payload(self, vuln_type="ssrf", context_url="") -> str:
        token = self._gen_token()
        subdomain = f"m7{token}.{self.server}"
        with self._lock:
            self._callbacks[token] = {"vuln_type":vuln_type,"context_url":context_url,
                                       "time":time.time(),"triggered":False}
        return f"http://{subdomain}"

    def start_http_callback_server(self, port=7331) -> str:
        """Blueprint Fix: Self-hosted HTTP callback listener."""
        from http.server import BaseHTTPRequestHandler, HTTPServer
        parent = self
        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._handle("GET")
            def do_POST(self):
                l = int(self.headers.get("Content-Length",0))
                body = self.rfile.read(l).decode(errors="ignore") if l else ""
                self._handle("POST", body)
            def _handle(self, method, body=""):
                cb = {"ts":time.time(),"method":method,"path":self.path,
                      "source":self.client_address[0],"body":body,
                      "headers":dict(self.headers)}
                parent._local_callbacks.append(cb)
                self.send_response(200); self.end_headers()
                self.wfile.write(b"ok")
            def log_message(self, *a): pass

        for p in range(port, port+5):
            try:
                srv = HTTPServer(("0.0.0.0", p), _Handler)
                t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
                self._http_server = srv; self._http_port = p
                try:
                    r = urllib.request.urlopen("https://api.ipify.org", timeout=5)
                    self._public_ip = r.read().decode().strip()
                except Exception: self._public_ip = "127.0.0.1"
                if self.log: self.log.info(f"HTTP callback server: {self._public_ip}:{p}")
                return f"http://{self._public_ip}:{p}"
            except OSError: continue
        return ""

    def get_all_callbacks(self, wait_seconds=30) -> list:
        """Blueprint Fix: Unified collector — Interactsh + local HTTP server."""
        results = []
        seen    = set()
        end     = time.time() + wait_seconds
        while time.time() < end:
            try: self._poll_once()
            except Exception as e: get_handler().capture("interactsh", e, "poll")
            triggered = self.get_triggered()
            for token, cb in triggered.items():
                key = f"interactsh:{token}"
                if key not in seen:
                    seen.add(key)
                    results.append({"source":"interactsh","token":token,
                                    "type":cb.get("interaction",{}).get("type","dns"),
                                    "timestamp":cb["time"],"raw_data":cb})
            for cb in list(self._local_callbacks):
                key = f"http:{cb['ts']}"
                if key not in seen:
                    seen.add(key)
                    results.append({"source":"http_local","token":"",
                                    "type":"http","timestamp":cb["ts"],"raw_data":cb})
            time.sleep(5)
        return results

    def _poll_loop(self):
        while self._running:
            try: self._poll_once()
            except Exception as e: get_handler().capture("interactsh", e, "poll_loop")
            time.sleep(5)

    def _poll_once(self):
        if not self._callbacks: return
        try:
            url = f"https://{self.server}/poll"
            req  = urllib.request.Request(url,headers={"User-Agent":"M7Hunter/7.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read().decode())
            for interaction in data.get("data",[]):
                full_id = interaction.get("full-id","")
                for token in list(self._callbacks.keys()):
                    if token in full_id:
                        with self._lock:
                            self._callbacks[token]["triggered"]   = True
                            self._callbacks[token]["interaction"] = interaction
                        if self.log:
                            cb = self._callbacks[token]
                            self.log.finding("high",
                                f"BLIND_{cb['vuln_type'].upper()}_OOB",
                                cb["context_url"],
                                f"OOB callback from {interaction.get('remote-address','?')}",
                            )
        except Exception as e: get_handler().capture("interactsh", e, "_poll_once")

    def get_triggered(self) -> dict:
        with self._lock:
            return {t:cb for t,cb in self._callbacks.items() if cb["triggered"]}

    def is_available(self) -> bool:
        try: urllib.request.urlopen(f"https://{self.server}", timeout=5); return True
        except Exception: return False
