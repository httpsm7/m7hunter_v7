#!/usr/bin/env python3
# integrations/telegram_bot.py — M7Hunter V7 Telegram Control Bot
# MilkyWay Intelligence | Author: Sharlix

import os, json, time, threading, urllib.request, urllib.parse

HELP_TEXT = """
*M7Hunter V7 Telegram Bot*

Commands:
/scan <url>   — Start scan
/status       — Active scans
/findings     — Latest findings
/stop         — Stop current scan
/help         — This message

*Authorized use only*
"""

AUTHORIZED_CHATS = set()


class TelegramBot:
    def __init__(self, token: str, log=None, results_dir: str = "results"):
        self.token       = token
        self.log         = log
        self.results_dir = results_dir
        self._offset     = 0
        self._running    = False
        self._active_scans = {}
        self._base_url   = f"https://api.telegram.org/bot{token}"

    def run(self):
        self._running = True
        if self.log:
            self.log.success("Telegram bot started — polling for commands")
        while self._running:
            try:
                self._poll()
            except Exception as e:
                if self.log:
                    self.log.warn(f"TG bot poll error: {e}")
            time.sleep(2)

    def stop(self):
        self._running = False

    def _poll(self):
        url    = f"{self._base_url}/getUpdates?offset={self._offset}&timeout=10"
        try:
            resp   = urllib.request.urlopen(url, timeout=15)
            data   = json.loads(resp.read().decode())
        except Exception:
            return

        if not data.get("ok"):
            return

        for update in data.get("result", []):
            self._offset = update["update_id"] + 1
            msg = update.get("message", {})
            if not msg:
                continue
            chat_id = msg.get("chat",{}).get("id","")
            text    = msg.get("text","").strip()
            if not chat_id or not text:
                continue
            AUTHORIZED_CHATS.add(chat_id)
            self._handle(chat_id, text)

    def _handle(self, chat_id, text: str):
        parts   = text.split(None, 1)
        command = parts[0].lower().split("@")[0]
        args    = parts[1].strip() if len(parts) > 1 else ""

        if command == "/start" or command == "/help":
            self._send(chat_id, HELP_TEXT)

        elif command == "/scan":
            if not args:
                self._send(chat_id, "Usage: /scan target.com")
                return
            self._send(chat_id, f"🚀 Starting scan: `{args}`\n_This may take 10–30 minutes_",
                        parse_mode="Markdown")
            threading.Thread(
                target=self._run_scan, args=(chat_id, args), daemon=True
            ).start()

        elif command == "/status":
            if self._active_scans:
                lines = [f"• {t}: {s}" for t, s in self._active_scans.items()]
                self._send(chat_id, "Active scans:\n" + "\n".join(lines))
            else:
                self._send(chat_id, "No active scans.")

        elif command == "/findings":
            self._send_findings(chat_id)

        elif command == "/stop":
            self._send(chat_id, "⚠️ Stop command received — stopping at next checkpoint")
            self._active_scans.clear()

        else:
            self._send(chat_id, f"Unknown command: {command}\n/help for commands")

    def _run_scan(self, chat_id: str, target: str):
        self._active_scans[target] = "running"
        try:
            import subprocess, sys
            script = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "m7hunter.py"
            )
            cmd = [sys.executable, script, "-u", target, "--fast",
                   "--output", self.results_dir]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            self._active_scans[target] = f"pid:{proc.pid}"
            proc.wait(timeout=1800)
            self._send(chat_id, f"✅ Scan complete: `{target}`\n/findings to view results",
                        parse_mode="Markdown")
        except Exception as e:
            self._send(chat_id, f"❌ Scan error: {e}")
        finally:
            self._active_scans.pop(target, None)

    def _send_findings(self, chat_id: str):
        try:
            all_findings = []
            for root, _, files in os.walk(self.results_dir):
                for fname in files:
                    if fname.endswith(".json") and "finding" in fname:
                        path = os.path.join(root, fname)
                        with open(path) as f:
                            data = json.load(f)
                            all_findings.extend(data.get("findings",[])[:5])
            if not all_findings:
                self._send(chat_id, "No findings yet.")
                return
            lines = []
            for f in all_findings[:10]:
                sev  = f.get("severity","?").upper()
                vt   = f.get("vuln_type") or f.get("type","?")
                url  = f.get("url","")[:50]
                lines.append(f"🔴 `{sev}` {vt}\n  `{url}`")
            self._send(chat_id, "\n\n".join(lines), parse_mode="Markdown")
        except Exception as e:
            self._send(chat_id, f"Error fetching findings: {e}")

    def _send(self, chat_id, text: str, parse_mode: str = ""):
        try:
            params = {"chat_id": chat_id, "text": text}
            if parse_mode:
                params["parse_mode"] = parse_mode
            data = urllib.parse.urlencode(params).encode()
            urllib.request.urlopen(
                urllib.request.Request(
                    f"{self._base_url}/sendMessage", data=data, method="POST"
                ), timeout=10
            )
        except Exception:
            pass
