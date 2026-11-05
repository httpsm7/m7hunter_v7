#!/usr/bin/env python3
# modules/step05_crawl.py — Web Crawl + JS Extraction V7 (BUG FIXED)
# FIXED: js_files.txt always populated correctly
# FIXED: auth uses new -s -a -j flags
# FIXED: JS extraction runs AFTER all crawl methods
# FIXED: katana cookie flag syntax
# FIXED: JS matched by content-type not just extension
# Source: Bug Hunter Methodology — crawl methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, asyncio, shutil, pathlib, urllib.request, urllib.error
from core.utils import count_lines, safe_read, FormatFixer

# JS URL patterns — catches .js, .jsx, .ts, .mjs, bundles, chunks
JS_URL_PATTERN = re.compile(
    r'https?://[^\s"\'<>]+\.(?:js|jsx|ts|mjs|bundle|chunk|min\.js)'
    r'(?:\?[^\s"\'<>]*)?',
    re.I
)
JS_SRC_PATTERN = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\']',
    re.I
)
# Also catch paths that look like JS (no extension but contain /js/ or /static/)
JS_PATH_PATTERN = re.compile(
    r'(?:href|src|url)=["\']([^"\']*(?:/js/|/scripts?/|/static/|/assets/|/bundle)[^"\']*)["\']',
    re.I
)


class Step05Crawl:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p    = self.p
        live = p.files["live_hosts"]
        out  = p.files["urls"]
        js   = p.files["js_files"]
        par  = p.files.get("params", f"{p.out}/{p.prefix}_params.txt")
        t    = p.tmgr.get

        # ── Get targets ───────────────────────────────────────────
        hosts = safe_read(p.files.get("fmt_url","")) or safe_read(live)
        if not hosts:
            tgt = p.target if p.target.startswith("http") else "https://" + p.target
            hosts = [tgt]
        hosts = hosts[:20]

        # ── Build auth flags from NEW cli (-s -a -j) ──────────────
        cookie  = getattr(p.args,"cookie",None)  or getattr(p.args,"session",None)
        auth_hv = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        jwt_tok = getattr(p.args,"jwt",None)     or getattr(p.args,"_jwt_token",None)

        if jwt_tok and not auth_hv:
            auth_hv = f"Bearer {jwt_tok}"

        cookie_hdr  = f"Cookie: {cookie}"   if cookie  else ""
        auth_hdr    = f"Authorization: {auth_hv}" if auth_hv else ""

        p.log.info(f"Crawling {len(hosts)} hosts — wayback + gau + katana + SPA + Python")

        # ── Ensure output files exist ─────────────────────────────
        for f_path in [out, js, par]:
            pathlib.Path(f_path).touch()

        domain = p.target.replace("https://","").replace("http://","").split("/")[0]

        # ── Waybackurls ───────────────────────────────────────────
        p.shell(
            f"waybackurls {domain} 2>/dev/null",
            label="waybackurls", tool_name="waybackurls",
            append_file=out, timeout=t("waybackurls")
        )

        # ── gau ───────────────────────────────────────────────────
        p.shell(
            f"gau --threads 5 --subs {domain} 2>/dev/null",
            label="gau", tool_name="gau",
            append_file=out, timeout=t("gau")
        )

        # ── katana (deep JS crawl + js file extraction) ───────────
        for host in hosts[:10]:
            hdrs = ""
            if cookie_hdr:  hdrs += f"-H '{cookie_hdr}' "
            if auth_hdr:    hdrs += f"-H '{auth_hdr}' "

            # katana writes JS files to separate output if -jsluice
            katana_js = f"{p.out}/{p.prefix}_katana_js.txt"
            p.shell(
                f"katana -u {host} -silent -d 3 -jc -kf all "
                f"-ef png,jpg,gif,svg,woff,ttf,css "
                f"{hdrs} 2>/dev/null",
                label=f"katana {host[:35]}",
                tool_name="katana",
                append_file=out, timeout=t("katana")
            )

        # ── hakrawler ─────────────────────────────────────────────
        for host in hosts[:5]:
            hdrs = f"-h '{cookie_hdr}'" if cookie_hdr else ""
            p.shell(
                f"echo {host} | hakrawler -d 3 -subs {hdrs} 2>/dev/null",
                label=f"hakrawler {host[:35]}",
                tool_name="hakrawler",
                append_file=out, timeout=t("hakrawler")
            )

        # ── gospider ─────────────────────────────────────────────
        for host in hosts[:5]:
            hdrs = f"-H '{cookie_hdr}'" if cookie_hdr else ""
            p.shell(
                f"gospider -s {host} -d 3 -t 10 {hdrs} --js --sitemap 2>/dev/null",
                label=f"gospider {host[:35]}",
                tool_name="gospider",
                append_file=out, timeout=t("gospider")
            )

        # ── SPA crawl (React/Vue/Angular) ─────────────────────────
        try:
            asyncio.run(self._spa_crawl(hosts[:5], out))
        except Exception as e:
            p.log.warn(f"SPA crawl: {e}")

        # ── Python fallback — runs regardless (never skip) ────────
        # BUG FIX: Previously only ran if out was EMPTY
        # Now ALWAYS runs to ensure JS files are captured
        self._python_crawl(hosts[:5], out, js, cookie, auth_hv)

        # ── JS EXTRACTION — runs AFTER all crawl methods ──────────
        # BUG FIX: Was running BEFORE python fallback → empty js_files
        self._extract_js_files(out, js, hosts)

        # ── Parameter extraction ──────────────────────────────────
        # gf patterns
        for gf_pat in ["xss","sqli","ssrf","redirect","lfi"]:
            p.shell(
                f"cat {out} 2>/dev/null | grep '?' | gf {gf_pat} 2>/dev/null",
                append_file=par, timeout=30
            )
        # Raw params (fallback)
        p.shell(
            f"cat {out} 2>/dev/null | grep '?' | sort -u | head -100",
            append_file=par, timeout=15
        )

        
        if count_lines(out) == 0:
            self.p.log.warn("  Crawl: 0 URLs — aggressive probe starting")
            for _h in hosts[:3]:
                self._aggressive_probe_crawl(_h.rstrip("/"), out, js)

        # ── Dedup everything ──────────────────────────────────────
        for f_path in [out, js, par]:
            if os.path.isfile(f_path) and count_lines(f_path) > 0:
                p.shell(f"sort -u {f_path} -o {f_path} 2>/dev/null", timeout=15)

        # ── Final stats ───────────────────────────────────────────
        n_urls   = count_lines(out)
        n_js     = count_lines(js)
        n_params = count_lines(par)
        p.log.success(f"URLs: {n_urls} | JS files: {n_js} | Params: {n_params}")

        if n_js == 0:
            p.log.warn("JS files: 0 found — JS analysis will be limited")
        else:
            p.log.info(f"  Sample JS: {safe_read(js)[:2]}")

    # ─────────────────────────────────────────────────────────────
    # BUG FIX: Python crawl now ALWAYS extracts JS, not just fallback
    # ─────────────────────────────────────────────────────────────
    def _aggressive_probe_crawl(self, host, out, js):
        """Last resort: probe common paths, extract all links."""
        import urllib.request, pathlib, re as r2
        hdrs = {"User-Agent": "Mozilla/5.0 (M7Hunter/7.0)"}
        c = getattr(self.p.args,"cookie",None) or getattr(self.p.args,"session",None)
        if c: hdrs["Cookie"] = c
        urls = set(); jss = set()
        host = host.rstrip("/")
        for path in ["/","/login","/api","/api/v1","/search",
                     "/register","/dashboard","/admin","/app",
                     "/static","/assets","/about","/contact"]:
            try:
                req  = urllib.request.Request(host+path, headers=hdrs)
                resp = urllib.request.urlopen(req, timeout=8)
                body = resp.read(500000).decode("utf-8","ignore")
                if resp.status not in (200,201): continue
                # extract links
                for item in (r2.findall(r'href="([^"<>]+)"', body)
                              + r2.findall(r"href='([^'<>]+)'", body)
                              + r2.findall(r'src="([^"<>]+)"', body)
                              + r2.findall(r"src='([^'<>]+)'", body)
                              + r2.findall(r'action="([^"<>]+)"', body)):
                    if not item: continue
                    if item.startswith("//"): item = "https:" + item
                    elif item.startswith("/"): item = host + item
                    elif not item.startswith("http"): continue
                    urls.add(item)
                    if r2.search(r"\.(?:js|jsx|ts|mjs)(\?|$)", item):
                        jss.add(item)
            except Exception:
                pass
        if urls:
            pathlib.Path(out).touch()
            open(out,"a").write("\n".join(sorted(urls))+"\n")
            self.p.log.info(f"  Aggressive: {len(urls)} URLs | {len(jss)} JS from {host[:35]}")
        if jss:
            pathlib.Path(js).touch()
            open(js,"a").write("\n".join(sorted(jss))+"\n")
        return len(urls)

    def _python_crawl(self, hosts: list, out: str, js: str,
                      cookie: str, auth_hv: str):
        """
        Python direct crawl — always runs to supplement tool output.
        Extracts all links + JS file URLs from HTML source.
        """
        headers = {"User-Agent": "Mozilla/5.0 (compatible; M7Hunter/7.0)"}
        if cookie:  headers["Cookie"] = cookie
        if auth_hv: headers["Authorization"] = auth_hv if auth_hv.startswith("Bearer") else f"Bearer {auth_hv}"

        for host in hosts:
            for path in ["/", "/app", "/api", "/static"]:
                url = host.rstrip("/") + path
                try:
                    req  = urllib.request.Request(url, headers=headers)
                    resp = urllib.request.urlopen(req, timeout=10)
                    body = resp.read(1000000).decode("utf-8","ignore")
                except Exception:
                    continue

                # Extract all hrefs
                links = re.findall(r'href=["\']([^"\'<>]+)["\']', body, re.I)
                # Extract script src
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
                # Extract fetch/axios URLs
                api_urls = re.findall(r'fetch\(["\']([^"\']+)["\']', body, re.I)

                full_links  = []
                full_js     = []

                for item in links + scripts + api_urls:
                    if not item.startswith("http"):
                        if item.startswith("//"):
                            item = "https:" + item
                        elif item.startswith("/"):
                            item = host.rstrip("/") + item
                        else:
                            item = host.rstrip("/") + "/" + item

                    if item.startswith("http"):
                        full_links.append(item)
                        # Check if JS
                        if (re.search(r'\.(?:js|jsx|ts|mjs)([\?#]|$)', item, re.I) or
                            any(x in item for x in ['/js/','/scripts/','/static/js','/bundle','/chunk'])):
                            full_js.append(item)

                if full_links:
                    with open(out,"a") as f:
                        f.write("\n".join(full_links) + "\n")

                if full_js:
                    with open(js,"a") as f:
                        f.write("\n".join(full_js) + "\n")
                    self.p.log.info(
                        f"  Python crawl: {len(full_links)} URLs, "
                        f"{len(full_js)} JS files from {url[:50]}"
                    )

    # ─────────────────────────────────────────────────────────────
    # BUG FIX: JS extraction now runs AFTER all crawl methods
    # ─────────────────────────────────────────────────────────────
    def _extract_js_files(self, out: str, js: str, hosts: list):
        """
        Extract JS file URLs from crawled output.
        Multiple extraction strategies to ensure nothing is missed.
        """
        # Strategy 1: grep from urls file
        self.p.shell(
            f"cat {out} 2>/dev/null | "
            f"grep -iE '\\.(js|jsx|ts|mjs)(\\?|$|#)' | "
            f"grep -v '\\.(css|png|jpg|gif|ico)' | sort -u",
            label="js extract grep",
            append_file=js, timeout=20
        )

        # Strategy 2: grep for JS-like paths
        self.p.shell(
            f"cat {out} 2>/dev/null | "
            f"grep -iE '/(js|scripts?|static/js|assets/js|bundle|chunk)/' | "
            f"grep -v '\\.(css|png|jpg)' | sort -u",
            label="js path extract",
            append_file=js, timeout=20
        )

        # Strategy 3: direct JS file probing on live hosts
        known_js_paths = [
            "/static/js/main.js", "/assets/js/app.js",
            "/js/app.js", "/bundle.js", "/main.js",
            "/app.js", "/js/main.js", "/dist/bundle.js",
            "/build/static/js/main.chunk.js",
            "/static/js/runtime-main.js",
            "/js/vendor.js", "/js/chunk-vendors.js",
            "/assets/index.js", "/resources/js/app.js",
        ]
        headers = {"User-Agent": "Mozilla/5.0 (compatible; M7Hunter/7.0)"}
        cookie  = getattr(self.p.args,"cookie",None) or getattr(self.p.args,"session",None)
        if cookie: headers["Cookie"] = cookie

        for host in hosts[:3]:
            for path in known_js_paths:
                url = host.rstrip("/") + path
                try:
                    req  = urllib.request.Request(url, headers=headers)
                    resp = urllib.request.urlopen(req, timeout=5)
                    ct   = resp.headers.get("content-type","")
                    # Accept if JS content-type or small JS-like response
                    if resp.status == 200 and ("javascript" in ct or "text/plain" in ct):
                        with open(js,"a") as f:
                            f.write(url + "\n")
                        self.p.log.info(f"  JS found: {url}")
                except Exception:
                    pass

    # ─────────────────────────────────────────────────────────────
    # SPA crawl
    # ─────────────────────────────────────────────────────────────
    async def _spa_crawl(self, hosts: list, out: str):
        crawler = self.p.spa_crawler
        for host in hosts:
            try:
                urls = await crawler.crawl(host, depth=2)
                if urls:
                    with open(out,"a") as f:
                        f.write("\n".join(u for u in urls if u.startswith("http")) + "\n")
                    info = crawler.detect_spa("")
                    if info.get("is_spa"):
                        self.p.log.info(
                            f"  SPA ({info['framework']}): {len(urls)} URLs — {host[:35]}")
            except Exception:
                pass
