#!/usr/bin/env python3
# modules/step34_content_discovery.py — Content Discovery + JS Analysis V7
# NEW MODULE: directory brute force, JS endpoint extraction, param discovery
# Source: Bug Hunter Methodology + Kali Linux PWK + Coding for Pentester
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, json, shutil, urllib.request, urllib.error
from core.utils import safe_read, count_lines

# ── High-value paths (smart wordlist from Bug Hunter Methodology) ─────────────
SMART_WORDLIST = [
    # Admin panels
    "admin","administrator","admin/login","adminpanel","backend",
    "manage","management","manager","superadmin","controlpanel",
    "wp-admin","wp-login.php","phpmyadmin","cpanel","plesk",
    # API endpoints
    "api","api/v1","api/v2","api/v3","api/docs","api/swagger",
    "swagger.json","swagger.yaml","openapi.json","openapi.yaml",
    "graphql","graphiql","playground","api/graphql",
    # Auth
    "login","signin","register","signup","auth","oauth",
    "logout","forgot-password","reset-password","verify",
    # Sensitive files
    ".env",".git/HEAD",".git/config","config.php","config.yml",
    "config.json","settings.py","web.config","application.yml",
    "application.properties","docker-compose.yml","Dockerfile",
    ".htaccess",".htpasswd","robots.txt","sitemap.xml",
    "crossdomain.xml","clientaccesspolicy.xml",
    # Backups
    "backup","backup.zip","backup.tar.gz","db.sql","database.sql",
    "dump.sql","www.zip","site.tar.gz","wp-content/backup",
    # Debug/info endpoints
    "info","phpinfo.php","info.php","test.php","debug",
    "trace","actuator","actuator/health","actuator/env",
    "actuator/metrics","actuator/mappings","metrics",
    "health","healthcheck","status","version","ping",
    # Console
    "console","rails/info","dev","development","staging",
    # Files
    "upload","uploads","files","documents","media","images",
    "assets","static","js","css","src","source",
    # Jenkins/CI
    "jenkins","jenkins/login","sonar","sonarqube","gitlab",
    "jira","confluence","travis",
    # Cloud
    "aws","azure","gcp","s3","storage","cdn","bucket",
]

# ── JS analysis patterns (Bug Hunter Methodology) ─────────────────────────────
JS_ENDPOINT_PATTERNS = [
    # API endpoints in JS code
    re.compile(r'["\'](/api/[a-zA-Z0-9/_\-\.?=&%]+)["\']',         re.I),
    re.compile(r'fetch\(["\']([^"\']+)["\']',                        re.I),
    re.compile(r'axios\.[a-z]+\(["\']([^"\']+)["\']',               re.I),
    re.compile(r'http\.get\(["\']([^"\']+)["\']',                    re.I),
    re.compile(r'XMLHttpRequest.*open\(["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'url:\s*["\']([^"\']+)["\']',                       re.I),
    re.compile(r'endpoint:\s*["\']([^"\']+)["\']',                  re.I),
    re.compile(r'baseURL:\s*["\']([^"\']+)["\']',                   re.I),
    re.compile(r'path:\s*["\']([/][^"\']+)["\']',                   re.I),
    # Route definitions
    re.compile(r'router\.[a-z]+\(["\']([^"\']+)["\']',              re.I),
    re.compile(r'app\.[a-z]+\(["\']([/][^"\']+)["\']',             re.I),
]

JS_SECRET_PATTERNS = [
    (re.compile(r'["\']?(?:api_?key|apikey|api_?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', re.I),      "API_KEY"),
    (re.compile(r'["\']?(?:secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),                    "SECRET"),
    (re.compile(r'["\']?(?:token|auth_?token|access_?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9._\-]{20,})["\']', re.I),     "TOKEN"),
    (re.compile(r'AKIA[0-9A-Z]{16}',                                re.I),                                               "AWS_KEY"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}',                             re.I),                                               "GITHUB_PAT"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}',                          re.I),                                               "GOOGLE_API"),
    (re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,}',                  re.I),                                               "SLACK_TOKEN"),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY',    re.I),                                               "PRIVATE_KEY"),
]

# ── Parameter discovery patterns ──────────────────────────────────────────────
PARAM_PATTERNS = [
    re.compile(r'["\']([a-z_][a-z0-9_]{1,30})["\']:\s*["\']?\w', re.I),
    re.compile(r'[?&]([a-z_][a-z0-9_]{1,30})=', re.I),
    re.compile(r'name=["\']([a-z_][a-z0-9_]{1,30})["\']', re.I),
    re.compile(r'param["\']:\s*["\']([a-z_][a-z0-9_]{1,30})', re.I),
]

SENSITIVE_DIRS = {
    ".git", ".env", "admin", "phpmyadmin", "backup", "config",
    "actuator", "swagger", "debug", "console", ".htaccess",
    "phpinfo", "wp-admin", "wp-login",
}


class Step34ContentDiscovery:
    """
    Content Discovery + JS Analysis.
    Bug Hunter Methodology: find hidden endpoints before testing.
    1. Directory brute force (smart wordlist + ffuf)
    2. JS file analysis (endpoints, secrets, params)
    3. Parameter discovery (arjun)
    4. Sensitive path detection
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("content_results",
                             f"{p.out}/{p.prefix}_content.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        js_f  = p.files.get("js_files","")
        urls  = safe_read(p.files.get("urls",""))
        found = 0

        if not live:
            p.log.warn("Content: no live hosts"); return

        auth_h = self._build_auth(p)
        p.log.info(f"Content V7: {len(live)} hosts — ffuf + smart wordlist + JS analysis + arjun")

        for host in live[:5]:
            host = host.rstrip("/")

            # Phase 1: Directory brute force
            r = self._directory_scan(host, auth_h, out)
            found += r

            # Phase 2: Sensitive path quick-check
            r = self._sensitive_paths(host, auth_h, out)
            found += r

            p.bypass.jitter()

        # Phase 3: JS file analysis
        r = self._analyze_js_files(js_f, live, auth_h, out)
        found += r

        # Phase 4: Parameter discovery
        r = self._discover_params(urls[:30], auth_h, out)
        found += r

        p.log.success(f"Content V7: {found} findings")

    # ── Phase 1: Directory brute force ────────────────────────────────────────
    def _directory_scan(self, host: str, auth_h: dict, out: str) -> int:
        found = 0

        # Build cookie/auth flags
        cookie  = auth_h.get("Cookie","")
        auth_hv = auth_h.get("Authorization","")

        cookie_flag = f'-H "Cookie: {cookie}"' if cookie else ""
        auth_flag   = f'-H "Authorization: {auth_hv}"' if auth_hv else ""

        # ffuf fast scan
        if shutil.which("ffuf"):
            wordlist = self._get_wordlist()
            ffuf_out = f"{self.p.out}/{self.p.prefix}_ffuf.json"
            self.p.shell(
                f"ffuf -u {host}/FUZZ -w {wordlist} "
                f"-mc 200,201,301,302,401,403 "
                f"-o {ffuf_out} -of json -s "
                f"{cookie_flag} {auth_flag} "
                f"-t 50 -rate 200 2>/dev/null",
                label="ffuf dir scan", tool_name="ffuf", timeout=180
            )
            if os.path.isfile(ffuf_out):
                found += self._parse_ffuf_results(ffuf_out, out)
        else:
            # Python fallback: check smart wordlist directly
            found += self._python_dir_scan(host, auth_h, out)

        return found

    def _python_dir_scan(self, host: str, auth_h: dict, out: str) -> int:
        """Lightweight Python dir scan when ffuf not available."""
        found = 0
        for path in SMART_WORDLIST[:50]:
            url = f"{host}/{path}"
            try:
                req  = urllib.request.Request(
                    url, headers={**auth_h, "User-Agent": self.p.bypass.ua()})
                resp = urllib.request.urlopen(req, timeout=6)
                st   = resp.status
                body = resp.read(5000).decode("utf-8","ignore")
            except urllib.error.HTTPError as e:
                st, body = e.code, ""
            except Exception:
                continue

            if st in (200, 201):
                sev = "critical" if any(s in path for s in SENSITIVE_DIRS) else "medium"
                detail = f"Content discovered: /{path} → HTTP {st}"
                with open(out,"a") as f: f.write(f"CONTENT: {url} | {detail}\n")
                self.p.add_finding(sev,"CONTENT_DISCOVERY",url,detail,"content-v7", response=response, payload=payload)
                found += 1

            elif st == 403:
                # 403 = exists but forbidden = worth noting
                detail = f"Forbidden (exists): /{path} → HTTP 403"
                with open(out,"a") as f: f.write(f"FORBIDDEN: {url} | {detail}\n")
                self.p.add_finding("low","FORBIDDEN_ENDPOINT",url,detail,"content-v7", response=response, payload=payload)
        return found

    def _parse_ffuf_results(self, json_file: str, out: str) -> int:
        found = 0
        try:
            data = json.loads(open(json_file).read())
            for result in data.get("results",[]):
                url    = result.get("url","")
                status = result.get("status",0)
                length = result.get("length",0)
                path   = url.split("/")[-1] if "/" in url else url

                sev = "critical" if any(s in path.lower() for s in SENSITIVE_DIRS) else \
                      "high" if status == 200 else "low"

                detail = f"Directory: {url} → {status} ({length}b)"
                with open(out,"a") as f: f.write(f"CONTENT_FFUF: {url} | {detail}\n")
                self.p.add_finding(sev,"CONTENT_DISCOVERY",url,detail,"ffuf", response=response, payload=payload)
                found += 1
        except Exception:
            pass
        return found

    # ── Phase 2: Sensitive paths ──────────────────────────────────────────────
    def _sensitive_paths(self, host: str, auth_h: dict, out: str) -> int:
        CRITICAL_PATHS = [
            (".git/HEAD",            "Git repository exposed"),
            (".env",                 ".env file exposed — credentials leak"),
            ("phpinfo.php",          "PHPInfo exposed — server config"),
            ("actuator/env",         "Spring Boot actuator env exposed"),
            ("actuator/heapdump",    "Spring Boot heap dump exposed"),
            ("api/swagger.json",     "Swagger API docs exposed"),
            ("swagger.json",         "Swagger API docs exposed"),
            ("openapi.json",         "OpenAPI spec exposed"),
            (".htaccess",            ".htaccess exposed — config leak"),
            ("config.json",          "Config file exposed"),
            ("wp-config.php.bak",    "WordPress config backup exposed"),
            ("backup.sql",           "Database backup exposed"),
            ("server-status",        "Apache server-status exposed"),
            ("server-info",          "Apache server-info exposed"),
            ("__debug__",            "Django debug endpoint exposed"),
            ("_profiler",            "Symfony profiler exposed"),
        ]
        found = 0
        for path, label in CRITICAL_PATHS:
            url = f"{host}/{path}"
            try:
                req  = urllib.request.Request(
                    url, headers={**auth_h, "User-Agent": self.p.bypass.ua()})
                resp = urllib.request.urlopen(req, timeout=6)
                st   = resp.status
                body = resp.read(5000).decode("utf-8","ignore")
            except urllib.error.HTTPError as e:
                st, body = e.code, ""
            except Exception:
                continue

            if st == 200 and len(body) > 10:
                detail = f"{label} at /{path}"
                with open(out,"a") as f: f.write(f"SENSITIVE: {url} | {detail}\n")
                self.p.add_finding("critical","SENSITIVE_FILE",url,detail,"content-v7", response=response, payload=payload)
                found += 1
        return found

    # ── Phase 3: JS file analysis ─────────────────────────────────────────────
    def _analyze_js_files(self, js_file: str, live: list, auth_h: dict, out: str) -> int:
        """
        Bug Hunter Methodology: extract hidden API endpoints and secrets from JS.
        """
        found      = 0
        js_urls    = safe_read(js_file)[:20] if js_file else []
        discovered = set()

        # Also find JS files from live hosts
        for host in live[:3]:
            for path in ["/static/js/main.js","/assets/js/app.js",
                         "/js/app.js","/bundle.js","/main.js"]:
                js_urls.append(host.rstrip("/") + path)

        for js_url in js_urls[:30]:
            try:
                req  = urllib.request.Request(
                    js_url, headers={**auth_h,
                                     "User-Agent": self.p.bypass.ua()})
                resp = urllib.request.urlopen(req, timeout=10)
                js   = resp.read(500000).decode("utf-8","ignore")
            except Exception:
                continue

            # Extract endpoints
            for pat in JS_ENDPOINT_PATTERNS:
                for m in pat.findall(js):
                    if m and m not in discovered and len(m) > 2:
                        discovered.add(m)
                        if m.startswith("/api") or m.startswith("/v"):
                            detail = f"JS endpoint: {m} from {js_url[:60]}"
                            with open(out,"a") as f: f.write(f"JS_ENDPOINT: {m} | {detail}\n")
                            self.p.add_finding("info","JS_ENDPOINT",m,detail,"js-analyzer", response=response, payload=payload)
                            found += 1

            # Extract secrets
            for pat, label in JS_SECRET_PATTERNS:
                matches = pat.findall(js)
                for match in matches[:3]:
                    val = match if isinstance(match,str) else str(match)
                    if val and val not in ("YOUR_KEY","EXAMPLE","undefined"):
                        detail = f"JS Secret ({label}): {val[:40]} in {js_url[:60]}"
                        with open(out,"a") as f: f.write(f"JS_SECRET: {js_url} | {detail}\n")
                        self.p.add_finding("critical","JS_SECRET",js_url,detail,"js-analyzer",
                                           payload=val[:40])
                        found += 1

        if discovered:
            self.p.log.info(f"  JS analysis: {len(discovered)} endpoints found")
        return found

    # ── Phase 4: Parameter discovery ─────────────────────────────────────────
    def _discover_params(self, urls: list, auth_h: dict, out: str) -> int:
        found = 0
        # arjun integration
        if shutil.which("arjun"):
            for url in urls[:5]:
                if "?" not in url:
                    result = self.p.shell(
                        f"arjun -u {url} --stable -q 2>/dev/null",
                        label="arjun param", timeout=60
                    )
                    if result and "[" in result:
                        detail = f"Parameters discovered: {result[:100]}"
                        with open(out,"a") as f: f.write(f"PARAMS: {url} | {detail}\n")
                        self.p.add_finding("info","PARAM_DISCOVERY",url,detail,"arjun", response=response, payload=payload)
                        found += 1
        return found

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _get_wordlist(self) -> str:
        for wl in [
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        ]:
            if os.path.isfile(wl):
                return wl
        # Write smart wordlist as fallback
        path = f"/tmp/m7hunter_smart.txt"
        with open(path,"w") as f:
            f.write("\n".join(SMART_WORDLIST))
        return path

    def _build_auth(self, p) -> dict:
        hdrs = {}
        c = getattr(p.args,"cookie",None) or getattr(p.args,"session",None)
        a = getattr(p.args,"authorization",None) or getattr(p.args,"auth",None)
        if c: hdrs["Cookie"] = c
        if a: hdrs["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        return hdrs
