#!/usr/bin/env python3
# modules/step16_github.py — GitHub Dorking V7 (UPGRADED)
# Added: TruffleHog integration, 30+ dorks, secret regex scanning, gitleaks
# Source: Bug Hunter's Methodology (Jason Haddix) — secret hunting methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, time, json, urllib.request, urllib.parse, shutil

# ── 30+ dorks (Bug Hunter Methodology: wide recon) ───────────────────────────
DORKS = [
    # Credentials
    "{target} password",
    "{target} passwd",
    "{target} secret",
    "{target} api_key OR apikey OR api-key",
    "{target} access_token OR accesstoken",
    "{target} auth_token OR authtoken",
    "{target} private_key OR privatekey",
    "{target} client_secret",
    # Cloud keys
    "{target} aws_access_key_id",
    "{target} aws_secret_access_key",
    "{target} AKIA",
    "{target} firebase",
    "{target} gcp OR google_cloud OR gcloud",
    # Database
    "{target} database_url OR DB_PASSWORD OR DATABASE_PASSWORD",
    "{target} mongodb+srv OR postgres:// OR mysql://",
    "{target} jdbc:",
    "{target} redis://",
    # Infrastructure
    "{target} BEGIN RSA PRIVATE KEY",
    "{target} BEGIN OPENSSH PRIVATE KEY",
    "{target} BEGIN EC PRIVATE KEY",
    "{target} id_rsa",
    # Services
    "{target} smtp_password OR email_password",
    "{target} twilio OR sendgrid OR mailgun",
    "{target} stripe OR paypal OR braintree",
    "{target} slack_token OR slack_webhook",
    "{target} discord_token OR telegram_token",
    # Config files
    "{target} .env extension:env",
    "{target} config.yml OR config.json OR settings.py",
    "{target} extension:pem certificate",
    "{target} extension:sql dump",
]

# ── Regex patterns for secret detection in code ───────────────────────────────
SECRET_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'),                      "critical","AWS_ACCESS_KEY"),
    (re.compile(r'["\'](?:aws)?_?secret_?(?:access)?_?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',re.I),
                                                            "critical","AWS_SECRET_KEY"),
    (re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY'),
                                                            "critical","PRIVATE_KEY"),
    (re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
                                                            "high",   "PASSWORD"),
    (re.compile(r'(?:api_?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9._\-]{20,})["\']',re.I),
                                                            "high",   "API_KEY"),
    (re.compile(r'(?:access_?token|auth_?token)\s*[:=]\s*["\']([A-Za-z0-9._\-]{20,})["\']',re.I),
                                                            "high",   "AUTH_TOKEN"),
    (re.compile(r'(?:database_url|db_url)\s*[:=]\s*["\']([^"\']{10,})["\']',re.I),
                                                            "critical","DB_URL"),
    (re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+',re.I),
                                                            "critical","MONGODB_URI"),
    (re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+',re.I),
                                                            "critical","POSTGRES_URI"),
    (re.compile(r'redis://[^:]*:[^@]+@[^\s"\']+',          re.I),
                                                            "high",   "REDIS_URI"),
    (re.compile(r'sk_live_[A-Za-z0-9]{20,}'),              "critical","STRIPE_KEY"),
    (re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,}'),        "high",   "SLACK_TOKEN"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                "high",   "GOOGLE_API_KEY"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'),                   "critical","GITHUB_PAT"),
    (re.compile(r'ghs_[A-Za-z0-9]{36}'),                   "high",   "GITHUB_APP_TOKEN"),
    (re.compile(r'github_pat_[A-Za-z0-9_]{82}'),           "critical","GITHUB_FINE_PAT"),
    (re.compile(r'EAACEdEose0cBA[A-Za-z0-9]+'),            "high",   "FACEBOOK_TOKEN"),
    (re.compile(r'[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com'),
                                                            "high",   "GOOGLE_OAUTH_ID"),
]


class GitHubDorkStep:
    def __init__(self, p):
        self.p   = p
        self.log = p.log
        self.f   = p.files

    def run(self):
        token  = (getattr(self.p.args,"github_token",None) or
                  getattr(self.p,"cfg",{}).get("github_token",""))
        target = (self.p.target.replace("https://","").replace("http://","")
                                .split("/")[0])
        out    = self.f["github_results"]

        self.log.info(f"GitHub V7: {len(DORKS)} dorks + secret regex scan")

        if not token:
            self.log.warn("GitHub: no token — limited search (add --github-token)")
            self._run_limited_search(target, out)
        else:
            self._run_full_search(target, token, out)

        # TruffleHog integration
        self._run_trufflehog(target, out)

        # Gitleaks integration
        self._run_gitleaks(target, out)

        n = sum(1 for _ in open(out) if _.strip()) if os.path.isfile(out) else 0
        self.log.success(f"GitHub V7: {n} secrets/findings")

    # ── Full search with token ─────────────────────────────────────────────────
    def _run_full_search(self, target: str, token: str, out: str):
        found = 0
        for dork_tpl in DORKS:
            dork    = dork_tpl.format(target=target)
            results = self._search(dork, token)
            if results is None:
                self.log.warn("GitHub: rate limited — waiting 60s")
                time.sleep(60)
                results = self._search(dork, token) or []

            for item in results[:3]:
                url      = item.get("html_url","?")
                repo     = item.get("repository",{}).get("full_name","?")
                fragment = item.get("text_matches",[{}])
                raw_url  = (f"https://raw.githubusercontent.com/"
                            f"{repo}/HEAD/{item.get('path','')}")

                # Download and scan content for secrets
                content = self._fetch_raw(raw_url, token)
                if content:
                    secrets = self._scan_for_secrets(content)
                    for sev, vtype, match in secrets:
                        detail = (f"Secret in {repo}: "
                                  f"{vtype}='{match[:40]}' at {url}")
                        with open(out,"a") as f:
                            f.write(f"GITHUB_SECRET: {url} | {detail}\n")
                        self.p.add_finding(sev,f"GITHUB_{vtype}",url,detail,"github-v7", response=response, payload=payload)
                        found += 1
                else:
                    # Log URL even without content
                    line = f"GITHUB_DORK: {url} | dork='{dork[:50]}'"
                    with open(out,"a") as f:
                        f.write(line+"\n")
                    self.p.add_finding("medium","GITHUB_SECRET_CANDIDATE",
                                       url, line, "github-v7", response=response, payload=payload)

            time.sleep(2.5)

    # ── Secret regex scanner ───────────────────────────────────────────────────
    def _scan_for_secrets(self, content: str) -> list:
        """Scan code content for secrets using regex patterns."""
        found = []
        for pattern, sev, vtype in SECRET_PATTERNS:
            matches = pattern.findall(content)
            for m in matches[:2]:
                val = m if isinstance(m, str) else m
                # Filter obvious placeholders
                if val and val not in ("YOUR_KEY","EXAMPLE","PLACEHOLDER",
                                       "xxxx","****","<key>"):
                    found.append((sev, vtype, str(val)[:60]))
        return found

    # ── TruffleHog ─────────────────────────────────────────────────────────────
    def _run_trufflehog(self, target: str, out: str):
        """TruffleHog: deep entropy + regex secret scanner."""
        if not shutil.which("trufflehog"):
            return
        self.log.info("  ↳ TruffleHog scanning...")
        self.p.shell(
            f"trufflehog github --org={target} --only-verified "
            f"--json 2>/dev/null | head -50",
            label="trufflehog", append_file=out, timeout=180
        )
        # Also scan as user
        self.p.shell(
            f"trufflehog github --repo=https://github.com/{target} "
            f"--only-verified --json 2>/dev/null | head -50",
            label="trufflehog repo", append_file=out, timeout=120
        )

    # ── Gitleaks ───────────────────────────────────────────────────────────────
    def _run_gitleaks(self, target: str, out: str):
        """Gitleaks: high-performance secret scanner."""
        if not shutil.which("gitleaks"):
            return
        self.log.info("  ↳ Gitleaks scanning...")
        repo_dir = os.path.join(self.p.out, f"{self.p.prefix}_gitrepos")
        os.makedirs(repo_dir, exist_ok=True)
        # Detect secrets in any cloned repos
        self.p.shell(
            f"gitleaks detect --source={repo_dir} "
            f"--report-path={out} --report-format=json --no-git 2>/dev/null",
            label="gitleaks", timeout=120
        )

    # ── Search API ─────────────────────────────────────────────────────────────
    def _search(self, query: str, token: str) -> list:
        url    = ("https://api.github.com/search/code?q="
                  + urllib.parse.quote(query) + "&per_page=5")
        try:
            req = urllib.request.Request(url, headers={
                "Authorization": f"token {token}",
                "Accept":        "application/vnd.github.v3.text-match+json",
                "User-Agent":    "M7Hunter/7.0",
            })
            resp = urllib.request.urlopen(req, timeout=15)
            data = json.loads(resp.read())
            return data.get("items",[])
        except urllib.request.HTTPError as e:
            if e.code == 403:
                return None  # rate limited
            return []
        except Exception:
            return []

    def _fetch_raw(self, url: str, token: str) -> str:
        try:
            req = urllib.request.Request(url, headers={
                "Authorization": f"token {token}",
                "User-Agent":    "M7Hunter/7.0",
            })
            resp = urllib.request.urlopen(req, timeout=10)
            return resp.read(200000).decode("utf-8","ignore")
        except Exception:
            return ""

    def _run_limited_search(self, target: str, out: str):
        """Unauthenticated search — very limited."""
        for dork in DORKS[:3]:
            q   = dork.format(target=target)
            url = (f"https://api.github.com/search/code?q="
                   + urllib.parse.quote(q) + "&per_page=3")
            try:
                req  = urllib.request.Request(url, headers={
                    "User-Agent": "M7Hunter/7.0",
                    "Accept":     "application/vnd.github.v3+json",
                })
                resp = urllib.request.urlopen(req, timeout=10)
                data = json.loads(resp.read())
                for item in data.get("items",[])[:2]:
                    line = f"GITHUB_HIT: {item.get('html_url','?')}"
                    with open(out,"a") as f:
                        f.write(line+"\n")
            except Exception:
                pass
            time.sleep(10)
