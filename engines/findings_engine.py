#!/usr/bin/env python3
# engines/findings_engine.py — M7Hunter v6 Findings Engine
# FIX: Findings = 0 bug — centralized finding registry with dedup + priority
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
import threading
import hashlib
from datetime import datetime

# ── Severity tiers (bug bounty priority order) ────────────────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEVERITY_COLORS = {
    "critical": "\033[91m\033[1m",
    "high"    : "\033[91m",
    "medium"  : "\033[93m",
    "low"     : "\033[92m",
    "info"    : "\033[96m",
}
RST = "\033[0m"

# ── Vulnerability type → severity mapping ────────────────────────────
VULN_SEVERITY_MAP = {
    # Critical
    "IDOR_ATO"              : "critical",
    "SQLI_CONFIRMED"        : "critical",
    "RCE_CONFIRMED"         : "critical",
    "SSRF_AWS"              : "critical",
    "SSRF_GCP"              : "critical",
    "SSRF_AZURE"            : "critical",
    "LFI_UNIX_PASSWD"       : "critical",
    "LFI_PRIVATE_KEY"       : "critical",
    "LFI_ENV_FILE"          : "critical",
    "JWT_ALG_NONE_BYPASS"   : "critical",
    "SSTI_RCE"              : "critical",
    "SUBDOMAIN_TAKEOVER"    : "critical",
    "OPEN_S3_BUCKET"        : "critical",
    "FIREBASE_OPEN_DB"      : "critical",
    "NOSQL_INJECTION"       : "critical",
    "XXE"                   : "critical",
    "HTTP_SMUGGLING_CLTE"   : "critical",
    "HTTP_SMUGGLING_TECL"   : "critical",
    "RACE_TRANSFER_DOUBLE"  : "critical",
    # High
    "IDOR"                  : "high",
    "IDOR_CONFIRMED"        : "high",
    "XSS"                   : "high",
    "SSRF"                  : "high",
    "LFI"                   : "high",
    "HOST_HEADER_INJECTION" : "high",
    "PASSWORD_RESET_POISONING": "high",
    "CORS_MISCONFIG"        : "high",
    "JWT_WEAK_SECRET"       : "high",
    "GITHUB_EXPOSURE"       : "high",
    "CSRF_MISSING_TOKEN"    : "high",
    "CSRF_API_NO_PROTECTION": "high",
    "NOSQL_PARAM_INJECTION" : "high",
    "GRAPHQL_INTROSPECTION" : "high",
    "OPEN_REDIRECT_CSRF"    : "high",
    "CRLF_INJECTION"        : "high",
    "RACE_VOTE_STUFFING"    : "high",
    # Medium
    "OPEN_REDIRECT"         : "medium",
    "CORS_VARY_MISSING"     : "medium",
    "CSRF_SAMESITE_NONE"    : "medium",
    "JWT_NO_EXPIRY"         : "medium",
    "CSRF_REFERER_BYPASS"   : "medium",
    "WORDPRESS"             : "medium",
    "EXPOSED_SERVICE"       : "medium",
    "AZURE_BLOB_EXISTS"     : "medium",
    # Low
    "JS_SECRETS"            : "low",
    "EXISTS_S3"             : "low",
    "NUCLEI"                : "low",
    "INFO"                  : "info",
}

# ── Impact descriptions for report ───────────────────────────────────
IMPACT_MAP = {
    "IDOR"             : "Unauthorized access to other users' data — potential account takeover",
    "IDOR_ATO"         : "Full account takeover via IDOR chain",
    "SSRF_AWS"         : "Cloud credentials theft — full AWS account compromise possible",
    "SQLI_CONFIRMED"   : "Database dump, authentication bypass, possible RCE",
    "LFI_UNIX_PASSWD"  : "Server file read — credentials, configs, private keys exposed",
    "SSTI_RCE"         : "Remote code execution on server",
    "CRLF_INJECTION"   : "Header injection → cache poisoning → phishing → session hijack",
    "OPEN_REDIRECT"    : "Phishing via trusted domain, OAuth token theft",
    "CORS_MISCONFIG"   : "Cross-origin data theft from authenticated sessions",
    "XSS"              : "Session hijack, credential theft, keylogging",
    "CSRF_MISSING_TOKEN": "Attacker forces authenticated actions on behalf of victim",
    "NOSQL_INJECTION"  : "Authentication bypass, data exfiltration from MongoDB",
    "HTTP_SMUGGLING_CLTE": "Cache poisoning, session hijack, request queue poisoning",
}


class FindingsEngine:
    """
    Central findings registry.
    - Thread-safe
    - Deduplication
    - Auto-severity assignment
    - Priority ordering
    - FIX: Findings count is always accurate
    """

    def __init__(self):
        self._findings  : list  = []
        self._seen      : set   = set()
        self._lock      = threading.Lock()
        self._stats     = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.start_time = time.time()

    # ── Core API ─────────────────────────────────────────────────────

    def add(self, vuln_type: str, url: str, detail: str = "",
            payload: str = "", tool: str = "", response: str = "",
            confidence: float = 0.8, severity: str = None,
            status: str = "potential", proof: dict = None) -> bool:
        """
        Add a finding. Returns True if new (not duplicate).
        Severity auto-assigned from vuln_type if not provided.
        """
        # Auto-assign severity from map
        if not severity:
            # Normalize vuln_type for lookup
            vt_upper = vuln_type.upper().replace(" ", "_")
            severity = VULN_SEVERITY_MAP.get(vt_upper, "info")

        # Dedup key: type + url + first 50 chars of payload
        dedup_key = hashlib.md5(
            f"{vuln_type}:{url}:{payload[:50]}".encode()
        ).hexdigest()

        with self._lock:
            if dedup_key in self._seen:
                return False
            self._seen.add(dedup_key)

            entry = {
                "id"         : f"F{len(self._findings)+1:04d}",
                "severity"   : severity,
                "vuln_type"  : vuln_type,
                "url"        : url,
                "detail"     : detail,
                "payload"    : payload,
                "tool"       : tool,
                "confidence" : round(confidence, 2),
                "status"     : status,
                "impact"     : IMPACT_MAP.get(vuln_type, f"Security vulnerability: {vuln_type}"),
                "timestamp"  : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "response_snippet": response[:300] if response else "",
                "proof"      : proof or {},
                "chain_hints": self._get_chain_hints(vuln_type),
                "repro_steps": self._get_repro_steps(vuln_type, url, payload),
            }
            self._findings.append(entry)
            self._stats[severity] = self._stats.get(severity, 0) + 1

        return True

    def mark_confirmed(self, finding_id: str, proof: dict = None):
        """Upgrade finding status to confirmed."""
        with self._lock:
            for f in self._findings:
                if f["id"] == finding_id:
                    f["status"] = "confirmed"
                    if proof:
                        f["proof"].update(proof)
                    break

    def get_all(self, min_severity: str = None, status: str = None) -> list:
        """Get findings sorted by severity."""
        with self._lock:
            results = list(self._findings)

        # Filter
        if min_severity:
            threshold = SEVERITY_ORDER.get(min_severity, 4)
            results = [f for f in results
                       if SEVERITY_ORDER.get(f["severity"], 4) <= threshold]
        if status:
            results = [f for f in results if f["status"] == status]

        # Sort: severity first, then confidence descending
        return sorted(results, key=lambda f: (
            SEVERITY_ORDER.get(f["severity"], 4),
            -f.get("confidence", 0)
        ))

    def get_stats(self) -> dict:
        """FIX: Accurate finding counts (was always 0 before)."""
        with self._lock:
            total = sum(self._stats.values())
            return {
                "total"    : total,
                "critical" : self._stats.get("critical", 0),
                "high"     : self._stats.get("high", 0),
                "medium"   : self._stats.get("medium", 0),
                "low"      : self._stats.get("low", 0),
                "info"     : self._stats.get("info", 0),
                "confirmed": sum(1 for f in self._findings if f["status"] == "confirmed"),
                "potential": sum(1 for f in self._findings if f["status"] == "potential"),
            }

    def print_live(self, finding: dict):
        """Print finding to console with color."""
        sev   = finding["severity"]
        col   = SEVERITY_COLORS.get(sev, "")
        vtype = finding["vuln_type"]
        url   = finding["url"][:70]
        detail = finding.get("detail","")[:60]
        fid   = finding["id"]
        ts    = finding["timestamp"].split(" ")[1]

        print(f"\033[2m[{ts}]\033[0m {col}[{sev.upper():8s}]{RST} "
              f"\033[93m{fid}\033[0m \033[97m{vtype}\033[0m → "
              f"\033[96m{url}\033[0m"
              + (f" \033[2m{detail}\033[0m" if detail else ""))

    def print_summary(self):
        """Print final summary table."""
        stats = self.get_stats()
        elapsed = round(time.time() - self.start_time, 1)

        print(f"\n\033[34m{'═'*70}\033[0m")
        print(f"\033[97m\033[1m  FINDINGS SUMMARY\033[0m")
        print(f"\033[34m{'═'*70}\033[0m")

        if stats["total"] == 0:
            print(f"  \033[93m[!] No findings. Try --deep mode or check scope.\033[0m")
        else:
            print(f"  \033[91m\033[1mCRITICAL : {stats['critical']:>4}\033[0m")
            print(f"  \033[91mHIGH     : {stats['high']:>4}\033[0m")
            print(f"  \033[93mMEDIUM   : {stats['medium']:>4}\033[0m")
            print(f"  \033[92mLOW      : {stats['low']:>4}\033[0m")
            print(f"  ─────────────────")
            print(f"  \033[97mTOTAL    : {stats['total']:>4}\033[0m")
            print(f"  CONFIRMED: {stats['confirmed']:>4}")
            print(f"  POTENTIAL: {stats['potential']:>4}")

        print(f"\n  \033[2mScan time: {elapsed}s\033[0m")
        print(f"\033[34m{'═'*70}\033[0m\n")

    # ── Chain hints ──────────────────────────────────────────────────

    def _get_chain_hints(self, vuln_type: str) -> list:
        """Suggest attack chains based on vulnerability type."""
        chains = {
            "IDOR": [
                "IDOR → change victim email → password reset → Account Takeover",
                "IDOR + XSS → stored payload in victim account → session hijack",
            ],
            "OPEN_REDIRECT": [
                "Open Redirect → OAuth token theft (redirect_uri bypass)",
                "Open Redirect + CRLF → cache poisoning → mass phishing",
            ],
            "SSRF": [
                "SSRF → cloud metadata → credentials → full infrastructure access",
                "SSRF → internal services (Redis/Elasticsearch) → data dump",
            ],
            "CORS_MISCONFIG": [
                "CORS + XSS → cross-origin credential theft",
                "CORS misconfiguration → read sensitive API responses from attacker site",
            ],
            "LFI": [
                "LFI → /proc/self/environ → log poisoning → RCE",
                "LFI → /etc/passwd + /etc/shadow → credential cracking",
            ],
            "NOSQL_INJECTION": [
                "NoSQL Auth Bypass → admin access → data dump",
                "NoSQL + IDOR → full user database enumeration",
            ],
            "XSS": [
                "XSS → steal session cookies → account takeover",
                "XSS + CSRF bypass → forced actions as victim",
            ],
        }
        # Normalize key
        key = vuln_type.split("_")[0]
        return chains.get(vuln_type, chains.get(key, []))

    def _get_repro_steps(self, vuln_type: str, url: str, payload: str) -> list:
        """Generate reproduction steps for report."""
        base = [
            f"1. Navigate to: {url}",
            f"2. Intercept request in Burp Suite",
            f"3. Apply payload: {payload[:100] if payload else 'see detail'}",
            "4. Observe response for vulnerability indicators",
        ]

        specific = {
            "IDOR": [
                "1. Login as User A (attacker), capture user_id from response",
                f"2. Send request to: {url}",
                "3. Replace own user_id with victim's user_id",
                "4. Observe: victim data returned → IDOR confirmed",
            ],
            "SSRF": [
                f"1. Identify URL parameter at: {url}",
                f"2. Replace value with: {payload or 'http://169.254.169.254/latest/meta-data/'}",
                "3. Forward request",
                "4. Check response for AWS/GCP/Azure metadata",
            ],
            "XSS": [
                f"1. Navigate to: {url}",
                f"2. Inject payload: {payload or '<svg/onload=alert(1)>'}",
                "3. If alert fires — reflected XSS confirmed",
                "4. For stored XSS: check if payload persists after page reload",
            ],
            "OPEN_REDIRECT": [
                f"1. Navigate to: {url}",
                "2. Observe browser redirects to attacker-controlled domain",
                "3. Can be used for phishing using trusted domain name",
            ],
        }

        key = vuln_type.split("_")[0]
        return specific.get(vuln_type, specific.get(key, base))

    # ── Export ───────────────────────────────────────────────────────

    def to_json(self) -> dict:
        """Export full findings to dict."""
        return {
            "generated"    : datetime.now().isoformat(),
            "stats"        : self.get_stats(),
            "findings"     : self.get_all(),
        }

    def save(self, path: str):
        """Save findings to JSON file."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_json(), f, indent=2)

    def load(self, path: str):
        """Load findings from JSON file (for resume/merge)."""
        if not os.path.isfile(path):
            return
        try:
            with open(path) as f:
                data = json.load(f)
            for finding in data.get("findings", []):
                self.add(
                    vuln_type  = finding.get("vuln_type",""),
                    url        = finding.get("url",""),
                    detail     = finding.get("detail",""),
                    payload    = finding.get("payload",""),
                    tool       = finding.get("tool",""),
                    confidence = finding.get("confidence", 0.8),
                    severity   = finding.get("severity"),
                    status     = finding.get("status","potential"),
                )
        except Exception as e:
            pass
