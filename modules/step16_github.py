#!/usr/bin/env python3
# modules/step16_github.py — GitHub Dorking v6 (FIXED)
# FIX: Skip ALL dorks if no token — no more 401 spam in logs
# FIX: Rate limit respected (unauthenticated = 10 req/min, token = 30/min)
# FIX: Added fallback to unauthenticated basic search (limited but working)
# MilkyWay Intelligence | Author: Sharlix

import os
import time
import urllib.request
import urllib.parse
import json

class GitHubDorkStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    DORKS = [
        "{target} password",
        "{target} secret",
        "{target} api_key OR apikey",
        "{target} access_token",
        "{target} private_key",
        "{target} aws_access_key_id",
        "{target} database_url OR DB_PASSWORD",
        "{target} smtp_password",
        "{target} firebase",
        "{target} BEGIN RSA PRIVATE KEY",
    ]

    def run(self):
        token  = getattr(self.p.args,"github_token",None) or self.p.cfg.get("github_token","")
        target = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        out    = self.f["github_results"]

        # FIX: If no token, do limited search or skip entirely
        if not token:
            self.log.warn("GitHub: no token — running limited unauthenticated search")
            self.log.warn("  → Add --github-token to get full results")
            # Try just 2 dorks unauthenticated (60s delay between each)
            self._run_limited_search(target, out)
            return

        self.log.info(f"GitHub dorking: {len(self.DORKS)} dorks with token")
        found = 0
        delay = 2.5  # Authenticated = 30 req/min → 2s between calls

        for dork_tpl in self.DORKS:
            dork = dork_tpl.format(target=target)
            results = self._search(dork, token)
            if results is None:  # Rate limited
                self.log.warn("GitHub: rate limited — waiting 60s")
                time.sleep(60)
                results = self._search(dork, token) or []

            for item in results[:3]:
                repo_name = item.get("repository",{}).get("full_name","?")
                file_name = item.get("name","?")
                html_url  = item.get("html_url","?")
                line = f"{dork[:50]} → {html_url}"
                with open(out,"a") as f:
                    f.write(line+"\n")
                self.p.add_finding("high","GITHUB_EXPOSURE", html_url,
                                   f"Dork: {dork[:50]} | repo: {repo_name} | file: {file_name}",
                                   "github-dork")
                found += 1

            time.sleep(delay)

        self.log.success(f"GitHub: {found} exposed items")

    def _run_limited_search(self, target: str, out: str):
        """FIX: Unauthenticated search — only 2 dorks, 20s apart."""
        limited_dorks = [
            f'"{target}" filename:.env',
            f'"{target}" api_key',
        ]
        found = 0
        for dork in limited_dorks:
            results = self._search(dork, token=None)
            if results:
                for item in results[:2]:
                    html_url = item.get("html_url","?")
                    with open(out,"a") as f:
                        f.write(f"{dork} → {html_url}\n")
                    self.p.add_finding("high","GITHUB_EXPOSURE", html_url,
                                       f"Dork (no token): {dork[:50]}", "github-dork")
                    found += 1
            else:
                break  # Stop on first rate limit/error
            time.sleep(20)  # Unauthenticated rate limit

        if found == 0:
            self.log.info("GitHub: no results (add --github-token for full search)")
        return found

    def _search(self, query: str, token: str | None) -> list | None:
        """
        FIX: Returns None on rate limit (caller handles retry).
        Returns [] on 401 instead of crashing logs with errors.
        """
        try:
            q   = urllib.parse.quote(query)
            url = f"https://api.github.com/search/code?q={q}&per_page=3"
            headers = {
                "Accept"    : "application/vnd.github.v3+json",
                "User-Agent": "M7Hunter/6.0",
            }
            if token:
                headers["Authorization"] = f"token {token}"

            req  = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=15)
            data = json.loads(resp.read().decode())
            return data.get("items", [])

        except urllib.error.HTTPError as e:
            if e.code == 401:
                # FIX: Silent fail on 401 — token invalid
                self.log.warn("GitHub: token invalid — check your --github-token")
                return []
            elif e.code == 403:
                # Rate limited
                return None
            elif e.code == 422:
                # Unprocessable query
                return []
            return []
        except Exception:
            return []
