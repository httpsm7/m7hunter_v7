#!/usr/bin/env python3
# core/scope_engine.py — Scope Validation Engine
# Blueprint: regex/wildcard scope rules, strict out-of-scope branch pruning
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import re
from urllib.parse import urlparse
from core.error_handler import get_handler

class ScopeEngine:
    """
    Blueprint: Strict scope validation.
    Every URL is checked before any engine processes it.
    Out-of-scope URLs are pruned from all queues.

    Supports:
    - Wildcard patterns   : *.example.com
    - Exact domain        : example.com
    - CIDR ranges         : 10.0.0.0/8
    - Regex patterns      : ^api\\.example\\.com$
    - Exclusion rules     : !staging.example.com
    """

    def __init__(self, target: str, scope_file: str = None,
                 extra_scope: list = None, log=None):
        self.log         = log
        self._include    = []   # compiled patterns → in scope
        self._exclude    = []   # compiled patterns → explicitly excluded
        self._cidr_ranges= []
        self._target     = target.replace("https://","").replace("http://","").split("/")[0]

        # Always include the primary target
        self._add_pattern(self._target)

        # Load scope file
        if scope_file:
            self._load_file(scope_file)

        # Extra CLI scope
        for s in (extra_scope or []):
            if s.startswith("!"):
                self._add_exclusion(s[1:])
            else:
                self._add_pattern(s)

    def _load_file(self, path: str):
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("!"):
                        self._add_exclusion(line[1:])
                    else:
                        self._add_pattern(line)
            if self.log:
                self.log.info(f"[Scope] Loaded: {path} "
                              f"({len(self._include)} in, {len(self._exclude)} out)")
        except Exception as e:
            get_handler().capture("scope_engine", e, f"load_file:{path}")

    def _add_pattern(self, pattern: str):
        """Convert wildcard/domain pattern to regex."""
        try:
            if "/" in pattern and pattern.replace(".","").replace("/","").isdigit():
                # CIDR range
                self._cidr_ranges.append(pattern)
                return
            # Wildcard → regex
            regex = pattern.replace(".", "\\.").replace("*", "[^.]+")
            if not regex.startswith("^"):
                regex = f"(^|\\.){regex}$"
            self._include.append(re.compile(regex, re.IGNORECASE))
        except Exception as e:
            get_handler().capture("scope_engine", e, f"add_pattern:{pattern}")

    def _add_exclusion(self, pattern: str):
        try:
            regex = pattern.replace(".", "\\.").replace("*", "[^.]+")
            if not regex.startswith("^"):
                regex = f"(^|\\.){regex}$"
            self._exclude.append(re.compile(regex, re.IGNORECASE))
        except Exception as e:
            get_handler().capture("scope_engine", e, f"add_exclusion:{pattern}")

    # ── Public API ────────────────────────────────────────────────────
    def is_in_scope(self, url_or_host: str) -> bool:
        """
        Returns True only if the URL/host is in scope AND not excluded.
        Blueprint: strict pruning — when in doubt, exclude.
        """
        try:
            host = self._extract_host(url_or_host)
            if not host:
                return False

            # Check exclusions first
            for excl in self._exclude:
                if excl.search(host):
                    return False

            # Check inclusions
            for inc in self._include:
                if inc.search(host):
                    return True

            # Check CIDR
            if self._cidr_ranges:
                ip = self._resolve_ip(host)
                if ip and self._in_cidr(ip):
                    return True

            return False
        except Exception as e:
            get_handler().capture("scope_engine", e, f"is_in_scope:{url_or_host[:60]}")
            return False

    def filter_urls(self, urls: list) -> tuple[list, list]:
        """
        Split url list into (in_scope, out_of_scope).
        Use this to prune entire URL lists before passing to engines.
        """
        in_scope  = []
        out_scope = []
        for url in urls:
            (in_scope if self.is_in_scope(url) else out_scope).append(url)
        if self.log and out_scope:
            self.log.info(f"[Scope] Pruned {len(out_scope)} out-of-scope URLs "
                          f"({len(in_scope)} remain)")
        return in_scope, out_scope

    def filter_file(self, path: str) -> int:
        """
        Rewrite a URL file in-place, keeping only in-scope lines.
        Returns number of lines removed.
        Blueprint: strict out-of-scope branch pruning.
        """
        try:
            import os
            if not os.path.isfile(path):
                return 0
            with open(path) as f:
                lines = [l.strip() for l in f if l.strip()]
            in_scope, out_scope = self.filter_urls(lines)
            with open(path, "w") as f:
                f.write("\n".join(in_scope) + ("\n" if in_scope else ""))
            return len(out_scope)
        except Exception as e:
            get_handler().capture("scope_engine", e, f"filter_file:{path}")
            return 0

    def assert_in_scope(self, url: str):
        """Raise ValueError if URL is out of scope. Use as a hard guard."""
        if not self.is_in_scope(url):
            raise ValueError(f"OUT OF SCOPE: {url}")

    # ── Helpers ───────────────────────────────────────────────────────
    @staticmethod
    def _extract_host(url_or_host: str) -> str:
        if "://" in url_or_host:
            return urlparse(url_or_host).hostname or ""
        return url_or_host.split(":")[0].split("/")[0]

    @staticmethod
    def _resolve_ip(host: str) -> str:
        try:
            import socket
            return socket.gethostbyname(host)
        except Exception:
            return ""

    def _in_cidr(self, ip: str) -> bool:
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            for cidr in self._cidr_ranges:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("scope_engine", _e)
        return False

    def summary(self) -> str:
        return (f"Scope: {len(self._include)} include patterns, "
                f"{len(self._exclude)} exclude patterns, "
                f"{len(self._cidr_ranges)} CIDR ranges")
