#!/usr/bin/env python3
# core/session_manager.py — Multi-Session Authentication Manager v6
# Supports: --cookie, --userA, --userB, multiple auth contexts
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import base64
import urllib.parse
from typing import Optional


class SessionManager:
    """
    Authentication Context Manager.
    
    Supports:
    - Single cookie session (--cookie)
    - Authorization header (--authorization)
    - Dual session (--userA / --userB) for IDOR testing
    - Cookie file input
    - Multiple named sessions
    """

    def __init__(self, args):
        self.args     = args
        self._sessions = {}
        self._load_all()

    def _load_all(self):
        """Load all session types from args."""
        # Primary session (attacker/default)
        primary = self._build_headers(
            cookie        = getattr(self.args,"cookie",None),
            authorization = getattr(self.args,"authorization",None),
            cookie_file   = getattr(self.args,"cookie_file",None),
        )
        self._sessions["default"] = primary
        self._sessions["userA"]   = primary  # attacker

        # Secondary session (victim) — for IDOR multi-session testing
        userB_cookie = getattr(self.args,"userB",None) or \
                       getattr(self.args,"cookie_b",None)
        userB_file   = getattr(self.args,"userB_file",None)

        if userB_cookie or userB_file:
            victim = self._build_headers(
                cookie      = userB_cookie,
                cookie_file = userB_file,
            )
            self._sessions["userB"] = victim
            self._sessions["victim"] = victim

        # Load extra sessions from file (--sessions-file sessions.json)
        sessions_file = getattr(self.args,"sessions_file",None)
        if sessions_file and os.path.isfile(sessions_file):
            self._load_sessions_file(sessions_file)

    def _build_headers(self, cookie: str = None, authorization: str = None,
                       cookie_file: str = None) -> dict:
        """Build HTTP headers dict from auth params."""
        headers = {
            "User-Agent"    : "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
            "Accept"        : "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection"    : "keep-alive",
        }

        # Cookie from file
        if cookie_file and os.path.isfile(cookie_file):
            cookie = self._parse_cookie_file(cookie_file) or cookie

        # Apply cookie
        if cookie:
            headers["Cookie"] = cookie

        # Authorization header
        if authorization:
            if not authorization.startswith(("Bearer","Basic","Token")):
                authorization = f"Bearer {authorization}"
            headers["Authorization"] = authorization

        # Custom headers from args
        custom_headers_file = getattr(self.args,"headers",None)
        if custom_headers_file and os.path.isfile(custom_headers_file):
            with open(custom_headers_file) as f:
                for line in f:
                    if ":" in line:
                        k, _, v = line.strip().partition(":")
                        headers[k.strip()] = v.strip()

        return headers

    def _parse_cookie_file(self, path: str) -> Optional[str]:
        """Parse Netscape/JSON cookie file."""
        try:
            # Try JSON first
            with open(path) as f:
                content = f.read().strip()

            if content.startswith("[") or content.startswith("{"):
                cookies = json.loads(content)
                if isinstance(cookies, list):
                    parts = [f"{c.get('name','')}={c.get('value','')}"
                             for c in cookies if c.get('name')]
                    return "; ".join(parts)
                elif isinstance(cookies, dict):
                    return "; ".join(f"{k}={v}" for k,v in cookies.items())

            # Netscape format: domain TAB flag TAB path TAB secure TAB expiry TAB name TAB value
            parts = []
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("#") or not line: continue
                fields = line.split("\t")
                if len(fields) >= 7:
                    parts.append(f"{fields[5]}={fields[6]}")
                elif "=" in line and not line.startswith("#"):
                    # Simple key=value format
                    parts.append(line)

            return "; ".join(parts) if parts else None

        except Exception:
            return None

    def _load_sessions_file(self, path: str):
        """Load multiple named sessions from JSON file."""
        try:
            with open(path) as f:
                sessions_data = json.load(f)
            for name, data in sessions_data.items():
                self._sessions[name] = self._build_headers(
                    cookie        = data.get("cookie"),
                    authorization = data.get("authorization"),
                )
        except Exception:
            pass

    # ── Public API ───────────────────────────────────────────────────

    def get(self, session_name: str = "default") -> dict:
        """Get headers for a named session."""
        return dict(self._sessions.get(session_name, self._sessions.get("default",{})))

    def get_userA(self) -> dict:
        """Get attacker/userA session headers."""
        return self.get("userA")

    def get_userB(self) -> dict:
        """Get victim/userB session headers. Returns None if not configured."""
        return self.get("userB") if "userB" in self._sessions else None

    def has_multi_session(self) -> bool:
        """Check if two different sessions are configured for IDOR testing."""
        return "userB" in self._sessions

    def is_authenticated(self) -> bool:
        """Check if any auth credentials are configured."""
        headers = self.get("default")
        return bool(headers.get("Cookie") or headers.get("Authorization"))

    def list_sessions(self) -> list:
        return list(self._sessions.keys())

    def add_session(self, name: str, cookie: str = None, authorization: str = None):
        """Dynamically add a session (e.g. discovered during scan)."""
        self._sessions[name] = self._build_headers(
            cookie=cookie, authorization=authorization)

    def make_request_headers(self, session_name: str = "default",
                              extra_headers: dict = None) -> dict:
        """Build complete headers for a request."""
        headers = self.get(session_name)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def describe(self) -> str:
        """Return human-readable description of sessions."""
        parts = []
        for name, headers in self._sessions.items():
            if name in ("userA","victim"): continue
            auth_type = "cookie" if headers.get("Cookie") else \
                        "bearer" if headers.get("Authorization") else "none"
            parts.append(f"{name}({auth_type})")
        return ", ".join(parts) if parts else "unauthenticated"
